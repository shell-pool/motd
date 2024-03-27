// We use pam-sys directly rather than higher level wrapper crates
// like pam or pam-client because we are only going to use libpam
// to get a PamHandle so that we can directly dlopen and call into
// pam_motd.so. I tried making a pam service that only contains pam_motd.so
// in its service config file, but it prompted me for a username and password
// anyway. Displaying the motd should not require credentials. By manually
// loading pam_motd.so we can avoid this.

use std::{
    env, ffi,
    fmt::Debug,
    fs, io,
    io::Write,
    mem,
    path::{Path, PathBuf},
    process::Command,
    ptr, slice,
};

use dlopen2::wrapper::WrapperApi;
use log::warn;
use pam_sys::types::{PamMessageStyle, PamReturnCode};
use serde_derive::{Deserialize, Serialize};

use crate::{ArgResolutionStrategy, Error};

const PAM_MOTD_NAME: &str = "pam_motd.so";
const LIB_DIR: &str = "/usr/lib";

const PAM_MOTD_SO_ARG_ENV_VAR: &str = "RUST_MOTD_CRATE__INTERNAL__PAM_MOTD_SO_ARG";
const ARG_RESOLVER_ARG_ENV_VAR: &str = "RUST_MOTD_CRATE__INTERNAL__ARG_RESOLVER_ARG";

macro_rules! merr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

/// Resolver knows how to fetch the current motd by re-execing
/// the current binary to get handle_reexec to call pam_motd.so.
#[derive(Debug, Clone)]
pub struct Resolver {
    pam_motd_so_path: PathBuf,
}

impl Resolver {
    /// Create a new Resolver based on the given strategy for
    /// finding pam_motd.so. The path to the file will be cached
    /// since some strategies for finding the shared library can
    /// be fairly expensive.
    pub fn new(so_finder: PamMotdResolutionStrategy) -> Result<Self, Error> {
        Ok(Resolver {
            pam_motd_so_path: so_finder.resolve()?,
        })
    }

    /// Get the current value of the motd. Works by re-execing
    /// the current binary in order to use the LD_PRELOAD trick,
    /// so make sure you have called `motd::handle_reexec()`
    /// in your main function.
    pub fn value(&self, arg_resolver: ArgResolutionStrategy) -> Result<String, Error> {
        let overlay_so = OverlaySo::new()?;

        let arg_resolver_json = serde_json::to_string(&arg_resolver)
            .map_err(|e| merr!("serializing arg_resolver: {}", e))?;
        let out = Command::new("/proc/self/exe")
            .env(
                PAM_MOTD_SO_ARG_ENV_VAR,
                self.pam_motd_so_path
                    .to_str()
                    .ok_or(merr!("could not convert so path to str"))?,
            )
            .env(ARG_RESOLVER_ARG_ENV_VAR, arg_resolver_json)
            .env("LD_PRELOAD", overlay_so.path())
            .output()
            .map_err(|e| merr!("error re-execing self: {}", e))?;

        if !out.status.success() {
            return Err(merr!("failed to re-exec, bad status = {}", out.status));
        }

        if !out.stderr.is_empty() {
            println!("{}", String::from_utf8_lossy(out.stdout.as_slice()));

            let stderr = String::from_utf8_lossy(out.stderr.as_slice());
            return Err(merr!("in re-execed process: {}", stderr));
        }

        if !out.stdout.is_empty() {
            return Ok(String::from_utf8_lossy(out.stdout.as_slice()).into());
        }

        Err(merr!("no motd output"))
    }
}

/// You MUST call this routine in the main function of the binary that uses
/// the motd crate. In order to work around an issue where `pam_motd.so` thinks
/// it is running as root, we use LD_PRELOAD to stub out some privilege
/// juggling methods. To do this, the value() routine re-execs the current binary,
/// and it is in this re-execd process that we actually load and call into
/// `pam_motd.so`.
pub fn handle_reexec() {
    if let (Ok(pam_motd_so), Ok(arg_resolver_json)) = (
        env::var(PAM_MOTD_SO_ARG_ENV_VAR),
        env::var(ARG_RESOLVER_ARG_ENV_VAR),
    ) {
        match reexec_call_so(pam_motd_so.as_str(), arg_resolver_json.as_str()) {
            Ok(motd_msg) => print!("{}", motd_msg),
            Err(e) => eprintln!("{}", e),
        }
        std::process::exit(0);
    }
}

/// Actually load and call the `pam_motd.so`
fn reexec_call_so(pam_motd_so: &str, arg_resolver_json: &str) -> Result<String, Error> {
    let pam_motd_so = PathBuf::from(pam_motd_so);
    let arg_resolver: ArgResolutionStrategy = serde_json::from_str(arg_resolver_json)
        .map_err(|e| merr!("parsing arg_resolver arg: {}", e))?;

    let mut conv_data = ConvData::new();
    let pam_conv = pam_sys::types::PamConversation {
        conv: Some(conv_handler),
        data_ptr: &mut conv_data as *mut ConvData as *mut libc::c_void,
    };

    let mut passwd_str_buf: [libc::c_char; 1024 * 4] = [0; 1024 * 4];
    let mut passwd = libc::passwd {
        pw_name: ptr::null_mut(),
        pw_passwd: ptr::null_mut(),
        pw_uid: 0,
        pw_gid: 0,
        pw_gecos: ptr::null_mut(),
        pw_dir: ptr::null_mut(),
        pw_shell: ptr::null_mut(),
    };
    let mut passwd_res_ptr: *mut libc::passwd = ptr::null_mut();
    // Safety: pretty much pure ffi, the errono access follows the instructions documented
    //         in man getpwuid.
    unsafe {
        let errno = libc::getpwuid_r(
            libc::getuid(),
            &mut passwd,
            passwd_str_buf.as_mut_ptr(),
            passwd_str_buf.len(),
            &mut passwd_res_ptr as *mut *mut libc::passwd,
        );
        if passwd_res_ptr.is_null() {
            if errno == 0 {
                return Err(merr!("could not find current user, should be impossible"));
            } else {
                return Err(merr!(
                    "error resolving user passwd: {}",
                    io::Error::from_raw_os_error(errno)
                ));
            }
        }
    };

    // Safety: user is documented to be nullable, pretty much just doing
    //         standard ffi otherwise. Cleanup is handled by our RAII
    //         wrapper.
    let pam_h = unsafe {
        PamHandle::start(
            "rust-motd-bogus--pam-service--".as_ptr() as *const libc::c_char,
            passwd.pw_name,
            &pam_conv,
        )?
    };

    // Now the unsafe party really gets started! Time to directly dl_open
    // pam_motd.so.

    // Safety: pretty much just pure ffi around dlopen
    let pam_motd_so: dlopen2::wrapper::Container<PamMotdSo> =
        unsafe { dlopen2::wrapper::Container::load(pam_motd_so) }
            .map_err(|e| merr!("loading pam_motd.so: {}", e))?;

    let mut args = arg_resolver
        .resolve()?
        .into_iter()
        .map(|a| ffi::CString::new(a).map_err(|e| merr!("creating arg: {:?}", e)))
        .collect::<Result<Vec<_>, Error>>()?;
    let mut arg_ptrs = args
        .iter_mut()
        .map(|s| s.as_ptr() as *mut libc::c_char)
        .collect::<Vec<_>>();
    // Safety: this routine must be present according to the contract of pam_motd.so,
    //         which is stable since it is part of the interface that the main pam
    //         module uses to talk to it.
    let code = unsafe {
        pam_motd_so.pam_sm_open_session(
            pam_h.pam_h as *mut pam_sys::PamHandle,
            pam_sys::PamFlag::NONE as libc::c_int,
            args.len() as libc::c_int,
            arg_ptrs.as_mut_ptr(),
        )
    };
    let code = PamReturnCode::from(code);
    if !(code == PamReturnCode::SUCCESS || code == PamReturnCode::IGNORE) {
        return Err(merr!("unexpected return code from pam_motd.so: {:?}", code));
    }

    // we skip calling pam_sm_close_session since it is stubbed out for pam_motd.so

    if !conv_data.errs.is_empty() {
        let mut err_msgs = vec![];
        for err in conv_data.errs.into_iter() {
            err_msgs.push(err.to_string());
        }
        Err(merr!(
            "collecting pam_motd.so results: {}",
            err_msgs.join(" AND ")
        ))
    } else {
        Ok(conv_data.motd_msg)
    }
}

//
// PamHandle impl
//

struct PamHandle {
    pam_h: *const pam_sys::PamHandle,
    error_status: libc::c_int,
}

impl PamHandle {
    /// Create a new RAII wrapper around a pam_sys::PamHandle. A very thin
    /// wrapper around pam_sys::raw::pam_start.
    ///
    /// Safety: see man pam_start for semantics. The Drop impl calls pam_end,
    ///         so the caller must keep that in mind.
    unsafe fn start(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conv: &pam_sys::PamConversation,
    ) -> Result<Self, Error> {
        let mut pam_h: *const pam_sys::PamHandle = ptr::null();

        let code = pam_sys::raw::pam_start(service_name, user, pam_conv, &mut pam_h);

        let code = PamReturnCode::from(code);
        if code != PamReturnCode::SUCCESS {
            return Err(merr!("starting pam session: error code = {}", code));
        }
        Ok(PamHandle {
            pam_h,
            error_status: 0,
        })
    }
}

impl std::ops::Drop for PamHandle {
    fn drop(&mut self) {
        let code = unsafe {
            // Error status is threaded down to cleanup functions for data that
            // has been set by pam_set_data. We don't really use it.
            //
            // Safety: this is fine as long as the caller has not mutated pam_h.
            //
            //         The cast to mut is pretty unfortunate, but required because
            //         pam_end needs a mut pointer. The underlying c functions all
            //         take mut pointers, but the sys crate has chosen to convert
            //         them to const pointers for most functions, presumably to
            //         signal that a pam_sys::PanHandle is an opaque type the user should
            //         never directly manipulate.
            pam_sys::raw::pam_end(self.pam_h as *mut pam_sys::PamHandle, self.error_status)
        };
        let code = PamReturnCode::from(code);

        if code != PamReturnCode::SUCCESS {
            warn!("error 'pam_end'ing a pam handle: {:?}", code);
        }
    }
}

//
// .so file wrapper
//

#[derive(WrapperApi)]
struct PamMotdSo {
    pam_sm_open_session: unsafe extern "C" fn(
        pam_h: *mut pam_sys::PamHandle,
        flags: libc::c_int,
        argc: libc::c_int,
        argv: *mut *mut libc::c_char,
    ) -> libc::c_int,
}

//
// Conversation callbacks
//

// The blob of user-data for the conversation handler. repr(C)
// since I'm not sure it is safe to pass things across ffi boundaries
// without a defined repr (I'm pretty sure it would be fine, but
// I just want to be on the safe side).
#[repr(C)]
struct ConvData {
    motd_msg: String,
    errs: Vec<Error>,
}

impl ConvData {
    fn new() -> Self {
        ConvData {
            motd_msg: String::from(""),
            errs: vec![],
        }
    }
}

// The handler routine that gets invoked every time pam_motd.so prints
// a message or an error.
//
// See `man 3 pam_conv` for details about the semantics of this callback.
extern "C" fn conv_handler(
    num_msg: libc::c_int,
    msgs: *mut *mut pam_sys::PamMessage,
    resp: *mut *mut pam_sys::PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> libc::c_int {
    // Safety: num_msgs is documented to be the length of the msgs array
    //         in the pam_conv man pange.
    assert!(num_msg >= 0);
    let msgs = unsafe { slice::from_raw_parts(msgs, num_msg as usize) };

    // Safety: `man pam_conv` says that the caller will free() the resp array
    //         after every call, so we must calloc a new one. It also expects
    //         there to be exactly one response slot per message.
    //
    //         It is ok to assigning to `*resp` because the man page documents the
    //         resp array to be a pointer to an array of PamResponses, rather than
    //         an array of PamResponse pointers. This means the double indirection
    //         is in order for us to write to the output variable, so the caller
    //         is responsible for making sure there is a word there for us to write
    //         to.
    unsafe {
        *resp = {
            let alloc_size = mem::size_of::<pam_sys::PamResponse>() * num_msg as usize;
            let resp_buf = libc::calloc(alloc_size, 1);
            mem::transmute(resp_buf)
        };
    }

    // Safety: we cast from a `&ConvData` to a `*mut c_void` when creating the PamConversation,
    //         so we are casting to the right type. The assertion against null means that
    //         it is safe to convert to a reference.
    assert!(!appdata_ptr.is_null());
    let conv_data = unsafe { &mut *mem::transmute::<_, *mut ConvData>(appdata_ptr) };

    #[allow(clippy::needless_range_loop)]
    for i in 0..(num_msg as usize) {
        // Safety: the caller is responsible for giving us a complete message list.
        //         Any issue with this operation would be due to an issue with how the
        //         caller has set things up since the loop means we are in-bounds.
        let msg = unsafe { *msgs[i] };

        let msg_style = pam_sys::types::PamMessageStyle::from(msg.msg_style);
        match msg_style {
            PamMessageStyle::PROMPT_ECHO_OFF => {
                conv_data
                    .errs
                    .push(merr!("pam_motd.so asked for a password"));
            }
            PamMessageStyle::PROMPT_ECHO_ON => {
                conv_data
                    .errs
                    .push(merr!("pam_motd.so asked for a username"));
            }
            PamMessageStyle::TEXT_INFO => {
                // Safety: pam_motd.so will give us a valid cstring here.
                let msg = unsafe { ffi::CStr::from_ptr(msg.msg) };
                match msg.to_str() {
                    Ok(s) => {
                        conv_data.motd_msg.push_str(s);
                        conv_data.motd_msg.push('\n');
                    }
                    Err(e) => conv_data
                        .errs
                        .push(merr!("err converting motd chunk: {}", e)),
                }
            }
            PamMessageStyle::ERROR_MSG => {
                // Safety: pam_motd.so will give us a valid cstring here.
                let msg = unsafe { ffi::CStr::from_ptr(msg.msg) };
                match msg.to_str() {
                    Ok(s) => conv_data.errs.push(merr!("pam_mod.so says '{}'", s)),
                    Err(e) => conv_data
                        .errs
                        .push(merr!("err converting motd err msg: {}", e)),
                }
            }
        }
    }

    PamReturnCode::SUCCESS as libc::c_int
}

//
// .so discovery logic
//

/// Specifies the strategy to use in order to find the pam_motd.so file
/// to interrogate for the motd message.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum PamMotdResolutionStrategy {
    /// Use the exact path to the given file. Do not attempt to do any
    /// searching.
    Exact(PathBuf),
    /// Search the given list of directories. If recursive is true, also
    /// search any subdirectories they have.
    Search { dirs: Vec<PathBuf>, recursive: bool },
    /// A good default. Equivalent to `Search { dirs: vec!["/usr/lib"], recursive: true }`.
    Auto,
}

impl PamMotdResolutionStrategy {
    fn resolve(&self) -> Result<PathBuf, Error> {
        match self {
            PamMotdResolutionStrategy::Exact(path) => Ok(path.to_path_buf()),
            PamMotdResolutionStrategy::Search { dirs, recursive } => {
                let mut err = None;

                for dir in dirs.iter() {
                    match Self::find_file(*recursive, dir, PAM_MOTD_NAME) {
                        Ok(path) => return Ok(path),
                        Err(e) => {
                            err = Some(e);
                        }
                    }
                }

                Err(err.unwrap_or(merr!("no directories to search provided")))
            }
            PamMotdResolutionStrategy::Auto => PamMotdResolutionStrategy::Search {
                dirs: vec![LIB_DIR.into()],
                recursive: true,
            }
            .resolve(),
        }
    }

    /// Search a directory to find a regular file with the given name.
    ///
    /// Used to automatically resolve pam_motd.so by recursively searching /usr/lib.
    fn find_file<P>(recursive: bool, dir: P, fname: &str) -> Result<PathBuf, Error>
    where
        P: AsRef<Path> + Debug,
    {
        if !dir.as_ref().is_dir() {
            return Err(merr!("{:?} is not a directory", dir));
        }

        let mut traversal = walkdir::WalkDir::new(&dir);
        if !recursive {
            traversal = traversal.max_depth(1);
        }
        for entry in traversal.into_iter().flatten() {
            if entry
                .path()
                .file_name()
                .map(|n| n == fname)
                .unwrap_or(false)
            {
                return Ok(PathBuf::from(entry.path()));
            }
        }

        Err(merr!("file {:?} not found in {:?}", fname, dir))
    }
}

/// A handle to an overlay .so file. It is normally stored as embedded data in the motd
/// rlib, but for the life of one of these handles it gets written out to a tmp file.
/// The overlay file gets cleaned up when this handle falls out of scope.
#[derive(Debug)]
struct OverlaySo {
    _overlay_dir: tempfile::TempDir,
    path: PathBuf,
}

impl OverlaySo {
    fn new() -> Result<Self, Error> {
        let overlay_blob = include_bytes!(concat!(env!("OUT_DIR"), "/pam_motd_overlay.so"));

        let overlay_dir = tempfile::TempDir::with_prefix("pam_motd_overlay")
            .map_err(|e| merr!("making tmp pam_motd_overlay.so dir: {}", e))?;
        let mut path = PathBuf::from(overlay_dir.path());
        path.push("pam_motd_overlay.so");

        let mut overlay_file =
            fs::File::create(&path).map_err(|e| merr!("making pam_motd_overlay.so: {}", e))?;
        overlay_file
            .write_all(overlay_blob)
            .map_err(|e| merr!("writing pam_motd_overlay.so: {}", e))?;

        Ok(OverlaySo {
            _overlay_dir: overlay_dir,
            path,
        })
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}
