/*!
The motd crate exposes a mechanism for dumping the current MOTD
on linux. In order to work around some issues with how pam_motd.so
handles permissions, it must re-exec the current binary to make
use of the LD_PRELOAD trick. You must make sure that your binary
can handle this re-execing by registering `motd::handle_reexec()`
in your main function. It is a no-op unless a few magic environment
variables have been set, so you don't need to worry about it impacting
the way your binary behaves otherwise.

Your main should look like this:

```
fn main() {
    motd::handle_reexec();

    ...
}
```

then elsewhere in your code you can call value to get
the motd message like

```
motd::value(motd::PamMotdResolutionStrategy::Auto,
            motd::ArgResolutionStrategy::Auto)?;
```
*/

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
    io::{BufRead, Write},
    mem,
    path::{Path, PathBuf},
    process::Command,
    ptr, slice,
};

use libc;
use log::warn;
use pam_sys;
use pam_sys::types::{PamMessageStyle, PamReturnCode};
use serde_derive::{Deserialize, Serialize};
use dlopen2::wrapper::WrapperApi;

macro_rules! merr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

const PAM_MOTD_NAME: &str = "pam_motd.so";
const LIB_DIR: &str = "/usr/lib";
const PAM_DIR: [&str; 2] = ["/etc", "pam.d"];

const SO_RESOLVER_ARG_ENV_VAR: &str = "RUST_MOTD_CRATE__INTERNAL__SO_RESOLVER_ARG";
const ARG_RESOLVER_ARG_ENV_VAR: &str = "RUST_MOTD_CRATE__INTERNAL__ARG_RESOLVER_ARG";

/// Get the current value of the MOTD. Works by re-execing the current binary
/// in order to use the LD_PRELOAD trick, so make sure you have called
/// `motd::handle_reexec()` in your main function.
pub fn value(
    so_resolver: PamMotdResolutionStrategy,
    arg_resolver: ArgResolutionStrategy,
) -> Result<String, Error> {
    let overlay_so = OverlaySo::new()?;

    let so_resolver_json =
        serde_json::to_string(&so_resolver).map_err(|e| merr!("serializing so_resolver: {}", e))?;
    let arg_resolver_json = serde_json::to_string(&arg_resolver)
        .map_err(|e| merr!("serializing arg_resolver: {}", e))?;
    let out = Command::new("/proc/self/exe")
        .env(SO_RESOLVER_ARG_ENV_VAR, so_resolver_json)
        .env(ARG_RESOLVER_ARG_ENV_VAR, arg_resolver_json)
        .env("LD_PRELOAD", overlay_so.path())
        .output()
        .map_err(|e| merr!("error re-execing self: {}", e))?;

    if !out.status.success() {
        return Err(merr!("failed to re-exec, bad status = {}", out.status));
    }

    if out.stderr.len() > 0 {
        println!("{}", String::from_utf8_lossy(out.stdout.as_slice()));

        let stderr = String::from_utf8_lossy(out.stderr.as_slice());
        return Err(merr!("in re-execed process: {}", stderr));
    }

    if out.stdout.len() > 0 {
        return Ok(String::from_utf8_lossy(out.stdout.as_slice()).into());
    }

    Err(merr!("no motd output"))
}

/// You MUST call this routine in the main function of the binary that uses
/// the motd crate. In order to work around an issue where `pam_motd.so` thinks
/// it is running as root, we use LD_PRELOAD to stub out some privilege
/// juggling methods. To do this, the value() routine re-execs the current binary,
/// and it is in this re-execd process that we actually load and call into
/// `pam_motd.so`.
pub fn handle_reexec() {
    if let (Ok(so_resolver_json), Ok(arg_resolver_json)) = (
        env::var(SO_RESOLVER_ARG_ENV_VAR),
        env::var(ARG_RESOLVER_ARG_ENV_VAR),
    ) {
        match reexec_call_so(so_resolver_json.as_str(), arg_resolver_json.as_str()) {
            Ok(motd_msg) => print!("{}", motd_msg),
            Err(e) => eprintln!("{}", e),
        }
        std::process::exit(0);
    }
}

/// Actually load and call the `pam_motd.so`
fn reexec_call_so(so_resolver_json: &str, arg_resolver_json: &str) -> Result<String, Error> {
    let so_resolver: PamMotdResolutionStrategy = serde_json::from_str(so_resolver_json)
        .map_err(|e| merr!("parsing so_resolver arg: {}", e))?;
    let arg_resolver: ArgResolutionStrategy = serde_json::from_str(arg_resolver_json)
        .map_err(|e| merr!("parsing arg_resolver arg: {}", e))?;

    let mut conv_data = ConvData::new();
    let pam_conv = pam_sys::types::PamConversation {
        conv: Some(conv_handler),
        // Safety: It is always safe to cast to void in the immediate moment,
        //         and we will be done with the conversation by the time this
        //         routine returns and removes the underlying allocation from
        //         the stack.
        data_ptr: unsafe { mem::transmute::<_, *mut libc::c_void>(&mut conv_data) },
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
            libc::getuid(), &mut passwd,
            passwd_str_buf.as_mut_ptr(), passwd_str_buf.len(),
            &mut passwd_res_ptr as *mut *mut libc::passwd);
        if passwd_res_ptr.is_null() {
            if errno == 0 {
                return Err(merr!("could not find current user, should be impossible"));
            } else {
                return Err(merr!("error resolving user passwd: {}", io::Error::from_raw_os_error(errno)));
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
    let so_path = so_resolver.resolve()?;

    // Safety: pretty much just pure ffi around dlopen
    let pam_motd_so: dlopen2::wrapper::Container<PamMotdSo> = unsafe {
        dlopen2::wrapper::Container::load(&so_path)
    }.map_err(|e| merr!("loading pam_motd.so: {}", e))?;

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

/// Errors encountered while resolving the message of the day.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// An opaque error with a useful debugging message but
    /// which callers should not dispatch on.
    Err {
        msg: String,
    },
    __NonExhaustive,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Error::Err { msg } => write!(f, "{}", msg)?,
            _ => write!(f, "{:?}", self)?,
        }

        Ok(())
    }
}

impl std::error::Error for Error {}

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
    unsafe fn start<'conv>(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conv: &'conv pam_sys::PamConversation,
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
            let code =
                pam_sys::raw::pam_end(self.pam_h as *mut pam_sys::PamHandle, self.error_status);

            code
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
                    Ok(s) => conv_data.motd_msg.push_str(s),
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
// TODO(ethan): I should try to resolve the location of pam_motd.so
//       the same way that ld does. It can clearly do it much
//       faster than the recursive walk of /usr/lib that we are doing
//       currently.

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

        for entry in fs::read_dir(&dir).map_err(|e| merr!("reading dir '{:?}': {:?}", dir, e))? {
            let entry = entry.map_err(|e| merr!("getting dir entry for '{:?}': {:?}", dir, e))?;
            let path = entry.path();

            if path.is_symlink() {
                continue;
            }

            if path.is_dir() && recursive {
                if let Ok(res) = Self::find_file(recursive, path, fname) {
                    return Ok(res);
                }
            } else if path.is_file() {
                if path.file_name().map(|name| name == fname).unwrap_or(false) {
                    return Ok(path);
                }
            }
        }

        Err(merr!("file {:?} not found in {:?}", fname, dir))
    }
}

//
// arg slurping logic
//

/// The strategy to use to determine which args should be passed to `pam_motd.so`.
/// pam configuration often includes arguments to various pam modules, and `pam_motd.so`
/// is one such module. You likely want to match the args that the config passes into
/// the module.
///
/// In all cases, the "noupdate" arg will be included since without it debian flavored
/// `pam_motd.so`s will fail for want of write permissions on the motd file. Non-debian
/// `pam_motd.so`s just write an error to syslog and trundle along for unknown args, so
/// this should not cause an issue in general.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum ArgResolutionStrategy {
    /// Pass the exact arg vector given with not parsing or resolution.
    Exact(Vec<String>),
    /// Parse the given service files (found in `/etc/pam.d/{service}`) looking for
    /// `pam_motd.so` entries and slurping any `motd=` or `motd_dir=` arguments. Multiple entries
    /// combine args into a single arg list. Afterwards, the args are deduped. If the service
    /// does not have a file, it is ignored.
    MatchServices(Vec<String>),
    /// A good default. Equivalent to `MatchServices(vec!["ssh", "login"])`
    Auto,
}

impl ArgResolutionStrategy {
    fn resolve(self) -> Result<Vec<String>, Error> {
        match self {
            ArgResolutionStrategy::Exact(args) => Ok(args),
            ArgResolutionStrategy::Auto => ArgResolutionStrategy::MatchServices(vec![
                String::from("ssh"),
                String::from("login"),
            ])
            .resolve(),
            ArgResolutionStrategy::MatchServices(services) => {
                let mut args = vec![];
                for service in services.into_iter() {
                    let mut service_path = PathBuf::new();
                    for part in PAM_DIR.iter() {
                        service_path.push(part);
                    }
                    service_path.push(service);

                    args.extend(Self::slurp_args(service_path)?);
                }

                // remove duplicates since parsing multiple service files means we probably
                // have some.
                args.sort_unstable();
                args.dedup();

                // make sure the debian variant still works
                args.push(String::from("noupdate"));

                Ok(args)
            }
        }
    }

    fn slurp_args<P: AsRef<Path> + Debug>(service_file: P) -> Result<Vec<String>, Error> {
        if !service_file.as_ref().is_file() {
            // ignore any missing services
            return Ok(vec![]);
        }

        let file = fs::File::open(&service_file)
            .map_err(|e| merr!("opening {:?} to parse args: {:?}", &service_file, e))?;
        let reader = io::BufReader::new(file);

        let mut args = vec![];
        for line in reader.lines() {
            let line = line.map_err(|e| merr!("reading line from {:?}: {:?}", &service_file, e))?;
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            if line.starts_with("@include") {
                // we need to recursively parse the included service
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() != 2 {
                    warn!(
                        "expect exactly 1 argument to @include, got {}",
                        parts.len() - 1
                    );
                }

                let mut included_service_path = PathBuf::new();
                for part in PAM_DIR.iter() {
                    included_service_path.push(part);
                }
                included_service_path.push(parts[1]);

                args.extend(Self::slurp_args(included_service_path)?);

                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                warn!("expect at least 3 parts for a pam module config");
                // likely a blank line
                continue;
            }

            let module = parts[2];
            if module != "pam_motd.so" {
                continue;
            }
            for arg in parts[3..].into_iter() {
                if *arg != "noupdate" {
                    args.push(String::from(*arg));
                }
            }
        }

        Ok(args)
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
