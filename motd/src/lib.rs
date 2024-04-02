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
# #[cfg(not(feature = "socall"))]
# fn main() {}
# #[cfg(feature = "socall")]
fn main() {
    motd::handle_reexec();

    // ...
}
```

then elsewhere in your code you can call value to get
the motd message like

```
# #[cfg(not(feature = "socall"))]
# fn main() {}
# #[cfg(feature = "socall")]
# fn main() -> Result<(), motd::Error> {
# motd::handle_reexec();
let motd_resolver = motd::Resolver::new(motd::PamMotdResolutionStrategy::Auto)?;
let motd_msg = motd_resolver.value(motd::ArgResolutionStrategy::Auto)?;
# Ok(())
# }
```

By default, motd finds and calls the pam_motd.so file that is the source
of truth implementation for motd resolution, but it also contains a pure
rust reimplementation of the motd resolution logic. This implementation has
the potential to diverge from the behavior of pam_motd.so, but it contains
0 unsafe rust and does a fairly good job. You can switch to this mode by
disabling default features for the crate. This will make the `so_finder`
argument to `Resolver::new` disapear and remove the need to register the
`handle_reexec` handler in your main function. You can then use it
like

```
# #[cfg(feature = "socall")]
# fn main() {}
# #[cfg(not(feature = "socall"))]
# fn main() -> Result<(), motd::Error> {
let motd_resolver = motd::Resolver::new()?;
let motd_msg = motd_resolver.value(motd::ArgResolutionStrategy::Auto)?;
# Ok(())
# }
```
*/

#![allow(clippy::needless_doctest_main)]

use std::{
    fmt::Debug,
    fs, io,
    io::BufRead,
    path::{Path, PathBuf},
};

use log::warn;
use serde_derive::{Deserialize, Serialize};

#[cfg(feature = "socall")]
mod socall;
#[cfg(feature = "socall")]
pub use socall::handle_reexec;
#[cfg(feature = "socall")]
pub use socall::PamMotdResolutionStrategy;
#[cfg(feature = "socall")]
pub use socall::Resolver;

#[cfg(not(feature = "socall"))]
mod reimpl;
#[cfg(not(feature = "socall"))]
pub use reimpl::Resolver;

const PAM_DIR: [&str; 2] = ["/etc", "pam.d"];

macro_rules! merr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

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
            for arg in &parts[3..] {
                if *arg != "noupdate" {
                    args.push(String::from(*arg));
                }
            }
        }

        Ok(args)
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
