use std::fs;

use log::warn;

use crate::{ArgResolutionStrategy, Error};

const DEFAULT_MOTD: &str = "/etc/motd:/run/motd:/usr/lib/motd";
const DEFAULT_MOTD_D: &str = "/etc/motd.d:/run/motd.d:/usr/lib/motd.d";

macro_rules! merr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

/// Resolver knows how to fetch the current motd by executing
/// a pure-rust reimplmentation of the logic found in pam_motd.so.
#[derive(Debug, Clone)]
pub struct Resolver {}

impl Resolver {
    /// Create a new resolver
    pub fn new() -> Result<Self, Error> {
        Ok(Resolver {})
    }

    /// Get the current value of the motd. pam_motd.so args are resolved using
    /// the given resolver and have the same effect that they do in pam_motd.so.
    pub fn value(&self, arg_resolver: ArgResolutionStrategy) -> Result<String, Error> {
        let args = arg_resolver.resolve()?;

        let mut motd = DEFAULT_MOTD;
        let mut motd_d = DEFAULT_MOTD_D;
        for arg in args.iter() {
            if arg.starts_with("motd=") {
                if let Some(motd_arg) = arg.strip_prefix("motd=") {
                    motd = motd_arg;
                }
            } else if arg.starts_with("motd_dir=") {
                if let Some(motd_dir_arg) = arg.strip_prefix("motd_dir=") {
                    motd_d = motd_dir_arg;
                }
            } else if arg != "noupdate" {
                warn!("unknown motd arg '{}', ignoring", arg);
            }
        }

        let mut msg = String::new();
        self.slurp_motd(motd, &mut msg)?;
        self.slurp_motd_d(motd_d, &mut msg)?;

        Ok(msg)
    }

    /// Go through the motd list and slurp the first file that exists.
    fn slurp_motd(&self, motd: &str, into: &mut String) -> Result<(), Error> {
        for path in motd.split(':') {
            if !fs::metadata(path).is_ok() {
                // motd file not present, just skip it
                continue;
            }
            let contents =
                fs::read_to_string(path).map_err(|e| merr!("reading motd file: {:?}", e))?;
            into.push_str(contents.as_str());
            break;
        }

        Ok(())
    }

    // Go through the motd_d list and slurp all the files, applying
    // name based overrides as described in `man pam_motd`.
    fn slurp_motd_d(&self, motd_d: &str, into: &mut String) -> Result<(), Error> {
        let mut direntries = vec![];
        let mut files = vec![];
        for dir in motd_d.split(':') {
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(e) => {
                    // just warn about it since the next one might be a real
                    // directory.
                    warn!("reading motd_d dir: {:?}", e);
                    continue;
                }
            };

            let mut entry_list = vec![];
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if entry.path().is_symlink() || entry.path().is_file() {
                    files.push(
                        entry
                            .path()
                            .file_name()
                            .and_then(|s| s.to_str())
                            .map(String::from)
                            .ok_or(merr!("could not get basename"))?,
                    );
                }
                entry_list.push(entry);
            }

            direntries.push(entry_list);
        }

        files.sort();

        for (i, file) in files.iter().enumerate() {
            if i > 0 && files[i - 1] == file.as_str() {
                // skip dups
                continue;
            }

            for entries in direntries.iter() {
                for entry in entries {
                    // skip non-matching files
                    if !entry
                        .path()
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s == file)
                        .unwrap_or(false)
                    {
                        continue;
                    }

                    let contents = match fs::read_to_string(entry.path()) {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    into.push_str(contents.as_str());
                    // move on to the next file
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate as motd;

    #[test]
    fn test_dump() -> Result<(), motd::Error> {
        assert!(!cfg!(feature = "socall"));
        let motd_resolver = motd::Resolver::new()?;
        motd_resolver.value(motd::ArgResolutionStrategy::Auto)?;
        Ok(())
    }
}
