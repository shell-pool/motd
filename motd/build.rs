use std::{env, path::PathBuf, process::Command};

use which::which;

/* Uncomment for debugging, you can't print normally from a build.rs
macro_rules! bprintln {
    ($($arg:tt)*) => {{
        println!("cargo:warning={}", format!($($arg)*))
    }}
}
*/

macro_rules! berr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            panic!("build failed: {}", e);
        }
    }
}

// build the overlay .so file
fn run() -> Result<(), Error> {
    println!("cargo:rerun-if-changed=src/pam_motd_overlay.c");
    println!("cargo:rerun-if-changed=src/pam_motd_overlay_versions.map");

    let out_dir = env::var("OUT_DIR").map_err(|e| berr!("no OUT_DIR: {}", e))?;

    let mut target_so = PathBuf::from(out_dir);
    target_so.push("pam_motd_overlay.so");

    let cc = select_cc()?;
    let output = Command::new(cc)
        .arg("-Wl,--version-script=./src/pam_motd_overlay_versions.map")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-o")
        .arg(target_so)
        .arg("./src/pam_motd_overlay.c")
        .output()
        .map_err(|e| berr!("building overlay: {}", e))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(output.stdout.as_slice());
        let stderr = String::from_utf8_lossy(output.stderr.as_slice());
        return Err(berr!(
            "error building overlay, code = {}\nSTDOUT: {}\nSTDERR: {}",
            output.status,
            stdout,
            stderr
        ));
    }

    Ok(())
}

fn select_cc() -> Result<PathBuf, Error> {
    if let Ok(cc) = env::var("CC") {
        Ok(PathBuf::from(cc))
    } else if let Ok(gcc) = which("gcc") {
        Ok(gcc)
    } else if let Ok(clang) = which("clang") {
        Ok(clang)
    } else {
        Err(berr!("could not select cc"))
    }
}

//
// Errors
//

#[non_exhaustive]
#[derive(Debug)]
enum Error {
    Err { msg: String },
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
