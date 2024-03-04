/*!
The motd crate exposes a mechanism for dumping the current MOTD
on linux. Use it like:

```
use motd;

let motd_contents = motd::value()?;
```
*/


macro_rules! merr {
    ($($arg:tt)*) => {{
        Error::Err { msg: format!($($arg)*) }
    }}
}

/// Get the current value of the MOTD.
pub fn value() -> Result<String, Error> {
    Err(merr!("motd::value() unimplemented"))
}

/// Errors encountered while resolving the message of the day.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// An opaque error with a useful debugging message but
    /// which callers should not dispatch on.
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
