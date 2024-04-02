# motd

`motd` is a crate for printing the current MOTD (message of the day)
on linux. Most of the logic lives in the `motd` crate, and the `dump-motd`
tool is a thin wrapper which provides a command line interface for the
crate.

## Dependencies

You must install libpam headers to build this crate. On debian based
systems you can do so with

```
sudo apt-get install libpam0g-dev
```

## Features

There are two modes of operation for the `motd` crate. By default, it
will load and call into the `pam_motd.so` file used by the pam stack,
but you can instead use a pure rust reimplementation of the logic found
in `pam_motd.so` if you want. The downside of the pure rust implementation
is that it no longer uses the same source-of-truth logic to resolve the
motd, though this is likely not a huge deal because `pam_motd` is fairly
stable. The pure rust implementation has the advantages that it uses zero
unsafe code, does not require a (sometimes slow) directory walk to
locate `pam_motd.so` the first time it is run, and requires many fewer
dependencies.

The feature for calling `pam_motd.so` directly is `socall`, and it is
enabled by default. To use the pure rust implementation, disable
default features. This will change the signature of a few functions.
