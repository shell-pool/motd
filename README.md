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
