# winlib

A command line tool for creating Windows libraries.

```
Usage:
        winlib create <LIB_PATH> --from <PATH> --remove-idata [--keep-removed <PATH>]

<LIB_PATH> is the path of the lib to create.

Options:
        --from <PATH>           The new lib will contain members from the old lib at <PATH>.
        --remove-idata          Remove members containing .idata sections.
        --keep-removed <PATH>   Store the removed members in a separate library at <PATH>.

Example:
        winlib create newlib.lib --from oldlib.lib --remove-idata --keep-remove import.lib
```

## Download

Either download from the [Releases](https://github.com/ChrisDenton/winlibtools/releases) page or install using `cargo`.

```
cargo install winlib
```
