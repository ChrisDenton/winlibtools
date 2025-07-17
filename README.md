# winlib

A command line tool for creating Windows libraries.

```
Usage:
        winlib list <LIB_PATH>
        winlib create <LIB_PATH> --from <PATH> --remove-idata [--keep-removed <PATH>]

<LIB_PATH> is the path of the lib to create or inspect.

Create Options:
        --from <PATH>           The new lib will contain members from the old lib at <PATH>.
        --remove <OFFSET>       Remove the member at the given offset
        --remove-idata          Remove members containing .idata sections.
        --keep-removed <PATH>   Store the removed members in a separate library at <PATH>.

Examples:
        winlib list oldlib.lib
        winlib create newlib.lib --from oldlib.lib --remove-idata --keep-remove import.lib
```

## Download

Either download from the [Releases](https://github.com/ChrisDenton/winlibtools/releases) page or install using `cargo`.

```
cargo install winlib
```
