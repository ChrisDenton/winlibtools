# winlib

A command line tool for creating Windows libraries.

```
Usage:
        winlib list <LIB_PATH>
        winlib create <LIB_PATH> --from <PATH> --exclude-idata [--save-excluded <PATH>]

<LIB_PATH> is the path of the lib to create or inspect.

Create Options:
        --from <PATH>           The new lib will contain members from the old lib at <PATH>.
        --exclude <OFFSET>      Exclude the member at the given offset
        --exclude-idata         Exclude members containing .idata sections.
        --save-excluded <PATH>  Store the excluded members in a separate library at <PATH>.

Examples:
        winlib list oldlib.lib
        winlib create newlib.lib --from oldlib.lib --exclude-idata --save-excluded import.lib
```

## Download

Either download from the [Releases](https://github.com/ChrisDenton/winlibtools/releases) page or install using `cargo`.

```
cargo install winlib
```
