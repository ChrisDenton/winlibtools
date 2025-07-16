use object::coff::{CoffFile, ImportFile};
use object::pe::ImageFileHeader;
use object::read::archive::ArchiveFile;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Cursor, Write};
use std::process::ExitCode;

#[derive(Debug)]
enum ExtractError {
    ObjectError { msg: String, cause: object::Error },
    IoError { msg: String, cause: io::Error },
}
impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectError { msg, cause } => {
                write!(f, "{msg}\ncause: {cause}")
            }
            Self::IoError { msg, cause } => {
                write!(f, "{msg}\ncause: {cause}")
            }
        }
    }
}
impl Error for ExtractError {}

fn extract_idata(
    lib_path: &OsStr,
    out_lib: &OsStr,
    import_lib: Option<&OsStr>,
) -> Result<(), ExtractError> {
    let data = fs::read(&lib_path).map_err(|e| ExtractError::IoError {
        msg: format!("cannot read {}", lib_path.display()),
        cause: e,
    })?;
    let archive = ArchiveFile::parse(&*data).map_err(|e| ExtractError::ObjectError {
        msg: format!("not a recognised archive file: {}", lib_path.display()),
        cause: e,
    })?;

    let mut idata_members = Vec::new();
    let mut other_members = Vec::new();

    for member in archive.members() {
        let member = member.map_err(|e| ExtractError::ObjectError {
            msg: format!("could not read archive member in {}", lib_path.display()),
            cause: e,
        })?;
        let data = member.data(&*data).map_err(|e| ExtractError::ObjectError {
            msg: format!(
                "could not get data from archive member at {:#x} in {}",
                member.file_range().0,
                lib_path.display()
            ),
            cause: e,
        })?;
        let mut found_idata = false;
        match CoffFile::<_, ImageFileHeader>::parse(&*data) {
            Ok(file) => {
                let strings = file.coff_symbol_table().strings();
                for section in file.coff_section_table().iter() {
                    let name = section.name(strings).map_err(|e| ExtractError::ObjectError {
                        msg: format!(
                            "unable to retrieve section name at {:#x} in {}",
                            member.file_range().0,
                            lib_path.display()
                        ),
                        cause: e,
                    })?;
                    if name.starts_with(b".idata$") {
                        found_idata = true;
                        break;
                    }
                }
            }
            Err(e) => {
                if let Ok(_) = ImportFile::parse(&*data) {
                    found_idata = true;
                } else {
                    // maybe we should just warn here?
                    return Err(ExtractError::ObjectError {
                        msg: format!(
                            "unrecognised archive member at {:#x} in {}",
                            member.file_range().0,
                            lib_path.display()
                        ),
                        cause: e,
                    });
                }
            }
        }
        let name = String::from_utf8_lossy(member.name());
        let new_member = ar_archive_writer::NewArchiveMember::new(
            data,
            &ar_archive_writer::DEFAULT_OBJECT_READER,
            name.into(),
        );
        if found_idata {
            if import_lib.is_some() {
                idata_members.push(new_member);
            }
        } else {
            other_members.push(new_member);
        }
    }

    if let Some(lib) = import_lib {
        let mut writer = Cursor::new(Vec::with_capacity(64 * 1024));
        ar_archive_writer::write_archive_to_stream(
            &mut writer,
            &idata_members,
            ar_archive_writer::ArchiveKind::Coff,
            false,
            false,
        )
        .map_err(|e| ExtractError::IoError {
            msg: "could not create new library file".into(),
            cause: e,
        })?;
        fs::write(lib, &writer.get_ref()).map_err(|e| ExtractError::IoError {
            msg: format!("unable to write library to {}", lib.display()),
            cause: e,
        })?;
    }

    let mut writer = Cursor::new(Vec::with_capacity(64 * 1024));
    ar_archive_writer::write_archive_to_stream(
        &mut writer,
        &other_members,
        ar_archive_writer::ArchiveKind::Coff,
        false,
        false,
    )
    .map_err(|e| ExtractError::IoError {
        msg: "could not create new library file".into(),
        cause: e,
    })?;
    fs::write(out_lib, &writer.get_ref()).map_err(|e| ExtractError::IoError {
        msg: format!("unable to write library to {}", out_lib.display()),
        cause: e,
    })?;

    Ok(())
}

#[derive(Default)]
struct Options {
    create: bool,
    remove_idata: bool,
    lib_path: Option<OsString>,
    out_lib: Option<OsString>,
    keep_removed: Option<OsString>,
    help: bool,
}

fn parse_args() -> Result<Options, lexopt::Error> {
    let mut options = Options::default();
    let mut parser = lexopt::Parser::from_env();
    let mut first = true;
    let mut unexpected = None;
    while let Some(arg) = parser.next()? {
        use lexopt::Arg::{Long, Short, Value};
        match arg {
            Short('h') | Long("help") => {
                options.help = true;
                return Ok(options);
            }
            Value(ref v) if first => {
                if v == "create" {
                    options.create = true;
                } else {
                    if unexpected.is_none() {
                        unexpected = Some(arg.unexpected());
                    }
                }
            }
            _ if first => {
                if unexpected.is_none() {
                    unexpected = Some(arg.unexpected());
                }
            }
            Value(v) if options.out_lib.is_none() => options.out_lib = Some(v),
            Long("from") => {
                options.lib_path = Some(parser.value()?);
            }
            Long("keep-removed") => {
                options.keep_removed = Some(parser.value()?);
            }
            Long("remove-idata") => {
                options.remove_idata = true;
            }
            _ => {
                if unexpected.is_none() {
                    unexpected = Some(arg.unexpected());
                }
            }
        }
        first = false;
    }
    if let Some(unexpected) = unexpected {
        return Err(unexpected);
    }
    Ok(options)
}

fn print_help() {
    println!(
        "Usage:
\twinlib create <LIB_PATH> --from <PATH> --remove-idata [--keep-removed <PATH>]

<LIB_PATH> is the path of the lib to create.

Options:
\t--from <PATH>        \tThe new lib will contain members from the old lib at <PATH>.
\t--remove-idata       \tRemove members containing .idata sections.
\t--keep-removed <PATH>\tStore the removed members in a separate library at <PATH>.

Example:
\twinlib create newlib.lib --from oldlib.lib --remove-idata --keep-remove import.lib
"
    );
}

fn println(args: fmt::Arguments<'_>) {
    let mut out = io::stdout().lock();
    _ = out.write_fmt(args);
    _ = out.write(b"\n");
}

macro_rules! failure {
    ($($arg:tt)*) => {{
        println(std::format_args!($($arg)*));
        ExitCode::FAILURE
    }};
}

fn main() -> ExitCode {
    let options = match parse_args() {
        Ok(options) => options,
        Err(e) => {
            print_help();
            return failure!("\nerror: could not parse arguments\n\t{e}");
        }
    };
    if options.help {
        print_help();
        return ExitCode::SUCCESS;
    }
    if !options.create || !options.remove_idata {
        return failure!("only winlib create --remove_idata is currently supported");
    }
    let Some(out_lib) = options.out_lib else {
        print_help();
        return failure!("error: no output lib path provided");
    };
    let Some(lib_path) = options.lib_path else {
        print_help();
        return failure!("error: no --from lib path provided");
    };
    if options.create {
        match extract_idata(&lib_path, &out_lib, options.keep_removed.as_deref()) {
            Ok(_) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}")
            }
        }
    }
    ExitCode::SUCCESS
}
