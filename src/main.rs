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
enum WinlibError {
    ObjectError { msg: String, cause: object::Error },
    IoError { msg: String, cause: io::Error },
}
impl fmt::Display for WinlibError {
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
impl Error for WinlibError {}

struct CreateOptions {
    remove_idata: bool,
    remove_offsets: Vec<u32>,
    keep_removed: Option<OsString>,
}

fn create_lib(
    lib_path: &OsStr,
    out_lib: &OsStr,
    options: &CreateOptions,
) -> Result<(), WinlibError> {
    let extracted_lib = options.keep_removed.as_deref();
    let data = fs::read(&lib_path).map_err(|e| WinlibError::IoError {
        msg: format!("cannot read {}", lib_path.display()),
        cause: e,
    })?;
    let archive = ArchiveFile::parse(&*data).map_err(|e| WinlibError::ObjectError {
        msg: format!("not a recognised archive file: {}", lib_path.display()),
        cause: e,
    })?;

    let mut extracted_members = Vec::new();
    let mut included_members = Vec::new();

    for member in archive.members() {
        let member = member.map_err(|e| WinlibError::ObjectError {
            msg: format!("could not read archive member in {}", lib_path.display()),
            cause: e,
        })?;
        let data = member.data(&*data).map_err(|e| WinlibError::ObjectError {
            msg: format!(
                "could not get data from archive member at {:#x} in {}",
                member.file_range().0,
                lib_path.display()
            ),
            cause: e,
        })?;
        let mut remove = false;
        if options.remove_offsets.contains(&(member.file_range().0 as u32)) {
            remove = true;
        } else if options.remove_idata {
            match CoffFile::<_, ImageFileHeader>::parse(&*data) {
                Ok(file) => {
                    let strings = file.coff_symbol_table().strings();
                    for section in file.coff_section_table().iter() {
                        let name = section.name(strings).map_err(|e| WinlibError::ObjectError {
                            msg: format!(
                                "unable to retrieve section name at {:#x} in {}",
                                member.file_range().0,
                                lib_path.display()
                            ),
                            cause: e,
                        })?;
                        if name.starts_with(b".idata$") {
                            remove = true;
                            break;
                        }
                    }
                }
                Err(e) => {
                    if let Ok(_) = ImportFile::parse(&*data) {
                        remove = true;
                    } else {
                        // maybe we should just warn here?
                        return Err(WinlibError::ObjectError {
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
        }
        let name = String::from_utf8_lossy(member.name());
        let new_member = ar_archive_writer::NewArchiveMember::new(
            data,
            &ar_archive_writer::DEFAULT_OBJECT_READER,
            name.into(),
        );
        if remove {
            if extracted_lib.is_some() {
                extracted_members.push(new_member);
            }
        } else {
            included_members.push(new_member);
        }
    }

    let mut writer = Cursor::new(Vec::with_capacity(64 * 1024));
    if let Some(lib) = extracted_lib {
        ar_archive_writer::write_archive_to_stream(
            &mut writer,
            &extracted_members,
            ar_archive_writer::ArchiveKind::Coff,
            false,
            false,
        )
        .map_err(|e| WinlibError::IoError {
            msg: "could not create new library file".into(),
            cause: e,
        })?;
        fs::write(lib, &writer.get_ref()).map_err(|e| WinlibError::IoError {
            msg: format!("unable to write library to {}", lib.display()),
            cause: e,
        })?;
    }

    let mut writer = writer.into_inner();
    writer.truncate(0);
    let mut writer = Cursor::new(writer);
    ar_archive_writer::write_archive_to_stream(
        &mut writer,
        &included_members,
        ar_archive_writer::ArchiveKind::Coff,
        false,
        false,
    )
    .map_err(|e| WinlibError::IoError {
        msg: "could not create new library file".into(),
        cause: e,
    })?;
    fs::write(out_lib, &writer.get_ref()).map_err(|e| WinlibError::IoError {
        msg: format!("unable to write library to {}", out_lib.display()),
        cause: e,
    })?;

    Ok(())
}

fn list_lib(lib_path: &OsStr) -> Result<(), WinlibError> {
    // TODO: options show size and symbols for each member
    // As well as the archive's symbol table.

    let data = fs::read(&lib_path).map_err(|e| WinlibError::IoError {
        msg: format!("cannot read {}", lib_path.display()),
        cause: e,
    })?;
    let archive = ArchiveFile::parse(&*data).map_err(|e| WinlibError::ObjectError {
        msg: format!("not a recognised archive file: {}", lib_path.display()),
        cause: e,
    })?;

    println!("{:>10}  {:>10}  member name", "offset", "size");
    for member in archive.members() {
        let member = member.map_err(|e| WinlibError::ObjectError {
            msg: format!("could not read archive member in {}", lib_path.display()),
            cause: e,
        })?;
        let name = String::from_utf8_lossy(member.name());
        let (offset, size) = member.file_range();
        println!("{offset:>#10X}  {size:>#10X}  {name}");
    }

    Ok(())
}

#[derive(PartialEq)]
enum Command {
    Create,
    List,
}

#[derive(Default)]
struct Options {
    command: Option<Command>,
    remove_idata: bool,
    remove_offsets: Vec<u32>,
    from_lib: Option<OsString>,
    target_lib: Option<OsString>,
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
                    options.command = Some(Command::Create);
                } else if v == "list" {
                    options.command = Some(Command::List);
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
            Value(v) if options.target_lib.is_none() => options.target_lib = Some(v),
            Long("from") if options.command == Some(Command::Create) => {
                options.from_lib = Some(parser.value()?);
            }
            Long("keep-removed") if options.command == Some(Command::Create) => {
                options.keep_removed = Some(parser.value()?);
            }
            Long("remove") if options.command == Some(Command::Create) => {
                let value = parser.value()?;
                let offset = match value.to_str() {
                    Some(s) => if s.starts_with("0x") {
                        u32::from_str_radix(&s[2..], 16)
                    } else {
                        u32::from_str_radix(s, 10)
                    }
                    .map_err(|_| lexopt::Error::ParsingFailed {
                        value: s.into(),
                        error: "value must be an offset in hexadecimal or decimal format".into(),
                    })?,
                    None => {
                        if unexpected.is_none() {
                            unexpected = Some(lexopt::Error::NonUnicodeValue(value));
                        }
                        continue;
                    }
                };
                options.remove_offsets.push(offset);
            }
            Long("remove-idata") if options.command == Some(Command::Create) => {
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
\twinlib list <LIB_PATH>
\twinlib create <LIB_PATH> --from <PATH> --remove-idata [--keep-removed <PATH>]

<LIB_PATH> is the path of the lib to create or inspect.

Create Options:
\t--from <PATH>        \tThe new lib will contain members from the old lib at <PATH>.
\t--remove <OFFSET>    \tRemove the member at the given offset
\t--remove-idata       \tRemove members containing .idata sections.
\t--keep-removed <PATH>\tStore the removed members in a separate library at <PATH>.

Examples:
\twinlib list oldlib.lib
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
            return failure!("\nerror {e}");
        }
    };
    if options.help {
        print_help();
        return ExitCode::SUCCESS;
    }
    let Some(target_lib) = options.target_lib else {
        print_help();
        return failure!("error: no output lib path provided");
    };
    match options.command {
        Some(Command::Create) => {
            let Some(lib_path) = options.from_lib else {
                print_help();
                return failure!("error: no --from lib path provided");
            };
            let options = CreateOptions {
                remove_offsets: options.remove_offsets,
                remove_idata: options.remove_idata,
                keep_removed: options.keep_removed,
            };
            match create_lib(&lib_path, &target_lib, &options) {
                Ok(_) => return ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}")
                }
            }
        }
        Some(Command::List) => match list_lib(&target_lib) {
            Ok(_) => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}")
            }
        },
        _ => {}
    }
    ExitCode::SUCCESS
}
