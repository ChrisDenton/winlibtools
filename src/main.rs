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
    exclude_idata: bool,
    exclude_offsets: Vec<u32>,
    save_excluded: Option<OsString>,
}

fn create_lib(
    lib_path: &OsStr,
    out_lib: &OsStr,
    options: &CreateOptions,
) -> Result<(), WinlibError> {
    let extracted_lib = options.save_excluded.as_deref();
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
        let mut exclude = false;
        if options.exclude_offsets.contains(&(member.file_range().0 as u32)) {
            exclude = true;
        } else if options.exclude_idata {
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
                            exclude = true;
                            break;
                        }
                    }
                }
                Err(e) => {
                    if let Ok(_) = ImportFile::parse(&*data) {
                        exclude = true;
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
        if exclude {
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
    exclude_idata: bool,
    exclude_offsets: Vec<u32>,
    from_lib: Option<OsString>,
    target_lib: Option<OsString>,
    save_excluded: Option<OsString>,
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
            Long("save-excluded") | Long("keep-removed")
                if options.command == Some(Command::Create) =>
            {
                options.save_excluded = Some(parser.value()?);
            }
            Long("exclude") | Long("remove") if options.command == Some(Command::Create) => {
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
                options.exclude_offsets.push(offset);
            }
            Long("exclude-idata") | Long("remove-idata")
                if options.command == Some(Command::Create) =>
            {
                options.exclude_idata = true;
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
\twinlib create <LIB_PATH> --from <PATH> --exclude-idata [--save-excluded <PATH>]

<LIB_PATH> is the path of the lib to create or inspect.

Create Options:
\t--from <PATH>        \tThe new lib will contain members from the old lib at <PATH>.
\t--exclude <OFFSET>    \tExclude the member at the given offset
\t--exclude-idata       \tExclude members containing .idata sections.
\t--save-excluded <PATH>\tStore the excluded members in a separate library at <PATH>.

Examples:
\twinlib list oldlib.lib
\twinlib create newlib.lib --from oldlib.lib --exclude-idata --save-excluded import.lib
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
                exclude_offsets: options.exclude_offsets,
                exclude_idata: options.exclude_idata,
                save_excluded: options.save_excluded,
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
