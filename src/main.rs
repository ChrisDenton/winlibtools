use clap::ArgAction;
use core::num::ParseIntError;
use object::coff::{CoffFile, ImportFile};
use object::pe::ImageFileHeader;
use object::read::archive::ArchiveFile;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Cursor};
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
    from_lib: &OsStr,
    out_lib: &OsStr,
    options: &CreateOptions,
) -> Result<(), WinlibError> {
    let extracted_lib = options.save_excluded.as_deref();
    let data = fs::read(&from_lib).map_err(|e| WinlibError::IoError {
        msg: format!("cannot read {}", from_lib.display()),
        cause: e,
    })?;
    let archive = ArchiveFile::parse(&*data).map_err(|e| WinlibError::ObjectError {
        msg: format!("not a recognised archive file: {}", from_lib.display()),
        cause: e,
    })?;

    let mut extracted_members = Vec::new();
    let mut included_members = Vec::new();

    for member in archive.members() {
        let member = member.map_err(|e| WinlibError::ObjectError {
            msg: format!("could not read archive member in {}", from_lib.display()),
            cause: e,
        })?;
        let data = member.data(&*data).map_err(|e| WinlibError::ObjectError {
            msg: format!(
                "could not get data from archive member at {:#x} in {}",
                member.file_range().0,
                from_lib.display()
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
                                from_lib.display()
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
                                from_lib.display()
                            ),
                            cause: e,
                        });
                    }
                }
            }
        }
        let name = String::from_utf8_lossy(member.name());

        let new_member = ar_archive_writer::NewArchiveMember {
            buf: Box::new(data),
            object_reader: &ar_archive_writer::DEFAULT_OBJECT_READER,
            member_name: name.into(),
            mtime: member.date().unwrap_or(0),
            uid: member.uid().unwrap_or(0) as u32,
            gid: member.gid().unwrap_or(0) as u32,
            perms: member.mode().unwrap_or(0o644) as u32,
        };
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

fn main() -> ExitCode {
    use clap::{arg, builder::ValueParser};
    fn hex_value(s: &str) -> Result<u32, ParseIntError> {
        let offset = if let Some(s) = s.strip_prefix("0x") {
            u32::from_str_radix(s, 16)
        } else {
            u32::from_str_radix(s, 10)
        }?;
        Ok(offset)
    }
    let matches = clap::Command::new("winlib")
        .version("0.2.1")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(clap::Command::new("list")
            .about("Show the contents of a lib.")
            .arg(arg!([LIB_PATH] "the path of the lib to inspect").value_parser(ValueParser::os_string())))
        .subcommand(
            clap::Command::new("create")
                .about("Create a new lib from an old lib.")
                .arg(arg!(<LIB_PATH> "the new path of the lib to create").required(true).value_parser(ValueParser::os_string()))
                .arg(arg!(--from <PATH> "The new lib will contain members from the old lib at <PATH>.").required(true).value_parser(ValueParser::os_string()))
                // FIXME: use a custom value parser
                .arg(arg!(--exclude <OFFSET> "Exclude the member at the given offset.").value_parser(hex_value).action(ArgAction::Append))
                .arg(arg!(--"exclude-idata" "Exclude members containing .idata sections."))
                .arg(arg!(--"save-excluded" <PATH> "Store the excluded members in a separate library at <PATH>.").value_parser(ValueParser::os_string()))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("create", cfg)) => {
            let Some(target_lib) = cfg.get_one::<OsString>("LIB_PATH") else { unreachable!() };
            let Some(from_lib) = cfg.get_one::<OsString>("from") else { unreachable!() };
            let exclude_offsets: Vec<u32> =
                cfg.get_many("exclude").unwrap_or_default().copied().collect();
            let exclude_idata = cfg.get_flag("exclude-idata");
            let save_excluded = cfg.get_one::<OsString>("save-excluded");
            let options = CreateOptions {
                exclude_offsets,
                exclude_idata,
                save_excluded: save_excluded.cloned(),
            };
            match create_lib(from_lib, target_lib, &options) {
                Ok(_) => return ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}")
                }
            }
        }
        Some(("list", cfg)) => {
            let Some(target_lib) = cfg.get_one::<OsString>("LIB_PATH") else { unreachable!() };
            match list_lib(target_lib) {
                Ok(_) => return ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}")
                }
            }
        }
        _ => (),
    }

    ExitCode::FAILURE
}
