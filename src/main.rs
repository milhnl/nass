#[path = "optparser.rs"]
mod optparser;
#[path = "otp.rs"]
mod otp;
#[path = "proto.rs"]
mod proto;
#[path = "state.rs"]
mod state;

use crate::optparser::{Argument, OptParser};
use crate::state::pass::{himitsu_to_pass_files, pass_file_to_himitsu};
use crate::state::{
    HimitsuKey, HimitsuQuery, MultiplexedRepository, Repository,
    RepositoryClient,
};
use base64::{Engine as _, engine::general_purpose};
use otp::Totp;
use shlex::split;
use std::collections::HashMap;
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio, exit};

fn run_utf8_command(command: &mut Command) -> Result<String, String> {
    command
        .output()
        .map_err(|err| err.to_string())
        .and_then(|result| {
            if result.status.success() {
                Ok(String::from_utf8_lossy(&result.stdout).to_string())
            } else {
                Err(String::from_utf8_lossy(&result.stderr).to_string())
            }
        })
}

fn pass_main(args: Vec<String>) -> Result<(), String> {
    let mut connection = proto::HimitsuProtocol::new()?;
    fn pass_show(
        connection: &mut impl Repository,
        path: &str,
    ) -> Result<(), String> {
        if path == "/" {
            let keys = connection.query(
                HimitsuQuery::from_components([format!("path")]).unwrap(),
                false,
            )?;
            let mut pass_files = himitsu_to_pass_files(keys.iter())
                .into_keys()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            pass_files.sort();
            let mut last_dir: Option<PathBuf> = None;
            println!("pass");
            pass_files.into_iter().for_each(|path| {
                fn print_path(file: &Path) {
                    println!(
                        "{:}{:}",
                        {
                            let depth = file.iter().count();
                            if depth == 0 {
                                "".to_owned()
                            } else {
                                format!(
                                    "{}{}",
                                    "│   ".repeat(depth - 1),
                                    "├── "
                                )
                            }
                        },
                        file.file_name()
                            .map(|leaf| leaf.to_str().unwrap())
                            .unwrap_or("")
                    )
                }
                if path.parent() != last_dir.as_deref() {
                    last_dir = path.parent().map(Path::to_path_buf);
                    if let Some(last_dir) = &last_dir {
                        print_path(last_dir);
                    }
                }
                print_path(&path);
            });
        } else {
            let keys = connection.query(
                HimitsuQuery::from_components([format!(
                    "path={}",
                    path.strip_prefix('/').unwrap_or(path)
                )])
                .unwrap(),
                true,
            )?;
            let pass_files = himitsu_to_pass_files(keys.iter());

            match pass_files.len() {
                1 => (),
                0 => return Err("Received no keys".to_string()),
                _ => return Err("Received multiple keys".to_string()),
            }
            print!("{}", pass_files.into_iter().next().unwrap().1);
        }
        Ok(())
    }
    let mut optparser = OptParser::new(args.into_iter());
    match optparser.next().as_deref() {
        Some("ls") | None => pass_show(&mut connection, "/"),
        Some("insert") => {
            while optparser.next_opt().is_some() {}
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .map_err(|err| err.to_string())?;
            pass_file_to_himitsu(
                &optparser.next().ok_or("missing path")?,
                &input,
            )
            .into_iter()
            .map(|key| connection.add(HimitsuQuery::try_from(key).unwrap()))
            .collect::<Result<Vec<_>, String>>()
            .map(|_| ())
        }
        Some("edit") => {
            while optparser.next_opt().is_some() {}
            let name = optparser.next().ok_or("missing path")?;
            let name = name.strip_prefix('/').unwrap_or(&name);
            let keys = connection.query(
                HimitsuQuery::from_components([format!("path={name}")])
                    .unwrap(),
                true,
            )?;
            let pass_files = himitsu_to_pass_files(keys.iter());
            let original = match pass_files.len() {
                1 => pass_files.into_values().next().unwrap(),
                0 => return Err("Received no keys".to_string()),
                _ => return Err("Received multiple keys".to_string()),
            };
            let path = run_utf8_command(&mut {
                let mut command = Command::new("mktemp");
                if Path::new("/dev/shm").is_dir() {
                    command.env("TMPDIR", "/dev/shm");
                }
                command
            })
            .map(|mut stdout| {
                if stdout.ends_with('\n') {
                    stdout.pop();
                };
                stdout
            })?;
            let edited = std::fs::write(&path, &original)
                .map_err(|err| err.to_string())
                .and_then(|()| {
                    Command::new(
                        env::var_os("EDITOR").ok_or("$EDITOR is not set")?,
                    )
                    .arg(&path)
                    .status()
                    .map_err(|err| err.to_string())
                    .and_then(|result| {
                        if result.success() {
                            Ok(())
                        } else {
                            Err("Editor exited with non-zero status".into())
                        }
                    })
                })
                .and_then(|_stdout| {
                    std::fs::read_to_string(&path).map_err(|err| {
                        format!("Could not read edited file: {err}")
                    })
                });
            let _ = std::fs::remove_file(&path);
            let Ok(edited) = edited else {
                return edited.map(|_| ());
            };

            if edited == original {
                return Ok(());
            }
            connection.delete(
                HimitsuQuery::from_components([format!("path={name}")])
                    .unwrap(),
            )?;
            pass_file_to_himitsu(name, &edited)
                .into_iter()
                .map(|key| {
                    connection.add(HimitsuQuery::try_from(key).unwrap())
                })
                .collect::<Result<Vec<_>, String>>()
                .map(|_| ())
        }
        Some("otp") => {
            while optparser.next_opt().is_some() {}
            let name = optparser.next().ok_or("missing path")?;
            let name = name.strip_prefix('/').unwrap_or(&name);
            let mut keys = connection.query(
                HimitsuQuery::from_components([
                    "proto=totp".into(),
                    format!("path={name}"),
                ])
                .unwrap(),
                true,
            )?;
            match keys.len() {
                1 => (),
                0 => return Err("Received no keys".to_string()),
                _ => return Err("Received multiple keys".to_string()),
            }
            let key = keys.pop().unwrap();
            let otp = himitsu_to_totp(&key);
            println!("{}", otp.unwrap().generate_string());
            Ok(())
        }
        Some("generate") => {
            let mut no_symbols = false;
            while let Some(opt) = optparser.next_opt() {
                match opt {
                    Argument::Short('n') => {
                        no_symbols = true;
                    }
                    _ => Err(&format!("unknown option {opt:?}"))?,
                }
            }
            let name = optparser.next().ok_or("missing path")?;
            let name = name.strip_prefix('/').unwrap_or(&name);
            let length = optparser
                .next()
                .as_deref()
                .unwrap_or("25")
                .parse::<usize>()
                .map_err(|_| "Could not parse password length")
                .unwrap();
            let random = Command::new("sh")
                .args([
                    "-c",
                    &format!(
                        "LC_ALL=C </dev/urandom tr -dc '{}' | head -c {}",
                        if no_symbols {
                            "[:alnum:]"
                        } else {
                            "[:punct:][:alnum:]"
                        },
                        length
                    ),
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .and_then(Child::wait_with_output)
                .map_err(|_| "Could not generate new password")?;
            let out = general_purpose::STANDARD.encode(&random.stdout);
            connection
                .add(
                    HimitsuQuery::from_components([
                        "proto=file".into(),
                        format!("path={name}"),
                        format!("content!={out}"),
                    ])
                    .unwrap(),
                )
                .map(|_| ())
        }
        Some("grep") => {
            let keys = connection.query(
                HimitsuQuery::from_components([format!("path")]).unwrap(),
                false,
            )?;
            let pass_files = himitsu_to_pass_files(keys.iter());
            let opts = &optparser.collect::<Vec<String>>();
            println!("{:?}", opts);

            pass_files
                .iter()
                .map(|(key, value)| {
                    let mut grep = Command::new("grep")
                        .args(opts)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap();

                    let mut stdin = grep.stdin.take().ok_or_else(|| {
                        let _ = grep.wait();
                        "Failed to open stdin"
                    })?;
                    let value = value.clone();
                    std::thread::spawn(move || {
                        stdin
                            .write_all(value.as_bytes())
                            .expect("Failed to write to stdin");
                    });

                    grep.wait_with_output().map_err(|err| err.to_string()).map(
                        |status| {
                            if status.status.success() {
                                Some((
                                    key,
                                    String::from_utf8_lossy(&status.stdout)
                                        .to_string(),
                                ))
                            } else {
                                None
                            }
                        },
                    )
                })
                .for_each(|out| match out {
                    Ok(Some((key, output))) => print!("{}:\n{}", key, output),
                    Err(err) => eprintln!("{err}"),
                    _ => (),
                });
            Ok(())
        }
        Some("show") => {
            while optparser.next_opt().is_some() {}
            let name =
                optparser.next().ok_or("Missing path argument")?.to_owned();
            pass_show(&mut connection, &name)
        }
        Some(subcommand) => {
            pass_show(&mut connection, subcommand).map_err(|_| {
                format!(
                    "Subcommand not known or not implemented: {} {}",
                    subcommand,
                    optparser.collect::<Vec<_>>().join(" ")
                )
            })
        }
    }
}

fn handle_client(
    mut unix_stream: UnixStream,
    mut state: impl Repository,
) -> Result<(), String> {
    fn reply(unix_stream: &mut UnixStream, msg: &str) -> Result<(), String> {
        dbg!(msg);
        unix_stream
            .write(msg.as_bytes())
            .map_err(|_| "Failed at writing onto the unix stream")?;
        Ok(())
    }
    let reader = BufReader::new(
        unix_stream.try_clone().map_err(|err| format!("{err}"))?,
    );
    let mut update_query = Option::<HimitsuQuery>::None;
    for message in reader.lines() {
        let message = message.map_err(|err| format!("{err}"))?;
        match message.split_once(' ').unwrap_or((message.as_ref(), "")) {
            ("set", query) if update_query.is_some() => {
                let Some(query) =
                    split(query).and_then(HimitsuQuery::from_components)
                else {
                    reply(
                        &mut unix_stream,
                        "error \"could not parse query\"\n",
                    )?;
                    continue;
                };
                state.update(update_query.take().unwrap(), query)?;
            }
            _ if update_query.is_some() => {
                reply(
                    &mut unix_stream,
                    "error \"command after update should be set\"\n",
                )?;
                update_query = None;
            }
            ("update", query) => {
                let Some(query) =
                    split(query).and_then(HimitsuQuery::from_components)
                else {
                    reply(
                        &mut unix_stream,
                        "error \"could not parse query\"\n",
                    )?;
                    continue;
                };
                update_query = Some(query);
                reply(&mut unix_stream, "update")?;
            }

            ("status", _) => reply(&mut unix_stream, "status unlocked\n")?,
            ("add", query) => {
                let Some(query) =
                    split(query).and_then(HimitsuQuery::from_components)
                else {
                    reply(
                        &mut unix_stream,
                        "error \"could not parse query\"\n",
                    )?;
                    continue;
                };
                println!("add {}", query.clone().encode());

                reply(
                    &mut unix_stream,
                    &state
                        .add(query)
                        .and_then(|keys| {
                            keys.iter()
                                .map(|key| {
                                    key.encode(false).map(|mut encoded_key| {
                                        encoded_key.insert_str(0, "key ");
                                        encoded_key.push('\n');
                                        encoded_key
                                    })
                                })
                                .chain(std::iter::once(Ok("end\n".into())))
                                .collect::<Result<Vec<String>, String>>()
                                .map(|keys| keys.join(""))
                        })
                        .unwrap_or_else(|err| format!("error \"{err}\"\n")),
                )?;
            }
            ("del", query) => {
                let Some(query) = split(query) else {
                    reply(
                        &mut unix_stream,
                        "error \"could not parse query\"\n",
                    )?;
                    continue;
                };
                let query = HimitsuQuery::from_components(query).unwrap();
                println!("del {}", query.clone().encode());

                reply(
                    &mut unix_stream,
                    &state
                        .delete(query)
                        .and_then(|keys| {
                            keys.iter()
                                .map(|key| {
                                    key.encode(false).map(|mut encoded_key| {
                                        encoded_key.insert_str(0, "key ");
                                        encoded_key.push('\n');
                                        encoded_key
                                    })
                                })
                                .chain(std::iter::once(Ok("end\n".into())))
                                .collect::<Result<Vec<String>, String>>()
                                .map(|keys| keys.join(""))
                        })
                        .unwrap_or_else(|err| format!("error \"{err}\"\n")),
                )?;
            }
            ("query", query) => {
                let Some(query) = split(query) else {
                    reply(
                        &mut unix_stream,
                        "error \"could not parse query\"\n",
                    )?;
                    continue;
                };
                let mut decrypt = false;
                let mut optparser = OptParser::new(query.into_iter());
                while let Some(opt) = optparser.next_opt() {
                    match opt {
                        Argument::Short('d') => decrypt = true,
                        _ => {
                            reply(
                                &mut unix_stream,
                                &format!("error \"unknown option {opt:?}\"\n"),
                            )?;
                            continue;
                        }
                    }
                }
                let query = HimitsuQuery::from_components(optparser).unwrap();
                println!(
                    "query {}{}",
                    if decrypt { "-d " } else { "" },
                    query.clone().encode()
                );
                reply(
                    &mut unix_stream,
                    &state
                        .query(query, decrypt)
                        .and_then(|keys| {
                            keys.iter()
                                .map(|key| {
                                    key.encode(decrypt).map(
                                        |mut encoded_key| {
                                            encoded_key.insert_str(0, "key ");
                                            encoded_key.push('\n');
                                            encoded_key
                                        },
                                    )
                                })
                                .chain(std::iter::once(Ok("end\n".into())))
                                .collect::<Result<Vec<String>, String>>()
                                .map(|keys| keys.join(""))
                        })
                        .unwrap_or_else(|err| format!("error \"{err}\"\n")),
                )?;
            }
            (command, _) => reply(
                &mut unix_stream,
                &format!("error \"unknown command: {command}\"\n"),
            )?,
        }
    }
    Ok(())
}

pub fn himitsu_to_totp(key: &HimitsuKey) -> Result<Totp, String> {
    Totp::from_slices(
        key.get_value("algorithm"),
        key.get_value("issuer"),
        key.get_value("label")
            .ok_or_else(|| format!("Key {key:?} is missing label"))?,
        key.get_value("digits"),
        key.get_value("period"),
        key.get_value("secret")
            .ok_or_else(|| format!("Key {key:?} is missing secret"))?,
        key.get_value("label_issuer"),
        HashMap::new(),
    )
}

fn himitsud_main(_args: Vec<String>) -> Result<(), String> {
    let socket_path =
        PathBuf::from(env::var("XDG_RUNTIME_DIR").unwrap()).join("himitsu");
    if std::fs::metadata(&socket_path).is_ok() {
        eprintln!("A socket is already present. Deleting...");
        std::fs::remove_file(&socket_path).map_err(|err| {
            format!("Could not delete socket path {:?}: {}", &socket_path, err)
        })?;
    }
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("Couldn't bind: {err:?}"))?;

    //let state = start_state_service::<RepositoryMultiplexActor>()?;
    let state = RepositoryClient::new::<MultiplexedRepository>()?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = state.clone();
                std::thread::spawn(move || handle_client(stream, state));
            }
            Err(err) => {
                eprintln!("Error: {err:?}");
                break;
            }
        }
    }
    Ok(())
}

fn hiq_main(args: Vec<String>) -> Result<(), String> {
    let mut connection = proto::HimitsuProtocol::new()?;
    let mut decrypt = false;
    let mut one = false;
    let mut optparser = OptParser::new(args.into_iter());
    while let Some(opt) = optparser.next_opt() {
        match opt {
            Argument::Short('d') => decrypt = true,
            Argument::Short('1') => one = true,
            Argument::Short(x) => Err(format!("Unknown option: {x}"))?,
            Argument::Long(x) => Err(format!("Unknown option: {x}"))?,
        }
    }
    let query = optparser.collect::<Vec<String>>();
    let keys = connection.query(
        HimitsuQuery::from_components(query)
            .ok_or_else(|| "Could not re-quote args".to_owned())?,
        decrypt,
    )?;

    if one {
        match keys.len() {
            1 => (),
            0 => return Err("Received no keys".to_string()),
            _ => return Err("Received multiple keys".to_string()),
        }
    }

    match keys
        .iter()
        .map(|key| key.encode(decrypt))
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(keys) => keys.into_iter().for_each(|key| println!("{key}")),
        Err(err) => eprintln!("{err}"),
    }

    Ok(())
}

fn main() {
    match match env::args()
        .next()
        .as_deref()
        .map(Path::new)
        .and_then(|x| x.file_stem())
        .and_then(|x| x.to_str())
    {
        Some("pass") => pass_main(env::args().skip(1).collect()),
        Some("himitsud") => himitsud_main(env::args().skip(1).collect()),
        Some("hiq") => hiq_main(env::args().skip(1).collect()),
        _ => Err("Hmmm".to_string()),
    } {
        Ok(()) => exit(0),
        Err(err) => {
            eprintln!("{err}");
            exit(1)
        }
    }
}
