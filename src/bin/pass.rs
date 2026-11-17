use base64::{Engine as _, engine::general_purpose};
use nass::himitsu_to_totp;
use nass::keyandquery::HimitsuKey;
use nass::optparser::{Argument, OptParser};
use nass::proto;
use nass::state::Repository;
use nass::state::pass::{himitsu_to_pass_files, pass_file_to_himitsu};
use std::env;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const HELP: &str = "Usage:
    pass ls
        Displays password files with tree
    pass show <name>
        Displays a password
    pass grep [grep-options...]
        Search with grep in all decrypted password files
    pass insert <name>
        Create a new password from standard input
    pass edit <name>
        Edit a password with $EDITOR
    pass generate [options...] <name> [length]
        Generate a new password
        -n                Only use alphanumerics
    pass otp <path>
        Show OTP code
    pass help
        Print help text
";

fn main() -> Result<(), String> {
    fn pass_show(
        connection: &mut impl Repository,
        path: &str,
    ) -> Result<(), String> {
        if path == "/" {
            let keys = connection.disclose(vec!["path".to_string()].into())?;
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
            let keys = connection.disclose(
                vec![format!(
                    "path={}",
                    path.strip_prefix('/').unwrap_or(path)
                )]
                .into(),
            )?;
            let pass_files = himitsu_to_pass_files(keys.iter());

            match pass_files.len() {
                1 => (),
                0 => return Err("Received no keys".to_string()),
                _ => return Err("Received multiple keys".to_string()),
            }
            std::io::stdout()
                .write_all(&pass_files.into_values().next().unwrap())
                .map_err(|err| format!("Failed to write to stdout: {err}"))?;
        }
        Ok(())
    }
    let mut optparser = OptParser::new(env::args().skip(1));
    let subcommand = optparser.next();
    if subcommand.as_deref() == Some("help") {
        print!("{HELP}");
        return Ok(());
    }

    let mut connection = proto::HimitsuProtocol::new()?;
    match subcommand.as_deref() {
        Some("ls") | None => pass_show(&mut connection, "/"),
        Some("insert") => {
            while optparser.next_opt().is_some() {}
            let mut input = Vec::new();
            std::io::stdin()
                .read_to_end(&mut input)
                .map_err(|err| err.to_string())?;
            pass_file_to_himitsu(
                &optparser.next().ok_or("missing path")?,
                &input,
            )
            .into_iter()
            .map(|key| connection.add(key))
            .collect::<Result<Vec<_>, String>>()
            .map(|_| ())
        }
        Some("edit") => {
            while optparser.next_opt().is_some() {}
            let name = optparser.next().ok_or("missing path")?;
            let name = name.strip_prefix('/').unwrap_or(&name);
            let keys =
                connection.disclose(vec![format!("path={name}")].into())?;
            let pass_files = himitsu_to_pass_files(keys.iter());
            let original = match pass_files.len() {
                1 => pass_files.into_values().next().unwrap(),
                0 => return Err("Received no keys".to_string()),
                _ => return Err("Received multiple keys".to_string()),
            };

            let path = ({
                let mut command = Command::new("mktemp");
                if Path::new("/dev/shm").is_dir() {
                    command.env("TMPDIR", "/dev/shm");
                }
                command
            })
            .output()
            .map_err(|err| err.to_string())
            .and_then(|result| {
                if result.status.success() {
                    Ok(String::from_utf8_lossy(&result.stdout).to_string())
                } else {
                    Err(String::from_utf8_lossy(&result.stderr).to_string())
                }
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
                    std::fs::read(&path).map_err(|err| {
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
            connection.delete(vec![format!("path={name}")].into())?;
            pass_file_to_himitsu(name, &edited)
                .into_iter()
                .map(|key| connection.add(key))
                .collect::<Result<Vec<_>, String>>()
                .map(|_| ())
        }
        Some("otp") => {
            while optparser.next_opt().is_some() {}
            let name = optparser.next().ok_or("missing path")?;
            let name = name.strip_prefix('/').unwrap_or(&name);
            let mut keys = connection.disclose(
                vec!["proto=totp".into(), format!("path={name}")].into(),
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
                .add(HimitsuKey(vec![
                    ("proto".into(), (false, "file".into())),
                    ("path".into(), (false, name.into())),
                    ("content".into(), (true, out)),
                ]))
                .map(|_| ())
        }
        Some("grep") => {
            let keys = connection.disclose(vec!["path".to_string()].into())?;
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
                            .write_all(value.as_slice())
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
