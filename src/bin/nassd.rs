use nass::optparser::{Argument, OptParser};
use nass::state::{
    HimitsuQuery, MultiplexedRepository, Repository, RepositoryClient,
};
use shlex::split;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

fn handle_client(
    mut unix_stream: UnixStream,
    mut state: impl Repository,
) -> Result<(), String> {
    fn reply(unix_stream: &mut UnixStream, msg: &str) -> Result<(), String> {
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
                reply(&mut unix_stream, "update\n")?;
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

fn main() -> Result<(), String> {
    let socket_path =
        PathBuf::from(env::var("XDG_RUNTIME_DIR").unwrap()).join("himitsu");
    if std::fs::metadata(&socket_path).is_ok() {
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
