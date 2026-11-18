use nass::keyandquery::HimitsuQuery;
use nass::optparser::{Argument, OptParser};
use nass::proto::SOCKET_PATH;
use nass::state::{MultiplexedRepository, Repository, RepositoryClient};
use shlex::{Quoter, split};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};

fn handle_client(
    unix_stream: UnixStream,
    mut state: impl Repository,
) -> Result<(), String> {
    fn reply(writer: &mut impl Write, msg: &str) -> Result<(), String> {
        writer
            .write_all(msg.as_bytes())
            .map_err(|_| "Failed at writing onto the unix stream")?;
        Ok(())
    }
    fn reply_err(writer: &mut impl Write, err: impl AsRef<str>) {
        reply(
            writer,
            &format!(
                "error {}\n",
                Quoter::new().allow_nul(true).quote(err.as_ref()).unwrap()
            ),
        )
        .unwrap_or_else(|err| {
            eprintln!("Error while reporting an error to the client: {err}")
        })
    }
    let reader = BufReader::new(
        unix_stream.try_clone().map_err(|err| format!("{err}"))?,
    );
    let mut writer = BufWriter::new(unix_stream);
    let mut update_query = Option::<HimitsuQuery>::None;
    for message in reader.lines() {
        let message = message.map_err(|err| format!("{err}"))?;
        match message.split_once(' ').unwrap_or((message.as_ref(), "")) {
            ("set", query) if update_query.is_some() => {
                query
                    .parse()
                    .and_then(|query| {
                        state.update(update_query.take().unwrap(), query)
                    })
                    .and_then(|keys| {
                        keys.into_iter().try_for_each(|key| {
                            reply(&mut writer, &format!("key {key}\n"))
                        })
                    })
                    .and_then(|()| reply(&mut writer, "end\n"))
                    .unwrap_or_else(|err| reply_err(&mut writer, err));
            }
            _ if update_query.is_some() => {
                reply(
                    &mut writer,
                    "error \"command after update should be set\"\n",
                )?;
                update_query = None;
            }
            ("update", query) => {
                query
                    .parse()
                    .and_then(|query| {
                        update_query = Some(query);
                        reply(&mut writer, "update\n")
                    })
                    .unwrap_or_else(|err| reply_err(&mut writer, err));
            }

            ("status", _) => reply(&mut writer, "status unlocked\n")?,
            ("add", key) => {
                key.parse()
                    .and_then(|key| state.add(key))
                    .and_then(|keys| {
                        keys.into_iter().try_for_each(|key| {
                            reply(&mut writer, &format!("key {key}\n"))
                        })
                    })
                    .and_then(|()| reply(&mut writer, "end\n"))
                    .unwrap_or_else(|err| reply_err(&mut writer, err));
            }
            ("del", query) => {
                query
                    .parse()
                    .and_then(|query| state.delete(query))
                    .and_then(|keys| {
                        keys.into_iter().try_for_each(|key| {
                            reply(&mut writer, &format!("key {key}\n"))
                        })
                    })
                    .and_then(|()| reply(&mut writer, "end\n"))
                    .unwrap_or_else(|err| reply_err(&mut writer, err));
            }
            ("query", query) => {
                let Some(query) = split(query) else {
                    reply(&mut writer, "error \"could not parse query\"\n")?;
                    continue;
                };
                let mut decrypt = false;
                let mut optparser = OptParser::new(query.into_iter());
                while let Some(opt) = optparser.next_opt() {
                    match opt {
                        Argument::Short('d') => decrypt = true,
                        _ => {
                            reply(
                                &mut writer,
                                &format!("error \"unknown option {opt:?}\"\n"),
                            )?;
                            continue;
                        }
                    }
                }
                let query: HimitsuQuery =
                    optparser.into_iter().collect::<Vec<_>>().into();
                if decrypt {
                    state
                        .disclose(query)
                        .and_then(|keys| {
                            keys.into_iter().try_for_each(|key| {
                                reply(&mut writer, &format!("key {key}\n"))
                            })
                        })
                        .and_then(|()| reply(&mut writer, "end\n"))
                        .unwrap_or_else(|err| reply_err(&mut writer, err));
                } else {
                    state
                        .query(query)
                        .and_then(|keys| {
                            keys.into_iter().try_for_each(|key| {
                                reply(&mut writer, &format!("key {key}\n"))
                            })
                        })
                        .and_then(|()| reply(&mut writer, "end\n"))
                        .unwrap_or_else(|err| reply_err(&mut writer, err));
                }
            }
            (command, _) => reply(
                &mut writer,
                &format!("error \"unknown command: {command}\"\n"),
            )?,
        }
        writer.flush().map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let socket_path = SOCKET_PATH.as_deref()?;
    eprintln!("{socket_path:?}");
    if std::fs::metadata(socket_path).is_ok() {
        std::fs::remove_file(socket_path).map_err(|err| {
            format!("Could not delete socket path {:?}: {}", socket_path, err)
        })?;
    }
    let listener = UnixListener::bind(socket_path)
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
