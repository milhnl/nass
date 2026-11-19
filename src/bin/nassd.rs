use nass::proto::{RepositoryReply, SOCKET_PATH, read_repository_operation};
use nass::state::{
    MultiplexedRepository, Repository, RepositoryClient, RepositoryOperation,
};
use std::io::{BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};

fn handle_client(
    unix_stream: UnixStream,
    mut state: impl Repository,
) -> Result<(), String> {
    let mut reader = BufReader::new(
        unix_stream.try_clone().map_err(|err| format!("{err}"))?,
    );
    let mut writer = BufWriter::new(unix_stream);
    loop {
        let command = read_repository_operation(&mut reader, &mut writer)
            .map_err(|err| err.to_string())?;
        let command = match command {
            Ok(Some(command)) => command,
            Ok(None) => return Ok(()),
            Err(err) => {
                write!(writer, "{}", RepositoryReply::Error(err))
                    .map_err(|err| err.to_string())?;
                writer.flush().map_err(|err| err.to_string())?;
                continue;
            }
        };

        let reply = match command {
            RepositoryOperation::Add(key) => {
                state.add(key).map(RepositoryReply::Keys)
            }
            RepositoryOperation::Delete(query) => {
                state.delete(query).map(RepositoryReply::Keys)
            }
            RepositoryOperation::Query(query) => {
                state.query(query).map(RepositoryReply::Keys)
            }
            RepositoryOperation::Disclose(query) => {
                state.disclose(query).map(RepositoryReply::DisclosedKeys)
            }
            RepositoryOperation::Update((query, set)) => {
                state.update(query, set).map(RepositoryReply::Keys)
            }
            RepositoryOperation::Status(()) => {
                state.status().map(RepositoryReply::Status)
            }
            RepositoryOperation::Lock(lock) => {
                state.lock(lock).map(|()| RepositoryReply::Locked)
            }
        }
        .unwrap_or_else(RepositoryReply::Error);
        write!(writer, "{reply}").map_err(|err| err.to_string())?;
        writer.flush().map_err(|err| err.to_string())?;
    }
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
