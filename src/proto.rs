mod operation;
pub use operation::read_protocol_command;
mod reply;
use crate::keyandquery::{
    CompleteHimitsuKey, HimitsuKey, HimitsuQuery, RedactedHimitsuKey,
};
use crate::state::{LockStatus, Repository};
pub use operation::read_repository_operation;
pub use reply::RepositoryReply;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

fn query_socket(
    connection: &mut BufReader<UnixStream>,
    query: &str,
) -> Result<(), String> {
    connection
        .get_mut()
        .write(query.as_bytes())
        .map_err(|_| "Failed at writing onto the unix stream".to_owned())
        .and(Ok(()))
}

fn parse_single_response(
    connection: &mut impl BufRead,
) -> Result<Option<(String, Vec<String>)>, String> {
    read_protocol_command(connection)
        .map_err(|err| err.to_string())
        .flatten()
        .map(|response| {
            response.map(|mut response| (response.remove(0), response))
        })
}

fn parse_keys_response<Field>(
    connection: &mut impl BufRead,
) -> Result<Vec<HimitsuKey<Field>>, String>
where
    HimitsuKey<Field>: TryFrom<Vec<String>, Error = String>,
{
    let mut keys = Vec::new();

    loop {
        let (name, rest) =
            parse_single_response(connection).and_then(|res| {
                res.ok_or_else(|| {
                    "Connection closed before an end response".to_owned()
                })
            })?;

        match name.as_str() {
            "key" => keys.push(HimitsuKey::<Field>::try_from(rest)?),
            "error" => return Err(rest.join(" ")),
            "end" if rest.is_empty() => return Ok(keys),
            _ => {
                return Err(format!(
                    "Unknown response: {}",
                    std::iter::once(name)
                        .chain(rest)
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
        }
    }
}

pub struct HimitsuProtocol {
    connection: BufReader<UnixStream>,
}

use std::sync::LazyLock;
pub static SOCKET_PATH: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| {
        env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| "XDG_RUNTIME_DIR is not set".to_owned())
            .or_else(|err| {
                if std::env::consts::OS == "macos" {
                    env::var_os("TMPDIR").ok_or_else(|| {
                        "TMPDIR (macOS fallback) is not set".to_owned()
                    })
                } else {
                    Err(err)
                }
            })
            .map(PathBuf::from)
            .map(|socket_root| socket_root.join("himitsu"))
    });

impl Repository for HimitsuProtocol {
    fn new() -> Result<Self, String> {
        Ok(Self {
            connection: BufReader::new(
                UnixStream::connect(SOCKET_PATH.as_deref()?)
                    .map_err(|_| "Could not create stream")?,
            ),
        })
    }

    fn add(
        &mut self,
        key: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        query_socket(&mut self.connection, &format!("add {key}\n"))
            .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        query_socket(&mut self.connection, &format!("del {query}\n"))
            .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        query_socket(&mut self.connection, &format!("query {query}\n"))
            .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn disclose(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<CompleteHimitsuKey>, String> {
        query_socket(&mut self.connection, &format!("query -d {query}\n"))
            .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        query_socket(&mut self.connection, &format!("update {query}\n"))
            .and_then(|()| parse_single_response(&mut self.connection))
            .and_then(|res| {
                res.ok_or_else(|| {
                    "Connection closed before update acknowledged".to_owned()
                })
            })
            .and_then(|(name, rest)| match name.as_str() {
                "update" => Ok(()),
                "error" => Err(rest.join(" ")),
                _ => Err(format!(
                    "Unknown update response: {} {}",
                    name,
                    rest.join(" ")
                )),
            })
            .and_then(|()| {
                query_socket(&mut self.connection, &format!("set {set}\n"))
            })
            .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn status(&mut self) -> Result<Option<LockStatus>, String> {
        query_socket(&mut self.connection, "status\n")
            .and_then(|()| parse_single_response(&mut self.connection))
            .and_then(|res| {
                res.ok_or_else(|| {
                    "Connection closed before status response".to_owned()
                })
            })
            .and_then(|(name, rest)| {
                match (name.as_str(), rest.get(0).map(String::as_str)) {
                    ("status", Some("unlocked")) => Ok(None),
                    ("status", Some("soft_locked")) => {
                        Ok(Some(LockStatus::Soft))
                    }
                    ("status", Some("hard_locked")) => {
                        Ok(Some(LockStatus::Hard))
                    }
                    ("error", _) => Err(rest.join(" ")),
                    _ => Err(format!(
                        "Unknown response: {name} {}",
                        rest.join(" ")
                    )),
                }
            })
    }
    fn lock(&mut self, lock: LockStatus) -> Result<(), String> {
        query_socket(
            &mut self.connection,
            &format!(
                "lock{}\n",
                if lock == LockStatus::Soft { " -s" } else { "" }
            ),
        )
        .and_then(|()| parse_single_response(&mut self.connection))
        .and_then(|res| {
            res.ok_or_else(|| {
                "Connection closed before status response".to_owned()
            })
        })
        .and_then(|(name, rest)| match name.as_str() {
            "locked" => Ok(()),
            "error" => Err(rest.join(" ")),
            _ => Err(format!("Unknown response: {name} {}", rest.join(" "))),
        })
    }
}
