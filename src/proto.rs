use crate::keyandquery::{
    CompleteHimitsuKey, HimitsuKey, HimitsuQuery, RedactedHimitsuKey,
};
use crate::state::{LockStatus, Repository};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::str::FromStr;

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

fn parse_keys_response<Field>(
    connection: &mut impl BufRead,
) -> Result<Vec<HimitsuKey<Field>>, String>
where
    HimitsuKey<Field>: FromStr,
{
    let mut keys = Vec::new();

    for line in connection.lines() {
        let line = line.map_err(|err| err.to_string())?;

        match line
            .split_once(' ')
            .map(|(op, val)| (op, Some(val)))
            .unwrap_or((line.as_ref(), None))
        {
            ("key", Some(encoded)) => {
                let key = HimitsuKey::<Field>::from_str(encoded)
                    .map_err(|_| format!("Invalid key response: {encoded}"))?;
                keys.push(key);
            }
            ("error", Some(error)) => {
                return Err(error.to_owned());
            }
            ("end", None) => {
                return Ok(keys);
            }
            _ => {
                return Err(format!("Unknown response: {line}"));
            }
        }
    }

    Err("Connection closed before an end response".into())
}

fn parse_single_response(
    connection: &mut impl BufRead,
) -> Result<String, String> {
    let mut line = String::new();
    connection
        .read_line(&mut line)
        .map_err(|err| err.to_string())
        .and_then(|size| {
            if size == 0 {
                Err("No response from socket".to_owned())
            } else {
                if line.ends_with('\n') {
                    line.pop();
                }
                Ok(line)
            }
        })
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
        query_socket(
            &mut self.connection,
            &format!("update {query}\nset {set}\n"),
        )
        .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn status(&mut self) -> Result<Option<LockStatus>, String> {
        query_socket(&mut self.connection, "status\n").and_then(|()| {
            let line = parse_single_response(&mut self.connection)?;

            match line
                .split_once(' ')
                .map(|(op, val)| (op, Some(val)))
                .unwrap_or((line.as_ref(), None))
            {
                ("status", Some("unlocked")) => Ok(None),
                ("status", Some("soft_locked")) => Ok(Some(LockStatus::Soft)),
                ("status", Some("hard_locked")) => Ok(Some(LockStatus::Hard)),
                ("error", Some(error)) => Err(error.to_owned()),
                _ => Err(format!("Unknown response: {line}")),
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
        .and_then(|()| {
            let line = parse_single_response(&mut self.connection)?;

            match line
                .split_once(' ')
                .map(|(op, val)| (op, Some(val)))
                .unwrap_or((line.as_ref(), None))
            {
                ("locked", None) => Ok(()),
                ("error", Some(error)) => Err(error.to_owned()),
                _ => Err(format!("Unknown response: {line}")),
            }
        })
    }
}
