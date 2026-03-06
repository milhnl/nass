use crate::state::{HimitsuKey, HimitsuQuery, Repository};
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
        .map_err(|_| "Failed at writing onto the unix stream")?;
    //unix_stream
    //    .shutdown(std::net::Shutdown::Write)
    //    .map_err(|_| "Could not shutdown writing on the stream")?;
    Ok(())
}

fn parse_keys_response(
    connection: &mut impl BufRead,
) -> Result<Vec<HimitsuKey>, String> {
    let mut keys = Vec::new();

    for line in connection.lines() {
        let line = line.map_err(|err| err.to_string())?;

        match line
            .split_once(' ')
            .map(|(op, val)| (op, Some(val)))
            .unwrap_or((line.as_ref(), None))
        {
            ("key", Some(encoded)) => {
                let key = HimitsuKey::from(encoded).ok_or_else(|| {
                    format!(
                        "Invalid key response:
                      {encoded}"
                    )
                })?;
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

pub struct HimitsuProtocol {
    connection: BufReader<UnixStream>,
}

impl Repository for HimitsuProtocol {
    fn new() -> Result<Self, String> {
        let socket_path = PathBuf::from(env::var("XDG_RUNTIME_DIR").unwrap())
            .join("himitsu");
        let connection = BufReader::new(
            UnixStream::connect(socket_path)
                .map_err(|_| "Could not create stream")?,
        );

        Ok(Self { connection })
    }

    fn add(&mut self, query: HimitsuQuery) -> Result<Vec<HimitsuKey>, String> {
        query_socket(
            &mut self.connection,
            &("add ".to_owned() + &query.encode() + "\n"),
        )
        .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        query_socket(
            &mut self.connection,
            &("del ".to_owned() + &query.encode() + "\n"),
        )
        .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
        decrypt: bool,
    ) -> Result<Vec<HimitsuKey>, String> {
        query_socket(
            &mut self.connection,
            &("query ".to_owned()
                + (if decrypt { "-d " } else { "" })
                + &query.encode()
                + "\n"),
        )
        .and_then(|()| parse_keys_response(&mut self.connection))
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set_query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        query_socket(
            &mut self.connection,
            //TODO: probably wrong. test.
            &("update ".to_owned()
                + &query.encode()
                + "\n"
                + "set "
                + &set_query.encode()
                + "\n"),
        )
        .and_then(|()| parse_keys_response(&mut self.connection))
    }
}
