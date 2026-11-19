use crate::keyandquery::{CompleteHimitsuKey, HimitsuQuery};
use crate::optparser::{Argument, OptParser};
use crate::state::{LockStatus, RepositoryOperation};
use shlex::split;
use std::io::{self, BufRead, Write};

pub fn read_protocol_command(
    reader: &mut impl BufRead,
) -> io::Result<Result<Option<Vec<String>>, String>> {
    let mut command = String::new();

    loop {
        if reader.read_line(&mut command)? == 0 {
            return Ok(if command.is_empty() {
                Ok(None)
            } else {
                Err("Input ended inside a quoted protocol value".into())
            });
        }

        if let Some(parsed) = split(&command) {
            return Ok(if parsed.is_empty() {
                Err("Empty command".into())
            } else {
                Ok(Some(parsed))
            });
        }
    }
}

pub fn read_repository_operation(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> io::Result<Result<Option<RepositoryOperation>, String>> {
    let (name, rest) = match read_protocol_command(reader)? {
        Ok(Some(mut command)) => (command.remove(0), command),
        Ok(None) => return Ok(Ok(None)),
        Err(err) => return Ok(Err(err)),
    };
    let operation = match name.as_str() {
        "add" => {
            CompleteHimitsuKey::try_from(rest).map(RepositoryOperation::Add)
        }
        "del" => Ok(RepositoryOperation::Delete(HimitsuQuery::from(rest))),
        "query" => {
            let mut decrypt = false;
            let mut optparser = OptParser::new(rest.into_iter());
            while let Some(opt) = optparser.next_opt() {
                match opt {
                    Argument::Short('d') => decrypt = true,
                    _ => {
                        return Ok(Err(format!(
                            "Unknown query option: {opt:?}"
                        )));
                    }
                }
            }
            let query: HimitsuQuery = optparser.collect::<Vec<_>>().into();
            if decrypt {
                Ok(RepositoryOperation::Disclose(query))
            } else {
                Ok(RepositoryOperation::Query(query))
            }
        }
        "update" => {
            let query = rest.into();
            writer.write_all(b"update\n")?;
            writer.flush()?;

            let (set_name, set_rest) = match read_protocol_command(reader)? {
                Ok(Some(mut command)) => (command.remove(0), command),
                Ok(None) => {
                    return Ok(Err(
                        "Expected set command after update".to_owned()
                    ));
                }
                Err(err) => return Ok(Err(err)),
            };

            if set_name != "set" {
                return Ok(Err(format!(
                    "Command after update should be set, got {set_name}"
                )));
            }

            CompleteHimitsuKey::try_from(set_rest)
                .map(|set| RepositoryOperation::Update((query, set)))
        }
        "status" if rest.is_empty() => Ok(RepositoryOperation::Status(())),
        "lock" => match rest.as_slice() {
            [] => Ok(RepositoryOperation::Lock(LockStatus::Hard)),
            [option] if option == "-s" => {
                Ok(RepositoryOperation::Lock(LockStatus::Soft))
            }
            _ => Err(format!("Invalid lock command: {name}")),
        },
        "set" => Err("Set command without a preceding update".into()),
        _ => Err(format!("Unknown command: {name}")),
    };

    Ok(operation.map(Some))
}
