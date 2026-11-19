use shlex::split;
use std::io::{self, BufRead};

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
