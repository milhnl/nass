use nass::optparser::{Argument, OptParser};
use nass::proto::HimitsuProtocol;
use nass::state::{HimitsuQuery, Repository};
use std::env;

fn main() -> Result<(), String> {
    let mut connection = HimitsuProtocol::new()?;
    let mut decrypt = false;
    let mut one = false;
    let mut optparser = OptParser::new(env::args().skip(1));
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
