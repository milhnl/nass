use nass::optparser::{Argument, OptParser};
use nass::proto::HimitsuProtocol;
use nass::state::Repository;
use std::env;

fn check_one(one: bool, len: usize) -> Result<(), String> {
    match len {
        1 if one => Ok(()),
        _ if !one => Ok(()),
        0 => Err("Received no keys".to_string()),
        _ => Err("Received multiple keys".to_string()),
    }
}

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
    if decrypt {
        let keys = connection.disclose(query.into())?;
        check_one(one, keys.len())?;
        keys.into_iter().for_each(|key| println!("{key}"))
    } else {
        let keys = connection.query(query.into())?;
        check_one(one, keys.len())?;
        keys.into_iter().for_each(|key| println!("{key}"))
    }
    Ok(())
}
