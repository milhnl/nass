pub mod optparser;
pub mod otp;
pub mod proto;
pub mod state;

use std::collections::HashMap;

use otp::Totp;
use state::HimitsuKey;

pub fn himitsu_to_totp(key: &HimitsuKey) -> Result<Totp, String> {
    Totp::from_slices(
        key.get_value("algorithm"),
        key.get_value("issuer"),
        key.get_value("label")
            .ok_or_else(|| format!("Key {key:?} is missing label"))?,
        key.get_value("digits"),
        key.get_value("period"),
        key.get_value("secret")
            .ok_or_else(|| format!("Key {key:?} is missing secret"))?,
        key.get_value("label_issuer"),
        HashMap::new(),
    )
}
