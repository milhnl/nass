pub mod keyandquery;
pub mod optparser;
pub mod otp;
pub mod proto;
pub mod state;

use std::collections::HashMap;

use keyandquery::CompleteHimitsuKey;
use otp::Totp;

pub fn himitsu_to_totp(key: &CompleteHimitsuKey) -> Result<Totp, String> {
    Totp::from_slices(
        key.get("algorithm").map(|(_, v)| v.as_ref()),
        key.get("issuer").map(|(_, v)| v.as_ref()),
        key.get("label")
            .map(|(_, v)| v.as_ref())
            .ok_or_else(|| format!("Key {key:?} is missing label"))?,
        key.get("digits").map(|(_, v)| v.as_ref()),
        key.get("period").map(|(_, v)| v.as_ref()),
        key.get("secret")
            .map(|(_, v)| v.as_ref())
            .ok_or_else(|| format!("Key {key:?} is missing secret"))?,
        key.get("label_issuer").map(|(_, v)| v.as_ref()),
        HashMap::new(),
    )
}
