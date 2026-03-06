pub use otp::Algorithm;
pub use otp::Secret;
use std::borrow::Cow;
use std::collections::HashMap;
pub struct Totp(otp::Totp, u64, Option<String>, HashMap<String, String>);

impl Totp {
    pub fn period(&self) -> u64 {
        self.1
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_slices(
        alg: Option<&str>,
        issuer: Option<&str>,
        label: &str,
        digits: Option<&str>,
        period: Option<&str>,
        secret: &str,
        label_issuer: Option<&str>,
        extra: HashMap<&str, &str>,
    ) -> Result<Self, String> {
        Ok(Self::new(
            match alg.map(|x| x.to_ascii_uppercase()).as_deref() {
                Some("SHA1") | None => otp::Algorithm::SHA1,
                Some("SHA256") => otp::Algorithm::SHA256,
                Some("SHA512") => otp::Algorithm::SHA512,
                Some(alg) => Err(format!("Unknown alg: {alg}"))?,
            },
            issuer.unwrap_or("").to_string(),
            label.to_string(),
            digits
                .map(|x| x.parse::<u8>())
                .unwrap_or(Ok(6))
                .map_err(|x| x.to_string())?,
            period
                .map(|x| x.parse::<u64>())
                .unwrap_or(Ok(30))
                .map_err(|x| x.to_string())?,
            Secret::from_base32(secret).unwrap(),
            label_issuer.map(str::to_string),
            extra
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alg: Algorithm,
        issuer: String,
        label: String,
        digits: u8,
        period: u64,
        secret: Secret,
        label_issuer: Option<String>,
        extra: HashMap<String, String>,
    ) -> Self {
        Self(
            otp::Totp::new(alg, issuer, label, digits, period, secret),
            period,
            label_issuer,
            extra,
        )
    }

    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let uri = uri
            .strip_prefix("otpauth://totp/")
            .ok_or("Not an otpauth://totp/ URI")?;
        let (label, query) = uri
            .split_once('?')
            .ok_or("Not a well-formed OTP uri, missing label or query")?;
        let label = otp::encoding::url::decode(label)
            .map_err(|_| "Decoding OTP label failed")?;
        let (label_issuer, label) = label
            .split_once(':')
            .map(|(label_issuer, label)| (Some(label_issuer), label))
            .unwrap_or((None, label.as_str()));
        let mut params = query
            .split('&')
            .map(|param| {
                param
                    .split_once('=')
                    .ok_or("OTP uri has param without value".to_string())
            })
            .collect::<Result<HashMap<&str, &str>, String>>()?;
        let alg = params.remove("alg");
        let issuer = params.remove("issuer");
        let digits = params.remove("digits");
        let period = params.remove("period");
        let secret = params
            .remove("secret")
            .ok_or("OTP uri misses secret".to_string())?;
        let (label_issuer, issuer) = match (label_issuer, issuer) {
            (Some(label_issuer), None) => (None, Some(label_issuer)),
            (Some(label_issuer), Some(issuer)) if label_issuer == issuer => {
                (None, Some(issuer))
            }
            (a, b) => (a, b),
        };
        Self::from_slices(
            alg,
            issuer,
            label,
            digits,
            period,
            secret,
            label_issuer,
            params,
        )
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, Cow<'_, str>)> {
        [
            ("secret", Some(Cow::Owned(self.0.secret().into_base32()))),
            (
                "algorithm",
                match self.0.alg() {
                    otp::Algorithm::SHA1 => None,
                    otp::Algorithm::SHA256 => Some(Cow::Borrowed("SHA256")),
                    otp::Algorithm::SHA512 => Some(Cow::Borrowed("SHA512")),
                },
            ),
            ("issuer", {
                let issuer = self.0.issuer();
                if issuer.is_empty() {
                    None
                } else {
                    Some(Cow::Borrowed(issuer))
                }
            }),
            ("label", Some(Cow::Borrowed(self.0.label()))),
            ("digits", {
                let digits = self.0.digits();
                if digits == 6 {
                    None
                } else {
                    Some(Cow::Owned(digits.to_string()))
                }
            }),
            ("period", {
                let period = self.period();
                if period == 30 {
                    None
                } else {
                    Some(Cow::Owned(period.to_string()))
                }
            }),
            ("label_issuer", self.2.as_deref().map(Cow::Borrowed)),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .chain(
            self.3
                .iter()
                .map(|(k, v)| (k.as_str(), Cow::Borrowed(v.as_str()))),
        )
    }

    pub fn to_uri(&self) -> String {
        use otp::encoding::url::encode;
        format!(
            "otpauth://totp/{}{}{}?{}",
            encode(
                self.2
                    .as_deref()
                    .map(|label_issuer| label_issuer.as_bytes())
                    .unwrap_or("".as_bytes())
            ),
            self.2.as_deref().map(|_| ":").unwrap_or(""),
            encode(self.0.label().as_bytes()),
            self.iter()
                .filter(|(k, _)| k != &"label_issuer" && k != &"label")
                .map(|(k, v)| format!("{k}={}", encode(v.as_bytes())))
                .collect::<Vec<String>>()
                .join("&")
        )
    }

    pub fn generate_string(&self) -> String {
        format!(
            "{:0digits$}",
            self.0.generate() % 10u32.pow(self.0.digits().into()),
            digits = self.0.digits().into()
        )
    }
}
