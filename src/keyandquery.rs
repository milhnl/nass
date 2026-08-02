use shlex::{Quoter, split};
use std::borrow::Cow;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HimitsuKey<Field>(pub Vec<(String, Field)>);

fn encode<'a>(s: &'a str) -> Cow<'a, str> {
    if s.len() > 1000
        || !s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '/' || c == '.' || c == ','
        })
    {
        //The reference implementation does not even support newlines, so
        //handling this correctly is scheduled for a later date
        Quoter::new().allow_nul(true).quote(s).unwrap()
    } else {
        Cow::Borrowed(s)
    }
}

pub trait HimitsuQueryMatchable {
    fn r#match(&self, query: &HimitsuQuery) -> bool;
}

// REDACTED

pub type RedactedHimitsuKey = HimitsuKey<Option<String>>;

impl Display for RedactedHimitsuKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().enumerate().try_for_each(|(i, field)| {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{}", field.0)?;
            if let Some(value) = &field.1 {
                write!(f, "={}", encode(value))
            } else {
                write!(f, "!")
            }
        })
    }
}

impl FromStr for RedactedHimitsuKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields =
            split(s).ok_or_else(|| "Could not split fields".to_string())?;
        fields
            .into_iter()
            .map(|mut pair| {
                let i = pair.find('=');
                let (mut key, value) = if let Some(i) = i {
                    let mut value = pair.split_off(i);
                    value.drain(..1);
                    (pair, Some(value))
                } else {
                    (pair, None)
                };
                let secret = key.ends_with('!');
                if secret {
                    key.truncate(key.len() - 1);
                }
                if value.is_none() && !secret {
                    Err(format!(
                        "Field {key} should be secret or have a value"
                    ))
                } else {
                    Ok((key, value))
                }
            })
            .collect::<Result<_, _>>()
            .map(HimitsuKey)
    }
}

impl From<CompleteHimitsuKey> for RedactedHimitsuKey {
    fn from(key: CompleteHimitsuKey) -> Self {
        HimitsuKey(
            key.0
                .into_iter()
                .map(|(k, (secret, v))| {
                    (k, if secret { None } else { Some(v) })
                })
                .collect(),
        )
    }
}

impl HimitsuQueryMatchable for RedactedHimitsuKey {
    fn r#match(&self, query: &HimitsuQuery) -> bool {
        query.0.iter().all(|(qk, qv)| {
            let Some(keyvalue) = self.get(qk) else {
                return qv.optional;
            };
            qv.value.is_none() || keyvalue.as_ref() == qv.value.as_ref()
        })
    }
}

// COMPLETE

pub type CompleteHimitsuKey = HimitsuKey<(bool, String)>;

impl Display for CompleteHimitsuKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().enumerate().try_for_each(|(i, field)| {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(
                f,
                "{}{}={}",
                field.0,
                if field.1.0 { "!" } else { "" },
                encode(&field.1.1)
            )
        })
    }
}

impl FromStr for CompleteHimitsuKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields =
            split(s).ok_or_else(|| "Could not split fields".to_string())?;
        fields
            .into_iter()
            .map(|mut pair| {
                let i = pair.find('=');
                let (mut key, value) = if let Some(i) = i {
                    let mut value = pair.split_off(i);
                    value.drain(..1);
                    (pair, value)
                } else {
                    return Err("Key should have all values".to_owned());
                };
                let secret = key.ends_with('!');
                if secret {
                    key.truncate(key.len() - 1);
                }
                Ok((key, (secret, value)))
            })
            .collect::<Result<_, _>>()
            .map(HimitsuKey)
    }
}

impl<Field> HimitsuKey<Field> {
    pub fn get(&self, k: impl AsRef<str>) -> Option<&Field> {
        let k = k.as_ref();
        self.0.iter().find(|field| field.0 == k).map(|(_, v)| v)
    }
}

impl HimitsuQueryMatchable for CompleteHimitsuKey {
    fn r#match(&self, query: &HimitsuQuery) -> bool {
        query.0.iter().all(|(qk, qv)| {
            let Some(keyvalue) = self.get(qk) else {
                return qv.optional;
            };
            qv.value.is_none() || keyvalue.1 == *qv.value.as_ref().unwrap()
        })
    }
}

impl CompleteHimitsuKey {
    pub fn update(&mut self, set: CompleteHimitsuKey) {
        set.0.into_iter().for_each(|new_field| {
            if let Some(old_field) = self
                .0
                .iter_mut()
                .find(|old_field| old_field.0 == new_field.0)
            {
                old_field.1 = new_field.1
            } else {
                self.0.push(new_field)
            }
        })
    }
}

// QUERY

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryField {
    pub optional: bool,
    pub value: Option<String>,
    pub secret: bool,
}

#[derive(Debug, Clone)]
pub struct HimitsuQuery(Vec<(String, QueryField)>, bool);

impl HimitsuQuery {
    pub fn from_components<T: IntoIterator<Item = String>>(
        query: T,
    ) -> Result<Self, String> {
        Ok(HimitsuQuery(
            query
                .into_iter()
                .map(|mut pair| {
                    let i = pair.find('=');
                    let (mut key, value) = if let Some(i) = i {
                        let mut value = pair.split_off(i);
                        value.drain(..1);
                        (pair, Some(value))
                    } else {
                        (pair, None)
                    };
                    let optional = key.ends_with('?');
                    if optional {
                        key.pop();
                    }
                    let secret = key.ends_with('!');
                    if secret {
                        key.pop();
                    }
                    (
                        key,
                        QueryField {
                            optional,
                            value,
                            secret,
                        },
                    )
                })
                .collect(),
            false,
        ))
    }

    pub fn r#match(&self, key: &impl HimitsuQueryMatchable) -> bool {
        key.r#match(self)
    }
}

impl Display for HimitsuQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.1 {
            write!(f, "-s ")?;
        }
        self.0.iter().enumerate().try_for_each(|(i, (k, value))| {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(
                f,
                "{k}{}{}{}",
                if value.secret {
                    "!"
                } else if value.optional {
                    "?"
                } else {
                    ""
                },
                if value.value.is_some() { "=" } else { "" },
                encode(value.value.as_ref().map_or("", |v| v))
            )
        })
    }
}

impl FromStr for HimitsuQuery {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        split(s).map_or_else(
            || Err("Could not split query".to_owned()),
            HimitsuQuery::from_components,
        )
    }
}
