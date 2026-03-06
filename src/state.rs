use shlex::{split, try_join, try_quote};
use std::collections::HashMap;
use std::sync::mpsc::{Sender, channel};

#[path = "repo/pass.rs"]
pub mod pass;

/// A stored key/value pair, preserving formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyField {
    pub value: Option<String>,
    pub secret: bool,
}

#[derive(Debug, Clone)]
pub struct HimitsuKey(pub Vec<(String, KeyField)>);

impl HimitsuKey {
    pub fn from<T: AsRef<str>>(s: T) -> Option<Self> {
        let fields = split(s.as_ref())?;
        Some(HimitsuKey(
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
                    (key, KeyField { value, secret })
                })
                .collect(),
        ))
    }
    pub fn update(&mut self, new: Self) {
        new.0.into_iter().for_each(|new_field| {
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
    pub fn encode(&self, decrypt: bool) -> Result<String, String> {
        use std::borrow::Cow;
        fn encode<'a>(s: &'a str) -> Result<Cow<'a, str>, String> {
            if s.len() > 1000
                || !s.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || c == '/'
                        || c == '.'
                        || c == ','
                })
            {
                try_quote(s)
                    .map_err(|_| "NUL byte in property name".to_string())
            } else {
                Ok(Cow::Borrowed(s))
            }
        }
        Ok(self
            .0
            .iter()
            .map(|pair| -> Result<String, String> {
                let key = encode(&pair.0)?;
                let value = (if !pair.1.secret || decrypt {
                    pair.1
                        .value
                        .as_ref()
                        .map(|x| encode(x.as_ref()))
                        .transpose()
                } else {
                    Ok(None)
                })?;
                Ok(format!(
                    "{}{}{}{}",
                    key,
                    if pair.1.secret { "!" } else { "" },
                    if value.is_some() { "=" } else { "" },
                    value.as_ref().unwrap_or(&Cow::Borrowed(""))
                ))
            })
            .collect::<Result<Vec<_>, String>>()?
            .join(" "))
    }
    pub fn get(&self, index: &str) -> Option<&KeyField> {
        self.0.iter().find(|(k, _)| k == index).map(|(_, v)| v)
    }
    pub fn get_value(&self, index: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == index)
            .and_then(|(_, v)| v.value.as_deref())
    }
}

impl TryFrom<HimitsuQuery> for HimitsuKey {
    type Error = &'static str;
    fn try_from(value: HimitsuQuery) -> Result<Self, Self::Error> {
        value
            .0
            .into_iter()
            .map(|(key, value)| -> Result<(String, KeyField), Self::Error> {
                if value.optional {
                    Err("Key can not have optional fields")
                } else if value.value.is_none() {
                    Err("Key can not have fields without value")
                } else {
                    Ok((
                        key,
                        KeyField {
                            value: value.value,
                            secret: value.secret,
                        },
                    ))
                }
            })
            .collect::<Result<_, Self::Error>>()
            .map(HimitsuKey)
    }
}

impl TryFrom<HimitsuKey> for HimitsuQuery {
    type Error = &'static str;
    fn try_from(value: HimitsuKey) -> Result<Self, Self::Error> {
        value
            .0
            .into_iter()
            .map(
                |(key, value)| -> Result<(String, QueryField), Self::Error> {
                    if value.value.is_none() {
                        Err("Key can not have fields without value")
                    } else {
                        Ok((
                            key,
                            QueryField {
                                value: value.value,
                                secret: value.secret,
                                optional: false,
                            },
                        ))
                    }
                },
            )
            .collect::<Result<_, Self::Error>>()
            .map(HimitsuQuery)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryField {
    pub optional: bool,
    pub value: Option<String>,
    pub secret: bool,
}

#[derive(Debug, Clone)]
pub struct HimitsuQuery(HashMap<String, QueryField>);

impl HimitsuQuery {
    pub fn from_components<T: IntoIterator<Item = String>>(
        query: T,
    ) -> Option<Self> {
        Some(HimitsuQuery(
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
        ))
    }

    pub fn encode(self) -> String {
        let query = self
            .0
            .into_iter()
            .map(|(key, value)| {
                format!(
                    "{key}{}{}{}",
                    if value.secret {
                        "!"
                    } else if value.optional {
                        "?"
                    } else {
                        ""
                    },
                    if value.value.is_some() { "=" } else { "" },
                    value.value.unwrap_or("".to_string())
                )
            })
            .collect::<Vec<_>>();
        try_join(query.iter().map(|x| x.as_ref())).unwrap()
    }

    pub fn r#match(&self, key: &HimitsuKey) -> bool {
        self.0.iter().all(|querypair| {
            let Some(keyvalue) = key.get(querypair.0 as &str) else {
                return querypair.1.optional;
            };
            querypair.1.value.is_none() || keyvalue.value == querypair.1.value
        })
    }
}

//Trait API
pub trait Repository: Send {
    fn new() -> Result<Self, String>
    where
        Self: Sized;
    fn add(&mut self, query: HimitsuQuery) -> Result<Vec<HimitsuKey>, String>;
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String>;
    fn query(
        &mut self,
        query: HimitsuQuery,
        decrypt: bool,
    ) -> Result<Vec<HimitsuKey>, String>;
    fn update(
        &mut self,
        query: HimitsuQuery,
        set_query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String>;
}

//Thread API
pub enum Message {
    Add {
        query: HimitsuQuery,
        reply: Sender<Result<Vec<HimitsuKey>, String>>,
    },
    Delete {
        query: HimitsuQuery,
        reply: Sender<Result<Vec<HimitsuKey>, String>>,
    },
    Query {
        query: HimitsuQuery,
        decrypt: bool,
        reply: Sender<Result<Vec<HimitsuKey>, String>>,
    },
    Update {
        query: HimitsuQuery,
        set_query: HimitsuQuery,
        reply: Sender<Result<Vec<HimitsuKey>, String>>,
    },
}

#[derive(Clone)]
pub struct RepositoryClient {
    tx: Sender<Message>,
}

impl RepositoryClient {
    pub fn new<T: Repository + 'static>() -> Result<Self, String> {
        let (tx, rx) = channel();

        let actor = T::new();

        actor.map(|mut actor| {
            std::thread::spawn(move || {
                for msg in rx {
                    match msg {
                        Message::Add { query, reply } => {
                            reply.send(T::add(&mut actor, query)).unwrap()
                        }
                        Message::Delete { query, reply } => {
                            reply.send(T::delete(&mut actor, query)).unwrap()
                        }
                        Message::Query {
                            query,
                            decrypt,
                            reply,
                        } => reply
                            .send(T::query(&mut actor, query, decrypt))
                            .unwrap(),
                        Message::Update {
                            query,
                            set_query,
                            reply,
                        } => reply
                            .send(T::update(&mut actor, query, set_query))
                            .unwrap(),
                    }
                }
            });
            RepositoryClient { tx }
        })
    }
    fn request<R>(&self, build: impl FnOnce(Sender<R>) -> Message) -> R {
        let (reply_tx, reply_rx) = channel();

        let msg = build(reply_tx);
        self.tx.send(msg).unwrap();

        reply_rx.recv().unwrap()
    }
}

impl Repository for RepositoryClient {
    fn new() -> Result<Self, String> {
        todo!()
    }

    fn add(&mut self, query: HimitsuQuery) -> Result<Vec<HimitsuKey>, String> {
        self.request(|reply| Message::Add { query, reply })
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        self.request(|reply| Message::Delete { query, reply })
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
        decrypt: bool,
    ) -> Result<Vec<HimitsuKey>, String> {
        self.request(|reply| Message::Query {
            query,
            decrypt,
            reply,
        })
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set_query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        self.request(|reply| Message::Update {
            query,
            set_query,
            reply,
        })
    }
}

pub struct MultiplexedRepository {
    repositories: Vec<Box<dyn Repository>>,
}

impl Repository for MultiplexedRepository {
    fn new() -> Result<Self, String> {
        Ok(Self {
            repositories: vec![Box::new(pass::PassRepository::new()?)],
        })
    }

    fn add(&mut self, query: HimitsuQuery) -> Result<Vec<HimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.add(query.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.delete(query.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
        decrypt: bool,
    ) -> Result<Vec<HimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.query(query.clone(), decrypt))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set_query: HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| {
                repository.update(query.clone(), set_query.clone())
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
}
