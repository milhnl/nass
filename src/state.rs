use crate::keyandquery::{
    CompleteHimitsuKey, HimitsuQuery, RedactedHimitsuKey,
};
use std::sync::mpsc::{Sender, channel};

#[path = "repo/pass.rs"]
pub mod pass;

//Trait API
pub trait Repository: Send {
    fn new() -> Result<Self, String>
    where
        Self: Sized;
    fn add(
        &mut self,
        key: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String>;
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String>;
    fn query(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String>;
    fn disclose(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<CompleteHimitsuKey>, String>;
    fn update(
        &mut self,
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String>;
}

//Thread API
pub enum Message {
    Add {
        key: CompleteHimitsuKey,
        reply: Sender<Result<Vec<RedactedHimitsuKey>, String>>,
    },
    Delete {
        query: HimitsuQuery,
        reply: Sender<Result<Vec<RedactedHimitsuKey>, String>>,
    },
    Query {
        query: HimitsuQuery,
        reply: Sender<Result<Vec<RedactedHimitsuKey>, String>>,
    },
    Disclose {
        query: HimitsuQuery,
        reply: Sender<Result<Vec<CompleteHimitsuKey>, String>>,
    },
    Update {
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
        reply: Sender<Result<Vec<RedactedHimitsuKey>, String>>,
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
                        Message::Add { key, reply } => {
                            reply.send(T::add(&mut actor, key)).unwrap()
                        }
                        Message::Delete { query, reply } => {
                            reply.send(T::delete(&mut actor, query)).unwrap()
                        }
                        Message::Query { query, reply } => {
                            reply.send(T::query(&mut actor, query)).unwrap()
                        }
                        Message::Disclose { query, reply } => {
                            reply.send(T::disclose(&mut actor, query)).unwrap()
                        }
                        Message::Update { query, set, reply } => reply
                            .send(T::update(&mut actor, query, set))
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

    fn add(
        &mut self,
        key: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| Message::Add { key, reply })
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| Message::Delete { query, reply })
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| Message::Query { query, reply })
    }
    fn disclose(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<CompleteHimitsuKey>, String> {
        self.request(|reply| Message::Disclose { query, reply })
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| Message::Update { query, set, reply })
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

    fn add(
        &mut self,
        key: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.add(key.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.delete(query.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.query(query.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn disclose(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<CompleteHimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.disclose(query.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.update(query.clone(), set.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map(|keys| keys.into_iter().flatten().collect())
    }
}
