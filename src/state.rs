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
    fn status(&mut self) -> Result<Option<LockStatus>, String>;
    fn lock(&mut self, lock: LockStatus) -> Result<(), String>;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LockStatus {
    Soft,
    Hard,
}

//This is just a HKT for Rust. Ugly though, sorry. I wanted 'one type' for both
pub trait RepositoryRequestMode {
    type Item<Arguments, Output>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Direct;

impl RepositoryRequestMode for Direct {
    type Item<Arguments, Output> = Arguments;
}

struct WithReply;

impl RepositoryRequestMode for WithReply {
    type Item<Arguments, Output> = (Arguments, Sender<Result<Output, String>>);
}

/// A repository request whose representation is selected by `Mode`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryRequest<Mode: RepositoryRequestMode> {
    Add(Mode::Item<CompleteHimitsuKey, Vec<RedactedHimitsuKey>>),
    Delete(Mode::Item<HimitsuQuery, Vec<RedactedHimitsuKey>>),
    Query(Mode::Item<HimitsuQuery, Vec<RedactedHimitsuKey>>),
    Disclose(Mode::Item<HimitsuQuery, Vec<CompleteHimitsuKey>>),
    Update(
        Mode::Item<
            (HimitsuQuery, CompleteHimitsuKey),
            Vec<RedactedHimitsuKey>,
        >,
    ),
    Status(Mode::Item<(), Option<LockStatus>>),
    Lock(Mode::Item<LockStatus, ()>),
}

/// A serializable call to a [`Repository`].
pub type RepositoryOperation = RepositoryRequest<Direct>;

type RepositoryMessage = RepositoryRequest<WithReply>;

#[derive(Clone)]
pub struct RepositoryClient {
    tx: Sender<RepositoryMessage>,
}

impl RepositoryClient {
    pub fn new<T: Repository + 'static>() -> Result<Self, String> {
        let (tx, rx) = channel();

        let actor = T::new();

        actor.map(|mut actor| {
            std::thread::spawn(move || {
                for msg in rx {
                    match msg {
                        RepositoryMessage::Add((key, reply)) => {
                            reply.send(T::add(&mut actor, key)).unwrap()
                        }
                        RepositoryMessage::Delete((query, reply)) => {
                            reply.send(T::delete(&mut actor, query)).unwrap()
                        }
                        RepositoryMessage::Query((query, reply)) => {
                            reply.send(T::query(&mut actor, query)).unwrap()
                        }
                        RepositoryMessage::Disclose((query, reply)) => {
                            reply.send(T::disclose(&mut actor, query)).unwrap()
                        }
                        RepositoryMessage::Update(((query, set), reply)) => {
                            reply
                                .send(T::update(&mut actor, query, set))
                                .unwrap()
                        }
                        RepositoryMessage::Status(((), reply)) => {
                            reply.send(T::status(&mut actor)).unwrap()
                        }
                        RepositoryMessage::Lock((lock, reply)) => {
                            reply.send(T::lock(&mut actor, lock)).unwrap()
                        }
                    }
                }
            });
            RepositoryClient { tx }
        })
    }

    fn request<R>(
        &self,
        build: impl FnOnce(Sender<Result<R, String>>) -> RepositoryMessage,
    ) -> Result<R, String> {
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
        self.request(|reply| RepositoryMessage::Add((key, reply)))
    }
    fn delete(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| RepositoryMessage::Delete((query, reply)))
    }
    fn query(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| RepositoryMessage::Query((query, reply)))
    }
    fn disclose(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<CompleteHimitsuKey>, String> {
        self.request(|reply| RepositoryMessage::Disclose((query, reply)))
    }
    fn update(
        &mut self,
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        self.request(|reply| RepositoryMessage::Update(((query, set), reply)))
    }
    fn status(&mut self) -> Result<Option<LockStatus>, String> {
        self.request(|reply| RepositoryMessage::Status(((), reply)))
    }
    fn lock(&mut self, lock: LockStatus) -> Result<(), String> {
        self.request(|reply| RepositoryMessage::Lock((lock, reply)))
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
    fn status(&mut self) -> Result<Option<LockStatus>, String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.status())
            .collect::<Result<Vec<_>, _>>()
            .map(|locks| {
                locks.into_iter().max().unwrap_or(Some(LockStatus::Hard))
            })
    }
    fn lock(&mut self, lock: LockStatus) -> Result<(), String> {
        self.repositories
            .iter_mut()
            .map(|repository| repository.lock(lock.clone()))
            .collect::<Vec<_>>()
            .into_iter()
            //TODO: Does not report later errors.
            .collect::<Result<(), _>>()
    }
}
