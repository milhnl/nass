use crate::keyandquery::{CompleteHimitsuKey, RedactedHimitsuKey};
use crate::state::LockStatus;
use shlex::Quoter;
use std::fmt::{self, Display};

pub enum RepositoryReply {
    Keys(Vec<RedactedHimitsuKey>),
    DisclosedKeys(Vec<CompleteHimitsuKey>),
    Status(Option<LockStatus>),
    Locked,
    Error(String),
}

impl Display for RepositoryReply {
    fn fmt(&self, writer: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keys(keys) => {
                for key in keys {
                    writeln!(writer, "key {key}")?;
                }
                writeln!(writer, "end")
            }
            Self::DisclosedKeys(keys) => {
                for key in keys {
                    writeln!(writer, "key {key}")?;
                }
                writeln!(writer, "end")
            }
            Self::Status(status) => writeln!(
                writer,
                "status {}",
                match status {
                    None => "unlocked",
                    Some(LockStatus::Soft) => "soft_locked",
                    Some(LockStatus::Hard) => "hard_locked",
                }
            ),
            Self::Locked => writeln!(writer, "locked"),
            Self::Error(error) => writeln!(
                writer,
                "error {}",
                Quoter::new().allow_nul(true).quote(error).unwrap()
            ),
        }
    }
}
