use crate::himitsu_to_totp;
use crate::keyandquery::{
    CompleteHimitsuKey, HimitsuKey, HimitsuQuery, RedactedHimitsuKey,
};
use crate::otp::Totp;
use crate::state::{LockStatus, Repository};
use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs::{File, remove_file};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use walkdir::{DirEntry, WalkDir};

pub struct PassRepository {
    root: PathBuf,
    state: PassRepositoryState,
}

enum PassRepositoryState {
    Unlocked(Vec<CompleteHimitsuKey>),
    SoftLocked(Vec<RedactedHimitsuKey>),
    HardLocked,
}

impl PassRepository {
    fn unlocked(&mut self) -> Result<&mut Vec<CompleteHimitsuKey>, String> {
        match &self.state {
            PassRepositoryState::Unlocked(_) => {}
            _ => {
                self.state = PassRepositoryState::Unlocked(read_pass_files(
                    &self.root,
                )?);
            }
        };
        match &mut self.state {
            PassRepositoryState::Unlocked(keys) => Ok(keys),
            _ => unreachable!("state was set to unlocked above"),
        }
    }
}

impl Repository for PassRepository {
    fn new() -> Result<Self, String> {
        let root = env::var_os("PASSWORD_STORE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                env::home_dir().unwrap().join(".password-store")
            });
        Ok(Self {
            root,
            state: PassRepositoryState::HardLocked,
        })
    }
    fn add(
        &mut self,
        key: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        let keys = self.unlocked()?;
        let prev = himitsu_to_pass_files(keys.iter());
        let next = himitsu_to_pass_files(keys.iter().chain([&key]));
        let res = std::iter::empty()
            .chain(
                next.keys()
                    .filter_map(|k| {
                        next.get(k)
                            .take_if(|v| Some(*v) != prev.get(k))
                            .map(|v| (k, v))
                    })
                    .map(|(k, v)| gpg_encrypt(&self.root, k, v)),
            )
            .chain(prev.keys().filter(|k| !next.contains_key(*k)).map(|k| {
                remove_file(self.root.join(format!("{k}.gpg")))
                    .map_err(|err| err.to_string())
            }))
            .collect::<Result<(), String>>()
            .map(|()| vec![key]);
        self.state = PassRepositoryState::Unlocked(
            next.into_iter()
                .flat_map(|(k, v)| pass_file_to_himitsu(&k, &v))
                .collect(),
        );
        res.map(|keys| keys.into_iter().map(|key| key.into()).collect())
    }

    fn delete(
        &mut self,
        query: super::HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        let keys = self.unlocked()?;
        let prev = himitsu_to_pass_files(keys.iter());
        let deleted = keys
            .extract_if(.., |key| query.r#match(key))
            .collect::<Vec<_>>();
        let next = himitsu_to_pass_files(keys.iter());
        let res = std::iter::empty()
            .chain(
                next.keys()
                    .filter_map(|k| {
                        next.get(k)
                            .take_if(|v| Some(*v) != prev.get(k))
                            .map(|v| (k, v))
                    })
                    .map(|(k, v)| gpg_encrypt(&self.root, k, v)),
            )
            .chain(prev.keys().filter(|k| !next.contains_key(*k)).map(|k| {
                remove_file(self.root.join(format!("{k}.gpg")))
                    .map_err(|err| err.to_string())
            }))
            .collect::<Result<(), String>>()
            .map(|()| deleted);
        self.state = PassRepositoryState::Unlocked(
            next.into_iter()
                .flat_map(|(k, v)| pass_file_to_himitsu(&k, &v))
                .collect(),
        );
        res.map(|keys| keys.into_iter().map(|key| key.into()).collect())
    }

    fn query(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        match &mut self.state {
            PassRepositoryState::Unlocked(keys) => Ok(keys
                .iter()
                .cloned()
                .map(|key| key.into())
                .filter(|key| query.r#match(key))
                .collect()),
            PassRepositoryState::SoftLocked(keys) => Ok(keys
                .iter()
                .filter(|key| query.r#match(*key))
                .cloned()
                .collect()),
            PassRepositoryState::HardLocked => {
                let keys = self.unlocked()?;
                Ok(keys
                    .iter()
                    .cloned()
                    .map(|key| key.into())
                    .filter(|key| query.r#match(key))
                    .collect())
            }
        }
    }

    fn disclose(
        &mut self,
        query: HimitsuQuery,
    ) -> Result<Vec<CompleteHimitsuKey>, String> {
        let keys = self.unlocked()?;
        Ok(keys
            .iter()
            .filter(|key| query.r#match(*key))
            .cloned()
            .collect())
    }

    fn update(
        &mut self,
        query: HimitsuQuery,
        set: CompleteHimitsuKey,
    ) -> Result<Vec<RedactedHimitsuKey>, String> {
        let keys = self.unlocked()?;
        let prev = himitsu_to_pass_files(keys.iter());
        keys.iter_mut().for_each(|key| {
            if query.r#match(key) {
                key.update(set.clone())
            }
        });
        let next = himitsu_to_pass_files(keys.iter());
        let res = std::iter::empty()
            .chain(
                next.keys()
                    .filter_map(|k| {
                        next.get(k)
                            .take_if(|v| Some(*v) != prev.get(k))
                            .map(|v| (k, v))
                    })
                    .map(|(k, v)| gpg_encrypt(&self.root, k, v)),
            )
            .chain(prev.keys().filter(|k| !next.contains_key(*k)).map(|k| {
                remove_file(self.root.join(format!("{k}.gpg")))
                    .map_err(|err| err.to_string())
            }))
            .collect::<Result<(), String>>()
            .map(|()| vec![set]);
        self.state = PassRepositoryState::Unlocked(
            next.into_iter()
                .flat_map(|(k, v)| pass_file_to_himitsu(&k, &v))
                .collect(),
        );
        res.map(|keys| keys.into_iter().map(|key| key.into()).collect())
    }

    fn status(&mut self) -> Result<Option<LockStatus>, String> {
        match self.state {
            PassRepositoryState::Unlocked(_) => Ok(None),
            PassRepositoryState::SoftLocked(_) => Ok(Some(LockStatus::Soft)),
            PassRepositoryState::HardLocked => Ok(Some(LockStatus::Hard)),
        }
    }

    fn lock(&mut self, lock: LockStatus) -> Result<(), String> {
        match lock {
            LockStatus::Soft => {
                if let PassRepositoryState::Unlocked(keys) = std::mem::replace(
                    &mut self.state,
                    PassRepositoryState::HardLocked,
                ) {
                    self.state = PassRepositoryState::SoftLocked(
                        keys.into_iter().map(|key| key.into()).collect(),
                    );
                }
                Ok(())
            }
            _ => {
                self.state = PassRepositoryState::HardLocked;
                Ok(())
            }
        }
    }
}

fn nodes(root: &Path) -> Vec<DirEntry> {
    WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|x| {
            x.path()
                .to_str()
                .map(|path| !path.ends_with("/.gpg-id"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>()
}

fn read_pass_files(root: &Path) -> Result<Vec<CompleteHimitsuKey>, String> {
    let keys = nodes(root)
        .iter()
        .filter(|x| x.file_type().is_file())
        .flat_map(|file| {
            let path = file.path();
            Command::new("gpg")
                .args([std::ffi::OsStr::new("-qd"), path.as_os_str()])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .and_then(Child::wait_with_output)
                .map_err(|err| {
                    format!("Could not start gpg for decryption: {}", err)
                })
                .and_then(|status| {
                    if status.status.success() {
                        Ok(status.stdout)
                    } else {
                        Err(String::from_utf8_lossy(&status.stderr)
                            .to_string())
                    }
                })
                .map(|value| {
                    pass_file_to_himitsu(
                        path.with_extension("")
                            .strip_prefix(root)
                            .unwrap()
                            .to_str()
                            .unwrap(),
                        value.as_ref(),
                    )
                })
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    Ok(keys)
}

fn recipients_for(root: &Path, key: &str) -> Result<Vec<String>, String> {
    let start = root
        .join(key)
        .parent()
        .map(Path::to_owned)
        .ok_or("Could not resolve $PASSWORD_STORE_DIR")?;
    let gpg_id = std::iter::successors(Some(start.as_path()), |p| p.parent())
        .take_while(|p| p.starts_with(root))
        .find_map(|p| File::open(p.join(".gpg-id")).ok())
        .ok_or("Could not open gpg-id file")?;

    Ok(BufReader::new(gpg_id)
        .lines()
        .map_while(Result::ok)
        .collect::<Vec<String>>())
}

fn gpg_encrypt(root: &Path, key: &str, value: &[u8]) -> Result<(), String> {
    let recipients = recipients_for(root, key)?;
    let mut gpg = Command::new("gpg")
        .args(
            [
                "-qe",
                "--yes",
                "--batch",
                "-o",
                root.join(format!("{key}.gpg")).to_str().unwrap(),
            ]
            .into_iter()
            .chain(recipients.iter().flat_map(|recipient| ["-r", recipient])),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            format!("Could not start gpg for encryption: {}", err)
        })?;

    let mut stdin = gpg.stdin.take().ok_or("Failed to open stdin")?;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            stdin.write_all(value).expect("Failed to write to stdin");
        });

        gpg.wait_with_output()
    })
    .map_err(|err| err.to_string())
    .and_then(|status| {
        if status.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&status.stderr).to_string())
        }
    })
}

static PROPERTY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(?:^(?P<name>[[:alnum:]_]+):\s*(?P<value>.*))").unwrap()
});

pub fn pass_file_to_himitsu(
    path: &str,
    content: &[u8],
) -> Vec<CompleteHimitsuKey> {
    let mut otp: Option<&str> = None;
    //Empty string falls through to 'file' proto
    let mut props = std::str::from_utf8(content)
        .unwrap_or_default()
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            if i == 0 {
                Some(("password", line))
            } else {
                PROPERTY.captures(line).map(|caps| {
                    (
                        caps.name("name").unwrap().as_str(),
                        caps.name("value").unwrap().as_str(),
                    )
                })
            }
        })
        .filter_map(|(k, v)| {
            if k == "login" || k == "user" {
                Some(("user", false, v))
            } else if k == "url" {
                Some(("host", false, v))
            } else if k == "proto" {
                Some(("proto", false, v))
            } else if k == "otpauth" {
                otp = Some(v);
                None
            } else {
                Some((k, true, v))
            }
        })
        .chain(std::iter::once(("path", false, path)))
        .collect::<Vec<_>>();
    let proto = props
        .iter()
        .find(|prop| prop.0 == "proto")
        .map(|prop| prop.2)
        .unwrap_or_else(|| {
            let proto = if props.iter().any(|prop| prop.0 == "host") {
                "web"
            } else {
                "file"
            };
            props.push(("proto", false, proto));
            proto
        });
    match proto {
        "web" => {
            fn prop_order(name: &str) -> usize {
                let props_ordering = ["proto", "password", "user", "host"];
                props_ordering
                    .iter()
                    .position(|&s| s == name)
                    .unwrap_or(props_ordering.len())
            }
            props.sort_by(|a, b| {
                match isize::signum(
                    (prop_order(a.0) as isize) - (prop_order(b.0) as isize),
                ) {
                    -1 => std::cmp::Ordering::Less,
                    0 => std::cmp::Ordering::Equal,
                    1 => std::cmp::Ordering::Greater,
                    _ => panic!(),
                }
            });
            let len = props.len();
            props.dedup_by_key(|prop| prop.0);
            if len != props.len() {
                eprintln!(
                    "Warning: pass file {path} has duplicate properties"
                );
            }

            std::iter::once(HimitsuKey(
                props
                    .iter()
                    .map(|(k, s, v)| {
                        ((*k).to_string(), { (*s, (*v).to_owned()) })
                    })
                    .collect::<Vec<_>>(),
            ))
            .chain(
                otp.and_then(|uri| {
                    Totp::from_uri(&format!("otpauth:{uri}"))
                        .map_err(|err| eprintln!("{err} {uri}"))
                        .ok()
                })
                .map(|otp| {
                    HimitsuKey(
                        std::iter::once(("proto", false, "totp".to_string()))
                            .chain(
                                props
                                    .into_iter()
                                    .filter(|prop| {
                                        prop.0 == "user"
                                            || prop.0 == "host"
                                            || prop.0 == "path"
                                    })
                                    .map(|(k, s, v)| (k, s, v.to_string())),
                            )
                            .chain(otp.iter().map(|(k, v)| {
                                (k, k == "secret", v.to_string())
                            }))
                            .map(|(k, s, v)| ((*k).to_string(), { (s, v) }))
                            .collect::<Vec<_>>(),
                    )
                }),
            )
            .collect::<Vec<_>>()
        }
        "file" => {
            let content = general_purpose::STANDARD.encode(content);
            props.retain(|prop| prop.0 == "path" || prop.0 == "proto");
            props.push(("content", true, &content));
            vec![HimitsuKey(
                props
                    .iter()
                    .map(|(k, s, v)| {
                        ((*k).to_string(), (*s, v.to_owned().to_owned()))
                    })
                    .collect::<Vec<_>>(),
            )]
        }
        _ => panic!(),
    }
}

pub fn himitsu_to_pass_files<
    'a,
    T: Iterator<Item = &'a CompleteHimitsuKey>,
>(
    keys: T,
) -> HashMap<String, Vec<u8>> {
    enum PassFile {
        Lines(Vec<String>),
        Raw(Vec<u8>),
    }
    fn entry_lines<'m>(
        map: &'m mut HashMap<String, PassFile>,
        path: &str,
    ) -> Option<&'m mut Vec<String>> {
        match map
            .entry(path.to_owned())
            .or_insert_with(|| PassFile::Lines(vec![String::new()]))
        {
            PassFile::Lines(lines) => Some(lines),
            PassFile::Raw(_) => {
                eprintln!("Double pass path detected. Weird");
                None
            }
        }
    }
    let mut map = HashMap::<String, PassFile>::new();
    keys.for_each(|key| {
        let Some((_, path)) = key.get("path") else {
            return;
        };
        match key.get("proto").map(|(_, v)| v.as_ref()) {
            Some("web") => {
                let Some(pass_lines) = entry_lines(&mut map, path) else {
                    return;
                };
                if let Some(password) =
                    key.get("password").map(|password| password.1.to_owned())
                {
                    pass_lines[0] = password;
                }
                key.0
                    .iter()
                    .filter(|(k, _)| k != "password" && k != "path")
                    .for_each(|(k, (_, v))| {
                        let encoded = format!(
                            "{}: {}",
                            if k == "host" { "url" } else { k.as_ref() },
                            v
                        );
                        if pass_lines.iter().all(|line| line != &encoded) {
                            pass_lines.push(encoded);
                        }
                    });
            }
            Some("totp") => {
                let Some(pass_lines) = entry_lines(&mut map, path) else {
                    return;
                };
                match himitsu_to_totp(key) {
                    Ok(totp) => {
                        pass_lines.push(totp.to_uri());
                    }
                    Err(err) => eprintln!("{err}"),
                }
            }
            Some("file") => {
                match key.get("content").ok_or(()).and_then(|(_, v)| {
                    general_purpose::STANDARD
                        .decode(v)
                        .map_err(|err| eprintln!("{err}"))
                }) {
                    Ok(payload) => {
                        if map
                            .insert(path.to_string(), PassFile::Raw(payload))
                            .is_some()
                        {
                            eprintln!("Double pass path detected. Weird");
                        }
                    }
                    Err(()) => eprintln!("No content in file pass entry"),
                }
            }
            _ => (),
        }
    });
    map.into_iter()
        .map(|(path, file)| {
            let bytes = match file {
                PassFile::Lines(lines) => {
                    (lines.join("\n") + "\n").into_bytes()
                }
                PassFile::Raw(payload) => payload,
            };
            (path, bytes)
        })
        .collect()
}
