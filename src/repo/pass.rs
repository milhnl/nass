use crate::himitsu_to_totp;
use crate::otp::Totp;
use crate::state::{HimitsuKey, KeyField, Repository};
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

    keys: Vec<HimitsuKey>,
}

//enum PassRepositoryState {
//    HardLocked,
//    SoftLocked(Vec<HimitsuKey>),
//    Unlocked(Vec<HimitsuKey>),
//}

impl Repository for PassRepository {
    fn new() -> Result<Self, String> {
        let root = PathBuf::from(env::var_os("PASSWORD_STORE_DIR").unwrap());

        let keys = nodes(&root)
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
                            Ok(String::from_utf8_lossy(&status.stdout)
                                .to_string())
                        } else {
                            Err(String::from_utf8_lossy(&status.stderr)
                                .to_string())
                        }
                    })
                    .map(|value| {
                        pass_file_to_himitsu(
                            path.with_extension("")
                                .strip_prefix(&root)
                                .unwrap()
                                .to_str()
                                .unwrap(),
                            value.as_ref(),
                        )
                    })
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        Ok(Self { root, keys })
    }

    fn add(
        &mut self,
        query: super::HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        let new_key = HimitsuKey::try_from(query).unwrap();
        let prev = himitsu_to_pass_files(self.keys.iter());
        let next = himitsu_to_pass_files(self.keys.iter().chain([&new_key]));
        let res = std::iter::empty()
            .chain(
                next.keys()
                    .filter_map(|k| {
                        next.get(k)
                            .take_if(|v| Some(*v) != prev.get(k))
                            .map(|v| (k, v))
                    })
                    .map(|(k, v)| gpg_encrypt(&self.root, k, v.into())),
            )
            .chain(prev.keys().filter(|k| !next.contains_key(*k)).map(|k| {
                remove_file(self.root.join(format!("{k}.gpg")))
                    .map_err(|err| err.to_string())
            }))
            .collect::<Result<(), String>>()
            .map(|()| vec![new_key]);
        self.keys = next
            .into_iter()
            .flat_map(|(k, v)| pass_file_to_himitsu(&k, &v))
            .collect();
        res
    }

    fn delete(
        &mut self,
        query: super::HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        let prev = himitsu_to_pass_files(self.keys.iter());
        let deleted =
            self.keys.extract_if(.., |key| query.r#match(key)).collect();
        eprintln!("deleted {:?}", deleted);
        let next = himitsu_to_pass_files(self.keys.iter());
        let res = std::iter::empty()
            .chain(
                next.keys()
                    .filter_map(|k| {
                        next.get(k)
                            .take_if(|v| Some(*v) != prev.get(k))
                            .map(|v| (k, v))
                    })
                    .map(|(k, v)| gpg_encrypt(&self.root, k, v.into())),
            )
            .chain(prev.keys().filter(|k| !next.contains_key(*k)).map(|k| {
                remove_file(self.root.join(format!("{k}.gpg")))
                    .map_err(|err| err.to_string())
            }))
            .collect::<Result<(), String>>()
            .map(|()| deleted);
        self.keys = next
            .into_iter()
            .flat_map(|(k, v)| pass_file_to_himitsu(&k, &v))
            .collect();
        res
    }

    fn query(
        &mut self,
        query: super::HimitsuQuery,
        decrypt: bool,
    ) -> Result<Vec<HimitsuKey>, String> {
        Ok(self
            .keys
            .iter()
            .filter(|key| query.r#match(key))
            .cloned()
            .map(|mut key| {
                if !decrypt {
                    key.0.iter_mut().for_each(|(_, value)| {
                        if value.secret {
                            value.value = None;
                        }
                    });
                };
                key
            })
            .collect())
    }

    fn update(
        &mut self,
        query: super::HimitsuQuery,
        set_query: super::HimitsuQuery,
    ) -> Result<Vec<HimitsuKey>, String> {
        let new_key = HimitsuKey::try_from(set_query).unwrap();
        let prev = himitsu_to_pass_files(self.keys.iter());
        self.keys.iter_mut().for_each(|key| {
            if query.r#match(key) {
                key.update(new_key.clone())
            }
        });
        let next = himitsu_to_pass_files(self.keys.iter().chain([&new_key]));
        let res = std::iter::empty()
            .chain(
                next.keys()
                    .filter_map(|k| {
                        next.get(k)
                            .take_if(|v| Some(*v) != prev.get(k))
                            .map(|v| (k, v))
                    })
                    .map(|(k, v)| gpg_encrypt(&self.root, k, v.into())),
            )
            .chain(prev.keys().filter(|k| !next.contains_key(*k)).map(|k| {
                remove_file(self.root.join(format!("{k}.gpg")))
                    .map_err(|err| err.to_string())
            }))
            .collect::<Result<(), String>>()
            .map(|()| vec![new_key]);
        self.keys = next
            .into_iter()
            .flat_map(|(k, v)| pass_file_to_himitsu(&k, &v))
            .collect();
        res
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

fn gpg_encrypt(root: &Path, key: &str, value: String) -> Result<(), String> {
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
    std::thread::spawn(move || {
        stdin
            .write_all(value.as_bytes())
            .expect("Failed to write to stdin");
    });

    gpg.wait_with_output()
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

pub fn pass_file_to_himitsu(path: &str, content: &str) -> Vec<HimitsuKey> {
    let mut otp: Option<&str> = None;
    let mut props = content
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
                        ((*k).to_string(), {
                            KeyField {
                                value: Some((*v).to_string()),
                                secret: *s,
                            }
                        })
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
                            .map(|(k, s, v)| {
                                ((*k).to_string(), {
                                    KeyField {
                                        value: Some(v),
                                        secret: s,
                                    }
                                })
                            })
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
                        ((*k).to_string(), {
                            KeyField {
                                value: Some((*v).into()),
                                secret: *s,
                            }
                        })
                    })
                    .collect::<Vec<_>>(),
            )]
        }
        _ => panic!(),
    }
}

pub fn himitsu_to_pass_files<'a, T: Iterator<Item = &'a HimitsuKey>>(
    keys: T,
) -> HashMap<String, String> {
    let mut map = HashMap::<String, Vec<String>>::new();
    keys.for_each(|key| {
        let Some(path) = key.get_value("path") else {
            return;
        };
        match key.get_value("proto") {
            Some("web") => {
                let pass_lines = map
                    .entry(path.to_string())
                    .or_insert(Vec::from(["".into()]));
                if let Some(password) = key
                    .get_value("password")
                    .map(|password| password.to_string())
                {
                    pass_lines[0] = password;
                }
                key.0
                    .iter()
                    .filter(|(k, v)| {
                        k != "password" && k != "path" && v.value.is_some()
                    })
                    .for_each(|(k, v)| {
                        let encoded = format!(
                            "{}: {}",
                            if k == "host" { "url" } else { k.as_ref() },
                            v.value.as_ref().unwrap().clone()
                        );
                        if pass_lines.iter().all(|line| line != &encoded) {
                            pass_lines.push(encoded);
                        }
                    });
            }
            Some("totp") => {
                let pass_lines = map
                    .entry(path.to_string())
                    .or_insert(Vec::from(["".into()]));
                if key
                    .get("secret")
                    .map(|x| x.secret && x.value.is_none())
                    .unwrap_or(false)
                {
                    pass_lines.push("otpauth:".into());
                } else {
                    match himitsu_to_totp(key) {
                        Ok(totp) => {
                            pass_lines.push(totp.to_uri());
                        }
                        Err(err) => eprintln!("{err}"),
                    }
                }
            }
            Some("file") => {
                if map
                    .insert(
                        path.to_string(),
                        key.get_value("content")
                            .ok_or(())
                            .and_then(|v| {
                                general_purpose::STANDARD
                                    .decode(v)
                                    .map_err(|err| eprintln!("{err}"))
                            })
                            .and_then(|v| {
                                String::from_utf8(v)
                                    .map_err(|err| eprintln!("{err}"))
                            })
                            .map(|v| vec![v])
                            .unwrap_or_else(|_| Vec::new()),
                    )
                    .is_some()
                {
                    eprintln!("Double pass path detected. Weird");
                }
            }
            _ => (),
        }
    });
    map.iter()
        .map(|(k, v)| (k.to_string(), v.join("\n") + "\n"))
        .collect::<HashMap<_, _>>()
}
