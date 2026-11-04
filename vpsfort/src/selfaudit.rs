//! A look at vpsfort's own files, at start and once a day: the SSH audit checks sshd's
//! key files and config; this checks the cluster key, the node key, the passwords, the
//! config, the state and the log, the directories other programs hand files to vpsfort
//! in, and the binary itself. A key another user can read joins the cluster; a directory
//! another user can write to plants a feed, a report or a message for the admins.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::engine::Severity;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// Stable per path and kind, for the alert gate: `secret-readable:/etc/vpsfort/cluster.key`.
    pub id: String,
    pub severity: Severity,
    pub message: String,
}

/// What a path should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    /// Nobody but the owner reads or writes it (a key, a password).
    Secret,
    /// Others don't read it (it names people, addresses or decisions); the group may.
    Private,
    /// Others may read it, never write it.
    Public,
    /// A directory vpsfort writes: nobody else writes there.
    Dir,
    /// A directory a bot and vpsfort share (root:bot 1770): the group writes by design,
    /// others never.
    Shared,
}

struct Item {
    path: PathBuf,
    want: Want,
    /// Why it matters, after "...: ".
    why: &'static str,
}

/// The uid files should belong to: root on a server. None skips the owner check.
pub fn own_uid() -> Option<u32> {
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Everything worth checking in `cfg`, whether or not it exists.
fn items(cfg: &Config, config_path: Option<&Path>) -> Vec<Item> {
    let mut v = Vec::new();
    let mut add = |path: PathBuf, want: Want, why: &'static str| {
        if !path.as_os_str().is_empty() {
            v.push(Item { path, want, why });
        }
    };
    if cfg.cluster.enabled {
        let key = &cfg.cluster.key_file;
        add(key.clone(), Want::Secret, "whoever reads it joins the cluster and bans, unbans and allowlists on every node");
        for ext in ["next", "prev"] {
            add(key.with_extension(ext), Want::Secret, "a cluster key in rotation: it joins the cluster like the current one");
        }
        add(cfg.cluster.identity_file.clone(), Want::Secret, "whoever reads it signs facts and files as this node");
        add(cfg.cluster.inbox.clone(), Want::Dir, "a file put there passes for a peer's abuse report");
        if !cfg.cluster.mirror_dir.as_os_str().is_empty() && cfg.cluster.mirror_dir.exists() {
            add(cfg.cluster.mirror_dir.clone(), Want::Dir, "the peers' mirrored logs could be edited there");
        }
    }
    add(cfg.notify.api_password_file.clone(), Want::Secret, "whoever reads it sends XMPP messages as any account through ejabberd's API");
    add(cfg.journal.verify_key_file.clone(), Want::Secret, "whoever reads it can seal edited journal entries of any past period");
    for src in &cfg.waf.sources {
        if let Some(k) = &src.api_key_file {
            add(k.clone(), Want::Secret, "a WAF's API key");
        }
    }
    if let Some(p) = config_path {
        let why = if cfg.cluster.key.is_empty() {
            "it names the admins, the peers, the allowlist and every password file"
        } else {
            "it holds the cluster key inline (`[cluster] key`): whoever reads it joins the cluster"
        };
        add(p.to_path_buf(), if cfg.cluster.key.is_empty() { Want::Private } else { Want::Secret }, why);
        if let Some(dir) = p.parent() {
            add(dir.to_path_buf(), Want::Dir, "a file there (the config, the keys) could be replaced");
        }
    }
    add(cfg.state_file.clone(), Want::Private, "it holds addresses, account names and the networks accounts log in from");
    if let Some(dir) = cfg.state_file.parent() {
        add(dir.to_path_buf(), Want::Dir, "the state file could be replaced");
    }
    if let Some(log) = &cfg.actions_log {
        add(log.clone(), Want::Private, "it holds every decision with its evidence and account names");
    }
    if cfg.feeds.enabled {
        add(cfg.feeds.cache_dir.clone(), Want::Dir, "a planted file there is loaded as a blocklist");
    }
    if cfg.waf.enabled {
        add(cfg.waf.cache_dir.clone(), Want::Dir, "a planted file there is loaded as a WAF's decisions");
    }
    if cfg.geo.enabled {
        add(cfg.geo.dir.clone(), Want::Dir, "a planted file there is loaded as the geo database");
    }
    for (name, dir) in [
        ("bot_outbox", &cfg.notify.bot_outbox),
        ("tg_outbox", &cfg.notify.tg_outbox),
        ("mail_outbox", &cfg.notify.mail_outbox),
        ("signal_outbox", &cfg.notify.signal_outbox),
        ("matrix_outbox", &cfg.notify.matrix_outbox),
        ("xmpp_outbox", &cfg.notify.xmpp_outbox),
    ] {
        let _ = name;
        if let Some(d) = dir {
            add(
                d.clone(),
                Want::Shared,
                "the admins' messages wait there: anyone could read them, or put messages of their own for the admins",
            );
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        add(exe, Want::Public, "vpsfort's own program could be replaced");
    }
    v
}

/// Checks every item that exists. `root`: the uid they should belong to (None: not checked).
pub fn audit(cfg: &Config, config_path: Option<&Path>, root: Option<u32>) -> Vec<Problem> {
    items(cfg, config_path).into_iter().filter_map(|it| check(&it, root)).flatten().collect()
}

fn check(it: &Item, root: Option<u32>) -> Option<Vec<Problem>> {
    let md = std::fs::metadata(&it.path).ok()?;
    let mode = md.mode() & 0o7777;
    let path = it.path.display();
    let mut out = Vec::new();
    let mut push = |kind: &str, severity: Severity, what: String, fix: &str| {
        out.push(Problem { id: format!("{kind}:{path}"), severity, message: format!("{path} {what} (mode {mode:04o}): {}{fix}", it.why) });
    };
    if let Some(uid) = root.filter(|uid| *uid != md.uid()) {
        push("owner", Severity::High, format!("is owned by uid {}, not by uid {uid}", md.uid()), "; that user can change it");
    }
    let group_or_other_write = mode & 0o022 != 0;
    let other_write = mode & 0o002 != 0;
    match it.want {
        Want::Secret => {
            if mode & 0o077 != 0 {
                let what = if mode & 0o022 != 0 { "is readable and writable by others" } else { "is readable by others" };
                push("secret-readable", Severity::High, what.into(), "; chmod 600 it");
            }
        }
        Want::Private => {
            if group_or_other_write {
                push("writable", Severity::High, "is writable by others".into(), "; chmod go-w it");
            } else if mode & 0o004 != 0 {
                push("readable", Severity::Warning, "is readable by everyone".into(), "; chmod o-r it");
            }
        }
        Want::Public => {
            if group_or_other_write {
                push("writable", Severity::High, "is writable by others".into(), "; chmod go-w it");
            }
        }
        Want::Dir => {
            if md.is_dir() && group_or_other_write && mode & 0o1000 == 0 {
                push("dir-writable", Severity::High, "is a directory others can write to".into(), "; chmod go-w it");
            }
        }
        Want::Shared => {
            if md.is_dir() && other_write {
                push("dir-writable", Severity::High, "is a directory everyone can write to".into(), "; chmod o-w it");
            } else if md.is_dir() && mode & 0o004 != 0 {
                push("readable", Severity::Warning, "is a directory everyone can read".into(), "; chmod o-rx it");
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    /// `kind:basename` of each problem.
    fn ids(problems: &[Problem]) -> Vec<String> {
        problems
            .iter()
            .map(|p| {
                let (kind, path) = p.id.split_once(':').unwrap();
                format!("{kind}:{}", path.rsplit('/').next().unwrap())
            })
            .collect()
    }

    #[test]
    fn keys_config_state_and_directories() {
        let d = std::env::temp_dir().join(format!("lg-selfaudit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::create_dir_all(d.join("outbox")).unwrap();
        std::fs::create_dir_all(d.join("inbox")).unwrap();
        std::fs::set_permissions(d.join("etc"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(d.join("outbox"), std::fs::Permissions::from_mode(0o1770)).unwrap();
        std::fs::set_permissions(d.join("inbox"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = file(&d.join("etc"), "cluster.key", 0o640);
        let node = file(&d.join("etc"), "node.key", 0o600);
        let conf = file(&d.join("etc"), "vpsfort.toml", 0o644);
        let state = file(&d, "state.json", 0o600);
        let log = file(&d, "actions.jsonl", 0o640);
        let me = std::fs::metadata(&key).unwrap().uid();
        let mut cfg = Config::default();
        cfg.cluster.enabled = true;
        cfg.cluster.key_file = key.clone();
        cfg.cluster.identity_file = node;
        cfg.cluster.inbox = d.join("inbox");
        cfg.state_file = state.clone();
        cfg.actions_log = Some(log);
        cfg.notify.tg_outbox = Some(d.join("outbox"));
        cfg.feeds.enabled = false;
        cfg.waf.enabled = false;
        cfg.geo.enabled = false;

        let problems = audit(&cfg, Some(&conf), Some(me));
        let mut got: Vec<&str> = problems.iter().map(|p| p.id.as_str()).collect();
        got.retain(|id| !id.ends_with(&std::env::current_exe().unwrap().display().to_string()));
        assert_eq!(got, [format!("secret-readable:{}", key.display()), format!("readable:{}", conf.display())], "{problems:#?}");
        assert_eq!(problems[0].severity, Severity::High);
        assert!(
            problems[0].message.contains("is readable by others (mode 0640): whoever reads it joins the cluster"),
            "{}",
            problems[0].message
        );
        assert_eq!(problems[1].severity, Severity::Warning);

        // the config holds the key inline: it is a secret then; another owner is high;
        // a state directory others can write to is high, the sticky outbox is fine
        cfg.cluster.key = "inline".into();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        let problems = audit(&cfg, Some(&conf), Some(me + 1));
        let got = ids(&problems);
        assert!(got.contains(&"secret-readable:vpsfort.toml".to_string()), "{got:?}");
        assert!(got.contains(&format!("dir-writable:{}", d.file_name().unwrap().to_str().unwrap())), "{got:?}");
        assert!(got.iter().filter(|g| g.starts_with("owner:")).count() >= 5, "every file has another owner: {got:?}");
        assert!(
            !got.iter().any(|g| g.ends_with(":outbox") && !g.starts_with("owner:")),
            "a sticky group-writable outbox is by design: {got:?}"
        );
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();

        // a world-writable outbox, a world-readable state file, and a missing file (skipped)
        std::fs::set_permissions(d.join("outbox"), std::fs::Permissions::from_mode(0o1777)).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        cfg.cluster.identity_file = d.join("missing.key");
        cfg.cluster.key.clear();
        let got = ids(&audit(&cfg, None, None));
        assert_eq!(got, ["readable:state.json", "dir-writable:outbox"], "{got:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
