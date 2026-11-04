//! A canary list that matches one of your own accounts locks you out: `[canary] ssh =
//! ["*"]` with a gateway user missing from `except` bans the admin's address at the next
//! login and raises a critical alert (seen on a real node). So the accounts that can log in
//! over SSH on this host are checked against the list: at install (`vpsfort canary-check`,
//! which the installers run and warn about while the SSH session is still open), at start
//! and daily in the daemon (a high alert).

use std::collections::BTreeSet;
use std::path::Path;

use crate::config::CanaryCfg;
use crate::record::Source;

/// The accounts that can log in over SSH, as far as the files say: a login shell in
/// `passwd`, or an authorized_keys file (`/etc/ssh/authorized_keys/<user>` as the hardened
/// gateway layout keeps them, or `~/.ssh/authorized_keys`). A key file in a home that an
/// account with a login shell lives in is that account's: a system account without a shell
/// that merely shares the home (Fedora's `operator`: home `/root`, shell `nologin`) has no
/// keys of its own, and nobody logs in as it.
pub fn ssh_accounts(passwd: &str, keys_dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let accounts = crate::sshaudit::parse_passwd(passwd, None);
    let login_homes: BTreeSet<&str> = accounts.iter().filter(|a| a.login_shell()).map(|a| a.home.as_str()).collect();
    for a in &accounts {
        let own_home = a.login_shell() || !login_homes.contains(a.home.as_str());
        let keys = own_home && Path::new(&a.home).join(".ssh/authorized_keys").is_file();
        if (a.login_shell() && (a.uid >= 1000 || a.uid == 0)) || keys {
            out.insert(a.name.clone());
        }
    }
    if let Ok(rd) = std::fs::read_dir(keys_dir) {
        for e in rd.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if e.path().is_file() && !name.starts_with('.') {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

/// The accounts among `accounts` the canary list matches: each one's next SSH login bans
/// its address.
pub fn locked_out<'a>(cfg: &CanaryCfg, accounts: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    accounts.into_iter().filter(|a| cfg.is_canary(Source::Ssh, a)).cloned().collect()
}

/// One message per such account, with the fix.
pub fn problems(cfg: &CanaryCfg, accounts: &BTreeSet<String>) -> Vec<String> {
    locked_out(cfg, accounts)
        .into_iter()
        .map(|a| {
            format!(
                "account '{a}' can log in over SSH on this host but [canary] ssh matches it: its next login bans the address it comes \
                 from and raises a critical alert. Add it to [canary] except (`except = [\"{a}\"]`) and restart vpsfort"
            )
        })
        .collect()
}

/// The live check: `/etc/passwd` and `/etc/ssh/authorized_keys`.
pub fn check(cfg: &CanaryCfg) -> Vec<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    problems(cfg, &ssh_accounts(&passwd, Path::new("/etc/ssh/authorized_keys")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gateway_user_on_the_wildcard_list_is_found() {
        let d = std::env::temp_dir().join(format!("lg-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("keys")).unwrap();
        std::fs::write(d.join("keys/gw7f3a"), "ssh-ed25519 AAAA\n").unwrap();
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      alice:x:1000:1000::/home/alice:/bin/bash\n\
                      backup:x:34:34::/var/backups:/usr/sbin/nologin\n\
                      gw7f3a:x:1001:1001::/nonexistent:/bin/sh\n";
        let accounts = ssh_accounts(passwd, &d.join("keys"));
        assert_eq!(accounts.iter().map(String::as_str).collect::<Vec<_>>(), ["alice", "gw7f3a", "root"]);
        let cfg = CanaryCfg { ssh: vec!["*".into()], except: vec!["alice".into()], ..Default::default() };
        let p = problems(&cfg, &accounts);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].starts_with("account 'gw7f3a' can log in over SSH"), "{}", p[0]);
        assert!(p[0].contains("except = [\"gw7f3a\"]"));
        let fixed = CanaryCfg { except: vec!["alice".into(), "gw7f3a".into(), "root".into()], ..cfg.clone() };
        assert!(problems(&fixed, &accounts).is_empty());
        let named = CanaryCfg { ssh: vec!["admin".into(), "Alice".into()], except: vec![], ..Default::default() };
        assert_eq!(locked_out(&named, &accounts), ["alice"], "names are matched as the canary list is");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_shell_less_account_sharing_a_home_has_no_keys_of_its_own() {
        // Fedora: operator:x:11:0:operator:/root:/usr/sbin/nologin, and root's key file
        let d = std::env::temp_dir().join(format!("lg-canary-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for home in ["root", "svc"] {
            std::fs::create_dir_all(d.join(home).join(".ssh")).unwrap();
            std::fs::write(d.join(home).join(".ssh/authorized_keys"), "ssh-ed25519 AAAA\n").unwrap();
        }
        let (root, svc) = (d.join("root"), d.join("svc"));
        let passwd = format!(
            "root:x:0:0:root:{root}:/bin/bash\n\
             operator:x:11:0:operator:{root}:/usr/sbin/nologin\n\
             svc:x:990:990::{svc}:/usr/sbin/nologin\n",
            root = root.display(),
            svc = svc.display()
        );
        let accounts = ssh_accounts(&passwd, &d.join("keys"));
        // root by its shell and key; svc by a key file in a home of its own (ssh -N works
        // without a shell); operator not at all
        assert_eq!(accounts.iter().map(String::as_str).collect::<Vec<_>>(), ["root", "svc"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
