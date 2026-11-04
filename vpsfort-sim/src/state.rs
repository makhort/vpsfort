//! The files the console needs, made when missing: the web key, the admin's password and
//! one-time secret, the certificate. Everything made is said aloud, with what to type.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use vpsfort_web::{auth, tls, totp, wire};

/// The admin's password when the simulator makes one.
pub const DEFAULT_PASSWORD: &str = "vpsfort-sim";

#[derive(Debug)]
pub struct Files {
    pub web_key: PathBuf,
    pub password: PathBuf,
    pub totp: PathBuf,
    pub admins: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn write(path: &Path, content: &str, mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f =
        fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    std::io::Write::write_all(&mut f, content.as_bytes())?;
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Makes what is missing under `dir` and says so. Returns the files and the web key.
pub fn prepare(dir: &Path, totp_on: bool) -> Result<(Files, [u8; 32])> {
    // The web key, the password hash and the TLS key live here, and the nodes' sockets: the
    // directory is ours alone. One made by someone else (the default is under /tmp) could hold
    // their web key, and would let any local user talk to the agents and the sockets.
    match fs::metadata(dir) {
        Err(_) => fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).with_context(|| format!("creating {}", dir.display()))?,
        Ok(m) if !m.is_dir() => bail!("{} is not a directory", dir.display()),
        Ok(m) if m.permissions().mode() & 0o077 != 0 => bail!(
            "{} can be read or written by other users (mode {:o}): chmod 700 it, or set another dir",
            dir.display(),
            m.permissions().mode() & 0o777
        ),
        Ok(_) => {}
    }
    let files = Files {
        web_key: dir.join("web.key"),
        password: dir.join("admin.password"),
        totp: dir.join("admin.totp"),
        admins: dir.join("admins"),
        cert: dir.join("tls.crt"),
        key: dir.join("tls.key"),
    };
    fs::create_dir_all(&files.admins)?;

    let key = match fs::read_to_string(&files.web_key) {
        Ok(text) => wire::decode_key(&text).with_context(|| format!("{}: not a web key", files.web_key.display()))?,
        Err(_) => {
            let text = wire::generate_key();
            write(&files.web_key, &format!("{text}\n"), 0o600)?;
            let key = wire::decode_key(&text)?;
            println!("made {} (web key, fingerprint {})", files.web_key.display(), wire::key_id(&key));
            key
        }
    };

    if !files.password.exists() {
        write(&files.password, &format!("{}\n", auth::hash_password(DEFAULT_PASSWORD)?), 0o600)?;
        println!("made {} with the password \"{DEFAULT_PASSWORD}\" for the account \"admin\"", files.password.display());
    }

    if totp_on {
        let secret = match fs::read_to_string(&files.totp) {
            Ok(text) => totp::unbase32(text.trim()).with_context(|| format!("{}: not a TOTP secret", files.totp.display()))?,
            Err(_) => {
                let mut secret = [0u8; 20];
                wire::getrandom(&mut secret)?;
                write(&files.totp, &format!("{}\n", totp::base32(&secret)), 0o600)?;
                println!("made {} (the one-time secret; add it to an authenticator app or read the code below)", files.totp.display());
                println!("  {}", totp::uri(&secret, "vpsfort-sim", "admin@sim"));
                secret.to_vec()
            }
        };
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        println!(
            "one-time code now: {:06} (the next in {} s; the simulator prints it, a real console never would)",
            totp::code(&secret, unix / 30),
            30 - unix % 30
        );
    }

    if !files.cert.exists() || !files.key.exists() {
        let names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        let (cert, key, fp) = tls::self_signed(&names)?;
        write(&files.key, &key, 0o600)?;
        write(&files.cert, &cert, 0o644)?;
        println!("made {} and {} (self-signed, for {}; SHA-256 {fp})", files.cert.display(), files.key.display(), names.join(", "));
    }
    Ok((files, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_files_are_made_once() {
        let dir = std::env::temp_dir().join(format!("vpsfort-sim-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (files, key) = prepare(&dir, true).unwrap();
        for p in [&files.web_key, &files.password, &files.totp, &files.cert, &files.key] {
            assert!(p.exists(), "{}", p.display());
        }
        let (_, again) = prepare(&dir, true).unwrap();
        assert_eq!(key, again, "an existing key is read, not replaced");
        assert!(tls::validity(&files.cert).is_some());
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700, "ours alone");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A directory other users can reach (one of theirs under /tmp, or one made 0755 by hand)
    /// is refused: the keys and sockets in it would be theirs to read or replace.
    #[test]
    fn a_shared_directory_is_refused() {
        let dir = std::env::temp_dir().join(format!("vpsfort-sim-shared-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let e = prepare(&dir, false).unwrap_err().to_string();
        assert!(e.contains("other users") && e.contains("755"), "{e}");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        prepare(&dir, false).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
