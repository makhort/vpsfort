//! Passkeys (WebAuthn, FIDO2) as the second factor at the login, next to the one-time code:
//! a security key or the phone's passkey instead of typing a code. The password stays.
//!
//! What this does, and no more: registration with `attestation: "none"` (the authenticator's
//! make is not checked: it is the admin's own), credentials of the two kinds every current
//! authenticator offers (ECDSA P-256, `-7`; Ed25519, `-8`), and the assertion check at the
//! login: the client data's type, challenge and origin, the authenticator data's RP id hash,
//! user-presence flag and signature counter, and the signature over both (ring). The
//! credentials live in `<admin>.passkeys` next to the password file. The RP id is the host
//! name the console is reached by: passkeys need a name, not an address (`localhost` works
//! through an SSH tunnel).

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::time::Micros;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Credentials per admin at most.
pub const MAX_PER_ADMIN: usize = 10;
/// A challenge is good for this long.
const CHALLENGE_LIFE: Micros = 300 * crate::time::SEC;
/// Challenges used lately, remembered against replays until they expire; beyond this the
/// oldest go (each was spent on a login or a registration: the lockouts' business).
const MAX_USED: usize = 50_000;

/// One registered passkey.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// The credential id (base64url).
    pub id: String,
    /// COSE algorithm: -7 ECDSA P-256 with SHA-256, -8 Ed25519.
    pub alg: i64,
    /// The public key (base64url): the uncompressed P-256 point (65 bytes), or the Ed25519 key (32).
    pub key: String,
    /// The authenticator's own signature counter, for spotting a cloned key. Passkeys that
    /// sync between devices (a phone's, a browser's keychain) keep none: theirs stays 0.
    #[serde(default)]
    pub sign_count: u32,
    pub name: String,
    pub added: Micros,
    /// Logins with this passkey, as the console counted them.
    #[serde(default)]
    pub logins: u32,
    /// The latest of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<Micros>,
}

/// The admin's passkeys file, read whole and written whole.
pub fn load(path: &Path) -> Result<Vec<Credential>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("{} is not a passkeys file", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(anyhow!("reading {}: {e}", path.display())),
    }
}

/// The file's directory, made (0700) when missing.
fn make_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else { return Ok(()) };
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).with_context(|| format!("creating {}", dir.display()))
}

/// Writes the file whole. An empty list removes it, unless `keep_empty`: then it stays as an
/// empty list (so an older file elsewhere, read when this one is missing, doesn't come back).
pub fn save(path: &Path, creds: &[Credential], keep_empty: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if creds.is_empty() && !keep_empty {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow!("removing {}: {e}", path.display())),
        };
    }
    make_dir(path)?;
    let tmp = path.with_extension("passkeys.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(&serde_json::to_vec_pretty(creds)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

/// Whether the console can write the passkeys file at `path`: asked before a registration
/// begins, so the browser never saves a passkey the console then can't keep.
pub fn writable(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    make_dir(path)?;
    let probe = path.with_extension("passkeys.probe");
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&probe).with_context(|| {
        format!("the console can't write {} (passkeys are kept in STATE_DIR: set it to a directory of the console's own)", path.display())
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// The relying party id for a request's `Host` header: the host name without its port, in
/// lower case. None for an address: browsers refuse passkeys there (an SSH tunnel to
/// `localhost` works).
pub fn rp_id(host: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let name = if host.starts_with('[') {
        return None; // an IPv6 address
    } else {
        host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host.as_str(), |(h, _)| h).to_string()
    };
    let ok = !name.is_empty()
        && name.len() <= 253
        && name.parse::<std::net::Ipv4Addr>().is_err()
        && name.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    ok.then_some(name)
}

/// The origin the browser sends for that `Host` header.
pub fn origin(host: &str) -> String {
    format!("https://{}", host.trim().to_ascii_lowercase())
}

/// What a challenge was issued for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    Register,
    Login,
}

/// Challenges handed out, each good once for its admin and purpose within [`CHALLENGE_LIFE`].
/// Like the proof of work's, a challenge carries what it is for: 16 random bytes, when it
/// expires, and an HMAC under a key made at start over those and the admin and purpose it
/// was issued for. Nothing is kept for a challenge handed out and never used, so asking for
/// them (`GET /api/v1/session?user=…` needs no login) fills no table and keeps no admin from
/// logging in or adding a key; only the salts spent are remembered, until their expiry.
pub struct Challenges {
    key: [u8; 32],
    used: Mutex<Used>,
}

#[derive(Default)]
struct Used {
    order: VecDeque<(Micros, Vec<u8>)>,
    set: HashSet<Vec<u8>>,
}

impl Default for Challenges {
    fn default() -> Self {
        let mut key = [0u8; 32];
        // without randomness the console doesn't start anyway (sessions need it)
        let _ = crate::wire::getrandom(&mut key);
        Challenges { key, used: Mutex::default() }
    }
}

impl Challenges {
    fn mac(&self, salt: &[u8], expires: Micros, user: &str, purpose: Purpose) -> [u8; 16] {
        use hmac::Mac;
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.key).expect("any key length");
        m.update(b"webauthn-challenge\0");
        m.update(salt);
        m.update(&expires.to_be_bytes());
        m.update(&[if purpose == Purpose::Register { 1 } else { 2 }]);
        m.update(user.as_bytes());
        m.finalize().into_bytes()[..16].try_into().expect("16 bytes")
    }

    fn issue_at(&self, user: &str, purpose: Purpose, now: Micros) -> Result<String> {
        let mut salt = [0u8; 16];
        crate::wire::getrandom(&mut salt)?;
        let expires = now + CHALLENGE_LIFE;
        let mut raw = salt.to_vec();
        raw.extend_from_slice(&expires.to_be_bytes());
        raw.extend_from_slice(&self.mac(&salt, expires, user, purpose));
        Ok(B64.encode(raw))
    }

    pub fn issue(&self, user: &str, purpose: Purpose) -> Result<String> {
        self.issue_at(user, purpose, crate::time::now())
    }

    fn take_at(&self, challenge: &str, user: &str, purpose: Purpose, now: Micros) -> bool {
        let Ok(raw) = B64.decode(challenge.trim_end_matches('=')) else { return false };
        if raw.len() != 16 + 8 + 16 {
            return false;
        }
        let (salt, rest) = raw.split_at(16);
        let (expires, mac) = rest.split_at(8);
        let expires = Micros::from_be_bytes(expires.try_into().expect("8 bytes"));
        if !crate::auth::same(&self.mac(salt, expires, user, purpose), mac) || expires < now {
            return false;
        }
        // last: a challenge is spent only when it was good for this very login
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        while used.order.front().is_some_and(|(e, _)| *e < now || used.order.len() > MAX_USED) {
            let (_, old) = used.order.pop_front().expect("not empty");
            used.set.remove(&old);
        }
        if !used.set.insert(salt.to_vec()) {
            return false;
        }
        used.order.push_back((expires, salt.to_vec()));
        true
    }

    /// Takes a challenge back: true when it was issued to `user` for `purpose` lately and
    /// wasn't used before (it is used up by this).
    pub fn take(&self, challenge: &str, user: &str, purpose: Purpose) -> bool {
        self.take_at(challenge, user, purpose, crate::time::now())
    }
}

/// `PublicKeyCredentialCreationOptions`, with the binary fields base64url (the page decodes).
pub fn creation_options(challenge: &str, rp_id: &str, user: &str, existing: &[Credential]) -> Value {
    json!({
        "challenge": challenge,
        "rp": { "id": rp_id, "name": "vpsfort console" },
        "user": { "id": B64.encode(format!("vpsfort-web:{user}")), "name": user, "displayName": user },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -8 }],
        "excludeCredentials": existing.iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect::<Vec<_>>(),
        "authenticatorSelection": { "residentKey": "preferred", "userVerification": "preferred" },
        "attestation": "none",
        "timeout": 120_000,
    })
}

/// `PublicKeyCredentialRequestOptions`.
pub fn request_options(challenge: &str, rp_id: &str, creds: &[Credential]) -> Value {
    json!({
        "challenge": challenge,
        "rpId": rp_id,
        "allowCredentials": creds.iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect::<Vec<_>>(),
        "userVerification": "preferred",
        "timeout": 120_000,
    })
}

// ------------------------------------------------------------------ CBOR (what WebAuthn uses)

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Other,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    depth: u32,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8> {
        let v = *self.b.get(self.at).ok_or_else(|| anyhow!("CBOR: cut short"))?;
        self.at += 1;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| anyhow!("CBOR: cut short"))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    /// The argument of a head byte: the value, or the length.
    fn arg(&mut self, info: u8) -> Result<u64> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("2"))),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("4"))),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8")),
            _ => bail!("CBOR: indefinite lengths are not used here"),
        })
    }

    fn item(&mut self) -> Result<Cbor> {
        if self.depth > 16 {
            bail!("CBOR: too deep");
        }
        let head = self.byte()?;
        let (major, info) = (head >> 5, head & 0x1f);
        let n = self.arg(info)?;
        if n > 1 << 20 {
            bail!("CBOR: too large");
        }
        Ok(match major {
            0 => Cbor::Int(i128::from(n)),
            1 => Cbor::Int(-1 - i128::from(n)),
            2 => Cbor::Bytes(self.take(n as usize)?.to_vec()),
            3 => Cbor::Text(String::from_utf8(self.take(n as usize)?.to_vec()).context("CBOR: text")?),
            4 => {
                self.depth += 1;
                let v = (0..n).map(|_| self.item()).collect::<Result<Vec<_>>>()?;
                self.depth -= 1;
                Cbor::Array(v)
            }
            5 => {
                self.depth += 1;
                let v = (0..n).map(|_| Ok((self.item()?, self.item()?))).collect::<Result<Vec<_>>>()?;
                self.depth -= 1;
                Cbor::Map(v)
            }
            6 => {
                self.depth += 1;
                let v = self.item()?;
                self.depth -= 1;
                v
            }
            _ => Cbor::Other,
        })
    }
}

fn cbor(bytes: &[u8]) -> Result<(Cbor, usize)> {
    let mut r = Reader { b: bytes, at: 0, depth: 0 };
    let v = r.item()?;
    Ok((v, r.at))
}

fn map_get<'a>(m: &'a [(Cbor, Cbor)], key: &Cbor) -> Option<&'a Cbor> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// A COSE key (CBOR map) to (alg, public key bytes): P-256 as the uncompressed point,
/// Ed25519 as is.
fn cose_key(bytes: &[u8]) -> Result<(i64, Vec<u8>)> {
    let (v, _) = cbor(bytes).context("the credential's public key")?;
    let Cbor::Map(m) = v else { bail!("the credential's public key is not a COSE map") };
    let int = |k: i128| map_get(&m, &Cbor::Int(k)).and_then(|v| if let Cbor::Int(i) = v { Some(*i) } else { None });
    let bytes = |k: i128| map_get(&m, &Cbor::Int(k)).and_then(|v| if let Cbor::Bytes(b) = v { Some(b.clone()) } else { None });
    match (int(1), int(3), int(-1)) {
        (Some(2), Some(-7), Some(1)) => {
            let (x, y) = (bytes(-2).context("no x")?, bytes(-3).context("no y")?);
            if x.len() != 32 || y.len() != 32 {
                bail!("a P-256 coordinate is not 32 bytes");
            }
            let mut key = vec![0x04];
            key.extend_from_slice(&x);
            key.extend_from_slice(&y);
            Ok((-7, key))
        }
        (Some(1), Some(-8), Some(6)) => {
            let x = bytes(-2).context("no key")?;
            if x.len() != 32 {
                bail!("an Ed25519 key is not 32 bytes");
            }
            Ok((-8, x))
        }
        (kty, alg, crv) => bail!("unsupported credential key (kty {kty:?}, alg {alg:?}, crv {crv:?}): P-256 (-7) or Ed25519 (-8) only"),
    }
}

// ------------------------------------------------------------------ the checks

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// The client data checked: type, challenge, origin.
fn check_client_data(client_data: &[u8], want_type: &str, challenge: &str, origin: &str) -> Result<()> {
    let v: Value = serde_json::from_slice(client_data).context("clientDataJSON is not JSON")?;
    if v["type"].as_str() != Some(want_type) {
        bail!("clientDataJSON type is not {want_type}");
    }
    let got = v["challenge"].as_str().unwrap_or("");
    // base64url, with or without padding, is the same challenge
    if got.trim_end_matches('=') != challenge.trim_end_matches('=') {
        bail!("the challenge doesn't match");
    }
    if v["origin"].as_str() != Some(origin) {
        bail!("the origin {} is not this console's ({origin})", v["origin"].as_str().unwrap_or("?"));
    }
    Ok(())
}

/// Authenticator data checked against the RP id: (flags, signCount, the rest after the counter).
fn check_auth_data<'a>(auth_data: &'a [u8], rp_id: &str) -> Result<(u8, u32, &'a [u8])> {
    if auth_data.len() < 37 {
        bail!("authenticator data too short");
    }
    if auth_data[..32] != sha256(rp_id.as_bytes()) {
        bail!("the authenticator data is for another site than {rp_id}");
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        bail!("the authenticator didn't check the user's presence");
    }
    let count = u32::from_be_bytes(auth_data[33..37].try_into().expect("4"));
    Ok((flags, count, &auth_data[37..]))
}

/// A registration's answer, checked: the new credential.
pub fn finish_registration(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    client_data: &[u8],
    attestation: &[u8],
    name: &str,
    now: Micros,
) -> Result<Credential> {
    check_client_data(client_data, "webauthn.create", challenge, origin)?;
    let (att, _) = cbor(attestation).context("attestationObject")?;
    let Cbor::Map(m) = att else { bail!("attestationObject is not a map") };
    let Some(Cbor::Bytes(auth_data)) = map_get(&m, &Cbor::Text("authData".into())) else { bail!("no authData") };
    let (flags, count, rest) = check_auth_data(auth_data, rp_id)?;
    if flags & 0x40 == 0 {
        bail!("no credential in the authenticator data");
    }
    if rest.len() < 18 {
        bail!("attested credential data too short");
    }
    let id_len = usize::from(u16::from_be_bytes(rest[16..18].try_into().expect("2")));
    let id = rest.get(18..18 + id_len).context("credential id cut short")?;
    if id.is_empty() || id.len() > 1024 {
        bail!("credential id of {} bytes", id.len());
    }
    let (alg, key) = cose_key(&rest[18 + id_len..])?;
    let name: String = name.chars().filter(|c| !c.is_control()).take(60).collect();
    Ok(Credential {
        id: B64.encode(id),
        alg,
        key: B64.encode(key),
        sign_count: count,
        name: if name.trim().is_empty() { "passkey".into() } else { name },
        added: now,
        logins: 0,
        last_used: None,
    })
}

/// A login's assertion, checked against `cred`: the new signature counter to store.
pub fn verify_assertion(
    rp_id: &str,
    origin: &str,
    challenge: &str,
    cred: &Credential,
    client_data: &[u8],
    auth_data: &[u8],
    signature: &[u8],
) -> Result<u32> {
    check_client_data(client_data, "webauthn.get", challenge, origin)?;
    let (_, count, _) = check_auth_data(auth_data, rp_id)?;
    let key = B64.decode(&cred.key).context("the stored key")?;
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&sha256(client_data));
    let algorithm: &dyn ring::signature::VerificationAlgorithm = match cred.alg {
        -7 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        -8 => &ring::signature::ED25519,
        a => bail!("unsupported algorithm {a}"),
    };
    ring::signature::UnparsedPublicKey::new(algorithm, &key)
        .verify(&signed, signature)
        .map_err(|_| anyhow!("the signature doesn't verify"))?;
    // a counter that went backwards means a cloned authenticator (0 means "none kept")
    if (cred.sign_count > 0 || count > 0) && count <= cred.sign_count {
        bail!("the signature counter went backwards ({} after {}): a cloned authenticator?", count, cred.sign_count);
    }
    Ok(count)
}

/// Whether the authenticator checked who holds it for this answer (a fingerprint, a face, its
/// PIN): the UV flag. An answer with only the presence flag proves the key was touched.
pub fn user_verified(auth_data: &[u8]) -> bool {
    auth_data.get(32).is_some_and(|flags| flags & 0x04 != 0)
}

pub fn decode(b64url: &str) -> Result<Vec<u8>> {
    B64.decode(b64url.trim_end_matches('=')).map_err(|_| anyhow!("not base64url"))
}

/// What the page shows about a credential.
pub fn view(c: &Credential) -> Value {
    json!({
        "id": c.id, "name": c.name, "added": c.added, "alg": if c.alg == -7 { "P-256" } else { "Ed25519" },
        "logins": c.logins, "last_used": c.last_used, "sign_count": c.sign_count,
    })
}

/// A credentials file next to the password file: `admin.passkeys`, `<name>.passkeys`. Where
/// passkeys live without a `STATE_DIR`; with one, only read (an older setup's).
pub fn file_for(password_file: &Path) -> PathBuf {
    password_file.with_extension("passkeys")
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ring::signature::KeyPair;

    /// CBOR as an authenticator writes it (just enough for the tests).
    pub(crate) fn enc(v: &Cbor) -> Vec<u8> {
        fn head(major: u8, n: u64) -> Vec<u8> {
            match n {
                0..=23 => vec![major << 5 | n as u8],
                24..=255 => vec![major << 5 | 24, n as u8],
                256..=65535 => {
                    let mut v = vec![major << 5 | 25];
                    v.extend_from_slice(&(n as u16).to_be_bytes());
                    v
                }
                _ => {
                    let mut v = vec![major << 5 | 26];
                    v.extend_from_slice(&(n as u32).to_be_bytes());
                    v
                }
            }
        }
        match v {
            Cbor::Int(i) if *i >= 0 => head(0, *i as u64),
            Cbor::Int(i) => head(1, (-1 - *i) as u64),
            Cbor::Bytes(b) => {
                let mut o = head(2, b.len() as u64);
                o.extend_from_slice(b);
                o
            }
            Cbor::Text(t) => {
                let mut o = head(3, t.len() as u64);
                o.extend_from_slice(t.as_bytes());
                o
            }
            Cbor::Array(a) => {
                let mut o = head(4, a.len() as u64);
                for x in a {
                    o.extend(enc(x));
                }
                o
            }
            Cbor::Map(m) => {
                let mut o = head(5, m.len() as u64);
                for (k, x) in m {
                    o.extend(enc(k));
                    o.extend(enc(x));
                }
                o
            }
            Cbor::Other => vec![0xf6],
        }
    }

    /// A fake authenticator: a key pair of one of the two kinds, and what it would send.
    pub struct Authenticator {
        pub alg: i64,
        p256: Option<ring::signature::EcdsaKeyPair>,
        ed: Option<ring::signature::Ed25519KeyPair>,
        pub id: Vec<u8>,
        pub count: u32,
        /// Whether it checks its holder (a fingerprint, a PIN) or only that it was touched.
        pub verifies: bool,
    }

    impl Authenticator {
        pub fn new(alg: i64) -> Self {
            let rng = ring::rand::SystemRandom::new();
            let (p256, ed) = if alg == -7 {
                let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
                (
                    Some(
                        ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref(), &rng)
                            .unwrap(),
                    ),
                    None,
                )
            } else {
                let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
                (None, Some(ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()))
            };
            Authenticator { alg, p256, ed, id: b"credential-one".to_vec(), count: 0, verifies: true }
        }

        fn cose(&self) -> Vec<u8> {
            match (&self.p256, &self.ed) {
                (Some(k), _) => {
                    let pk = k.public_key().as_ref().to_vec(); // 0x04 || x || y
                    enc(&Cbor::Map(vec![
                        (Cbor::Int(1), Cbor::Int(2)),
                        (Cbor::Int(3), Cbor::Int(-7)),
                        (Cbor::Int(-1), Cbor::Int(1)),
                        (Cbor::Int(-2), Cbor::Bytes(pk[1..33].to_vec())),
                        (Cbor::Int(-3), Cbor::Bytes(pk[33..65].to_vec())),
                    ]))
                }
                (_, Some(k)) => enc(&Cbor::Map(vec![
                    (Cbor::Int(1), Cbor::Int(1)),
                    (Cbor::Int(3), Cbor::Int(-8)),
                    (Cbor::Int(-1), Cbor::Int(6)),
                    (Cbor::Int(-2), Cbor::Bytes(k.public_key().as_ref().to_vec())),
                ])),
                _ => unreachable!(),
            }
        }

        fn auth_data(&self, rp_id: &str, flags: u8, attested: bool) -> Vec<u8> {
            let mut d = sha256(rp_id.as_bytes()).to_vec();
            d.push(flags);
            d.extend_from_slice(&self.count.to_be_bytes());
            if attested {
                d.extend_from_slice(&[0u8; 16]);
                d.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
                d.extend_from_slice(&self.id);
                d.extend(self.cose());
            }
            d
        }

        pub fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
            serde_json::to_vec(&json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })).unwrap()
        }

        /// (clientDataJSON, attestationObject) for a registration.
        pub fn register(&self, rp_id: &str, origin: &str, challenge: &str) -> (Vec<u8>, Vec<u8>) {
            let att = enc(&Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(self.auth_data(rp_id, 0x45, true))),
            ]));
            (Self::client_data("webauthn.create", challenge, origin), att)
        }

        /// (clientDataJSON, authenticatorData, signature) for a login.
        pub fn assert(&mut self, rp_id: &str, origin: &str, challenge: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.count += 1;
            let cd = Self::client_data("webauthn.get", challenge, origin);
            let ad = self.auth_data(rp_id, if self.verifies { 0x05 } else { 0x01 }, false);
            let mut signed = ad.clone();
            signed.extend_from_slice(&sha256(&cd));
            let sig = match (&self.p256, &self.ed) {
                (Some(k), _) => k.sign(&ring::rand::SystemRandom::new(), &signed).unwrap().as_ref().to_vec(),
                (_, Some(k)) => k.sign(&signed).as_ref().to_vec(),
                _ => unreachable!(),
            };
            (cd, ad, sig)
        }
    }

    #[test]
    fn registers_and_verifies_both_key_kinds() {
        for alg in [-7, -8] {
            let mut a = Authenticator::new(alg);
            let (rp, origin) = ("console.example.org", "https://console.example.org:7948");
            let (cd, att) = a.register(rp, origin, "chal-1");
            let cred = finish_registration(rp, origin, "chal-1", &cd, &att, " Yubi\u{7}Key ", 5).unwrap();
            assert_eq!((cred.alg, cred.name.as_str(), cred.added, cred.id.as_str()), (alg, " YubiKey ", 5, B64.encode(&a.id).as_str()));
            // another challenge, origin or site is refused
            assert!(finish_registration(rp, origin, "chal-2", &cd, &att, "k", 5).unwrap_err().to_string().contains("challenge"));
            assert!(finish_registration(rp, "https://evil.example", "chal-1", &cd, &att, "k", 5)
                .unwrap_err()
                .to_string()
                .contains("origin"));
            assert!(finish_registration("other.example.org", origin, "chal-1", &cd, &att, "k", 5)
                .unwrap_err()
                .to_string()
                .contains("another site"));
            // a login
            let (cd, ad, sig) = a.assert(rp, origin, "chal-3");
            let count = verify_assertion(rp, origin, "chal-3", &cred, &cd, &ad, &sig).unwrap();
            assert_eq!(count, 1);
            let mut bad = sig.clone();
            bad[10] ^= 1;
            assert!(verify_assertion(rp, origin, "chal-3", &cred, &cd, &ad, &bad).unwrap_err().to_string().contains("doesn't verify"));
            let other = Authenticator::new(alg);
            let (cd2, ad2, sig2) = Authenticator { count: 1, ..other }.assert(rp, origin, "chal-4");
            assert!(verify_assertion(rp, origin, "chal-4", &cred, &cd2, &ad2, &sig2).is_err(), "another key");
            // a counter that doesn't advance: a clone
            let stale = Credential { sign_count: 1, ..cred.clone() };
            let (cd, ad, sig) = Authenticator { count: 0, ..a }.assert(rp, origin, "chal-5");
            assert!(verify_assertion(rp, origin, "chal-5", &stale, &cd, &ad, &sig).unwrap_err().to_string().contains("counter"));
        }
    }

    #[test]
    fn rp_ids_challenges_and_files() {
        assert_eq!(rp_id("Console.Example.org:7948").as_deref(), Some("console.example.org"));
        assert_eq!(rp_id("localhost:7948").as_deref(), Some("localhost"));
        assert_eq!(rp_id("203.0.113.5:7948"), None, "an address is no relying party");
        assert_eq!(rp_id("[2001:db8::1]:7948"), None);
        assert_eq!(rp_id("bad host"), None);
        assert_eq!(origin("Console.example.org:7948"), "https://console.example.org:7948");
        let ch = Challenges::default();
        let c = ch.issue("admin", Purpose::Login).unwrap();
        assert!(!ch.take(&c, "admin", Purpose::Register), "another purpose");
        assert!(!ch.take(&c, "alice", Purpose::Login), "another admin");
        assert!(ch.take(&c, "admin", Purpose::Login), "neither spent it");
        assert!(!ch.take(&c, "admin", Purpose::Login), "used once");
        let c = ch.issue("admin", Purpose::Register).unwrap();
        assert!(ch.take(&c, "admin", Purpose::Register));
        // forged, from another console, expired: refused; a flood of unused ones costs nothing
        let mut forged = ch.issue("admin", Purpose::Login).unwrap();
        forged.replace_range(..1, if forged.starts_with('A') { "B" } else { "A" });
        assert!(!ch.take(&forged, "admin", Purpose::Login));
        assert!(!Challenges::default().take(&ch.issue("admin", Purpose::Login).unwrap(), "admin", Purpose::Login));
        let old = ch.issue_at("admin", Purpose::Login, crate::time::now() - CHALLENGE_LIFE - crate::time::SEC).unwrap();
        assert!(!ch.take(&old, "admin", Purpose::Login), "expired");
        for _ in 0..10_000 {
            ch.issue("x", Purpose::Login).unwrap();
        }
        assert_eq!(ch.used.lock().unwrap().order.len(), 2, "only the two spent are remembered");
        assert!(ch.take(&ch.issue("admin", Purpose::Login).unwrap(), "admin", Purpose::Login), "still good after the flood");
        let d = std::env::temp_dir().join(format!("lgw-passkeys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = file_for(&d.join("admin.password"));
        assert_eq!(f, d.join("admin.passkeys"));
        assert!(load(&f).unwrap().is_empty());
        let cred = Credential {
            id: "aWQ".into(),
            alg: -7,
            key: "a2V5".into(),
            sign_count: 3,
            name: "key".into(),
            added: 1,
            logins: 0,
            last_used: None,
        };
        save(&f, std::slice::from_ref(&cred), false).unwrap();
        assert_eq!(load(&f).unwrap(), vec![cred]);
        save(&f, &[], false).unwrap();
        assert!(!f.exists(), "no keys: no file");
        let opts = creation_options("c", "console.example.org", "alice", &[]);
        assert_eq!(opts["rp"]["id"], "console.example.org");
        assert_eq!(request_options("c", "x", &[]).as_object().unwrap()["allowCredentials"].as_array().unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
