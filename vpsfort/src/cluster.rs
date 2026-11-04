//! Cluster mode: vpsfort nodes share attack information directly over TCP,
//! with no VPN or other infrastructure required.
//!
//! **What is shared** ("facts"): bans and unbans, per-address suspicion reports
//! (points this node scored for an address since the last sync), and addresses
//! that authenticated successfully (trust). Each fact has a globally unique id
//! `(origin node, sequence)`; nodes apply each fact once and forward it to their own
//! peers up to `max_hops`, so full meshes, chains and stars all work without loops.
//!
//! **Security**: every message is encrypted and authenticated with
//! XChaCha20-Poly1305 under a pre-shared 256-bit cluster key (random 192-bit nonce per
//! message). Anyone without the key can neither read nor inject facts. Messages older
//! than `max_clock_skew` are rejected (replays are idempotent anyway, as facts are
//! de-duplicated). Without node identities, all members are equally trusted: protect the
//! key like a root password, except peers named in `peer_accept`: what arrives over a
//! connection from such a peer's address (its own facts and those it forwards) is limited to
//! the kinds listed there. The limit goes by the connection's source address, not the node
//! name in the message, which any key holder can write; so it needs `allow_only_peers`.
//!
//! **Node identities** (`identity_file`, `nodes`, `require_signatures`): each node signs the
//! facts it originates and the files it sends with an Ed25519 key of its own; the signature
//! covers `(origin, seq, created, body)` and travels with the fact through forwarding (`hops`
//! stays outside it). A fact or file whose origin has a key pinned in `nodes` is taken only
//! with a valid signature from that key, so a broken-into node, or anyone with a stolen
//! cluster key, can speak only for itself; with `require_signatures`, origins without a
//! pinned key are refused, and removing a node's key drops it without a new cluster key.
//! The shared key still encrypts every message.
//!
//! **Wire format, with forward secrecy** (`"LGC2"`, the default): the sender opens a
//! connection and sends a *hello*, `"LGC2"` | u32 big-endian length | 24-byte nonce |
//! XChaCha20-Poly1305 under the cluster key (associated data [`HELLO_AAD`]) of a JSON
//! [`Hello`]: when, a random id and a fresh X25519 public key. The receiver answers with the
//! same frame shape holding a [`HelloReply`] (the id, its own fresh key), sealed under the
//! key the hello was sealed with. Both derive the *message key*, HKDF-SHA-256(salt = the
//! cluster key, ikm = X25519 of the two fresh keys, info = [`MESSAGE_INFO`] | id | both
//! public keys), and the sender then sends `"LGC2"` | length | nonce | ciphertext of the JSON
//! `Envelope` under it (associated data [`MESSAGE_INFO`]). Only a holder of the cluster key
//! can take part, and once both sides dropped their fresh secrets nobody can read a
//! recording of the message, not even with the cluster key: a key that leaks later gives
//! away nothing that was said before (forward secrecy).
//!
//! **Without it** (`"LGC1"`, what versions before this spoke): `"LGC1"` | length | nonce |
//! ciphertext of the envelope under the cluster key itself, no reply. A sender tries LGC2
//! first and falls back to LGC1 for a peer that closes the connection without a reply (an
//! older version), remembering that for 10 minutes; `forward_secrecy = "require"` refuses
//! LGC1 both ways once every node is current. One envelope per TCP connection either way.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::net::Net;
use crate::time::{self, Dur, Micros, SEC};

const MAGIC: &[u8; 4] = b"LGC1";
const AAD: &[u8] = b"vpsfort-cluster-v1";
const MAGIC2: &[u8; 4] = b"LGC2";
pub const HELLO_AAD: &[u8] = b"vpsfort-cluster-hello-v2";
pub const MESSAGE_INFO: &[u8] = b"vpsfort-cluster-message-v2";
/// A hello (a few hundred bytes) claiming more than this is not one.
const MAX_HELLO: usize = 4096;
/// How long a peer that didn't answer a hello is sent LGC1 frames before LGC2 is tried again.
pub const LGC1_FALLBACK_FOR: Micros = 10 * time::MIN;
/// Largest accepted frame. Senders split their facts into chunks of `CHUNK` bytes, so even
/// a full sync of `MAX_KNOWN` facts never needs more; and at most `MAX_CONNECTIONS` frames
/// (each also decrypted into a copy) fit easily in the service's memory limit.
const MAX_FRAME: usize = 1 << 20;
const CHUNK: usize = 512 * 1024;
const MAX_CONNECTIONS: usize = 8;
/// Connections one address may have open at once: a peer sends one frame at a time, and with
/// `allow_only_peers = false` a stranger holding every slot (30 s each) would cut the cluster off.
const MAX_PER_SOURCE: usize = 2;
/// Whole-frame deadline per connection: a slow sender can't hold a connection slot open.
const READ_DEADLINE: Duration = Duration::from_secs(30);
/// Facts remembered at once (bans with long timeouts accumulate).
const MAX_KNOWN: usize = 200_000;
/// Text of the relayed notices remembered at once (each for an hour): a peer that may send
/// nothing else (a Telegram relay node, even broken into) can't exhaust the memory with them.
const MAX_NOTICE_BYTES: usize = 2 << 20;
/// Longest notice body kept from a peer: a digest is a few KB.
const MAX_NOTICE_BODY: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    Bans,
    Unbans,
    Reports,
    /// Trusted addresses and operator allowlist entries.
    Trust,
    /// Admin notifications relayed to a node that delivers them (XMPP, or Telegram).
    Notices,
    /// Each day's hash of a node's actions log, kept by the peers as tamper evidence.
    LogDigests,
    /// A node's request to its direct peers to try its public ports from outside, and
    /// their answers (`[exposure] peer_probe`).
    Probes,
    /// The lines of a node's actions log, for the one peer that keeps a copy of it
    /// (`[cluster] mirror_to`).
    Mirror,
    /// Files sent with `vpsfort cluster-send-report` (abuse reports). Not a fact: only
    /// `peer_accept` lists it; other peers' files are taken whenever `inbox` is set.
    Files,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterCfg {
    pub enabled: bool,
    /// Unique name of this node; defaults to the host name.
    pub node_id: String,
    /// Address to accept peers on; empty = send-only node.
    pub listen: String,
    /// Other nodes, `host:port`. Partial lists work: facts are forwarded.
    pub peers: Vec<String>,
    /// Base64 cluster key (`vpsfort cluster-keygen`). Prefer `key_file`.
    pub key: String,
    /// File containing the base64 key (mode 0600). During a key rotation, keys in
    /// `<key_file>.next` and `<key_file>.prev` are accepted from peers too (messages are always
    /// sent with this one), so nodes can switch one at a time (README, "Rotating the key").
    pub key_file: PathBuf,
    /// Remind the admins, once a week, to rotate a key file older than this (0 = never).
    /// Its age is the file's modification time: when it was installed or last rotated.
    pub rotate_after: Dur,
    pub sync_interval: Dur,
    /// Resend everything this often, so restarted peers catch up.
    pub full_sync_every: Dur,
    /// What this node sends its peers: its own facts and the ones it forwards.
    pub share: Vec<FactKind>,
    pub accept: Vec<FactKind>,
    /// Bans learned from peers last at most this long here.
    pub max_remote_ban: Dur,
    /// Peer-reported points count this much here (0 disables, 1 = like local evidence).
    pub report_factor: f64,
    /// Report an address once this node scored at least this many points for it.
    pub min_report_points: f64,
    pub max_hops: u8,
    pub max_clock_skew: Dur,
    /// Accept connections only from the addresses `peers` resolve to.
    pub allow_only_peers: bool,
    /// Where files from peers (`vpsfort cluster-send-report`, e.g. a weekly abuse
    /// report) are written; empty = refuse them.
    pub inbox: PathBuf,
    /// What some peers may hand this node, by the peer as written in `peers`, e.g.
    /// `{ "203.0.113.9:7946" = ["notices", "files"] }` for a node that only relays to
    /// Telegram: it can't ban, unban, report or trust anything here, even if it is broken
    /// into. Peers not listed: `accept`. Needs `allow_only_peers`.
    pub peer_accept: BTreeMap<String, Vec<FactKind>>,
    /// Relay this node's admin notifications to the peers even though it delivers them
    /// itself ([notify] enabled), e.g. to a node that forwards them to Telegram. Without
    /// it, only nodes with [notify] off relay theirs.
    pub relay_notices: bool,
    /// This node's own signing key (`vpsfort cluster-identity --out <file>`, mode 0600):
    /// the facts it originates and the files it sends are signed with it. Empty = unsigned.
    pub identity_file: PathBuf,
    /// Public keys pinned by node name (what `cluster-identity` prints), e.g.
    /// `{ xmpp = "...", vpn = "..." }`: a fact or file from a node listed here is taken only
    /// with a valid signature by its key. Its own entry, if any, must match `identity_file`
    /// (so one list can be copied to every node).
    pub nodes: BTreeMap<String, String>,
    /// Refuse facts and files from nodes not in `nodes` (and unsigned ones): then removing a
    /// node's key drops it from the cluster without rotating the cluster key.
    pub require_signatures: bool,
    /// `prefer` (the default): a fresh key exchange per connection, falling back to the plain
    /// cluster-key frame for peers that don't answer one (older versions); `require`: refuse
    /// the plain frame both ways, once every node is current; `off`: the plain frame only.
    pub forward_secrecy: ForwardSecrecy,
    /// How long a relayed notice (an alert or digest a peer delivers for this node) is kept
    /// for peers that can't be reached: a relay node down for the night still gets what was
    /// relayed meanwhile when it is back (within [`MAX_NOTICE_BYTES`] in all). Delivered late,
    /// a notice says so.
    pub notice_ttl: Dur,
    /// The node (by name, a direct peer) that keeps a copy of this node's actions log: every
    /// line goes there at the next sync, so what a wiped node decided is still somewhere.
    /// Empty: no copy.
    pub mirror_to: String,
    /// Where the copies of the peers' logs that name this node in `mirror_to` are written
    /// (`<node>.jsonl`, rotated once at `mirror_max_mb`). Empty: refuse them.
    pub mirror_dir: PathBuf,
    pub mirror_max_mb: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardSecrecy {
    #[default]
    Prefer,
    Require,
    Off,
}

impl Default for ClusterCfg {
    fn default() -> Self {
        let all = vec![
            FactKind::Bans,
            FactKind::Unbans,
            FactKind::Reports,
            FactKind::Trust,
            FactKind::Notices,
            FactKind::LogDigests,
            FactKind::Probes,
            FactKind::Mirror,
        ];
        ClusterCfg {
            enabled: false,
            node_id: String::new(),
            listen: "0.0.0.0:7946".into(),
            peers: vec![],
            key: String::new(),
            key_file: PathBuf::new(),
            rotate_after: Dur(180 * 86_400),
            sync_interval: Dur(10),
            full_sync_every: Dur(600),
            share: all.clone(),
            accept: all,
            max_remote_ban: Dur(86_400),
            report_factor: 0.5,
            min_report_points: 10.0,
            max_hops: 3,
            max_clock_skew: Dur(300),
            allow_only_peers: true,
            inbox: PathBuf::from("/var/lib/vpsfort/inbox"),
            peer_accept: BTreeMap::new(),
            relay_notices: false,
            identity_file: PathBuf::new(),
            nodes: BTreeMap::new(),
            require_signatures: false,
            forward_secrecy: ForwardSecrecy::Prefer,
            notice_ttl: Dur(86_400),
            mirror_to: String::new(),
            mirror_dir: PathBuf::from("/var/lib/vpsfort/mirror"),
            mirror_max_mb: 64,
        }
    }
}

pub fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "vpsfort".into())
}

impl ClusterCfg {
    pub fn node_name(&self) -> String {
        if self.node_id.is_empty() {
            hostname()
        } else {
            self.node_id.clone()
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.key.is_empty() && self.key_file.as_os_str().is_empty() {
            bail!("[cluster] needs `key` or `key_file` (generate one with `vpsfort cluster-keygen`)");
        }
        if !self.key.is_empty() {
            decode_key(&self.key)?;
        }
        if !self.listen.is_empty() {
            self.listen.parse::<SocketAddr>().map_err(|_| anyhow!("[cluster] listen must be ip:port, got '{}'", self.listen))?;
        }
        if let Some(p) = self.peers.iter().find(|p| p.rsplit_once(':').is_none_or(|(_, port)| port.parse::<u16>().is_err())) {
            bail!("[cluster] peer '{p}' must be host:port");
        }
        if !(0.0..=1.0).contains(&self.report_factor) {
            bail!("[cluster] report_factor must be within 0..=1");
        }
        if !node_name_ok(&self.node_name()) {
            bail!("[cluster] node_id must be 1-253 characters without whitespace");
        }
        if let Some(p) = self.peer_accept.keys().find(|p| !self.peers.contains(p)) {
            bail!("[cluster] peer_accept: '{p}' is not one of the peers (write it as in `peers`)");
        }
        if !self.peer_accept.is_empty() && !self.allow_only_peers {
            bail!("[cluster] peer_accept needs allow_only_peers = true: the limit goes by the connection's address");
        }
        NodeKeys::new(self)?;
        if self.require_signatures && self.nodes.is_empty() {
            bail!("[cluster] require_signatures needs the nodes' public keys in `nodes` (`vpsfort cluster-identity` prints them)");
        }
        if !self.mirror_to.is_empty() && (self.mirror_to == self.node_name() || !node_name_ok(&self.mirror_to)) {
            bail!("[cluster] mirror_to must name another node (its node_id)");
        }
        if !self.mirror_to.is_empty() && !self.share.contains(&FactKind::Mirror) {
            bail!("[cluster] mirror_to needs \"mirror\" in `share`");
        }
        Ok(())
    }

    pub fn load_key(&self) -> Result<[u8; 32]> {
        if !self.key.is_empty() {
            return decode_key(&self.key);
        }
        let text = std::fs::read_to_string(&self.key_file).with_context(|| format!("reading {}", self.key_file.display()))?;
        decode_key(text.trim())
    }

    /// When the key file was installed or last rotated (its modification time); None for a
    /// key written inline in the config.
    pub fn key_since(&self) -> Option<Micros> {
        if !self.key.is_empty() {
            return None;
        }
        let modified = std::fs::metadata(&self.key_file).and_then(|m| m.modified()).ok()?;
        modified.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_micros() as Micros)
    }

    /// The weekly reminder to rotate the key, once it is older than `rotate_after`.
    pub fn rotation_reminder(&self, since: Option<Micros>, now: Micros) -> Option<String> {
        let since = since?;
        let age = now - since;
        (self.rotate_after.0 > 0 && age >= self.rotate_after.micros()).then(|| {
            format!(
                "the cluster key {} is {} days old (rotate after {}): rotate it with deploy/rotate-cluster-key.sh start|switch|finish",
                self.key_file.display(),
                age / (86_400 * SEC),
                self.rotate_after
            )
        })
    }

    /// Keys accepted from peers besides the main one, during a rotation: `<key_file>.next`
    /// and `<key_file>.prev` when present, with their file names. A file that exists but
    /// holds no valid key is an error, so a botched rotation step stops the daemon loudly.
    pub fn load_extra_keys(&self) -> Result<Vec<(PathBuf, [u8; 32])>> {
        if !self.key.is_empty() || self.key_file.as_os_str().is_empty() {
            return Ok(vec![]);
        }
        let mut out = vec![];
        for ext in ["next", "prev"] {
            let mut name = self.key_file.clone().into_os_string();
            name.push(format!(".{ext}"));
            let path = PathBuf::from(name);
            match std::fs::read_to_string(&path) {
                Ok(text) => out.push((path.clone(), decode_key(text.trim()).with_context(|| format!("in {}", path.display()))?)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            }
        }
        Ok(out)
    }
}

/// A key's public fingerprint (SHA-256, first 6 bytes in hex): equal on every node that
/// has the same key, and revealing nothing about it.
pub fn key_id(key: &[u8; 32]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(key)[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// A key as `cluster-keygen` writes it (base64 of 32 bytes).
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).context("cluster key is not valid base64")?;
    raw.try_into().map_err(|_| anyhow!("cluster key must be exactly 32 bytes (use `vpsfort cluster-keygen`)"))
}

pub fn generate_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(XChaCha20Poly1305::generate_key(&mut OsRng))
}

// ------------------------------------------------------------------ node identities

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A node's own signing key (`[cluster] identity_file`): base64 of the 32-byte Ed25519 seed.
pub struct Identity(ed25519_dalek::SigningKey);

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&XChaCha20Poly1305::generate_key(&mut OsRng));
        Identity(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let raw = B64.decode(text.trim()).with_context(|| format!("{} is not base64", path.display()))?;
        let seed: [u8; 32] =
            raw.try_into().map_err(|_| anyhow!("{} must hold 32 bytes (use `vpsfort cluster-identity --out`)", path.display()))?;
        Ok(Identity(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// Writes a new key to `path` (mode 0600) unless one is there already; returns the key in
    /// the file and whether it is new.
    pub fn create(path: &Path) -> Result<(Self, bool)> {
        use std::os::unix::fs::OpenOptionsExt;
        if path.exists() {
            return Ok((Identity::load(path)?, false));
        }
        let id = Identity::generate();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(format!("{}\n", B64.encode(id.0.to_bytes())).as_bytes())?;
        f.sync_all()?;
        Ok((id, true))
    }

    /// The public key, as `[cluster] nodes` takes it.
    pub fn public(&self) -> String {
        B64.encode(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        use ed25519_dalek::Signer;
        B64.encode(self.0.sign(msg).to_bytes())
    }
}

/// A public key as `cluster-identity` prints it.
pub fn decode_public(b64: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let raw = B64.decode(b64.trim()).context("node key is not valid base64")?;
    let raw: [u8; 32] =
        raw.try_into().map_err(|_| anyhow!("node key must be exactly 32 bytes (what `vpsfort cluster-identity` prints)"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| anyhow!("not an Ed25519 public key"))
}

/// The pinned node keys (`[cluster] nodes`) and `require_signatures`.
#[derive(Clone, Debug, Default)]
pub struct NodeKeys {
    keys: BTreeMap<String, ed25519_dalek::VerifyingKey>,
    require: bool,
}

impl NodeKeys {
    pub fn new(cfg: &ClusterCfg) -> Result<Self> {
        let mut keys = BTreeMap::new();
        for (node, k) in &cfg.nodes {
            if !node_name_ok(node) {
                bail!("[cluster] nodes: '{node}' is not a node name");
            }
            keys.insert(node.clone(), decode_public(k).with_context(|| format!("[cluster] nodes.{node}"))?);
        }
        Ok(NodeKeys { keys, require: cfg.require_signatures })
    }

    /// Whether `node` may say what it signed with `sig` (base64) over `msg`: `Ok(true)` when
    /// the signature is valid for its pinned key, `Ok(false)` for a node without one (taken
    /// unchecked unless `require_signatures`), else why not. `msg` is built only when needed.
    pub fn check(&self, node: &str, sig: &str, msg: impl FnOnce() -> Vec<u8>) -> Result<bool, &'static str> {
        let Some(key) = self.keys.get(node) else {
            return if self.require { Err("not in [cluster] nodes (require_signatures)") } else { Ok(false) };
        };
        if sig.is_empty() {
            return Err("unsigned, but its key is pinned in [cluster] nodes");
        }
        let sig = B64.decode(sig).ok().and_then(|s| ed25519_dalek::Signature::from_slice(&s).ok()).ok_or("signature malformed")?;
        key.verify_strict(&msg(), &sig).map(|_| true).map_err(|_| "signature does not match its pinned key")
    }
}

/// What a fact's signature covers: everything but `hops` (forwarders change it).
fn fact_message(origin: &str, seq: u64, created: Micros, body: &FactBody) -> Vec<u8> {
    let mut m = b"vpsfort-fact-v1\0".to_vec();
    m.extend_from_slice(&(origin.len() as u32).to_be_bytes());
    m.extend_from_slice(origin.as_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&created.to_be_bytes());
    // serde_json writes the fields in their declared order: the same bytes on every node
    m.extend_from_slice(&serde_json::to_vec(body).unwrap_or_default());
    m
}

/// What a peer file's signature covers: its sender, when it was sent, its name and content.
fn file_message(from: &str, sent: Micros, name: &str, gz: &str) -> Vec<u8> {
    let mut m = b"vpsfort-file-v1\0".to_vec();
    for s in [from, name] {
        m.extend_from_slice(&(s.len() as u32).to_be_bytes());
        m.extend_from_slice(s.as_bytes());
    }
    m.extend_from_slice(&sent.to_be_bytes());
    m.extend_from_slice(gz.as_bytes());
    m
}

// ------------------------------------------------------------------ facts

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactBody {
    Ban {
        net: Net,
        until: Micros,
        reason: String,
        /// The evidence is firewall logs only (blocked packets), whose source address is
        /// easily forged: not applied to an address that logged in at the receiving node
        /// lately. Older nodes leave it out, and ignore it.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        forgeable: bool,
        /// A few lines of what the source did, private details withheld (`abuse::shareable`),
        /// so a peer's log and reports say more than the score. Older nodes send none.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        evidence: Vec<String>,
    },
    Unban {
        net: Net,
        reason: String,
    },
    Report {
        ip: IpAddr,
        points: f64,
        signals: String,
        /// As for `Ban`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        forgeable: bool,
    },
    Trust {
        ip: IpAddr,
    },
    /// Operator allowlist entry; `until` in the past revokes it.
    Allow {
        net: Net,
        until: Micros,
        note: String,
    },
    Notice {
        subject: String,
        body: String,
    },
    /// SHA-256 of the origin's actions log lines of one UTC day (`logdigest`): a peer keeps
    /// it, so an edit of the log on the origin later shows.
    LogDigest {
        day: String,
        sha256: String,
        lines: u64,
    },
    /// The origin asks the peers it is directly connected to to try these ports of its
    /// ("22/tcp"), as the internet would: a firewall in front of the host, or a hole in
    /// it, shows. Not forwarded.
    Probe {
        ports: Vec<String>,
    },
    /// A peer's answer: which of `target`'s ports it could connect to, and which not.
    ProbeResult {
        target: String,
        reachable: Vec<String>,
        unreachable: Vec<String>,
    },
    /// The origin's actions log lines since its last batch, for the direct peer `to` that
    /// keeps a copy (`mirror`). Numbered, so a missing batch shows; not forwarded.
    LogLines {
        to: String,
        batch: u64,
        /// Lines the origin had to drop (more than a batch holds).
        #[serde(default, skip_serializing_if = "u64_is_zero")]
        dropped: u64,
        lines: Vec<String>,
    },
}

fn u64_is_zero(n: &u64) -> bool {
    *n == 0
}

impl FactBody {
    pub fn kind(&self) -> FactKind {
        match self {
            FactBody::Ban { .. } => FactKind::Bans,
            FactBody::Unban { .. } => FactKind::Unbans,
            FactBody::Report { .. } => FactKind::Reports,
            FactBody::Trust { .. } | FactBody::Allow { .. } => FactKind::Trust,
            FactBody::Notice { .. } => FactKind::Notices,
            FactBody::LogDigest { .. } => FactKind::LogDigests,
            FactBody::Probe { .. } | FactBody::ProbeResult { .. } => FactKind::Probes,
            FactBody::LogLines { .. } => FactKind::Mirror,
        }
    }

    fn expires(&self, created: Micros, notice_ttl: i64) -> Micros {
        let after = |secs: i64| created.saturating_add(secs * SEC);
        match self {
            FactBody::Ban { until, .. } => *until,
            FactBody::Unban { .. } => after(86_400),
            FactBody::Report { .. } => after(3600),
            FactBody::Trust { .. } => after(14 * 86_400),
            FactBody::Allow { until, .. } => (*until).max(after(3600)),
            FactBody::Notice { .. } => after(notice_ttl.clamp(60, 7 * 86_400)),
            // long enough for a peer that is down over the night; the receiver keeps it
            FactBody::LogDigest { .. } => after(3 * 86_400),
            FactBody::Probe { .. } => after(600),
            FactBody::ProbeResult { .. } => after(3600),
            FactBody::LogLines { .. } => after(3600),
        }
    }

    /// A peer's text, made fit to show: it reaches alerts, the actions log and `vpsfort
    /// status` on a terminal, so no control or hidden characters, and a bounded length.
    fn tidy(&mut self) {
        use crate::event::{clean, plain_text};
        match self {
            FactBody::Ban { reason, evidence, .. } => {
                *reason = clean(reason, 500);
                evidence.truncate(crate::engine::SHARED_EVIDENCE);
                for e in evidence.iter_mut() {
                    *e = clean(e, 300);
                }
            }
            FactBody::Unban { reason, .. } => *reason = clean(reason, 500),
            FactBody::Report { signals, .. } => *signals = clean(signals, 200),
            FactBody::Allow { note, .. } => *note = clean(note, 200),
            FactBody::Notice { subject, body } => {
                *subject = clean(subject, 300);
                *body = plain_text(body).chars().take(MAX_NOTICE_BODY).collect();
            }
            FactBody::Trust { .. } => {}
            FactBody::LogDigest { day, sha256, .. } => {
                *day = clean(day, 10);
                *sha256 = clean(sha256, 64).to_ascii_lowercase();
            }
            FactBody::Probe { ports } => tidy_ports(ports),
            FactBody::ProbeResult { target, reachable, unreachable } => {
                *target = clean(target, 253);
                tidy_ports(reachable);
                tidy_ports(unreachable);
            }
            FactBody::LogLines { to, lines, .. } => {
                *to = clean(to, 253);
                lines.truncate(crate::mirror::MAX_BATCH_LINES);
                let mut total = 0;
                lines.retain_mut(|l| {
                    if l.len() > crate::mirror::MAX_LINE {
                        *l = l.chars().take(crate::mirror::MAX_LINE).collect();
                    }
                    total += l.len();
                    total <= crate::mirror::MAX_BATCH_BYTES
                });
            }
        }
    }

    /// Most ports in one probe request or answer.
    pub const MAX_PROBE_PORTS: usize = 32;
}

/// Port specs as a peer may send them: "22/tcp", at most [`FactBody::MAX_PROBE_PORTS`].
fn tidy_ports(ports: &mut Vec<String>) {
    ports.retain(|p| p.strip_suffix("/tcp").is_some_and(|n| n.parse::<u16>().is_ok_and(|n| n > 0)));
    ports.sort();
    ports.dedup();
    ports.truncate(FactBody::MAX_PROBE_PORTS);
}

impl FactBody {
    /// The text a notice holds (0 for other facts).
    fn notice_len(&self) -> usize {
        match self {
            FactBody::Notice { subject, body } => subject.len() + body.len(),
            _ => 0,
        }
    }
}

/// A node name as peers may send it: what `node_id` may be (a host name by default).
fn node_name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 253 && !n.chars().any(|c| c.is_whitespace() || c.is_control() || crate::event::is_hidden(c))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub origin: String,
    pub seq: u64,
    pub created: Micros,
    pub hops: u8,
    #[serde(flatten)]
    pub body: FactBody,
    /// The origin's signature over [`fact_message`] (base64), when it has `identity_file`.
    /// Older nodes ignore it, and leave it out when they forward the fact.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    pub from: String,
    pub sent: Micros,
    pub facts: Vec<Fact>,
    /// A file sent once to the direct peers (`vpsfort cluster-send-report`). Not a fact:
    /// it is neither kept, forwarded nor resent. Older nodes ignore the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<PeerFile>,
}

/// Names of the files peers may send, and so of the files written to `[cluster] inbox`:
/// a node's own abuse report (JSON, for merging), and a merged one (text, for a node
/// that hands it to a bot without merging itself).
pub const PEER_FILES: &[&str] = &["abuse", "abuse-report"];

/// The inbox file a peer's file is written to: `abuse-<node>.json.gz`, `abuse-report-<node>.txt.gz`.
pub fn inbox_name(name: &str, node: &str) -> String {
    let ext = if name == "abuse-report" { "txt" } else { "json" };
    format!("{name}-{node}.{ext}.gz")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerFile {
    /// What it is: one of [`PEER_FILES`].
    pub name: String,
    /// The content, gzip-compressed, in base64.
    pub gz: String,
    /// The sender's signature over [`file_message`] (base64), when it has `identity_file`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

/// A frame carrying `content` as the file `name` (gzip-compressed: a week's JSON abuse
/// report shrinks ~10x, and a frame holds at most 1 MB), signed with `identity` if any.
pub fn file_frame(key: &[u8; 32], identity: Option<&Identity>, from: &str, name: &str, content: &[u8], now: Micros) -> Result<Vec<u8>> {
    if !PEER_FILES.contains(&name) {
        bail!("unknown file name '{name}' (known: {})", PEER_FILES.join(", "));
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(content)?;
    let gz = base64::engine::general_purpose::STANDARD.encode(gz.finish()?);
    let sig = identity.map(|id| id.sign(&file_message(from, now, name, &gz))).unwrap_or_default();
    let env = Envelope { v: 1, from: from.into(), sent: now, facts: vec![], file: Some(PeerFile { name: name.into(), gz, sig }) };
    seal(key, &env)
}

/// Whether a peer file's sender is who it says (see [`NodeKeys::check`]): `Ok(true)` when
/// signed by the key pinned for that name, which then needs no [`Senders`] check.
pub fn file_signed(keys: &NodeKeys, env: &Envelope) -> Result<bool, &'static str> {
    let file = env.file.as_ref().ok_or("no file in the message")?;
    keys.check(&env.from, &file.sig, || file_message(&env.from, env.sent, &file.name, &file.gz))
}

/// Most files the inbox holds: two per peer (its report, a merged one) leave plenty of room,
/// and each is at most a frame (1 MB), so peers can't fill the disk.
const MAX_INBOX_FILES: usize = 32;

/// Which node names the peers' connections use. A file is written to the inbox under its
/// sender's node name, which any key holder can write, and the abuse report job trusts that
/// name: so a peer limited by `peer_accept` keeps the one name it first sent under, and may
/// not use one an unlimited peer uses. (Right after a restart, before the other peers' first
/// heartbeats, a limited peer could still claim one of their names once.) A file signed by
/// the key pinned for its sender's name ([`file_signed`]) needs none of this.
#[derive(Clone, Debug, Default)]
pub struct Senders(Arc<std::sync::Mutex<SenderNames>>);

#[derive(Debug, Default)]
struct SenderNames {
    limited: HashMap<IpAddr, String>,
    unlimited: std::collections::HashSet<String>,
}

impl Senders {
    /// Records that a connection from `ip` sent a message as `name`; false when that name
    /// isn't the sender's to use (only ever for a limited peer).
    pub fn observe(&self, name: &str, ip: Option<IpAddr>, limited: bool) -> bool {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !limited {
            if s.unlimited.len() < 1000 {
                s.unlimited.insert(name.to_string());
            }
            return true;
        }
        let Some(ip) = ip.map(crate::net::normalize) else { return false };
        if s.unlimited.contains(name) || (s.limited.len() >= 1000 && !s.limited.contains_key(&ip)) {
            return false;
        }
        s.limited.entry(ip).or_insert_with(|| name.to_string()) == name
    }
}

/// Writes a peer's file to `dir` as [`inbox_name`] (mode 0600, replacing the
/// previous one atomically) and returns its path. The content is only checked to be gzip:
/// nothing here parses it.
pub fn store_file(dir: &Path, env: &Envelope, max_skew: Dur, now: Micros) -> Result<PathBuf> {
    let file = env.file.as_ref().context("no file in the message")?;
    if dir.as_os_str().is_empty() {
        bail!("[cluster] inbox is empty: files from peers are refused");
    }
    if env.sent.abs_diff(now) > max_skew.micros().unsigned_abs() {
        bail!("sent at {}, beyond max_clock_skew", time::fmt_ts(env.sent));
    }
    if !PEER_FILES.contains(&file.name.as_str()) {
        bail!("unknown file name '{}'", file.name.chars().take(40).collect::<String>());
    }
    let node_ok =
        |n: &str| (1..=64).contains(&n.len()) && !n.starts_with('.') && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !node_ok(&env.from) {
        bail!("node name unfit for a file name");
    }
    let gz = base64::engine::general_purpose::STANDARD.decode(&file.gz).context("file content is not base64")?;
    if !gz.starts_with(&[0x1f, 0x8b]) {
        bail!("file content is not gzip");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let path = dir.join(inbox_name(&file.name, &env.from));
    let held = std::fs::read_dir(dir)?.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.')).count();
    if held >= MAX_INBOX_FILES && !path.exists() {
        bail!("the inbox {} already holds {held} files", dir.display());
    }
    let tmp = dir.join(format!(".{}-{}.tmp", file.name, env.from));
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(&gz)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

// ------------------------------------------------------------------ crypto / framing

pub fn seal(key: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plain = serde_json::to_vec(env)?;
    let ct = cipher.encrypt(&nonce, Payload { msg: &plain, aad: AAD }).map_err(|_| anyhow!("encryption failed"))?;
    if 24 + ct.len() > MAX_FRAME {
        bail!("message too large for one frame ({} bytes)", 24 + ct.len());
    }
    let mut frame = Vec::with_capacity(8 + 24 + ct.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&((24 + ct.len()) as u32).to_be_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ct);
    Ok(frame)
}

/// Opens a frame with whichever of `keys` it was sealed with.
pub fn open_any(keys: &[[u8; 32]], body: &[u8]) -> Result<Envelope> {
    let mut last = anyhow!("no cluster key");
    for k in keys {
        match open(k, body) {
            Ok(env) => return Ok(env),
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub fn open(key: &[u8; 32], body: &[u8]) -> Result<Envelope> {
    if body.len() < 24 + 16 {
        bail!("frame too short");
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&body[..24]);
    let plain = cipher
        .decrypt(nonce, Payload { msg: &body[24..], aad: AAD })
        .map_err(|_| anyhow!("authentication failed (wrong cluster key or tampered message)"))?;
    let env: Envelope = serde_json::from_slice(&plain).context("decoding envelope")?;
    if env.v != 1 {
        bail!("unsupported protocol version {}", env.v);
    }
    Ok(env)
}

// ------------------------------------------------------------------ forward secrecy (LGC2)

/// The first frame of an LGC2 connection, sealed under the cluster key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub v: u8,
    pub sent: Micros,
    /// 16 random bytes in hex: binds the reply and the message key to this exchange.
    pub id: String,
    /// The sender's fresh X25519 public key (base64).
    pub epk: String,
}

/// The receiver's answer, sealed under the same cluster key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReply {
    pub v: u8,
    pub id: String,
    pub epk: String,
}

fn frame2(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(MAGIC2);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn seal_bytes(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, Payload { msg: plain, aad }).map_err(|_| anyhow!("encryption failed"))?;
    let mut body = nonce.to_vec();
    body.extend_from_slice(&ct);
    Ok(body)
}

fn open_bytes(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 24 + 16 {
        bail!("frame too short");
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad })
        .map_err(|_| anyhow!("authentication failed (wrong cluster key or tampered message)"))
}

fn decode_epk(b64: &str) -> Result<[u8; 32]> {
    B64.decode(b64).ok().and_then(|k| k.try_into().ok()).ok_or_else(|| anyhow!("bad public key"))
}

/// A random hex id of 16 bytes.
fn random_id() -> Result<String> {
    use chacha20poly1305::aead::rand_core::RngCore;
    let mut id = [0u8; 16];
    OsRng.try_fill_bytes(&mut id).map_err(|e| anyhow!("no randomness from the system: {e}"))?;
    Ok(id.iter().map(|b| format!("{b:02x}")).collect())
}

/// The message key of one exchange.
fn message_key(key: &[u8; 32], shared: &[u8; 32], id: &str, sender_pk: &[u8; 32], receiver_pk: &[u8; 32]) -> [u8; 32] {
    let mut info = MESSAGE_INFO.to_vec();
    info.extend_from_slice(id.as_bytes());
    info.extend_from_slice(sender_pk);
    info.extend_from_slice(receiver_pk);
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(key), shared).expand(&info, &mut out).expect("32 bytes is a valid length");
    out
}

/// The sender's side of one exchange: its fresh secret until the reply comes.
pub struct Offered {
    secret: EphemeralSecret,
    epk: [u8; 32],
    id: String,
}

/// A hello frame (whole: magic, length, body) and the secret to finish the exchange with.
pub fn hello(key: &[u8; 32], now: Micros) -> Result<(Vec<u8>, Offered)> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&secret).to_bytes();
    let id = random_id()?;
    let h = Hello { v: 2, sent: now, id: id.clone(), epk: B64.encode(epk) };
    let body = seal_bytes(key, HELLO_AAD, &serde_json::to_vec(&h)?)?;
    Ok((frame2(&body), Offered { secret, epk, id }))
}

/// A hello as the receiver checked it, with what it needs to answer.
pub struct Greeted {
    /// Which of the receiver's keys opened it: the reply goes under the same one.
    pub key: [u8; 32],
    id: String,
    epk: [u8; 32],
}

/// Opens a hello's body with whichever of `keys` it was sealed with, and checks it is fresh.
pub fn open_hello(keys: &[[u8; 32]], body: &[u8], now: Micros, skew: Micros) -> Result<Greeted> {
    let mut last = anyhow!("no cluster key");
    for key in keys {
        match open_bytes(key, HELLO_AAD, body) {
            Ok(plain) => {
                let h: Hello = serde_json::from_slice(&plain).context("decoding the hello")?;
                if h.v != 2 {
                    bail!("unsupported hello version {}", h.v);
                }
                if h.sent.abs_diff(now) > skew.unsigned_abs() {
                    bail!("hello sent at {}, beyond max_clock_skew", time::fmt_ts(h.sent));
                }
                if h.id.len() != 32 || !h.id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!("bad hello id");
                }
                return Ok(Greeted { key: *key, id: h.id, epk: decode_epk(&h.epk)? });
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The receiver's reply frame to a hello, and the message key it will open the message with.
pub fn reply_to_hello(g: &Greeted) -> Result<(Vec<u8>, [u8; 32])> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(g.epk));
    if !shared.was_contributory() {
        bail!("the sender's public key is a low-order point");
    }
    let mk = message_key(&g.key, shared.as_bytes(), &g.id, &g.epk, &epk);
    let r = HelloReply { v: 2, id: g.id.clone(), epk: B64.encode(epk) };
    let body = seal_bytes(&g.key, HELLO_AAD, &serde_json::to_vec(&r)?)?;
    Ok((frame2(&body), mk))
}

/// The sender's message key, from the receiver's reply body.
pub fn finish_hello(key: &[u8; 32], offered: Offered, reply_body: &[u8]) -> Result<[u8; 32]> {
    let plain = open_bytes(key, HELLO_AAD, reply_body).context("the hello's reply")?;
    let r: HelloReply = serde_json::from_slice(&plain).context("decoding the hello's reply")?;
    if r.v != 2 || r.id != offered.id {
        bail!("the hello's reply is for another exchange");
    }
    let their = decode_epk(&r.epk)?;
    let shared = offered.secret.diffie_hellman(&PublicKey::from(their));
    if !shared.was_contributory() {
        bail!("the receiver's public key is a low-order point");
    }
    Ok(message_key(key, shared.as_bytes(), &offered.id, &offered.epk, &their))
}

/// Seals an envelope under a message key, as an LGC2 frame.
pub fn seal_message(mk: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    let body = seal_bytes(mk, MESSAGE_INFO, &serde_json::to_vec(env)?)?;
    if body.len() > MAX_FRAME {
        bail!("message too large for one frame ({} bytes)", body.len());
    }
    Ok(frame2(&body))
}

/// Opens a message frame's body under a message key.
pub fn open_message(mk: &[u8; 32], body: &[u8]) -> Result<Envelope> {
    let plain = open_bytes(mk, MESSAGE_INFO, body)?;
    let env: Envelope = serde_json::from_slice(&plain).context("decoding envelope")?;
    if env.v != 1 {
        bail!("unsupported protocol version {}", env.v);
    }
    Ok(env)
}

/// Delivers one envelope to `addr`: with a key exchange when `try_fs` (falling back to the
/// plain frame when the peer closes the connection without a reply, unless `require`), else
/// as a plain frame. `Ok(true)`: delivered with forward secrecy.
pub fn send_envelope(addr: &str, key: &[u8; 32], env: &Envelope, try_fs: bool, require: bool) -> Result<bool, String> {
    if try_fs {
        match send_with_exchange(addr, key, env) {
            Ok(()) => return Ok(true),
            Err(Exchange::NoReply(why)) if !require => {
                eprintln!("vpsfort: cluster: {addr}: no answer to the key exchange ({why}): sending the plain frame");
            }
            Err(Exchange::NoReply(why)) => {
                return Err(format!("the peer doesn't answer key exchanges ({why}) and forward_secrecy = \"require\""))
            }
            Err(Exchange::Failed(e)) => return Err(e),
        }
    }
    let frame = seal(key, env).map_err(|e| format!("{e:#}"))?;
    send_frame(addr, &frame).map(|()| false)
}

/// Why an exchange didn't end in a delivery: the peer closed without answering (an older
/// version: try the plain frame), or anything else.
enum Exchange {
    NoReply(String),
    Failed(String),
}

fn send_with_exchange(addr: &str, key: &[u8; 32], env: &Envelope) -> Result<(), Exchange> {
    let target = addr
        .to_socket_addrs()
        .map_err(|e| Exchange::Failed(format!("resolve: {e}")))?
        .next()
        .ok_or_else(|| Exchange::Failed("no address".into()))?;
    let mut s = TcpStream::connect_timeout(&target, Duration::from_secs(5)).map_err(|e| Exchange::Failed(format!("connect: {e}")))?;
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let (frame, offered) = hello(key, time::now()).map_err(|e| Exchange::Failed(format!("{e:#}")))?;
    s.write_all(&frame).map_err(|e| Exchange::Failed(format!("send: {e}")))?;
    let mut r = Deadline { s: &mut s, until: std::time::Instant::now() + Duration::from_secs(10) };
    let body = match read_frame2(&mut r, MAX_HELLO) {
        Ok(body) => body,
        // closed, reset, or an LGC1 frame back (nothing of the sort exists): an older peer
        Err(e) => return Err(Exchange::NoReply(format!("{e:#}"))),
    };
    let mk = finish_hello(key, offered, &body).map_err(|e| Exchange::Failed(format!("{e:#}")))?;
    let frame = seal_message(&mk, env).map_err(|e| Exchange::Failed(format!("{e:#}")))?;
    s.write_all(&frame).map_err(|e| Exchange::Failed(format!("send: {e}")))?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(())
}

/// Applies one overall deadline to all reads of a TCP stream.
struct Deadline<'a> {
    s: &'a mut TcpStream,
    until: std::time::Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "frame not received in time"));
        }
        self.s.set_read_timeout(Some(left))?;
        self.s.read(buf)
    }
}

/// Reads a frame's head: which protocol it is, and the body's length.
fn read_head(s: &mut impl Read) -> Result<(bool, usize)> {
    let mut head = [0u8; 8];
    s.read_exact(&mut head)?;
    let fs = match &head[..4] {
        m if m == MAGIC => false,
        m if m == MAGIC2 => true,
        _ => bail!("not a vpsfort cluster connection"),
    };
    Ok((fs, u32::from_be_bytes(head[4..].try_into().expect("4 bytes")) as usize))
}

fn read_body(s: &mut impl Read, len: usize, max: usize) -> Result<Vec<u8>> {
    if len > max {
        bail!("frame too large ({len} bytes)");
    }
    // Grow with the data actually received: a peer can't make us reserve memory by
    // merely claiming a large frame.
    let mut body = Vec::with_capacity(len.min(64 * 1024));
    s.take(len as u64).read_to_end(&mut body)?;
    if body.len() != len {
        bail!("truncated frame ({} of {len} bytes)", body.len());
    }
    Ok(body)
}

/// An LGC2 frame's body (a hello's reply, or the message).
fn read_frame2(s: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    match read_head(s)? {
        (true, len) => read_body(s, len, max),
        (false, _) => bail!("a plain frame where a key exchange was expected"),
    }
}

/// A plain (LGC1) frame's body.
#[cfg(test)]
fn read_frame(s: &mut impl Read) -> Result<Vec<u8>> {
    match read_head(s)? {
        (false, len) => read_body(s, len, MAX_FRAME),
        (true, _) => bail!("a key exchange where a plain frame was expected"),
    }
}

// ------------------------------------------------------------------ state

#[derive(Clone, Debug)]
struct Stored {
    fact: Fact,
    expires: Micros,
    learned: Micros,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerView {
    pub addr: String,
    pub last_ok: Option<Micros>,
    pub last_error: Option<String>,
    pub failing_since: Option<Micros>,
    /// Whether the last delivery had forward secrecy (LGC2); false: the peer runs an older
    /// version and got the plain frame. None before the first delivery.
    #[serde(default)]
    pub forward_secret: Option<bool>,
    /// When the peer last failed to answer a hello: LGC1 is sent for a while after that.
    #[serde(skip)]
    pub lgc1_since: Option<Micros>,
    #[serde(skip)]
    watermark: Micros,
    #[serde(skip)]
    last_full: Micros,
}

impl PeerView {
    /// Whether to try a key exchange with this peer now (`prefer`: not while it is known to
    /// speak LGC1 only, for [`LGC1_FALLBACK_FOR`]).
    pub fn try_forward_secrecy(&self, mode: ForwardSecrecy, now: Micros) -> bool {
        match mode {
            ForwardSecrecy::Off => false,
            ForwardSecrecy::Require => true,
            ForwardSecrecy::Prefer => self.lgc1_since.is_none_or(|t| now - t >= LGC1_FALLBACK_FOR),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClusterView {
    pub node_id: String,
    pub listen: String,
    pub peers: Vec<PeerView>,
    /// Nodes we heard from (directly), with the time of their last message.
    pub heard_from: BTreeMap<String, Micros>,
    pub facts_known: usize,
    pub facts_received: u64,
    pub facts_sent: u64,
    pub rejected: u64,
    /// Facts a limited peer may not hand this node (`peer_accept`).
    #[serde(default)]
    pub refused_by_limit: u64,
    /// Fingerprint of the key messages are sent with.
    #[serde(default)]
    pub key_id: String,
    /// Fingerprints of the other keys accepted (during a rotation).
    #[serde(default)]
    pub extra_key_ids: Vec<String>,
    /// When the key file was installed or last rotated.
    #[serde(default)]
    pub key_since: Option<Micros>,
    /// This node's public key (`identity_file`); empty when it signs nothing.
    #[serde(default)]
    pub identity: String,
    /// Nodes with a pinned key (`nodes`).
    #[serde(default)]
    pub pinned: usize,
    /// Facts refused for their signature: missing, wrong, or from an unpinned node.
    #[serde(default)]
    pub refused_signature: u64,
}

pub struct Cluster {
    pub cfg: ClusterCfg,
    pub node_id: String,
    key: [u8; 32],
    /// Also accepted from peers (key rotation).
    extra_keys: Vec<[u8; 32]>,
    last_seq: u64,
    known: HashMap<(String, u64), Stored>,
    /// The notices' share of `known` (see [`MAX_NOTICE_BYTES`]).
    notice_bytes: usize,
    pub view: ClusterView,
    /// `peer_accept` by address, shared with the listener (files are taken there).
    pub limits: PeerLimits,
    /// (sender, kind) pairs already logged as refused.
    refused_logged: std::collections::HashSet<(String, FactKind)>,
    /// Signs this node's facts (`identity_file`).
    identity: Option<Identity>,
    /// Checks the others' (`nodes`).
    pub node_keys: NodeKeys,
    /// Origins already logged as refused for their signature.
    unsigned_logged: std::collections::HashSet<String>,
    /// Refusals the daemon hasn't alerted about yet: (origin, sender, why).
    refusals: Vec<(String, String, String)>,
    /// The address each node last spoke from directly (for probing it).
    direct: HashMap<String, IpAddr>,
}

impl Cluster {
    pub fn new(cfg: &ClusterCfg) -> Result<Self> {
        let key = cfg.load_key()?;
        let extra: Vec<[u8; 32]> = cfg.load_extra_keys()?.into_iter().map(|(_, k)| k).filter(|k| *k != key).collect();
        let node_id = cfg.node_name();
        let identity = (!cfg.identity_file.as_os_str().is_empty()).then(|| Identity::load(&cfg.identity_file)).transpose()?;
        let node_keys = NodeKeys::new(cfg)?;
        if let (Some(id), Some(pinned)) = (&identity, cfg.nodes.get(&node_id)) {
            if decode_public(pinned)?.to_bytes() != id.0.verifying_key().to_bytes() {
                bail!("[cluster] nodes.{node_id} is not the public key of {} ({})", cfg.identity_file.display(), id.public());
            }
        }
        let peers = cfg.peers.iter().map(|p| PeerView { addr: p.clone(), ..Default::default() }).collect();
        Ok(Cluster {
            cfg: cfg.clone(),
            view: ClusterView {
                node_id: node_id.clone(),
                listen: cfg.listen.clone(),
                peers,
                key_id: key_id(&key),
                extra_key_ids: extra.iter().map(key_id).collect(),
                key_since: cfg.key_since(),
                identity: identity.as_ref().map(Identity::public).unwrap_or_default(),
                pinned: cfg.nodes.len(),
                ..Default::default()
            },
            node_id,
            key,
            extra_keys: extra,
            last_seq: 0,
            known: HashMap::new(),
            notice_bytes: 0,
            limits: PeerLimits::new(cfg),
            refused_logged: Default::default(),
            identity,
            node_keys,
            unsigned_logged: Default::default(),
            refusals: Vec::new(),
            direct: HashMap::new(),
        })
    }

    /// Signs this node's files (`cluster-send-report`).
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Every key accepted from peers: the main one first.
    pub fn keys(&self) -> Vec<[u8; 32]> {
        std::iter::once(self.key).chain(self.extra_keys.iter().copied()).collect()
    }

    /// Resolves peers to addresses; they are never banned (and accepted by nftables).
    pub fn peer_nets(&self) -> Vec<Net> {
        let (nets, errors) = resolve_peers(&self.cfg.peers);
        for e in errors {
            eprintln!("vpsfort: {e}");
        }
        nets
    }

    /// Records a fact produced by this node. Sequence numbers are time-based, so they stay
    /// unique across restarts without persistence.
    pub fn originate(&mut self, mut body: FactBody, now: Micros) {
        if !self.cfg.share.contains(&body.kind()) {
            return;
        }
        let seq = self.last_seq.saturating_add(1).max(time::now().max(now) as u64);
        self.last_seq = seq;
        // as the peers will keep it: what they forward must still match the signature
        body.tidy();
        let sig = self.identity.as_ref().map(|id| id.sign(&fact_message(&self.node_id, seq, now, &body))).unwrap_or_default();
        let fact = Fact { origin: self.node_id.clone(), seq, created: now, hops: 0, body, sig };
        let expires = fact.body.expires(now, self.cfg.notice_ttl.0 as i64);
        self.notice_bytes += fact.body.notice_len();
        self.known.insert((fact.origin.clone(), seq), Stored { fact, expires, learned: now });
    }

    /// Validates an incoming envelope (that came from the address `from`) and returns the
    /// facts this node hasn't seen yet.
    pub fn ingest(&mut self, env: Envelope, from: Option<IpAddr>, now: Micros) -> Vec<Fact> {
        let skew = self.cfg.max_clock_skew.micros();
        if env.from == self.node_id || env.sent.abs_diff(now) > skew.unsigned_abs() || !node_name_ok(&env.from) {
            self.view.rejected += 1;
            return vec![];
        }
        self.view.heard_from.insert(env.from.clone(), now);
        if let Some(ip) = from {
            if self.direct.len() < 256 || self.direct.contains_key(&env.from) {
                self.direct.insert(env.from.clone(), ip);
            }
        }
        let limit = self.limits.of(from);
        let mut fresh = Vec::new();
        for mut f in env.facts {
            let id = (f.origin.clone(), f.seq);
            if f.origin == self.node_id || self.known.contains_key(&id) || !node_name_ok(&f.origin) {
                continue;
            }
            let kind = f.body.kind();
            if limit.as_ref().is_some_and(|l| !l.contains(&kind)) {
                self.view.refused_by_limit += 1;
                if self.refused_logged.len() < 100 && self.refused_logged.insert((env.from.clone(), kind)) {
                    eprintln!(
                        "vpsfort: cluster: {kind:?} from '{}' ({}) refused: [cluster] peer_accept doesn't allow it from there",
                        env.from,
                        from.map_or("?".into(), |ip| ip.to_string())
                    );
                }
                continue;
            }
            let expires = f.body.expires(f.created, self.cfg.notice_ttl.0 as i64);
            if f.hops >= self.cfg.max_hops || expires <= now || f.created > now + skew || !self.cfg.accept.contains(&f.body.kind()) {
                continue;
            }
            if self.known.len() >= MAX_KNOWN {
                self.view.rejected += 1;
                continue;
            }
            // before `tidy`: the signature covers the body as its origin sent it
            if let Err(why) = self.node_keys.check(&f.origin, &f.sig, || fact_message(&f.origin, f.seq, f.created, &f.body)) {
                self.view.refused_signature += 1;
                if self.unsigned_logged.len() < 100 && self.unsigned_logged.insert(f.origin.clone()) {
                    eprintln!("vpsfort: cluster: facts from '{}' (received from '{}') refused: {why}", f.origin, env.from);
                }
                if self.refusals.len() < 100 && !self.refusals.iter().any(|(o, _, _)| *o == f.origin) {
                    self.refusals.push((f.origin.clone(), env.from.clone(), why.to_string()));
                }
                continue;
            }
            f.hops += 1;
            if matches!(f.body, FactBody::Probe { .. } | FactBody::LogLines { .. }) {
                f.hops = self.cfg.max_hops; // for the direct peers only: a probe needs the origin's address, log lines their keeper
            }
            f.body.tidy();
            let notice = f.body.notice_len();
            if notice > 0 && self.notice_bytes + notice > MAX_NOTICE_BYTES {
                self.view.rejected += 1;
                continue;
            }
            self.notice_bytes += notice;
            self.known.insert(id, Stored { fact: f.clone(), expires, learned: now });
            fresh.push(f);
        }
        self.view.facts_received += fresh.len() as u64;
        fresh
    }

    /// The facts refused for their signature since the last call, one entry per origin:
    /// (origin, the peer it came through, why). The daemon alerts about each.
    pub fn take_refusals(&mut self) -> Vec<(String, String, String)> {
        std::mem::take(&mut self.refusals)
    }

    /// The address `node` last sent a message from directly, if it ever did.
    pub fn address_of(&self, node: &str) -> Option<IpAddr> {
        self.direct.get(node).copied()
    }

    /// [`Cluster::outgoing_envelopes`] sealed as plain LGC1 frames.
    pub fn outgoing(&mut self, now: Micros) -> Vec<(usize, Vec<u8>)> {
        let key = self.key;
        self.outgoing_envelopes(now)
            .into_iter()
            .filter_map(|(i, env)| match seal(&key, &env) {
                Ok(frame) => Some((i, frame)),
                Err(e) => {
                    eprintln!("vpsfort: cluster: {e:#}");
                    None
                }
            })
            .collect()
    }

    /// Builds one envelope per peer: new facts since the last send, or everything on a
    /// full sync. Empty envelopes double as heartbeats.
    pub fn outgoing_envelopes(&mut self, now: Micros) -> Vec<(usize, Envelope)> {
        let mut freed = 0;
        self.known.retain(|_, s| {
            let keep = s.expires > now;
            if !keep {
                freed += s.fact.body.notice_len();
            }
            keep
        });
        self.notice_bytes = self.notice_bytes.saturating_sub(freed);
        self.view.facts_known = self.known.len();
        let full_every = self.cfg.full_sync_every.micros();
        let mut out = Vec::new();
        for i in 0..self.view.peers.len() {
            let peer = &mut self.view.peers[i];
            let full = now - peer.last_full >= full_every;
            let since = if full { Micros::MIN } else { peer.watermark };
            let share = &self.cfg.share;
            let facts: Vec<Fact> = self
                .known
                .values()
                .filter(|s| s.learned > since && s.fact.hops < self.cfg.max_hops && share.contains(&s.fact.body.kind()))
                .map(|s| s.fact.clone())
                .collect();
            if full {
                peer.last_full = now;
            }
            peer.watermark = now;
            self.view.facts_sent += facts.len() as u64;
            // One frame per CHUNK bytes of facts (an empty one still says "alive").
            let mut chunks: Vec<Vec<Fact>> = vec![vec![]];
            let mut size = 0;
            for f in facts {
                let n = serde_json::to_vec(&f).map_or(0, |v| v.len()) + 1;
                if size + n > CHUNK && !chunks.last().is_some_and(|c| c.is_empty()) {
                    chunks.push(vec![]);
                    size = 0;
                }
                size += n;
                chunks.last_mut().expect("never empty").push(f);
            }
            for facts in chunks {
                out.push((i, Envelope { v: 1, from: self.node_id.clone(), sent: time::now(), facts, file: None }));
            }
        }
        out
    }

    /// Records a delivery result (`Ok`: whether it had forward secrecy). A failed delivery
    /// forces a full resend next time. Returns an alert message when a peer has been
    /// unreachable for 5 minutes.
    pub fn delivered(&mut self, peer: usize, result: Result<bool, String>, now: Micros) -> Option<String> {
        let p = self.view.peers.get_mut(peer)?;
        match result {
            Ok(forward_secret) => {
                p.last_ok = Some(now);
                p.last_error = None;
                p.failing_since = None;
                if p.forward_secret.is_some_and(|was| was != forward_secret) || p.forward_secret.is_none() {
                    eprintln!(
                        "vpsfort: cluster: peer {} {}",
                        p.addr,
                        if forward_secret {
                            "answers key exchanges: forward secrecy on"
                        } else {
                            "doesn't answer key exchanges (an older version?): plain frames"
                        }
                    );
                }
                p.forward_secret = Some(forward_secret);
                p.lgc1_since = if forward_secret { None } else { Some(now) };
                None
            }
            Err(e) => {
                p.last_full = Micros::MIN / 2;
                p.last_error = Some(e.clone());
                let since = *p.failing_since.get_or_insert(now);
                (now - since >= 5 * time::MIN).then(|| format!("cluster peer {} unreachable since {}: {e}", p.addr, time::fmt_ts(since)))
            }
        }
    }
}

/// The firewall the installers open the cluster port in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Firewall {
    Ufw,
    Firewalld,
    Iptables,
}

/// The commands that open the cluster port to the peers only (`vpsfort cluster-ufw-rules`),
/// and the peers left out: a documentation address is a template's example that was never
/// replaced, not a node, and gets no rule.
pub fn peer_rules(peers: &[Net], port: u16, firewall: Firewall) -> (Vec<String>, Vec<Net>) {
    let (examples, nodes): (Vec<Net>, Vec<Net>) = peers.iter().partition(|n| n.is_documentation());
    let rules = nodes
        .iter()
        .map(|net| match firewall {
            Firewall::Ufw => format!("ufw allow from {net} to any port {port} proto tcp comment 'vpsfort cluster'"),
            Firewall::Firewalld => {
                let family = if net.is_v4() { "ipv4" } else { "ipv6" };
                format!(
                    "firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" source address=\"{net}\" port port=\"{port}\" protocol=\"tcp\" accept'"
                )
            }
            Firewall::Iptables => {
                let cmd = if net.is_v4() { "iptables" } else { "ip6tables" };
                format!("{cmd} -I INPUT -p tcp -s {net} --dport {port} -j ACCEPT -m comment --comment 'vpsfort cluster'")
            }
        })
        .collect();
    (rules, examples)
}

/// The addresses `peers` (`host:port`) resolve to, sorted, and what could not be resolved.
pub fn resolve_peers(peers: &[String]) -> (Vec<Net>, Vec<String>) {
    let (mut nets, mut errors) = (Vec::new(), Vec::new());
    for p in peers {
        match p.to_socket_addrs() {
            Ok(addrs) => nets.extend(addrs.map(|a| Net::host(crate::net::normalize(a.ip())))),
            Err(e) => errors.push(format!("cluster peer {p}: cannot resolve: {e}")),
        }
    }
    nets.sort();
    nets.dedup();
    (nets, errors)
}

// ------------------------------------------------------------------ network threads

/// `peer_accept` by the addresses the limited peers resolve to, shared between the
/// listener's threads (files) and the main loop (facts).
#[derive(Clone, Debug, Default)]
pub struct PeerLimits(Arc<RwLock<Vec<Limit>>>);

/// A limited peer (as in `peers`), one of its addresses, and what it may hand over.
type Limit = (String, Net, Vec<FactKind>);

impl PeerLimits {
    pub fn new(cfg: &ClusterCfg) -> Self {
        let limits = PeerLimits::default();
        limits.refresh(cfg);
        limits
    }

    /// Resolves the limited peers again. A peer that doesn't resolve keeps its old
    /// addresses: the listener may still admit them.
    pub fn refresh(&self, cfg: &ClusterCfg) {
        let mut list = self.0.write().unwrap_or_else(|e| e.into_inner());
        for (peer, kinds) in &cfg.peer_accept {
            let (nets, errors) = resolve_peers(std::slice::from_ref(peer));
            if !errors.is_empty() || nets.is_empty() {
                continue;
            }
            list.retain(|(p, _, _)| p != peer);
            list.extend(nets.into_iter().map(|n| (peer.clone(), n, kinds.clone())));
        }
    }

    /// What a connection from `ip` may deliver: `None` when it isn't limited. An address
    /// of several limited peers gets what any of them may.
    pub fn of(&self, ip: Option<IpAddr>) -> Option<Vec<FactKind>> {
        let list = self.0.read().unwrap_or_else(|e| e.into_inner());
        if list.is_empty() {
            return None;
        }
        let Some(ip) = ip.map(crate::net::normalize) else { return Some(vec![]) };
        let mut kinds: Option<Vec<FactKind>> = None;
        for (_, _, k) in list.iter().filter(|(_, n, _)| n.contains(ip)) {
            kinds.get_or_insert_with(Vec::new).extend(k.iter().copied());
        }
        kinds
    }
}

/// Who may connect to the cluster listener.
#[derive(Clone, Debug)]
pub enum PeerFilter {
    /// Anyone (`allow_only_peers = false`, for NATed peers): the key still decides.
    Anyone,
    /// The addresses the peers resolve to, kept current by the daemon. While none resolved
    /// (DNS down at boot), every connection is refused: never "anyone" by accident.
    Peers(Arc<RwLock<Vec<Net>>>),
}

impl PeerFilter {
    pub fn peers(nets: Vec<Net>) -> Self {
        PeerFilter::Peers(Arc::new(RwLock::new(nets)))
    }

    /// Replaces the peers' addresses (no-op for `Anyone`).
    pub fn set(&self, nets: Vec<Net>) {
        if let PeerFilter::Peers(list) = self {
            *list.write().unwrap_or_else(|e| e.into_inner()) = nets;
        }
    }

    fn admits(&self, ip: Option<IpAddr>) -> bool {
        match self {
            PeerFilter::Anyone => true,
            PeerFilter::Peers(list) => ip.is_some_and(|ip| list.read().unwrap_or_else(|e| e.into_inner()).iter().any(|n| n.contains(ip))),
        }
    }
}

/// Accepts peer connections; authenticated envelopes are passed to `deliver`.
/// Connections `allowed` doesn't admit are dropped unread.
pub fn serve(
    listen: &str,
    keys: Vec<[u8; 32]>,
    allowed: PeerFilter,
    forward_secrecy: ForwardSecrecy,
    deliver: impl Fn(Envelope, Option<IpAddr>) -> bool + Send + Sync + 'static,
) -> Result<()> {
    let keys = Arc::new(keys);
    let skew = 5 * time::MIN;
    let listener = TcpListener::bind(listen).with_context(|| format!("binding cluster listener {listen}"))?;
    let deliver = Arc::new(deliver);
    let active = Arc::new(AtomicUsize::new(0));
    let per_source: Arc<std::sync::Mutex<HashMap<Option<IpAddr>, usize>>> = Arc::default();
    std::thread::spawn(move || {
        let mut logged = std::collections::HashSet::new();
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let from = s.peer_addr().map(|a| crate::net::normalize(a.ip())).ok();
            if !allowed.admits(from) {
                if let Some(ip) = from.filter(|_| logged.len() < 1000) {
                    if logged.insert(ip) {
                        eprintln!("vpsfort: cluster: refused connection from {ip} (not a configured peer; set allow_only_peers = false if it is NATed)");
                    }
                }
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                continue; // dropped: too many concurrent peers/probes
            }
            {
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                let n = open.entry(from).or_default();
                if *n >= MAX_PER_SOURCE {
                    continue; // dropped: that address has its share
                }
                *n += 1;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let (deliver, active, keys, per_source) =
                (Arc::clone(&deliver), Arc::clone(&active), Arc::clone(&keys), Arc::clone(&per_source));
            std::thread::spawn(move || {
                let peer = s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
                let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                let mut r = Deadline { s: &mut s, until: std::time::Instant::now() + READ_DEADLINE };
                match receive(&mut r, &keys, forward_secrecy, skew) {
                    Ok(env) => {
                        deliver(env, from);
                    }
                    Err(e) => eprintln!("vpsfort: cluster: rejected connection from {peer}: {e:#}"),
                }
                let mut open = per_source.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(n) = open.get_mut(&from) {
                    *n -= 1;
                    if *n == 0 {
                        open.remove(&from);
                    }
                }
                drop(open);
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(())
}

/// One connection's worth: a plain frame (LGC1), or a hello answered and the message that
/// follows it (LGC2), as `forward_secrecy` allows.
fn receive(r: &mut Deadline<'_>, keys: &[[u8; 32]], forward_secrecy: ForwardSecrecy, skew: Micros) -> Result<Envelope> {
    let (fs, len) = read_head(r)?;
    if !fs {
        if forward_secrecy == ForwardSecrecy::Require {
            bail!("a plain frame, refused: forward_secrecy = \"require\" (an older peer?)");
        }
        return open_any(keys, &read_body(r, len, MAX_FRAME)?);
    }
    if forward_secrecy == ForwardSecrecy::Off {
        bail!("a key exchange, refused: forward_secrecy = \"off\"");
    }
    let greeted = open_hello(keys, &read_body(r, len, MAX_HELLO)?, time::now(), skew)?;
    let (reply, mk) = reply_to_hello(&greeted)?;
    r.s.write_all(&reply).context("answering the hello")?;
    let body = read_frame2(r, MAX_FRAME)?;
    open_message(&mk, &body)
}

/// Delivers one frame to `addr` (connect + write, 5 s timeouts).
pub fn send_frame(addr: &str, frame: &[u8]) -> Result<(), String> {
    let target = addr.to_socket_addrs().map_err(|e| format!("resolve: {e}"))?.next().ok_or_else(|| "no address".to_string())?;
    let mut s = TcpStream::connect_timeout(&target, Duration::from_secs(5)).map_err(|e| format!("connect: {e}"))?;
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    s.write_all(frame).map_err(|e| format!("send: {e}"))?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_rules_leave_documentation_addresses_out() {
        let peers: Vec<Net> = ["192.0.2.1", "11.145.1.2", "2001:db8::7", "198.51.100.9", "203.0.113.200", "fd12:3456::1", "3fff:100::1"]
            .iter()
            .map(|p| p.parse().unwrap())
            .collect();
        let (rules, examples) = peer_rules(&peers, 7946, Firewall::Ufw);
        assert_eq!(
            rules,
            [
                "ufw allow from 11.145.1.2 to any port 7946 proto tcp comment 'vpsfort cluster'",
                "ufw allow from fd12:3456::1 to any port 7946 proto tcp comment 'vpsfort cluster'"
            ]
        );
        assert_eq!(examples.len(), 5);
        let (rules, _) = peer_rules(&peers, 7946, Firewall::Firewalld);
        assert!(
            rules[0].contains("family=\"ipv4\" source address=\"11.145.1.2\" port port=\"7946\"") && rules[1].contains("family=\"ipv6\""),
            "{rules:?}"
        );
        let (rules, _) = peer_rules(&peers, 7946, Firewall::Iptables);
        assert!(
            rules[0].starts_with("iptables -I INPUT -p tcp -s 11.145.1.2 --dport 7946") && rules[1].starts_with("ip6tables "),
            "{rules:?}"
        );
        // only the template's examples: nothing to open
        assert!(peer_rules(&peers[..1], 7946, Firewall::Ufw).0.is_empty());
    }

    #[test]
    fn rotation_reminder_after_rotate_after() {
        let day = 86_400 * SEC;
        let cfg = ClusterCfg { key_file: "/etc/vpsfort/cluster.key".into(), ..Default::default() };
        assert_eq!(cfg.rotation_reminder(Some(0), 179 * day), None, "not yet 180 days");
        let msg = cfg.rotation_reminder(Some(0), 200 * day).unwrap();
        assert!(msg.contains("200 days old (rotate after 180d)"), "{msg}");
        assert_eq!(cfg.rotation_reminder(None, 200 * day), None, "inline key: age unknown");
        let never = ClusterCfg { rotate_after: Dur(0), ..cfg.clone() };
        assert_eq!(never.rotation_reminder(Some(0), 1000 * day), None);
        // the key file's modification time
        let d = std::env::temp_dir().join(format!("lg-keyage-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("k"), "x").unwrap();
        let since = ClusterCfg { key_file: d.join("k"), ..Default::default() }.key_since().unwrap();
        assert!((time::now() - since).abs() < 60 * SEC);
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn cluster(name: &str, key: &str, peers: Vec<String>) -> Cluster {
        let cfg = ClusterCfg { enabled: true, node_id: name.into(), key: key.into(), peers, ..Default::default() };
        cfg.validate().unwrap();
        Cluster::new(&cfg).unwrap()
    }

    fn ban(net: &str, until_s: i64) -> FactBody {
        FactBody::Ban { net: net.parse().unwrap(), until: until_s * SEC, reason: "scan".into(), forgeable: false, evidence: vec![] }
    }

    #[test]
    fn key_rotation_without_a_gap() {
        let dir = std::env::temp_dir().join(format!("lg-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (old, new) = (generate_key(), generate_key());
        let node = |name: &str, main: &str, extra: &[(&str, &str)]| {
            let d = dir.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("cluster.key"), format!("{main}\n")).unwrap();
            for (ext, k) in extra {
                std::fs::write(d.join(format!("cluster.key.{ext}")), k).unwrap();
            }
            let cfg = ClusterCfg { enabled: true, node_id: name.into(), key_file: d.join("cluster.key"), ..Default::default() };
            Cluster::new(&cfg).unwrap()
        };
        let env = Envelope { v: 1, from: "x".into(), sent: 0, facts: vec![], file: None };
        let talks = |a: &Cluster, b: &Cluster| {
            let frame = seal(a.key(), &env).unwrap();
            open_any(&b.keys(), &frame[8..]).is_ok()
        };
        // before: both on the old key
        let (a0, b0) = (node("a0", &old, &[]), node("b0", &old, &[]));
        assert!(talks(&a0, &b0) && a0.view.extra_key_ids.is_empty());
        // start done on a only, then on both: the new key is accepted, still sent with the old
        let a1 = node("a1", &old, &[("next", &new)]);
        assert!(talks(&a1, &b0) && talks(&b0, &a1));
        let b1 = node("b1", &old, &[("next", &new)]);
        // switch done on a only: a sends with the new key, b (with .next) reads it, and back
        let a2 = node("a2", &new, &[("prev", &old)]);
        assert!(talks(&a2, &b1) && talks(&b1, &a2));
        assert_eq!(a2.view.key_id, key_id(&decode_key(&new).unwrap()));
        assert_eq!(a2.view.extra_key_ids, vec![key_id(&decode_key(&old).unwrap())]);
        // switch done on both, then finish on a only
        let b2 = node("b2", &new, &[("prev", &old)]);
        let a3 = node("a3", &new, &[]);
        assert!(talks(&a3, &b2) && talks(&b2, &a3) && talks(&a2, &b2));
        // a node left on the old key alone can't read the new one: why `start` goes first
        assert!(!talks(&a3, &b0));
        // a damaged rotation file is an error, not silently ignored
        let d = dir.join("bad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("cluster.key"), &old).unwrap();
        std::fs::write(d.join("cluster.key.next"), "not a key").unwrap();
        let cfg = ClusterCfg { enabled: true, key_file: d.join("cluster.key"), ..Default::default() };
        assert!(Cluster::new(&cfg).is_err());
        // the same key in .prev and main isn't listed twice
        assert!(node("same", &new, &[("prev", &new)]).keys().len() == 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_open_and_tamper() {
        let key = decode_key(&generate_key()).unwrap();
        let env = Envelope { v: 1, from: "a".into(), sent: 5, facts: vec![], file: None };
        let frame = seal(&key, &env).unwrap();
        let body = read_frame(&mut frame.as_slice()).unwrap();
        assert_eq!(open(&key, &body).unwrap().from, "a");
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, &bad).unwrap_err().to_string().contains("authentication failed"));
        let other = decode_key(&generate_key()).unwrap();
        assert!(open(&other, &body).is_err(), "wrong key");
        assert!(read_frame(&mut &b"GET / HTTP/1.1\r\n"[..]).is_err());
    }

    #[test]
    fn peer_file_is_stored_once_checked() {
        use std::io::Read as _;
        use std::os::unix::fs::PermissionsExt;
        let key = decode_key(&generate_key()).unwrap();
        let now = time::now();
        let skew = Dur(300);
        let dir = std::env::temp_dir().join(format!("lg-inbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let report = br#"{"servers":[],"from":0,"to":1,"offenders":[]}"#.repeat(1000);
        let frame = file_frame(&key, None, "vpn", "abuse", &report, now).unwrap();
        assert!(frame.len() < report.len() / 4, "compressed: {} bytes", frame.len());
        let env = open(&key, &read_frame(&mut frame.as_slice()).unwrap()).unwrap();
        assert!(env.facts.is_empty());
        let path = store_file(&dir, &env, skew, now).unwrap();
        assert_eq!(path, dir.join("abuse-vpn.json.gz"));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let mut back = Vec::new();
        flate2::read::GzDecoder::new(std::fs::File::open(&path).unwrap()).read_to_end(&mut back).unwrap();
        assert_eq!(back, report);
        // a newer one replaces it; no temporary file is left behind
        let env2 = open(&key, &read_frame(&mut file_frame(&key, None, "vpn", "abuse", b"{}", now).unwrap().as_slice()).unwrap()).unwrap();
        store_file(&dir, &env2, skew, now).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        assert!(file_frame(&key, None, "vpn", "passwd", b"x", now).is_err(), "only known names are sent");
        let refused = |e: &Envelope, dir: &Path| store_file(dir, e, skew, now).unwrap_err().to_string();
        assert!(refused(&env, Path::new("")).contains("refused"));
        let stale = Envelope { sent: now - 3600 * SEC, ..env.clone() };
        assert!(refused(&stale, &dir).contains("max_clock_skew"));
        for from in ["../etc", ".hidden", "a/b", ""] {
            assert!(refused(&Envelope { from: from.into(), ..env.clone() }, &dir).contains("node name"), "{from}");
        }
        let mut other = env.clone();
        other.file.as_mut().unwrap().name = "../../root/.ssh/authorized_keys".into();
        assert!(refused(&other, &dir).contains("unknown file name"));
        let mut plain = env.clone();
        plain.file.as_mut().unwrap().gz = base64::engine::general_purpose::STANDARD.encode(b"not gzip");
        assert!(refused(&plain, &dir).contains("not gzip"));
        // a full inbox takes no new names, but still replaces a file it has
        for i in 0..MAX_INBOX_FILES {
            std::fs::write(dir.join(format!("other-{i}")), "x").unwrap();
        }
        assert!(refused(&Envelope { from: "new".into(), ..env.clone() }, &dir).contains("already holds"));
        store_file(&dir, &env, skew, now).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A limited peer sends files under its own node name only, never under another peer's.
    #[test]
    fn limited_peers_keep_their_own_name() {
        let s = Senders::default();
        let (tg, vpn): (IpAddr, IpAddr) = ("192.0.2.30".parse().unwrap(), "192.0.2.20".parse().unwrap());
        assert!(s.observe("tg", Some(tg), true));
        assert!(s.observe("tg", Some(tg), true), "again");
        assert!(!s.observe("tg2", Some(tg), true), "a second name");
        assert!(s.observe("vpn", Some(vpn), false));
        assert!(!s.observe("vpn", Some(tg), true), "an unlimited peer's name");
        // a limited address that first claimed another's name is stuck with it once that one speaks
        let s = Senders::default();
        assert!(s.observe("vpn", Some(tg), true));
        assert!(s.observe("vpn", Some(vpn), false));
        assert!(!s.observe("vpn", Some(tg), true));
        assert!(!s.observe("tg", Some(tg), true));
        assert!(!s.observe("tg", None, true), "no address: no name");
    }

    /// Nodes without the `file` field (older versions) still read such a message: as a
    /// heartbeat without facts.
    #[test]
    fn peer_file_is_ignored_by_older_nodes() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldEnvelope {
            v: u8,
            from: String,
            sent: Micros,
            facts: Vec<Fact>,
        }
        let key = decode_key(&generate_key()).unwrap();
        let frame = file_frame(&key, None, "vpn", "abuse", b"{}", 7).unwrap();
        let body = read_frame(&mut frame.as_slice()).unwrap();
        let plain =
            XChaCha20Poly1305::new((&key).into()).decrypt(XNonce::from_slice(&body[..24]), Payload { msg: &body[24..], aad: AAD }).unwrap();
        let old: OldEnvelope = serde_json::from_slice(&plain).unwrap();
        assert!(old.facts.is_empty());
        let without: Envelope = serde_json::from_str(r#"{"v":1,"from":"a","sent":1,"facts":[]}"#).unwrap();
        assert!(without.file.is_none());
    }

    #[test]
    fn mesh_forwarding_dedup_and_hop_limit() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["b:1".into()]);
        let mut b = cluster("b", &k, vec!["c:1".into()]);
        let mut c = cluster("c", &k, vec!["a:1".into()]);
        a.originate(ban("1.2.3.4", now / SEC + 3600), now);

        let deliver = |from: &mut Cluster, to: &mut Cluster| -> Vec<Fact> {
            let frames = from.outgoing(now);
            let body = read_frame(&mut frames[0].1.as_slice()).unwrap();
            to.ingest(open(from.key(), &body).unwrap(), None, now)
        };
        let got_b = deliver(&mut a, &mut b);
        assert_eq!(got_b.len(), 1);
        assert_eq!(got_b[0].hops, 1);
        let got_c = deliver(&mut b, &mut c);
        assert_eq!(got_c.len(), 1, "b forwards a's fact to c");
        assert_eq!(got_c[0].hops, 2);
        assert!(deliver(&mut c, &mut a).is_empty(), "origin ignores its own fact coming back");
        // incremental: nothing new for b
        assert!(deliver(&mut a, &mut b).is_empty());
        let mut far = cluster("d", &k, vec![]);
        let mut env = Envelope { v: 1, from: "c".into(), sent: now, facts: got_c.clone(), file: None };
        env.facts[0].hops = 3;
        assert!(far.ingest(env, None, now).is_empty(), "hop limit");
    }

    #[test]
    fn limited_peers_hand_over_only_what_they_may() {
        let now = time::now();
        let key = generate_key();
        let mut tg = cluster("tg", &key, vec!["127.0.0.1:7946".into()]);
        let mut xmpp = cluster("xmpp", &key, vec!["127.0.0.2:7946".into(), "127.0.0.3:7946".into()]);
        xmpp.cfg.peer_accept.insert("127.0.0.3:7946".into(), vec![FactKind::Notices, FactKind::Files]);
        xmpp.cfg.validate().unwrap();
        xmpp.limits = PeerLimits::new(&xmpp.cfg);
        tg.originate(ban("10.9.9.9", now / SEC + 3600), now);
        tg.originate(FactBody::Trust { ip: "10.8.8.8".parse().unwrap() }, now);
        tg.originate(FactBody::Notice { subject: "s".into(), body: "b".into() }, now);
        let (_, frame) = tg.outgoing(now).remove(0);
        let env = || open(tg.key(), &frame[8..]).unwrap();
        // from the limited peer's address: only the notice
        let got = xmpp.ingest(env(), Some("127.0.0.3".parse().unwrap()), now);
        assert_eq!(got.iter().map(|f| f.body.kind()).collect::<Vec<_>>(), [FactKind::Notices]);
        assert_eq!(xmpp.view.refused_by_limit, 2);
        // the same message from another peer's address (or as IPv4-mapped IPv6) is judged by that
        let mut other = cluster("xmpp", &key, vec!["127.0.0.2:7946".into(), "127.0.0.3:7946".into()]);
        other.cfg.peer_accept = xmpp.cfg.peer_accept.clone();
        other.limits = PeerLimits::new(&other.cfg);
        assert_eq!(other.ingest(env(), Some("::ffff:127.0.0.3".parse().unwrap()), now).len(), 1);
        assert_eq!(other.ingest(env(), Some("127.0.0.2".parse().unwrap()), now).len(), 2, "the rest, unlimited");
        assert_eq!(other.limits.of(None), Some(vec![]), "no address: nothing");
        assert_eq!(other.limits.of(Some("127.0.0.2".parse().unwrap())), None);
        assert_eq!(PeerLimits::new(&ClusterCfg::default()).of(None), None, "no limits configured");
        // a node sharing only notices doesn't pass the others' bans on either
        let mut relay = cluster("tg", &key, vec!["127.0.0.1:7946".into()]);
        relay.cfg.share = vec![FactKind::Notices];
        let mut from_xmpp = cluster("xmpp", &key, vec!["127.0.0.1:7946".into()]);
        from_xmpp.originate(ban("10.7.7.7", now / SEC + 3600), now);
        from_xmpp.originate(FactBody::Notice { subject: "s".into(), body: "b".into() }, now);
        let (_, f) = from_xmpp.outgoing(now).remove(0);
        assert_eq!(relay.ingest(open(from_xmpp.key(), &f[8..]).unwrap(), None, now).len(), 2, "it takes both");
        let (_, f) = relay.outgoing(now + SEC).remove(0);
        let passed: Vec<FactKind> = open(relay.key(), &f[8..]).unwrap().facts.iter().map(|f| f.body.kind()).collect();
        assert_eq!(passed, [FactKind::Notices]);
        // the limit goes by address: it needs the listener to admit only peers
        let mut bad = xmpp.cfg.clone();
        bad.allow_only_peers = false;
        assert!(bad.validate().is_err());
        bad = xmpp.cfg.clone();
        bad.peer_accept.insert("127.0.0.9:7946".into(), vec![]);
        assert!(bad.validate().is_err(), "not a peer");
    }

    #[test]
    fn probes_reach_direct_peers_only_and_are_tidied() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["192.0.2.2:7946".into()]);
        let mut b = cluster("b", &k, vec!["192.0.2.1:7946".into(), "192.0.2.3:7946".into()]);
        a.originate(FactBody::Probe { ports: vec!["80/tcp".into(), "22/tcp".into(), "80/tcp".into(), "x".into(), "53/udp".into()] }, now);
        a.originate(ban("10.1.1.1", now / SEC + 60), now);
        let (_, f) = a.outgoing(now).remove(0);
        let env = open(a.key(), &f[8..]).unwrap();
        let got = b.ingest(env, Some("192.0.2.1".parse().unwrap()), now);
        assert_eq!(got.len(), 2);
        let probe = got.iter().find(|f| matches!(f.body, FactBody::Probe { .. })).unwrap();
        assert_eq!(probe.body, FactBody::Probe { ports: vec!["22/tcp".into(), "80/tcp".into()] }, "sorted, deduplicated, tcp only");
        assert_eq!(probe.hops, b.cfg.max_hops, "not forwarded");
        assert_eq!(b.address_of("a"), Some("192.0.2.1".parse().unwrap()), "the address to try");
        assert_eq!(b.address_of("c"), None);
        // what b forwards: the ban, not the probe
        let forwarded: Vec<FactKind> =
            b.outgoing(now + SEC).into_iter().flat_map(|(_, f)| open(b.key(), &f[8..]).unwrap().facts).map(|f| f.body.kind()).collect();
        assert!(forwarded.iter().all(|k| *k == FactKind::Bans), "{forwarded:?}");
        // the answer is a fact like any other
        b.originate(
            FactBody::ProbeResult { target: "a".into(), reachable: vec!["22/tcp".into()], unreachable: vec!["80/tcp".into()] },
            now + 2 * SEC,
        );
        let answers: Vec<Fact> = b.outgoing(now + 3 * SEC).into_iter().flat_map(|(_, f)| open(b.key(), &f[8..]).unwrap().facts).collect();
        assert!(answers.iter().any(|f| matches!(&f.body, FactBody::ProbeResult { target, .. } if target == "a")));
    }

    #[test]
    fn notices_are_bounded_in_memory() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["192.0.2.1:7946".into()]);
        let notices = |at: Micros, from_seq: u64, n: u64| Envelope {
            v: 1,
            from: "tg".into(),
            sent: at,
            facts: (from_seq..from_seq + n)
                .map(|seq| Fact {
                    origin: "tg".into(),
                    seq,
                    created: at,
                    hops: 0,
                    body: FactBody::Notice { subject: "s".into(), body: "x".repeat(100 * 1024) },
                    sig: String::new(),
                })
                .collect(),
            file: None,
        };
        // each cut to 16 KB; 2 MB of them at once
        let got = a.ingest(notices(now, 1, 200), None, now);
        assert_eq!(got.len(), 127, "{} notices kept", got.len());
        assert!(got.iter().all(|f| matches!(&f.body, FactBody::Notice { body, .. } if body.len() == MAX_NOTICE_BODY)));
        assert_eq!(a.view.rejected, 73);
        // other facts still get in
        let ban = Envelope {
            facts: vec![Fact {
                origin: "tg".into(),
                seq: 999,
                created: now,
                hops: 0,
                body: ban("9.9.9.9", now / SEC + 60),
                sig: String::new(),
            }],
            ..notices(now, 0, 0)
        };
        assert_eq!(a.ingest(ban, None, now).len(), 1);
        // once they expire (`notice_ttl`, a day), there is room again
        let later = now + 86_401 * SEC;
        a.outgoing(later);
        assert_eq!(a.ingest(notices(later, 1000, 3), None, later).len(), 3);
    }

    #[test]
    fn rejects_stale_and_unaccepted() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec![]);
        let fact = |body| Fact { origin: "x".into(), seq: 1, created: now, hops: 0, body, sig: String::new() };
        let stale =
            Envelope { v: 1, from: "x".into(), sent: now - 3600 * SEC, facts: vec![fact(ban("9.9.9.9", now / SEC + 60))], file: None };
        assert!(a.ingest(stale, None, now).is_empty());
        assert_eq!(a.view.rejected, 1);
        a.cfg.accept = vec![FactKind::Bans];
        let env = Envelope {
            v: 1,
            from: "x".into(),
            sent: now,
            facts: vec![fact(FactBody::Trust { ip: "9.9.9.9".parse().unwrap() })],
            file: None,
        };
        assert!(a.ingest(env, None, now).is_empty(), "trust not accepted");
        let expired =
            Envelope { v: 1, from: "x".into(), sent: now, facts: vec![Fact { seq: 2, ..fact(ban("9.9.9.9", now / SEC - 1)) }], file: None };
        assert!(a.ingest(expired, None, now).is_empty());
    }

    /// Peers' names and text reach alerts and terminals: odd names are refused, text is cleaned.
    #[test]
    fn peer_text_is_cleaned_on_arrival() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec![]);
        let fact = |origin: &str, seq, body| Fact { origin: origin.into(), seq, created: now, hops: 0, body, sig: String::new() };
        let env = |from: &str, facts| Envelope { v: 1, from: from.into(), sent: now, facts, file: None };
        assert!(
            a.ingest(env("x\u{1b}]52;c;", vec![]), None, now).is_empty() && a.view.rejected == 1,
            "a sender's name with control characters"
        );
        assert!(!a.view.heard_from.keys().any(|n| n.contains('\u{1b}')));
        let notice = FactBody::Notice { subject: "s\u{1b}[2Jt".into(), body: "line 1\nline\u{7} 2\u{202e}".into() };
        let ban = FactBody::Ban {
            net: "9.9.9.9".parse().unwrap(),
            until: now + 3600 * SEC,
            reason: "r\u{1b}[0m".into(),
            forgeable: false,
            evidence: vec![],
        };
        let got = a.ingest(
            env("b", vec![fact("b", 1, notice), fact("b", 2, ban), fact("c\nd", 3, FactBody::Trust { ip: "9.9.9.8".parse().unwrap() })]),
            None,
            now,
        );
        assert_eq!(got.len(), 2, "an origin with a line break is dropped");
        assert_eq!(got[0].body, FactBody::Notice { subject: "s[2Jt".into(), body: "line 1\nline 2".into() });
        assert!(matches!(&got[1].body, FactBody::Ban { reason, .. } if reason == "r[0m"));
    }

    #[test]
    fn over_real_tcp() {
        let k = generate_key();
        let key = decode_key(&k).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        serve(&addr, vec![key], PeerFilter::peers(vec!["127.0.0.1".parse().unwrap()]), ForwardSecrecy::Prefer, move |env, _| {
            tx.send(env).is_ok()
        })
        .unwrap();
        let now = time::now();
        let mut a = cluster("a", &k, vec![addr.clone()]);
        a.originate(
            FactBody::Report { ip: "5.6.7.8".parse().unwrap(), points: 40.0, signals: "3x fw_tripwire".into(), forgeable: false },
            now,
        );
        let frames = a.outgoing(now);
        send_frame(&addr, &frames[0].1).unwrap();
        let env = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(env.from, "a");
        assert!(matches!(env.facts[0].body, FactBody::Report { points, .. } if points == 40.0));
        assert!(send_frame("127.0.0.1:1", b"x").is_err());
        assert!(a.delivered(0, Err("connect: refused".into()), now).is_none());
        assert!(a.delivered(0, Err("connect: refused".into()), now + 6 * time::MIN).unwrap().contains("unreachable"));
    }

    #[test]
    fn key_exchange_round_trip_and_refusals() {
        let key = decode_key(&generate_key()).unwrap();
        let other = decode_key(&generate_key()).unwrap();
        let now = time::now();
        let (frame, offered) = hello(&key, now).unwrap();
        assert_eq!(&frame[..4], b"LGC2");
        let body = &frame[8..];
        let skew = 5 * time::MIN;
        assert!(open_hello(&[other], body, now, skew).map(drop).unwrap_err().to_string().contains("authentication failed"));
        assert!(open_hello(&[other, key], body, now + 6 * time::MIN, skew)
            .map(drop)
            .unwrap_err()
            .to_string()
            .contains("beyond max_clock_skew"));
        let greeted = open_hello(&[other, key], body, now + 10 * SEC, skew).unwrap();
        assert_eq!(greeted.key, key, "the reply goes under the key the hello was sealed with");
        let (reply, mk_receiver) = reply_to_hello(&greeted).unwrap();
        // a tampered reply, and one under another key, are refused by the sender
        let mut bad = reply[8..].to_vec();
        bad[30] ^= 1;
        let (_, offered2) = hello(&key, now).unwrap();
        assert!(finish_hello(&key, offered2, &bad).is_err());
        let (_, offered3) = hello(&key, now).unwrap();
        assert!(finish_hello(&key, offered3, &reply[8..]).unwrap_err().to_string().contains("another exchange"), "another hello's reply");
        let mk_sender = finish_hello(&key, offered, &reply[8..]).unwrap();
        assert_eq!(mk_sender, mk_receiver);
        let env = Envelope { v: 1, from: "a".into(), sent: now, facts: vec![], file: None };
        let msg = seal_message(&mk_sender, &env).unwrap();
        assert_eq!(open_message(&mk_receiver, &msg[8..]).unwrap().from, "a");
        assert!(open_message(&key, &msg[8..]).is_err(), "the cluster key alone doesn't read the message");
        assert!(open_any(&[key], &msg[8..]).is_err());
        // a low-order public key is refused on both sides
        let low = B64.encode([0u8; 32]);
        let (_, offered4) = hello(&key, now).unwrap();
        let r = HelloReply { v: 2, id: offered4.id.clone(), epk: low.clone() };
        let bad_reply = seal_bytes(&key, HELLO_AAD, &serde_json::to_vec(&r).unwrap()).unwrap();
        assert!(finish_hello(&key, offered4, &bad_reply).unwrap_err().to_string().contains("low-order"));
        let h = Hello { v: 2, sent: now, id: "0".repeat(32), epk: low };
        let bad_hello = seal_bytes(&key, HELLO_AAD, &serde_json::to_vec(&h).unwrap()).unwrap();
        assert!(reply_to_hello(&open_hello(&[key], &bad_hello, now, skew).unwrap()).unwrap_err().to_string().contains("low-order"));
    }

    /// A receiver of the versions before LGC2: reads one plain frame per connection and
    /// closes any other connection unread.
    fn old_receiver(key: [u8; 32]) -> (String, std::sync::mpsc::Receiver<Envelope>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(mut s) = s else { continue };
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                if let Ok(env) = read_frame(&mut s).and_then(|body| open_any(&[key], &body)) {
                    let _ = tx.send(env);
                }
            }
        });
        (addr, rx)
    }

    #[test]
    fn plain_frames_for_an_older_peer_unless_required() {
        let k = generate_key();
        let key = decode_key(&k).unwrap();
        let (addr, rx) = old_receiver(key);
        let now = time::now();
        let mut a = cluster("a", &k, vec![addr.clone()]);
        a.originate(FactBody::Trust { ip: "5.6.7.8".parse().unwrap() }, now);
        let envs = a.outgoing_envelopes(now);
        assert_eq!(send_envelope(&addr, &key, &envs[0].1, true, false), Ok(false), "no answer to the hello: the plain frame goes");
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().from, "a");
        let err = send_envelope(&addr, &key, &envs[0].1, true, true).unwrap_err();
        assert!(err.contains("doesn't answer key exchanges") && err.contains("require"), "{err}");
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "nothing sent with require");
        // the sender remembers: plain frames for 10 minutes, then a key exchange is tried again
        assert!(a.delivered(0, Ok(false), now).is_none());
        let p = &a.view.peers[0];
        assert_eq!(p.forward_secret, Some(false));
        assert!(!p.try_forward_secrecy(ForwardSecrecy::Prefer, now + 5 * time::MIN));
        assert!(p.try_forward_secrecy(ForwardSecrecy::Prefer, now + 11 * time::MIN));
        assert!(p.try_forward_secrecy(ForwardSecrecy::Require, now) && !p.try_forward_secrecy(ForwardSecrecy::Off, now + 60 * time::MIN));
    }

    #[test]
    fn forward_secrecy_over_tcp_in_each_mode() {
        let k = generate_key();
        let key = decode_key(&k).unwrap();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["x:1".into()]);
        a.originate(FactBody::Trust { ip: "5.6.7.8".parse().unwrap() }, now);
        let env = a.outgoing_envelopes(now).remove(0).1;
        let me = PeerFilter::peers(vec!["127.0.0.1".parse().unwrap()]);
        let serve_as = |mode: ForwardSecrecy| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            drop(listener);
            let (tx, rx) = std::sync::mpsc::channel();
            serve(&addr, vec![key], me.clone(), mode, move |env, _| tx.send(env).is_ok()).unwrap();
            (addr, rx)
        };
        // prefer: both ways in
        let (addr, rx) = serve_as(ForwardSecrecy::Prefer);
        assert_eq!(send_envelope(&addr, &key, &env, true, false), Ok(true));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().from, "a");
        assert_eq!(send_envelope(&addr, &key, &env, false, false), Ok(false));
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(a.delivered(0, Ok(true), now).is_none());
        assert_eq!(a.view.peers[0].forward_secret, Some(true));
        // require: the plain frame is dropped, the exchange gets through
        let (addr, rx) = serve_as(ForwardSecrecy::Require);
        assert_eq!(send_envelope(&addr, &key, &env, false, false), Ok(false), "sent, and refused there");
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
        assert_eq!(send_envelope(&addr, &key, &env, true, true), Ok(true));
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
        // off: a hello is dropped without a reply, so a preferring sender falls back to the plain frame
        let (addr, rx) = serve_as(ForwardSecrecy::Off);
        assert_eq!(send_envelope(&addr, &key, &env, true, false), Ok(false));
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn listener_refuses_strangers_and_lazy_reads() {
        let k = generate_key();
        let key = decode_key(&k).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let filter = PeerFilter::peers(vec!["192.0.2.1".parse().unwrap()]);
        serve(&addr, vec![key], filter.clone(), ForwardSecrecy::Prefer, move |env, _| tx.send(env).is_ok()).unwrap();
        let mut a = cluster("a", &k, vec![addr.clone()]);
        a.originate(FactBody::Trust { ip: "5.6.7.8".parse().unwrap() }, time::now());
        let frames = a.outgoing(time::now());
        let _ = send_frame(&addr, &frames[0].1);
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "localhost is not a configured peer");
        // no peer resolved: nobody gets in (not everybody)
        filter.set(vec![]);
        let _ = send_frame(&addr, &frames[0].1);
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "an empty peer list refuses everyone");
        // re-resolved to this address: accepted
        filter.set(vec!["127.0.0.1".parse().unwrap()]);
        send_frame(&addr, &frames[0].1).unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());

        // one address that opens connections and sends nothing holds two slots at most: the
        // other peers still get through (with allow_only_peers = false, anyone could)
        let idle: Vec<TcpStream> = (0..MAX_CONNECTIONS).map(|_| TcpStream::connect(&addr).unwrap()).collect();
        std::thread::sleep(Duration::from_millis(200));
        let mut refused = 0;
        for mut s in idle {
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            // a dropped one reads as closed at once; an open one waits for its frame
            refused += usize::from(matches!(s.read(&mut [0u8; 1]), Ok(0)));
        }
        assert_eq!(refused, MAX_CONNECTIONS - MAX_PER_SOURCE);

        // a header claiming 1 MB but delivering 3 bytes is rejected without allocating 1 MB
        let mut frame = b"LGC1".to_vec();
        frame.extend_from_slice(&(MAX_FRAME as u32).to_be_bytes());
        frame.extend_from_slice(b"abc");
        let err = read_frame(&mut frame.as_slice()).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn full_sync_is_split_into_frames() {
        let k = generate_key();
        let now = time::now();
        let mut a = cluster("a", &k, vec!["b:1".into(), "c:1".into()]);
        let mut b = cluster("b", &k, vec![]);
        for i in 0..20_000u32 {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            a.originate(
                FactBody::Ban {
                    net: Net::host(ip.into()),
                    until: now + 3600 * SEC,
                    reason: "x".repeat(60),
                    forgeable: false,
                    evidence: vec![],
                },
                now,
            );
        }
        let frames = a.outgoing(now);
        let to_b: Vec<&Vec<u8>> = frames.iter().filter(|(i, _)| *i == 0).map(|(_, f)| f).collect();
        assert!(to_b.len() > 1, "split: {} frame(s)", to_b.len());
        assert_eq!(frames.iter().filter(|(i, _)| *i == 1).count(), to_b.len(), "every peer gets every chunk");
        let mut got = 0;
        for f in to_b {
            assert!(f.len() <= 8 + MAX_FRAME);
            let body = read_frame(&mut f.as_slice()).unwrap();
            got += b.ingest(open(a.key(), &body).unwrap(), None, now).len();
        }
        assert_eq!(got, 20_000);
    }

    /// A node that signs with its own key, and one that checks against `pinned` keys.
    fn signer(name: &str, key: &str, peers: Vec<String>) -> Cluster {
        let mut c = cluster(name, key, peers);
        c.identity = Some(Identity::generate());
        c
    }

    fn pin(c: &mut Cluster, pinned: &[(&str, String)], require: bool) {
        c.cfg.nodes = pinned.iter().map(|(n, k)| (n.to_string(), k.clone())).collect();
        c.cfg.require_signatures = require;
        c.node_keys = NodeKeys::new(&c.cfg).unwrap();
    }

    fn deliver(from: &mut Cluster, to: &mut Cluster, now: Micros) -> Vec<Fact> {
        let frames = from.outgoing(now);
        to.ingest(open(from.key(), &frames[0].1[8..]).unwrap(), None, now)
    }

    /// A key holder can't make facts under another node's name once that name's key is pinned.
    #[test]
    fn forged_origin_is_refused() {
        let k = generate_key();
        let now = time::now();
        let mut a = signer("a", &k, vec!["b:1".into()]);
        let mut m = signer("m", &k, vec!["b:1".into()]);
        let mut b = cluster("b", &k, vec![]);
        pin(&mut b, &[("a", a.identity().unwrap().public())], false);
        let forged = |origin: &str, seq, sig: String| Envelope {
            v: 1,
            from: "m".into(),
            sent: now,
            facts: vec![Fact { origin: origin.into(), seq, created: now, hops: 0, body: ban("10.1.1.1", now / SEC + 60), sig }],
            file: None,
        };
        // unsigned, signed by another key, or a valid signature moved onto another fact
        assert!(b.ingest(forged("a", 1, String::new()), None, now).is_empty());
        let m_sig = m.identity().unwrap().sign(&fact_message("a", 2, now, &ban("10.1.1.1", now / SEC + 60)));
        assert!(b.ingest(forged("a", 2, m_sig), None, now).is_empty());
        a.originate(ban("10.2.2.2", now / SEC + 60), now);
        let genuine = a.known.values().next().unwrap().fact.clone();
        assert!(b.ingest(forged("a", 3, genuine.sig.clone()), None, now).is_empty(), "the signature covers the body");
        let mut moved = genuine.clone();
        moved.created -= SEC;
        assert!(b.ingest(Envelope { facts: vec![moved], ..forged("a", 0, String::new()) }, None, now).is_empty());
        assert_eq!(b.view.refused_signature, 4);
        let refusals = b.take_refusals();
        assert_eq!(refusals.len(), 1, "one entry per origin for the daemon's alert: {refusals:?}");
        assert_eq!(refusals[0].0, "a");
        assert!(b.take_refusals().is_empty(), "taken once");
        // a refused forgery doesn't take the real fact's place
        assert_eq!(deliver(&mut a, &mut b, now).len(), 1);
        // m still speaks for itself: it isn't pinned, and signatures aren't required here
        m.originate(ban("10.3.3.3", now / SEC + 60), now);
        assert_eq!(deliver(&mut m, &mut b, now).len(), 1);
    }

    /// Forwarders change `hops` (and clean the text): the origin's signature still holds.
    #[test]
    fn forwarded_fact_still_verifies() {
        let k = generate_key();
        let now = time::now();
        let mut a = signer("a", &k, vec!["b:1".into()]);
        let mut b = cluster("b", &k, vec!["c:1".into()]);
        let mut c = cluster("c", &k, vec![]);
        let a_pub = a.identity().unwrap().public();
        pin(&mut b, &[("a", a_pub.clone())], true);
        pin(&mut c, &[("a", a_pub)], true);
        a.originate(
            FactBody::Ban {
                net: "10.4.4.4".parse().unwrap(),
                until: now + 3600 * SEC,
                reason: "r\u{1b}[0m\u{202e}".into(),
                forgeable: true,
                evidence: vec![],
            },
            now,
        );
        a.originate(FactBody::Notice { subject: "s".into(), body: "x\u{7}".repeat(20_000) }, now);
        assert_eq!(deliver(&mut a, &mut b, now).len(), 2);
        let got = deliver(&mut b, &mut c, now);
        assert_eq!(got.len(), 2, "refused: {}", c.view.refused_signature);
        assert!(got.iter().all(|f| f.hops == 2 && !f.sig.is_empty()));
        // and on a full sync later, one hop further
        let mut d = cluster("d", &k, vec![]);
        pin(&mut d, &[("a", a.identity().unwrap().public())], true);
        let mut c2 = cluster("c", &k, vec!["d:1".into()]);
        pin(&mut c2, &[("a", a.identity().unwrap().public())], true);
        assert!(b.delivered(0, Err("lost".into()), now).is_none(), "a failed delivery: everything again");
        assert_eq!(deliver(&mut b, &mut c2, now).len(), 2);
        assert_eq!(deliver(&mut c2, &mut d, now).len(), 2);
    }

    /// With `require_signatures`, removing a node's key drops it; without, unsigned facts from
    /// unpinned nodes are taken as before (a rollout, or nodes without identities).
    #[test]
    fn revoked_and_unsigned_nodes() {
        let k = generate_key();
        let now = time::now();
        let mut a = signer("a", &k, vec!["c:1".into()]);
        let mut old = cluster("old", &k, vec!["c:1".into()]);
        let mut c = cluster("c", &k, vec![]);
        a.originate(ban("10.5.5.5", now / SEC + 60), now);
        old.originate(ban("10.6.6.6", now / SEC + 60), now);
        let (fa, fo) = (a.outgoing(now).remove(0).1, old.outgoing(now).remove(0).1);
        let key = *c.key();
        let env = |f: &[u8]| open(&key, &f[8..]).unwrap();
        // nothing pinned: both taken, signed or not
        assert_eq!(c.ingest(env(&fa), None, now).len() + c.ingest(env(&fo), None, now).len(), 2);
        // a pinned, the unsigned node not: still taken unless signatures are required
        let mut c = cluster("c", &k, vec![]);
        pin(&mut c, &[("a", a.identity().unwrap().public())], false);
        assert_eq!(c.ingest(env(&fa), None, now).len() + c.ingest(env(&fo), None, now).len(), 2);
        let mut c = cluster("c", &k, vec![]);
        pin(&mut c, &[("a", a.identity().unwrap().public())], true);
        assert_eq!(c.ingest(env(&fa), None, now).len(), 1);
        assert!(c.ingest(env(&fo), None, now).is_empty(), "unpinned, with require_signatures");
        // a's key removed: a, though it still has the cluster key, is out
        let mut c = cluster("c", &k, vec![]);
        pin(&mut c, &[("b", Identity::generate().public())], true);
        assert!(c.ingest(env(&fa), None, now).is_empty());
        assert_eq!(c.view.refused_signature, 1);
    }

    /// Older nodes read facts with signatures (and ignore them); this one reads theirs.
    #[test]
    fn signatures_are_ignored_by_older_nodes() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldFact {
            origin: String,
            seq: u64,
            created: Micros,
            hops: u8,
            #[serde(flatten)]
            body: FactBody,
        }
        let now = time::now();
        let mut a = signer("a", &generate_key(), vec![]);
        a.originate(ban("10.7.7.7", now / SEC + 60), now);
        let json = serde_json::to_string(&a.known.values().next().unwrap().fact).unwrap();
        assert!(json.contains("\"sig\""));
        let old: OldFact = serde_json::from_str(&json).unwrap();
        assert_eq!(old.body, ban("10.7.7.7", now / SEC + 60));
        let unsigned: Fact =
            serde_json::from_str(r#"{"origin":"x","seq":1,"created":1,"hops":0,"kind":"trust","ip":"192.0.2.1"}"#).unwrap();
        assert!(unsigned.sig.is_empty());
        assert!(!serde_json::to_string(&unsigned).unwrap().contains("sig"), "nothing new on the wire without a key");
    }

    /// A signed file is its sender's whatever peer it comes from; a forged one is refused.
    #[test]
    fn peer_files_are_signed() {
        let key = decode_key(&generate_key()).unwrap();
        let (vpn, other) = (Identity::generate(), Identity::generate());
        let now = time::now();
        let cfg = ClusterCfg { nodes: [("vpn".to_string(), vpn.public())].into(), ..Default::default() };
        let keys = NodeKeys::new(&cfg).unwrap();
        let env = |id: Option<&Identity>, from: &str| open(&key, &file_frame(&key, id, from, "abuse", b"{}", now).unwrap()[8..]).unwrap();
        assert_eq!(file_signed(&keys, &env(Some(&vpn), "vpn")), Ok(true));
        assert!(file_signed(&keys, &env(None, "vpn")).is_err(), "unsigned under a pinned name");
        assert!(file_signed(&keys, &env(Some(&other), "vpn")).is_err(), "another node's key");
        let mut tampered = env(Some(&vpn), "vpn");
        tampered.file.as_mut().unwrap().name = "abuse-report".into();
        assert!(file_signed(&keys, &tampered).is_err());
        let late = Envelope { sent: now + SEC, ..env(Some(&vpn), "vpn") };
        assert!(file_signed(&keys, &late).is_err(), "the time it was sent is signed too");
        assert_eq!(file_signed(&keys, &env(None, "tg")), Ok(false), "unpinned: left to Senders");
        let strict = NodeKeys { require: true, ..keys };
        assert!(file_signed(&strict, &env(Some(&other), "tg")).is_err());
    }

    #[test]
    fn identity_file_and_pinned_keys() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lg-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        let (id, new) = Identity::create(&path).unwrap();
        assert!(new);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let (again, new) = Identity::create(&path).unwrap();
        assert!(!new && again.public() == id.public(), "an existing key is kept");
        let ok = ClusterCfg {
            enabled: true,
            node_id: "a".into(),
            key: generate_key(),
            identity_file: path.clone(),
            nodes: [("a".to_string(), id.public()), ("b".to_string(), Identity::generate().public())].into(),
            require_signatures: true,
            ..Default::default()
        };
        ok.validate().unwrap();
        let c = Cluster::new(&ok).unwrap();
        assert_eq!(c.view.identity, id.public());
        assert_eq!(c.view.pinned, 2);
        let wrong_own = ClusterCfg { node_id: "b".into(), ..ok.clone() };
        assert!(Cluster::new(&wrong_own).err().unwrap().to_string().contains("not the public key"));
        let mut bad = ok.clone();
        bad.nodes.insert("c".into(), "c2hvcnQ=".into());
        assert!(bad.validate().is_err(), "short key");
        bad = ok.clone();
        bad.nodes.insert("c d".into(), id.public());
        assert!(bad.validate().is_err(), "not a node name");
        assert!(ClusterCfg { nodes: BTreeMap::new(), ..ok.clone() }.validate().is_err(), "require_signatures with no keys");
        std::fs::write(&path, "not a key").unwrap();
        assert!(Cluster::new(&ok).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_validation() {
        let ok = ClusterCfg { enabled: true, key: generate_key(), peers: vec!["vpn.example.org:7946".into()], ..Default::default() };
        assert!(ok.validate().is_ok());
        assert!(ClusterCfg { key: String::new(), ..ok.clone() }.validate().is_err());
        assert!(ClusterCfg { key: "c2hvcnQ=".into(), ..ok.clone() }.validate().is_err(), "short key");
        assert!(ClusterCfg { peers: vec!["nohost".into()], ..ok.clone() }.validate().is_err());
        assert!(ClusterCfg { listen: "7946".into(), ..ok }.validate().is_err());
    }
}
