//! The bot against a fake ntfy, Gotify and webhook on 127.0.0.1: what reaches the service
//! from the outbox, with account names replaced, files only encrypted, and what stays when
//! the service refuses or rate-limits.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use pgp::composed::{
    EncryptionCaps, KeyType, Message as PgpMessage, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::ser::Serialize;
use vpsfort_push_bot::bot::{Bot, Config, Refused, FILE_CAPTION};
use vpsfort_push_bot::push::{Kind, Push};
use vpsfort_push_bot::redact::{parse_domains, Pseudonyms};
use vpsfort_push_bot::seal::Recipient;
use vpsfort_push_bot::servers::ServerNames;

#[derive(Debug, Clone)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct Fake {
    requests: Mutex<Vec<Request>>,
    /// The next request gets 429 with Retry-After: 30.
    flood: AtomicBool,
    /// Every request gets this status (0: 200).
    status: AtomicU16,
}

impl Fake {
    fn take(&self) -> Vec<Request> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }
}

/// One HTTP/1.1 request (Content-Length body), or None at the end of the connection.
async fn read_request<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut words = line.split_whitespace();
    let method = words.next()?.to_string();
    let path = words.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        r.read_line(&mut h).await.ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        headers.push((k.trim().to_lowercase(), v.trim().to_string()));
    }
    let mut body = Vec::new();
    if let Some(len) = headers.iter().find(|(n, _)| n == "content-length").map(|(_, v)| v.clone()) {
        body.resize(len.parse().ok()?, 0);
        r.read_exact(&mut body).await.ok()?;
    }
    Some((method, path, headers, body))
}

async fn serve(fake: Arc<Fake>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let fake = fake.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = stream.into_split();
                let mut rd = BufReader::new(rd);
                while let Some((method, path, headers, body)) = read_request(&mut rd).await {
                    let (status, extra) = if fake.flood.swap(false, Ordering::SeqCst) {
                        (429, "Retry-After: 30\r\n")
                    } else {
                        match fake.status.load(Ordering::SeqCst) {
                            0 => (200, ""),
                            s => (s, ""),
                        }
                    };
                    fake.requests.lock().unwrap().push(Request { method, path, headers, body });
                    let reply = if status == 200 { r#"{"id":"x"}"# } else { "no" };
                    let head =
                        format!("HTTP/1.1 {status} X\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n", reply.len());
                    if wr.write_all(head.as_bytes()).await.is_err() || wr.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    url
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

/// A throwaway OpenPGP key as phones make them (Ed25519, a Curve25519 encryption subkey).
fn keypair() -> (SignedSecretKey, Vec<u8>) {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("admin <admin@example.org>".into())
        .subkeys(vec![enc.build().unwrap()]);
    let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
    let public = SignedPublicKey::from(secret.clone()).to_bytes().unwrap();
    (secret, public)
}

fn alert(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("To: admin@example.org\nSubject: s\n\n{body}")).unwrap();
    path
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn setup(tag: &str) -> (PathBuf, PathBuf, Pseudonyms) {
    let dir = std::env::temp_dir().join(format!("vpsfort-push-bot-fake-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let outbox = dir.join("outbox");
    std::fs::create_dir_all(&outbox).unwrap();
    (dir, outbox, Pseudonyms::new([1; 32], parse_domains("example.org")))
}

fn config(outbox: &Path) -> Config {
    Config {
        outbox: outbox.to_path_buf(),
        outbox_max_age: Duration::from_secs(7 * 86400),
        alert_max_age: Duration::from_secs(24 * 3600),
        servers: ServerNames::parse("xmpp=192.0.2.10,example.org; vpn=198.51.100.20").unwrap(),
        recipient: None,
    }
}

#[tokio::test]
async fn outbox_to_ntfy() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let (dir, outbox, names) = setup("ntfy");
    let alice = names.tag("alice@example.org");
    let push = Push::new(Kind::Ntfy, &format!("{url}/alerts/vpsfort"), Some("tk_abc".into()), None).unwrap();
    let mut bot = Bot::new(push, config(&outbox), names);

    // an alert naming an account, and one that waited too long
    alert(
        &outbox,
        "alert-0001.msg",
        "[xmpp] vpsfort: new registration\n\n[High] account alice@example.org registered from 1.2.3.4\n  \
         cluster peer 198.51.100.20:7946 failing; nextcloud.example.org:443 5d",
    );
    let old = alert(&outbox, "alert-0000.msg", "[xmpp] vpsfort: system\n\nold");
    std::fs::File::options().write(true).open(&old).unwrap().set_modified(SystemTime::now() - Duration::from_secs(25 * 3600)).unwrap();
    bot.deliver_alerts().await.unwrap();
    let sent = fake.take();
    assert_eq!(sent.len(), 2, "{sent:?}");
    let m = sent[0].json();
    assert_eq!((sent[0].method.as_str(), sent[0].path.as_str()), ("POST", "/"), "ntfy's JSON publishing, at the server's root");
    assert_eq!(m["topic"], "vpsfort");
    assert_eq!(m["title"], "[xmpp] vpsfort: new registration");
    assert_eq!(
        m["message"],
        format!("[High] account {alice} registered from 1.2.3.4\n  cluster peer vpn:7946 failing; nextcloud.xmpp:443 5d"),
        "account names and the servers' addresses replaced"
    );
    assert_eq!(m["priority"], 4, "[High]");
    assert_eq!(m["markdown"], false);
    assert_eq!(sent[0].header("authorization"), Some("Bearer tk_abc"));
    assert!(sent[1].json()["message"].as_str().unwrap().starts_with("1 alert(s) waited more than 24 h"), "{:?}", sent[1].json());
    assert!(listing(&outbox).is_empty(), "sent and dropped: {:?}", listing(&outbox));

    // the weekly report: without the admin's OpenPGP key it waits, never sent in clear
    let report =
        "Abuse report from xmpp (192.0.2.10) and vpn\nPeriod: 2026-10-12 to 2026-10-19 UTC.\n\nHello, abuse@example.net,\n1.2.3.4 tried\n";
    std::fs::write(outbox.join("abuse-report-2026-10-19.txt"), report).unwrap();
    bot.deliver_files().await.unwrap();
    assert!(fake.take().is_empty());
    assert!(listing(&outbox).contains(&"abuse-report-2026-10-19.txt".to_string()));

    // with it: one PUT with the encrypted file, a neutral name and caption, nothing in clear
    let (secret, public) = keypair();
    bot.cfg.recipient = Some(Recipient::parse(&public, now_secs() as u32).unwrap());
    bot.deliver_files().await.unwrap();
    let sent = fake.take();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].method.as_str(), sent[0].path.as_str()), ("PUT", "/alerts/vpsfort"));
    let today = chrono::Utc::now().format("%Y-%m-%d");
    assert_eq!(sent[0].header("filename"), Some(format!("report-{today}.txt.pgp").as_str()));
    assert_eq!(sent[0].header("title"), Some(FILE_CAPTION));
    let body = String::from_utf8_lossy(&sent[0].body);
    for clear in ["Abuse", "abuse", "Period", "example.net", "192.0.2.10", "1.2.3.4"] {
        assert!(!body.contains(clear), "{clear} in clear");
    }
    let opened = PgpMessage::from_bytes(&sent[0].body[..]).unwrap().decrypt(&"".into(), &secret).unwrap().as_data_vec().unwrap();
    assert_eq!(String::from_utf8(opened).unwrap(), report, "the admin's key opens the whole report, unchanged");
    assert!(listing(&outbox).is_empty());

    // rate limited: the alert stays and nothing is tried until the wait is over
    alert(&outbox, "alert-0002.msg", "[vpn] vpsfort: system\n\nsecond");
    fake.flood.store(true, Ordering::SeqCst);
    bot.deliver_alerts().await.unwrap();
    assert_eq!(fake.take().len(), 1);
    assert!(listing(&outbox).contains(&"alert-0002.msg".to_string()), "put back: {:?}", listing(&outbox));
    bot.deliver_alerts().await.unwrap();
    assert!(fake.take().is_empty(), "waiting out Retry-After");

    // a refused token stops the bot (exit 78), the alert stays
    let push = Push::new(Kind::Ntfy, &format!("{url}/alerts/vpsfort"), Some("tk_wrong".into()), None).unwrap();
    let mut bot = Bot::new(push, config(&outbox), bot.names);
    fake.status.store(403, Ordering::SeqCst);
    let e: Refused = bot.deliver_alerts().await.unwrap_err();
    assert!(e.0.contains("refused the token"), "{e}");
    assert!(listing(&outbox).contains(&"alert-0002.msg".to_string()));
    // refused for good: dropped with a note, the next alert still goes
    fake.status.store(413, Ordering::SeqCst);
    bot.deliver_alerts().await.unwrap();
    assert!(listing(&outbox).is_empty(), "{:?}", listing(&outbox));
    fake.status.store(0, Ordering::SeqCst);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn outbox_to_gotify_and_a_webhook() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Arc::new(Fake::default());
    let url = serve(fake.clone()).await;
    let (dir, outbox, names) = setup("gotify");
    let (secret, public) = keypair();
    let mut cfg = config(&outbox);
    cfg.recipient = Some(Recipient::parse(&public, now_secs() as u32).unwrap());

    // Gotify: a message with its priority and the application token; no attachments
    let push = Push::new(Kind::Gotify, &format!("{url}/gotify/"), Some("A1b2".into()), None).unwrap();
    let mut bot = Bot::new(push, cfg, names);
    alert(&outbox, "alert-0001.msg", "[xmpp] vpsfort: system\n\n[Critical] LOGGED IN to canary account x from 1.2.3.4");
    bot.deliver_alerts().await.unwrap();
    let sent = fake.take();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].method.as_str(), sent[0].path.as_str()), ("POST", "/gotify/message"));
    assert_eq!(sent[0].header("x-gotify-key"), Some("A1b2"));
    let m = sent[0].json();
    assert_eq!((m["title"].as_str(), m["priority"].as_u64()), (Some("[xmpp] vpsfort: system"), Some(10)));
    std::fs::write(outbox.join("abuse-report-2026-10-19.txt"), "report").unwrap();
    bot.deliver_files().await.unwrap();
    let sent = fake.take();
    assert_eq!(sent.len(), 1, "a note, once a day: {sent:?}");
    assert!(sent[0].json()["message"].as_str().unwrap().contains("takes no attachments"));
    bot.deliver_files().await.unwrap();
    assert!(fake.take().is_empty(), "not again today");
    assert!(listing(&outbox).contains(&"abuse-report-2026-10-19.txt".to_string()), "the file waits");

    // a webhook: JSON with the alert, and the file in base64
    let push = Push::new(Kind::Webhook, &format!("{url}/hook?key=1"), Some("tk".into()), None).unwrap();
    let mut bot = Bot::new(push, config(&outbox), bot.names);
    bot.cfg.recipient = Some(Recipient::parse(&public, now_secs() as u32).unwrap());
    alert(&outbox, "alert-0002.msg", "[vpn] vpsfort: system\n\n[Info] fine");
    bot.deliver_alerts().await.unwrap();
    bot.deliver_files().await.unwrap();
    let sent = fake.take();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0].path, "/hook?key=1");
    assert_eq!(sent[0].header("authorization"), Some("Bearer tk"));
    let m = sent[0].json();
    assert_eq!(
        (m["kind"].as_str(), m["subject"].as_str(), m["priority"].as_str()),
        (Some("alert"), Some("[vpn] vpsfort: system"), Some("low"))
    );
    let f = sent[1].json();
    assert_eq!(f["kind"], "file");
    assert_eq!(f["caption"], FILE_CAPTION);
    use base64::Engine;
    let sealed = base64::engine::general_purpose::STANDARD.decode(f["content_base64"].as_str().unwrap()).unwrap();
    let opened = PgpMessage::from_bytes(&sealed[..]).unwrap().decrypt(&"".into(), &secret).unwrap().as_data_vec().unwrap();
    assert_eq!(opened, b"report");
    assert!(listing(&outbox).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
