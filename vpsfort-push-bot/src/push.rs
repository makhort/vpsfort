//! The three ways out: ntfy (<https://docs.ntfy.sh/publish/>), Gotify
//! (<https://gotify.net/api-docs>) and a plain webhook, over reqwest with rustls. None of
//! them encrypts end to end: the service reads what the bot sends, so alerts go sanitized
//! (`redact`) and files only OpenPGP-encrypted (`seal`). The token never leaves this module in
//! an error: errors carry the status and the service's text, not the request.

use std::time::Duration;

use serde::Serialize;

/// Every call (an upload of a few MB included) finishes within this.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest reply read (the services answer with a few hundred bytes).
const MAX_REPLY: usize = 1 << 20;
/// Alerts longer than this go out in pieces (ntfy takes 4096 bytes a message; Gotify and
/// a webhook have no such limit, but a phone shows a short message better).
pub const MESSAGE_LIMIT: usize = 4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ntfy,
    Gotify,
    Webhook,
}

impl Kind {
    pub fn parse(s: &str) -> Result<Kind, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ntfy" => Ok(Kind::Ntfy),
            "gotify" => Ok(Kind::Gotify),
            "webhook" => Ok(Kind::Webhook),
            other => Err(format!("'{other}' is not one of ntfy, gotify, webhook")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Ntfy => "ntfy",
            Kind::Gotify => "Gotify",
            Kind::Webhook => "the webhook",
        }
    }

    /// Whether the service takes files (Gotify has no attachments).
    pub fn takes_files(self) -> bool {
        self != Kind::Gotify
    }
}

/// How urgent a message is, from vpsfort's severity tag: the services' priority scales.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

impl Priority {
    /// From the first line of the message's body (`[High] ...`, `[Critical] ...`), as
    /// vpsfort's admin messages start.
    pub fn of(text: &str) -> Priority {
        let body = text.split_once("\n\n").map_or(text, |(_, b)| b).trim_start();
        if body.starts_with("[Critical]") {
            Priority::Urgent
        } else if body.starts_with("[High]") {
            Priority::High
        } else if body.starts_with("[Info]") {
            Priority::Low
        } else {
            Priority::Normal
        }
    }

    /// ntfy's 1 to 5.
    pub fn ntfy(self) -> u8 {
        match self {
            Priority::Low => 2,
            Priority::Normal => 3,
            Priority::High => 4,
            Priority::Urgent => 5,
        }
    }

    /// Gotify's 0 to 10 (8 and up are shown over everything on Android).
    pub fn gotify(self) -> u8 {
        match self {
            Priority::Low => 2,
            Priority::Normal => 5,
            Priority::High => 8,
            Priority::Urgent => 10,
        }
    }
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq)]
pub enum PushError {
    /// The service answered with an error status, and said this.
    Refused { status: u16, text: String, retry_after: Option<u64> },
    /// No usable answer: network, TLS, a timeout.
    Transport(String),
}

impl PushError {
    /// The token is wrong or was revoked: no message will ever go through.
    pub fn token_refused(&self) -> bool {
        matches!(self, PushError::Refused { status: 401 | 403, .. })
    }

    /// The service will never take this request as it is (too large, malformed): retrying it
    /// would block what comes after.
    pub fn permanent(&self) -> bool {
        matches!(self, PushError::Refused { status: 400 | 404 | 405 | 413 | 415 | 422, .. })
    }

    /// Rate limited: how long the service wants us to wait.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            PushError::Refused { status: 429, retry_after, .. } => Some(Duration::from_secs(retry_after.unwrap_or(60).clamp(1, 3600))),
            PushError::Refused { status: 503, retry_after: Some(s), .. } => Some(Duration::from_secs((*s).clamp(1, 3600))),
            _ => None,
        }
    }
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PushError::Refused { status, text, .. } if text.is_empty() => write!(f, "HTTP {status}"),
            PushError::Refused { status, text, .. } => write!(f, "HTTP {status}: {text}"),
            PushError::Transport(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for PushError {}

/// reqwest's error and its causes, without the request URL (a webhook URL may carry a secret).
fn transport(e: reqwest::Error) -> PushError {
    let e = e.without_url();
    let mut text = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        text += &format!(": {s}");
        source = s.source();
    }
    PushError::Transport(text)
}

/// Checks the service's address: HTTPS, or plain HTTP to this machine (a Gotify or ntfy
/// next to the bot). A path is the topic (ntfy) or the server's root (Gotify).
pub fn check_url(url: &str) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match u.scheme() {
        "https" => {}
        "http" if local => {}
        s => return Err(format!("{s}:// is not allowed: https, or http to localhost only")),
    }
    if u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return Err("no credentials or fragment in the URL (the token goes in PUSH_TOKEN)".into());
    }
    if u.host_str().is_none() {
        return Err("no host".into());
    }
    Ok(u)
}

/// What a sent file came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Sent {
    Delivered,
    /// The service takes no files (Gotify).
    Unsupported,
}

#[derive(Clone)]
pub struct Push {
    http: reqwest::Client,
    pub kind: Kind,
    url: reqwest::Url,
    /// ntfy: a Bearer token, or `user:password` for Basic; Gotify: the application token
    /// (`X-Gotify-Key`); a webhook: a Bearer token. None: no authentication.
    token: Option<String>,
    /// ntfy's Basic authentication user (with `token` as the password).
    user: Option<String>,
}

#[derive(Serialize)]
struct NtfyMessage<'a> {
    topic: &'a str,
    title: &'a str,
    message: &'a str,
    priority: u8,
    markdown: bool,
}

impl Push {
    pub fn new(kind: Kind, url: &str, token: Option<String>, user: Option<String>) -> Result<Push, String> {
        let url = check_url(url)?;
        if kind == Kind::Ntfy && url.path().trim_matches('/').is_empty() {
            return Err("an ntfy URL names the topic: https://ntfy.example.org/<topic>".into());
        }
        if let Some(t) = &token {
            if t.is_empty() || t.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("the token has blanks or control characters".into());
            }
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(CALL_TIMEOUT)
            // a redirect would carry the message (and the token) elsewhere
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("vpsfort-push-bot/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| transport(e).to_string())?;
        Ok(Push { http, kind, url, token, user })
    }

    /// ntfy: the topic (the URL's last path segment) and the server's root.
    fn ntfy_topic_and_root(&self) -> (String, String) {
        let topic = self.url.path().trim_matches('/').rsplit('/').next().unwrap_or("").to_string();
        let mut root = self.url.clone();
        root.set_path("/");
        root.set_query(None);
        (topic, root.to_string())
    }

    /// Gotify's `/message` on the server named.
    fn gotify_message_url(&self) -> String {
        let mut u = self.url.clone();
        let base = u.path().trim_end_matches('/').to_string();
        u.set_path(&format!("{base}/message"));
        u.set_query(None);
        u.to_string()
    }

    fn authorized(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match (self.kind, &self.token, &self.user) {
            (_, None, _) => req,
            (Kind::Gotify, Some(t), _) => req.header("X-Gotify-Key", t),
            (_, Some(t), Some(u)) if !u.is_empty() => req.basic_auth(u, Some(t)),
            (_, Some(t), _) => req.bearer_auth(t),
        }
    }

    async fn reply(resp: Result<reqwest::Response, reqwest::Error>) -> Result<(), PushError> {
        let mut resp = resp.map_err(transport)?;
        let status = resp.status().as_u16();
        let retry_after = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
            if body.len() + chunk.len() > MAX_REPLY {
                break;
            }
            body.extend_from_slice(&chunk);
        }
        if (200..300).contains(&status) {
            return Ok(());
        }
        // what the service said, as one short line (its text may be HTML or JSON)
        let text: String = String::from_utf8_lossy(&body).chars().filter(|c| !c.is_control()).take(200).collect();
        Err(PushError::Refused { status, text: text.trim().to_string(), retry_after })
    }

    /// One message: `title` is the subject, `text` the body (at most [`MESSAGE_LIMIT`]
    /// characters: the caller splits longer ones).
    pub async fn send_message(&self, title: &str, text: &str, priority: Priority) -> Result<(), PushError> {
        let req = match self.kind {
            Kind::Ntfy => {
                let (topic, root) = self.ntfy_topic_and_root();
                let msg = NtfyMessage { topic: &topic, title, message: text, priority: priority.ntfy(), markdown: false };
                self.http.post(root).json(&msg)
            }
            Kind::Gotify => self
                .http
                .post(self.gotify_message_url())
                .json(&serde_json::json!({ "title": title, "message": text, "priority": priority.gotify() })),
            Kind::Webhook => self.http.post(self.url.clone()).json(&serde_json::json!({
                "kind": "alert",
                "subject": title,
                "text": text,
                "priority": match priority { Priority::Low => "low", Priority::Normal => "normal", Priority::High => "high", Priority::Urgent => "urgent" },
            })),
        };
        Self::reply(self.authorized(req).send().await).await
    }

    /// A file (already encrypted), with a neutral caption. ntfy takes it as an attachment
    /// (`PUT` with `Filename`), a webhook as JSON with the content in base64; Gotify has no
    /// attachments.
    pub async fn send_file(&self, name: &str, data: Vec<u8>, caption: &str) -> Result<Sent, PushError> {
        let req = match self.kind {
            Kind::Ntfy => {
                self.http.put(self.url.clone()).header("Filename", name).header("Title", caption).header("Priority", "3").body(data)
            }
            Kind::Gotify => return Ok(Sent::Unsupported),
            Kind::Webhook => {
                use base64::Engine;
                self.http.post(self.url.clone()).json(&serde_json::json!({
                    "kind": "file",
                    "name": name,
                    "caption": caption,
                    "content_base64": base64::engine::general_purpose::STANDARD.encode(&data),
                }))
            }
        };
        Self::reply(self.authorized(req).send().await).await?;
        Ok(Sent::Delivered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_urls_and_priorities() {
        assert_eq!(Kind::parse(" Ntfy "), Ok(Kind::Ntfy));
        assert!(Kind::parse("pushover").is_err());
        assert!(check_url("https://ntfy.example.org/vpsfort").is_ok());
        assert!(check_url("http://127.0.0.1:8080/").is_ok());
        assert!(check_url("http://ntfy.example.org/t").is_err(), "plain http elsewhere");
        assert!(check_url("https://user:pw@ntfy.example.org/t").is_err());
        assert!(check_url("https://ntfy.example.org/t#x").is_err());
        assert!(Push::new(Kind::Ntfy, "https://ntfy.example.org/", None, None).is_err(), "no topic");
        assert!(Push::new(Kind::Ntfy, "https://ntfy.example.org/t", Some("a b".into()), None).is_err());
        let p = Push::new(Kind::Ntfy, "https://ntfy.example.org/alerts/vpsfort?x=1", Some("tk_x".into()), None).unwrap();
        assert_eq!(p.ntfy_topic_and_root(), ("vpsfort".to_string(), "https://ntfy.example.org/".to_string()));
        let g = Push::new(Kind::Gotify, "https://gotify.example.org/push/", Some("A1".into()), None).unwrap();
        assert_eq!(g.gotify_message_url(), "https://gotify.example.org/push/message");
        assert_eq!(Priority::of("[xmpp] vpsfort: system\n\n[High] ban"), Priority::High);
        assert_eq!(Priority::of("s\n\n[Critical] x"), Priority::Urgent);
        assert_eq!(Priority::of("s\n\n[Info] x"), Priority::Low);
        assert_eq!(Priority::of("digest\n\nPeriod ..."), Priority::Normal);
        assert_eq!((Priority::Urgent.ntfy(), Priority::High.gotify()), (5, 8));
    }

    #[test]
    fn errors_are_sorted() {
        let r = |status, retry| PushError::Refused { status, text: "x".into(), retry_after: retry };
        assert!(r(401, None).token_refused() && r(403, None).token_refused() && !r(400, None).token_refused());
        assert!(r(413, None).permanent() && r(400, None).permanent() && !r(500, None).permanent() && !r(429, None).permanent());
        assert_eq!(r(429, Some(7)).retry_after(), Some(Duration::from_secs(7)));
        assert_eq!(r(429, None).retry_after(), Some(Duration::from_secs(60)));
        assert_eq!(r(503, Some(5)).retry_after(), Some(Duration::from_secs(5)));
        assert_eq!(r(500, None).retry_after(), None);
        assert!(!PushError::Transport("timeout".into()).permanent());
        assert_eq!(r(404, None).to_string(), "HTTP 404: x");
    }

    #[tokio::test]
    async fn errors_never_carry_the_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // nothing listens on port 1
        let p = Push::new(Kind::Ntfy, "http://127.0.0.1:1/t", Some("tk_secret_token".into()), None).unwrap();
        let e = p.send_message("t", "m", Priority::Normal).await.unwrap_err();
        assert!(matches!(e, PushError::Transport(_)), "{e:?}");
        assert!(!e.to_string().contains("secret"), "{e}");
    }
}
