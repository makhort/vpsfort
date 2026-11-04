//! A plain-HTTP door to the HTTPS console (`plain_http`), for a browser that can't take the
//! self-signed certificate. Each request is read, its Host, Origin and Referer rewritten to
//! the console's own, and passed on over TLS (the console's certificate is not checked: it is
//! the simulator's own); the answer comes back without the HSTS header. One request per
//! connection.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

/// The console takes bodies of a few KB (a login): a Content-Length beyond this is refused
/// before anything is read into memory.
const MAX_BODY: usize = 64 * 1024;

#[derive(Debug)]
struct Trusting(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for Trusting {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Trusting(provider)))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// The request head up to the blank line, with the headers rewritten for the console.
fn rewrite_head(head: &str, plain: &str, console: &str) -> String {
    let mut out = String::with_capacity(head.len() + 64);
    for (i, line) in head.split("\r\n").enumerate() {
        if i == 0 {
            out.push_str(line);
        } else if let Some((name, value)) = line.split_once(':') {
            let n = name.trim().to_ascii_lowercase();
            let v = value.trim();
            match n.as_str() {
                "host" => out.push_str(&format!("Host: {console}")),
                "origin" | "referer" => {
                    out.push_str(&format!("{name}: {}", v.replace(&format!("http://{plain}"), &format!("https://{console}"))))
                }
                "connection" | "accept-encoding" => continue,
                _ => out.push_str(line),
            }
        } else {
            continue;
        }
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

fn serve_one(mut down: TcpStream, plain: &str, console: &str, tls: &Arc<ClientConfig>) -> Result<()> {
    down.set_read_timeout(Some(Duration::from_secs(30)))?;
    // the head
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = down.read(&mut chunk)?;
        if n == 0 {
            bail!("closed before the request head");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 64 * 1024 {
            bail!("request head too long");
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let length: usize = head
        .split("\r\n")
        .find_map(|l| {
            l.split_once(':').filter(|(n, _)| n.trim().eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse().ok())
        })
        .unwrap_or(0);
    if length > MAX_BODY {
        bail!("request body too large ({length} bytes)");
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = down.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    // up, over TLS
    let addr: SocketAddr = console.parse()?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).context("the console doesn't answer")?;
    tcp.set_read_timeout(Some(Duration::from_secs(120)))?;
    let name = ServerName::try_from(addr.ip().to_string()).context("server name")?;
    let conn = ClientConnection::new(Arc::clone(tls), name)?;
    let mut up = StreamOwned::new(conn, tcp);
    up.write_all(rewrite_head(&head, plain, console).as_bytes())?;
    up.write_all(&body)?;
    up.flush()?;
    // the answer: its head without HSTS, then the rest as it comes
    let mut ans = Vec::new();
    let mut sent_head = false;
    loop {
        let n = match up.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        if sent_head {
            down.write_all(&chunk[..n])?;
            continue;
        }
        ans.extend_from_slice(&chunk[..n]);
        if let Some(i) = ans.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&ans[..i + 4]).into_owned();
            let kept: Vec<&str> =
                head.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("strict-transport-security:")).collect();
            down.write_all(kept.join("\r\n").as_bytes())?;
            down.write_all(&ans[i + 4..])?;
            sent_head = true;
        }
    }
    if !sent_head {
        down.write_all(&ans)?;
    }
    down.flush()?;
    Ok(())
}

/// Listens on `plain` and passes each request to the console at `console`.
pub fn serve(plain: &str, console: &str) -> Result<()> {
    let listener = TcpListener::bind(plain).with_context(|| format!("binding {plain}"))?;
    let tls = client_config();
    let (plain, console) = (plain.to_string(), console.to_string());
    thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let (plain, console, tls) = (plain.clone(), console.clone(), Arc::clone(&tls));
            thread::spawn(move || {
                if let Err(e) = serve_one(s, &plain, &console, &tls) {
                    eprintln!("vpsfort-sim: plain-http: {e:#}");
                }
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_is_rewritten_for_the_console() {
        let head = "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:7950\r\nOrigin: http://127.0.0.1:7950\r\nReferer: http://127.0.0.1:7950/\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\n";
        let out = rewrite_head(head, "127.0.0.1:7950", "127.0.0.1:7948");
        assert_eq!(out, "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:7948\r\nOrigin: https://127.0.0.1:7948\r\nReferer: https://127.0.0.1:7948/\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
    }
}
