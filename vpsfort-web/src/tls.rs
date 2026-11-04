//! The console's TLS: TLS 1.3 only, with a certificate and key from PEM files that are read
//! again when they change (a renewed Let's Encrypt certificate needs no restart). `gen-cert`
//! makes a self-signed one; the browser then shows its fingerprint to compare with
//! `vpsfort-web fingerprint`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::say;

/// How often the files are looked at for a renewal.
const CHECK_EVERY: Duration = Duration::from_secs(60);

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Reads a certificate chain and its key.
pub fn load(cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("{}: not a PEM certificate", cert.display()))?;
    if chain.is_empty() {
        bail!("{}: no certificate in it", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("{}: no PEM private key in it", key.display()))?;
    let ck = CertifiedKey::from_der(chain, key, &provider()).map_err(|e| anyhow!("certificate and key: {e}"))?;
    Ok(Arc::new(ck))
}

/// When the certificate in `cert` (the first of the chain) is valid from and until, in
/// microseconds since the epoch: read from its DER, so the console's own health check can
/// say how many days it has left.
pub fn validity(cert: &Path) -> Option<(crate::time::Micros, crate::time::Micros)> {
    let first = CertificateDer::pem_file_iter(cert).ok()?.next()?.ok()?;
    validity_der(&first)
}

/// A DER element at `at`: its tag, where its content starts and how long it is.
fn tlv(d: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *d.get(at)?;
    let first = *d.get(at + 1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *d.get(at + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = at + header;
    (start + len <= d.len()).then_some((tag, start, len))
}

/// `Certificate { tbsCertificate { [0] version?, serial, signature, issuer, validity { notBefore,
/// notAfter } ... } ... }` (RFC 5280).
pub fn validity_der(der: &[u8]) -> Option<(crate::time::Micros, crate::time::Micros)> {
    let (_, cert, _) = tlv(der, 0)?;
    let (_, tbs, _) = tlv(der, cert)?;
    let mut at = tbs;
    let (tag, s, l) = tlv(der, at)?;
    if tag == 0xa0 {
        at = s + l;
    }
    for _ in 0..3 {
        let (_, s, l) = tlv(der, at)?;
        at = s + l;
    }
    let (_, v, _) = tlv(der, at)?;
    let (t1, s1, l1) = tlv(der, v)?;
    let (t2, s2, l2) = tlv(der, s1 + l1)?;
    Some((asn_time(t1, &der[s1..s1 + l1])?, asn_time(t2, &der[s2..s2 + l2])?))
}

/// A UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
fn asn_time(tag: u8, b: &[u8]) -> Option<crate::time::Micros> {
    let s = std::str::from_utf8(b).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(0..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let n = |a: usize, b: usize| rest.get(a..b)?.parse::<i64>().ok();
    let (month, day, hour, min) = (n(0, 2)?, n(2, 4)?, n(4, 6)?, n(6, 8)?);
    let sec = n(8, 10).unwrap_or(0);
    // days since 1970-01-01 (Howard Hinnant's civil calendar)
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + hour * 3600 + min * 60 + sec) * crate::time::SEC)
}

fn modified(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Hands out the current certificate; reloads it when its files change.
#[derive(Debug)]
pub struct Reloading {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<(Option<SystemTime>, Option<SystemTime>, Arc<CertifiedKey>)>,
    checked: Mutex<Instant>,
}

impl Reloading {
    pub fn new(cert: PathBuf, key: PathBuf) -> Result<Self> {
        let ck = load(&cert, &key)?;
        let stamps = (modified(&cert), modified(&key));
        Ok(Reloading { current: RwLock::new((stamps.0, stamps.1, ck)), cert, key, checked: Mutex::new(Instant::now()) })
    }

    fn maybe_reload(&self) {
        {
            let mut checked = self.checked.lock().unwrap_or_else(|e| e.into_inner());
            if checked.elapsed() < CHECK_EVERY {
                return;
            }
            *checked = Instant::now();
        }
        let stamps = (modified(&self.cert), modified(&self.key));
        let changed = {
            let cur = self.current.read().unwrap_or_else(|e| e.into_inner());
            (cur.0, cur.1) != stamps
        };
        if !changed {
            return;
        }
        match load(&self.cert, &self.key) {
            Ok(ck) => {
                *self.current.write().unwrap_or_else(|e| e.into_inner()) = (stamps.0, stamps.1, ck);
                say!("console: certificate reloaded from {}", self.cert.display());
            }
            // a renewal half written (the certificate before its key): kept, tried again later
            Err(e) => say!("console: certificate not reloaded, keeping the old one: {e:#}"),
        }
    }
}

impl ResolvesServerCert for Reloading {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.maybe_reload();
        Some(Arc::clone(&self.current.read().unwrap_or_else(|e| e.into_inner()).2))
    }
}

/// The server's TLS settings: TLS 1.3, HTTP/1.1.
pub fn server_config(cert: PathBuf, key: PathBuf) -> Result<Arc<rustls::ServerConfig>> {
    let resolver = Reloading::new(cert, key)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// A certificate's SHA-256 fingerprint as browsers show it (`AB:CD:...`).
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// The fingerprint of the first certificate in a PEM file.
pub fn file_fingerprint(cert: &Path) -> Result<String> {
    let first = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .next()
        .with_context(|| format!("{}: no certificate in it", cert.display()))?
        .with_context(|| format!("{}: not a PEM certificate", cert.display()))?;
    Ok(fingerprint(&first))
}

/// A self-signed certificate (ECDSA P-256, five years) for `names` (host names or
/// addresses): `(certificate PEM, key PEM, fingerprint)`.
pub fn self_signed(names: &[String]) -> Result<(String, String, String)> {
    let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| anyhow!("certificate names: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, format!("vpsfort-web {}", names.first().map_or("", String::as_str)));
    let day = |offset_days: i64| {
        let (y, m, d) = crate::time::ymd(crate::time::now() + offset_days * 86_400 * crate::time::SEC);
        rcgen::date_time_ymd(y as i32, m as u8, d as u8)
    };
    params.not_before = day(-1);
    params.not_after = day(5 * 365);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| anyhow!("key: {e}"))?;
    let cert = params.self_signed(&key).map_err(|e| anyhow!("certificate: {e}"))?;
    Ok((cert.pem(), key.serialize_pem(), fingerprint(cert.der())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificates_validity_is_read_from_its_der() {
        let (pem, _, _) = self_signed(&["127.0.0.1".into()]).unwrap();
        let der = CertificateDer::pem_slice_iter(pem.as_bytes()).next().unwrap().unwrap();
        let (from, until) = validity_der(&der).expect("validity");
        let now = crate::time::now();
        assert!(from < now && until > now, "{from} {until} around {now}");
        assert!(until - from > 86_400 * crate::time::SEC);
        assert_eq!(asn_time(0x17, b"261030140000Z"), Some(1_793_368_800 * crate::time::SEC));
        assert_eq!(asn_time(0x18, b"20000101000000Z"), Some(946_684_800 * crate::time::SEC));
        assert!(validity_der(b"\x30\x03\x02\x01").is_none(), "a truncated DER");
    }

    #[test]
    fn self_signed_loads() {
        let (cert, key, fp) = self_signed(&["console.example.org".into(), "192.0.2.10".into()]).unwrap();
        let dir = std::env::temp_dir().join(format!("lgw-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("c.pem"), &cert).unwrap();
        std::fs::write(dir.join("k.pem"), &key).unwrap();
        load(&dir.join("c.pem"), &dir.join("k.pem")).unwrap();
        assert_eq!(file_fingerprint(&dir.join("c.pem")).unwrap(), fp);
        assert_eq!(fp.len(), 32 * 3 - 1);
        server_config(dir.join("c.pem"), dir.join("k.pem")).unwrap();
        // a key that isn't the certificate's
        let (_, other, _) = self_signed(&["x".into()]).unwrap();
        std::fs::write(dir.join("k2.pem"), other).unwrap();
        assert!(load(&dir.join("c.pem"), &dir.join("k2.pem")).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
