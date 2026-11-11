//! Offline IP -> country and network owner ("Germany / Hetzner Online GmbH (AS24940)").
//!
//! Everything is looked up in memory from database files downloaded once a week, so no
//! address ever leaves the server. Default source: DB-IP's free "lite" databases
//! (CC BY 4.0, monthly, no account; https://db-ip.com): country per address range
//! (geolocated, not just where the network is registered) and the owning network (ASN
//! and organisation name). DB-IP's commercial CSVs (IP to Country first; IP to Location
//! and IP to ISP in their own columns) and iptoasn.com's `ip2asn-*.tsv.gz` (public domain;
//! registry handles instead of company names) are read as they are, and so is any CSV
//! whose header row names its columns: see `Layout`.

use std::borrow::Cow;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::net::Net;
use crate::time::Dur;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoCfg {
    pub enabled: bool,
    /// `{month}` is replaced by the current `YYYY-MM` (the previous month if that isn't out yet).
    /// Empty = don't use that database.
    pub country_url: String,
    pub asn_url: String,
    /// Downloaded databases are kept here (`country.gz`, `asn.gz`) and reused after restarts.
    pub dir: PathBuf,
    pub refresh: Dur,
    /// Download command; the URL is appended and the file is read from its stdout.
    pub fetch: Vec<String>,
    /// Networks the database places in the wrong country, pinned to the right one: e.g.
    /// `"198.51.100.0/24" = "GE"` (an ISO code, or a name like "Georgia"). The most specific
    /// network wins. Places in alerts, bans, accounts' countries and the counters use it;
    /// `[geoblock]` doesn't (its lists come from the database as it is).
    pub places: std::collections::BTreeMap<String, String>,
    /// Refuse a database with more address ranges than this. A range takes 16 bytes (IPv4)
    /// or 24 (IPv6), about twice that while it loads: the lite databases and DB-IP's IP to
    /// Country hold 0.7-1.2 million; a city-level database (DB-IP's city lite: 7.8 million,
    /// with the city and coordinates of each range) needs this and the unit's MemoryMax
    /// (vpsfort.service) raised together.
    pub max_ranges: usize,
}

impl GeoCfg {
    pub fn validate(&self) -> Result<()> {
        for (net, country) in &self.places {
            net.parse::<Net>().map_err(|e| anyhow::anyhow!("[geo] places: '{net}': {e}"))?;
            if parse_country(country).is_none() {
                bail!("[geo] places: '{country}' is not a country (an ISO code like \"GE\", or a name like \"Georgia\")");
            }
        }
        if self.max_ranges < 1000 {
            bail!("[geo] max_ranges: at least 1000");
        }
        Ok(())
    }

    /// `places`, parsed (validated at load), most specific first.
    fn pinned(&self) -> Vec<(Net, [u8; 2])> {
        let mut v: Vec<(Net, [u8; 2])> =
            self.places.iter().filter_map(|(n, c)| Some((n.parse::<Net>().ok()?, parse_country(c)?))).collect();
        v.sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix));
        v
    }
}

impl Default for GeoCfg {
    fn default() -> Self {
        GeoCfg {
            enabled: false,
            country_url: "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz".into(),
            asn_url: "https://download.db-ip.com/free/dbip-asn-lite-{month}.csv.gz".into(),
            dir: "/var/lib/vpsfort/geo".into(),
            refresh: Dur(7 * 86_400),
            // a redirect may not leave https
            fetch: ["curl", "-fsSL", "--proto-redir", "=https", "--max-time", "300", "--retry", "2", "--max-filesize", "200000000"]
                .map(String::from)
                .to_vec(),
            places: std::collections::BTreeMap::new(),
            max_ranges: MAX_RANGES,
        }
    }
}

/// Dropping whole countries or networks (ASNs) by the same databases (`[geoblock]`): their
/// address ranges, from what is loaded already, go into sets of their own in the firewall,
/// next to the blocklist feeds. Lite databases misplace some addresses; this is coarse.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoblockCfg {
    pub enabled: bool,
    /// Countries whose addresses are dropped: ISO codes ("CN") or names as vpsfort spells
    /// them ("China").
    pub countries: Vec<String>,
    /// Drop every other country's addresses: only these (and addresses the database places
    /// nowhere) can reach the server. Together with `countries`, both apply.
    pub only_countries: Vec<String>,
    /// Networks (AS numbers) whose addresses are dropped, from the network database.
    pub asns: Vec<u32>,
    /// Refuse to load more networks than this (each is a set element in the kernel).
    pub max_entries: usize,
    /// Only these local ports are closed to the blocked countries and networks (`"22/tcp"`,
    /// `"5222"` for both protocols); empty: everything. A web site stays open to the world
    /// while SSH and XMPP don't. nftables and ipset only: firewalld's zone drops everything.
    pub ports: Vec<crate::config::PortSpec>,
}

impl Default for GeoblockCfg {
    fn default() -> Self {
        GeoblockCfg { enabled: false, countries: vec![], only_countries: vec![], asns: vec![], max_entries: 200_000, ports: vec![] }
    }
}

impl GeoblockCfg {
    pub fn validate(&self, geo: &GeoCfg) -> Result<()> {
        for c in self.countries.iter().chain(&self.only_countries) {
            if parse_country(c).is_none() {
                bail!("[geoblock]: '{c}' is not a country (an ISO code like \"CN\", or a name like \"China\")");
            }
        }
        if !self.enabled {
            return Ok(());
        }
        if self.countries.is_empty() && self.only_countries.is_empty() && self.asns.is_empty() {
            bail!("[geoblock] is enabled but lists no countries, only_countries or asns");
        }
        if !geo.enabled {
            bail!("[geoblock] needs the [geo] databases: [geo] enabled = true");
        }
        if (!self.countries.is_empty() || !self.only_countries.is_empty()) && geo.country_url.is_empty() {
            bail!("[geoblock] countries need the [geo] country database (country_url)");
        }
        if !self.asns.is_empty() && geo.asn_url.is_empty() {
            bail!("[geoblock] asns need the [geo] network database (asn_url)");
        }
        if let Some(c) = self.only_countries.iter().find(|c| self.countries.iter().any(|b| parse_country(b) == parse_country(c))) {
            bail!("[geoblock]: '{c}' is both blocked (countries) and the only one let in (only_countries)");
        }
        Ok(())
    }

    fn codes(list: &[String]) -> std::collections::BTreeSet<[u8; 2]> {
        list.iter().filter_map(|c| parse_country(c)).collect()
    }

    /// The ISO codes of `countries` and of `only_countries`, sorted.
    pub fn country_codes(&self) -> (Vec<String>, Vec<String>) {
        let codes = |list: &[String]| Self::codes(list).iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect();
        (codes(&self.countries), codes(&self.only_countries))
    }

    /// "CN, RU; all but UA; 2 networks" for status lines.
    pub fn describe(&self) -> String {
        let show = |set: std::collections::BTreeSet<[u8; 2]>| {
            set.iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(", ")
        };
        let mut parts = Vec::new();
        if !self.countries.is_empty() {
            parts.push(show(Self::codes(&self.countries)));
        }
        if !self.only_countries.is_empty() {
            parts.push(format!("all but {}", show(Self::codes(&self.only_countries))));
        }
        if !self.asns.is_empty() {
            parts.push(format!("{} networks (ASNs)", self.asns.len()));
        }
        parts.join("; ")
    }
}

/// What `[geoblock]` loaded, for status and the dashboard.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GeoblockStatus {
    pub computed: crate::time::Micros,
    /// `GeoblockCfg::describe`.
    pub what: String,
    pub v4: usize,
    pub v6: usize,
    /// In the firewall (false in shadow mode, with a backend without it, or on error).
    pub applied: bool,
    pub error: Option<String>,
    /// The blocked countries' ISO codes (`countries`), and those of `only_countries` (every
    /// other country is blocked), for the web console's map. Older daemons leave them out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_countries: Vec<String>,
    /// The blocked networks' AS numbers (`asns`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asns: Vec<u32>,
}

/// An ISO code ("cn", "CN") or a name as `country_name` spells it ("China"), any case.
pub fn parse_country(s: &str) -> Option<[u8; 2]> {
    let s = s.trim();
    COUNTRIES.split('|').find_map(|e| {
        let (code, name) = e.split_once(' ')?;
        (code.len() == 2 && (code.eq_ignore_ascii_case(s) || name.eq_ignore_ascii_case(s)))
            .then(|| [code.as_bytes()[0], code.as_bytes()[1]])
    })
}

/// Sorted, merged intervals (touching ones join).
fn merge_intervals(mut v: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    v.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(v.len());
    for (lo, hi) in v {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// Intervals that come sorted by start (a database's ranges), merged as they come: only the
/// merged ones are kept, not every range (all but one country is most of the database).
fn merge_sorted(sorted: impl Iterator<Item = (u128, u128)>) -> Vec<(u128, u128)> {
    let mut out: Vec<(u128, u128)> = Vec::new();
    for (lo, hi) in sorted {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// `keep` (merged) cut out of `from` (merged).
fn subtract_intervals(from: Vec<(u128, u128)>, keep: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut out = Vec::new();
    let mut k = 0;
    for (mut lo, hi) in from {
        while k < keep.len() && keep[k].1 < lo {
            k += 1;
        }
        let mut j = k;
        while lo <= hi {
            match keep.get(j) {
                Some(&(klo, khi)) if klo <= hi => {
                    if klo > lo {
                        out.push((lo, klo - 1));
                    }
                    match khi.checked_add(1) {
                        Some(next) if khi < hi => lo = next,
                        _ => break,
                    }
                    j += 1;
                }
                _ => {
                    out.push((lo, hi));
                    break;
                }
            }
        }
    }
    out
}

/// A network as an interval of the databases' keys: IPv4 addresses, or IPv6 /64s (a
/// network inside one /64 keeps all of it).
fn key_interval(n: &Net) -> (bool, u128, u128) {
    match n.addr {
        IpAddr::V4(a) => {
            let lo = u32::from(a);
            (false, u128::from(lo), u128::from(lo | u32::MAX.checked_shr(u32::from(n.prefix)).unwrap_or(0)))
        }
        IpAddr::V6(a) => {
            let lo = (u128::from(a) >> 64) as u64;
            (true, u128::from(lo), u128::from(lo | u64::MAX.checked_shr(u32::from(n.prefix.min(64))).unwrap_or(0)))
        }
    }
}

/// What is known about one address.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Geo {
    pub country: Option<[u8; 2]>,
    /// From a city-level database: the city, and the latitude and longitude of the
    /// address's range, for maps.
    pub city: Option<String>,
    pub coords: Option<(f32, f32)>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

impl Geo {
    pub fn country_name(&self) -> Option<&'static str> {
        self.country.map(|c| country_name(&c))
    }

    /// "Germany", or "Germany, Berlin" when a city-level database names the city.
    pub fn place(&self) -> Option<String> {
        let country = self.country_name()?;
        Some(match &self.city {
            Some(city) => format!("{country}, {city}"),
            None => country.to_string(),
        })
    }

    /// "Germany / Hetzner Online GmbH (AS24940)" ("Germany, Berlin / ..." with a city), or
    /// whichever half is known.
    pub fn label(&self) -> Option<String> {
        let net = match (&self.org, self.asn) {
            (Some(o), Some(n)) => Some(format!("{o} (AS{n})")),
            (None, Some(n)) => Some(format!("AS{n}")),
            (Some(o), None) => Some(o.clone()),
            (None, None) => None,
        };
        match (self.place(), net) {
            (Some(c), Some(n)) => Some(format!("{c} / {n}")),
            (Some(c), None) => Some(c),
            (None, n) => n,
        }
    }
}

/// A label's place half back into a country and city: "Germany, Berlin" -> (DE, "Berlin"),
/// "Germany" -> (DE, None). No country's name holds a comma.
pub fn parse_place(s: &str) -> Option<([u8; 2], Option<&str>)> {
    if let Some(c) = country_code(s) {
        return Some((c, None));
    }
    let (country, city) = s.split_once(", ")?;
    Some((country_code(country)?, Some(city).filter(|c| !c.is_empty())))
}

/// Sorted, non-overlapping ranges. IPv6 is kept at /64 granularity (the upper 64 bits),
/// which halves memory; no database distinguishes locations inside a /64.
#[derive(Default)]
struct Ranges<K, V> {
    v: Vec<(K, K, V)>,
}

impl<K: Ord + Copy, V: PartialEq + Copy> Ranges<K, V> {
    fn push(&mut self, start: K, end: K, val: V, adjacent: impl Fn(K, K) -> bool) {
        if let Some(last) = self.v.last_mut() {
            // Neighbouring ranges with the same value merge (e.g. a country's consecutive blocks).
            if last.2 == val && adjacent(last.1, start) {
                last.1 = last.1.max(end);
                return;
            }
        }
        self.v.push((start, end, val));
    }

    fn finish(&mut self) {
        self.v.sort_unstable_by_key(|r| r.0);
        self.v.shrink_to_fit();
    }

    fn get(&self, k: K) -> Option<V> {
        let i = self.v.partition_point(|r| r.0 <= k).checked_sub(1)?;
        let r = self.v[i];
        (k <= r.1).then_some(r.2)
    }

    /// The values of the ranges overlapping `lo..=hi` (ranges don't overlap each other, so
    /// their ends are sorted too).
    fn within(&self, lo: K, hi: K) -> impl Iterator<Item = V> + '_ {
        let i = self.v.partition_point(|r| r.1 < lo);
        self.v[i..].iter().take_while(move |r| r.0 <= hi).map(|r| r.2)
    }
}

/// (country, asn, org index into `orgs`)
type AsVal = ([u8; 2], u32, u32);
/// (index into `locations`, latitude, longitude): a range's place, the coordinates in
/// hundredths of a degree (`NO_COORDS` without any). Inline, since a city-level database
/// gives each range its own.
type Loc = (u32, i16, i16);
const NO_COORDS: (i16, i16) = (i16::MIN, i16::MIN);

/// A country and, from a city-level database, a city ("" without): what ranges share.
#[derive(Clone, Debug, PartialEq)]
struct Location {
    country: [u8; 2],
    city: String,
}

#[derive(Default)]
pub struct GeoDb {
    loc4: Ranges<u32, Loc>,
    loc6: Ranges<u64, Loc>,
    locations: Vec<Location>,
    as4: Ranges<u32, AsVal>,
    as6: Ranges<u64, AsVal>,
    orgs: Vec<String>,
    /// `[geo] places`: networks pinned to a country, most specific first.
    pinned: Vec<(Net, [u8; 2])>,
    /// e.g. "country 712345 ranges, network 498765 ranges"
    pub summary: String,
}

const NO_CC: [u8; 2] = *b"--";
/// Longest organisation name kept (the longest real ones are about 100 characters).
const MAX_ORG_LEN: usize = 120;
const MAX_CITY_LEN: usize = 60;

/// The fields of one database line: iptoasn's tab-separated ones, or CSV as RFC 4180 has
/// it (quoted fields may hold commas and doubled quotes). Borrowed from the line wherever
/// nothing needs unescaping, so a wide line costs one allocation.
fn fields(line: &str) -> Vec<Cow<'_, str>> {
    if line.contains('\t') {
        return line.split('\t').map(Cow::Borrowed).collect();
    }
    let mut out = Vec::new();
    let mut rest = line;
    loop {
        let (field, after) = match rest.strip_prefix('"') {
            Some(q) => quoted(q),
            None => match rest.find(',') {
                Some(i) => (Cow::Borrowed(&rest[..i]), Some(&rest[i + 1..])),
                None => (Cow::Borrowed(rest), None),
            },
        };
        out.push(field);
        match after {
            Some(a) => rest = a,
            None => return out,
        }
    }
}

/// A quoted field, `q` being what follows its opening quote: the field, and what follows
/// the comma after it (`None` at the end of the line).
fn quoted(q: &str) -> (Cow<'_, str>, Option<&str>) {
    let mut text: Option<String> = None; // only once a doubled quote needs unescaping
    let mut s = q;
    loop {
        match s.find('"') {
            Some(i) if s[i + 1..].starts_with('"') => {
                let t = text.get_or_insert_with(String::new);
                t.push_str(&s[..i]);
                t.push('"');
                s = &s[i + 2..];
            }
            Some(i) => {
                let field = match text {
                    Some(mut t) => {
                        t.push_str(&s[..i]);
                        Cow::Owned(t)
                    }
                    None => Cow::Borrowed(&s[..i]),
                };
                return (field, s[i + 1..].find(',').map(|c| &s[i + 2 + c..]));
            }
            // an unterminated quote: the rest of the line is the field
            None => {
                let field = match text {
                    Some(mut t) => {
                        t.push_str(s);
                        Cow::Owned(t)
                    }
                    None => Cow::Borrowed(q),
                };
                return (field, None);
            }
        }
    }
}

enum Key {
    V4(u32, u32),
    V6(u64, u64),
}

fn key(start: &str, end: &str) -> Option<Key> {
    match (start.trim().parse::<IpAddr>().ok()?, end.trim().parse::<IpAddr>().ok()?) {
        (IpAddr::V4(a), IpAddr::V4(b)) => Some(Key::V4(a.into(), b.into())),
        (IpAddr::V6(a), IpAddr::V6(b)) => Some(Key::V6((u128::from(a) >> 64) as u64, (u128::from(b) >> 64) as u64)),
        _ => None,
    }
}

/// Two letters: a country or continent code.
fn is_code(s: &str) -> bool {
    let b = s.trim().as_bytes();
    b.len() == 2 && b.iter().all(u8::is_ascii_alphabetic)
}

fn cc(s: &str) -> Option<[u8; 2]> {
    let s = s.trim();
    (is_code(s) && s != "ZZ").then(|| [s.as_bytes()[0].to_ascii_uppercase(), s.as_bytes()[1].to_ascii_uppercase()])
}

/// An AS number, with or without the "AS" some files prefix it with; 0 is "none".
fn as_number(s: &str) -> Option<u32> {
    let s = s.trim();
    let digits = s.strip_prefix("AS").or_else(|| s.strip_prefix("as")).unwrap_or(s);
    digits.parse::<u32>().ok().filter(|n| *n > 0)
}

/// Latitude and longitude in hundredths of a degree, when both are given and plausible
/// (0, 0, in the Gulf of Guinea, is a database's "unknown").
fn coords(lat: &str, lon: &str) -> Option<(i16, i16)> {
    let (lat, lon) = (lat.trim().parse::<f32>().ok()?, lon.trim().parse::<f32>().ok()?);
    if !(lat.abs() <= 90.0 && lon.abs() <= 180.0) || (lat == 0.0 && lon == 0.0) {
        return None;
    }
    Some(((lat * 100.0).round() as i16, (lon * 100.0).round() as i16))
}

/// iptoasn descriptions start with the registry handle: "GTELECOM-AS-AP Gtelecom Pty Ltd".
fn tidy_org(desc: &str) -> &str {
    let desc = desc.trim();
    match desc.split_once(' ') {
        Some((handle, rest))
            if !rest.trim().is_empty() && handle.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_') =>
        {
            rest.trim()
        }
        _ => desc,
    }
}

/// Which columns hold what. Known by their shape, without a header row: DB-IP's lite
/// `start,end,country` and `start,end,asn,name`; its commercial files, which put the
/// continent before the country (IP to Country: 4 columns; the city lite: 8, with the city
/// and coordinates; IP to Location: 15; IP to ISP: 9 and IP to Location + ISP: 20, ending
/// in `isp_name,as_number,usage_type,connection_type,organization_name`); and iptoasn's
/// `start,end,asn,country,description`. A header row names the columns of anything else
/// (`country`, `country_code`, `city`, `latitude`, `longitude`, `asn`, `as_number`,
/// `organization_name`, `name`, `isp_name`, ...).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Layout {
    Place {
        cc: usize,
        city: Option<usize>,
        coords: Option<(usize, usize)>,
    },
    Network {
        asn: usize,
        /// the registration country, where the file has one
        cc: Option<usize>,
        /// organisation name columns, first choice first: the AS organisation, then the ISP
        orgs: [Option<usize>; 2],
        /// descriptions start with a registry handle (iptoasn)
        handles: bool,
    },
}

impl Layout {
    /// From a header row, when it names what the reader needs.
    fn from_header(f: &[Cow<str>], is_country: bool) -> Option<Layout> {
        let names: Vec<String> =
            f.iter().map(|s| s.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()).collect();
        let col = |wanted: &[&str]| wanted.iter().find_map(|w| names.iter().position(|n| n.as_str() == *w));
        let cc = col(&["countrycode", "countryisocode", "countrycode2", "countryiso", "isocode", "cc", "country"]);
        if is_country {
            let coords = col(&["latitude", "lat"]).zip(col(&["longitude", "lon", "lng", "long"]));
            return Some(Layout::Place { cc: cc?, city: col(&["city", "cityname"]), coords });
        }
        let asn = col(&["asn", "asnumber", "autonomoussystemnumber", "asnum", "as"])?;
        let org = col(&[
            "asorganization",
            "autonomoussystemorganization",
            "asname",
            "asnname",
            "asorg",
            "organizationname",
            "organisationname",
            "organization",
            "organisation",
            "orgname",
            "org",
            "name",
            "description",
        ]);
        Some(Layout::Network { asn, cc, orgs: [org, col(&["ispname", "isp"])], handles: false })
    }

    /// From the first data row's shape.
    fn from_row(f: &[Cow<str>], is_country: bool) -> Option<Layout> {
        let code = |i: usize| f.get(i).is_some_and(|s| is_code(s));
        let num = |i: usize| f.get(i).and_then(|s| as_number(s)).is_some();
        if is_country {
            // DB-IP's commercial files put the continent before the country
            let cc = if f.len() >= 4 && code(3) {
                3
            } else if code(2) {
                2
            } else {
                return None;
            };
            let (city, coords) = match f.len() {
                8 if cc == 3 => (Some(5), Some((6, 7))),
                15 | 20 if cc == 3 => (Some(7), Some((9, 10))),
                _ => (None, None),
            };
            return Some(Layout::Place { cc, city, coords });
        }
        let net = |asn, cc, orgs, handles| Some(Layout::Network { asn, cc, orgs, handles });
        match f.len() {
            3 if num(2) => net(2, None, [None, None], false),
            4 if num(2) => net(2, None, [Some(3), None], false),
            5 if num(2) => net(2, Some(3), [Some(4), None], true),
            9 if num(5) => net(5, Some(3), [Some(8), Some(4)], false),
            20 if num(16) => net(16, Some(3), [Some(19), Some(15)], false),
            _ => None,
        }
    }

    /// The row's usable content, if any.
    fn row<'a>(&self, f: &'a [Cow<'a, str>]) -> Option<Row<'a>> {
        match *self {
            Layout::Place { cc: i, city, coords: c } => Some(Row::Place {
                country: cc(f.get(i)?)?,
                city: city.and_then(|i| f.get(i)).map_or("", |s| s.trim()),
                coords: c.and_then(|(lat, lon)| coords(f.get(lat)?, f.get(lon)?)),
            }),
            Layout::Network { asn, cc: country, orgs, handles } => {
                let asn = as_number(f.get(asn)?)?;
                let country = country.and_then(|i| f.get(i)).and_then(|s| cc(s)).unwrap_or(NO_CC);
                let org = orgs.iter().flatten().filter_map(|&i| f.get(i)).map(|s| s.trim()).find(|s| !s.is_empty()).unwrap_or("");
                Some(Row::Network { country, asn, org: if handles { tidy_org(org) } else { org } })
            }
        }
    }
}

/// One database row, as the loader keeps it.
enum Row<'a> {
    Place {
        country: [u8; 2],
        city: &'a str,
        coords: Option<(i16, i16)>,
    },
    /// The network's registration country (`--` without), AS number and name.
    Network {
        country: [u8; 2],
        asn: u32,
        org: &'a str,
    },
}

/// Streams a database (CSV, or iptoasn's TSV), calling `f` for each usable row. The
/// column layout is settled once: by a header row when the file has one, else by the
/// first data row's shape (see `Layout`).
fn parse_rows(r: impl BufRead, is_country: bool, max_lines: usize, mut f: impl FnMut(Key, Row)) -> Result<()> {
    let mut layout: Option<Layout> = None;
    let (mut first, mut seen_data, mut columns) = (true, false, 0);
    for_each_line(r, max_lines, |line| {
        let line = if std::mem::take(&mut first) { line.trim_start_matches('\u{feff}') } else { line };
        let fields = fields(line);
        let Some(k) = fields.get(1).and_then(|end| key(&fields[0], end)) else {
            if !seen_data && layout.is_none() {
                layout = Layout::from_header(&fields, is_country);
            }
            return;
        };
        seen_data = true;
        if layout.is_none() {
            layout = Layout::from_row(&fields, is_country);
            columns = fields.len();
        }
        if let Some(row) = layout.and_then(|l| l.row(&fields)) {
            f(k, row);
        }
    })?;
    if layout.is_none() {
        if !seen_data {
            bail!("no address ranges found (not a DB-IP CSV or iptoasn TSV file?)");
        }
        bail!(
            "unknown column layout ({columns} columns): not a DB-IP or iptoasn file; a header row naming the columns ({}) makes any CSV readable",
            if is_country { "country, and city, latitude, longitude" } else { "asn, organization_name or name, isp_name" }
        );
    }
    Ok(())
}

impl GeoDb {
    /// Loads the databases in `[geo] dir` and pins its `places`.
    pub fn open(cfg: &GeoCfg) -> Result<GeoDb> {
        let mut db = GeoDb::load(&cfg.dir, cfg.max_ranges)?;
        db.pinned = cfg.pinned();
        if !db.pinned.is_empty() {
            db.summary += &format!(", {} networks pinned by [geo] places", db.pinned.len());
        }
        db.summary += &format!(", about {} MB in memory", db.approx_bytes() >> 20);
        Ok(db)
    }

    /// About how much memory the loaded database takes.
    pub fn approx_bytes(&self) -> usize {
        use std::mem::size_of;
        let ranges = self.loc4.v.capacity() * size_of::<(u32, u32, Loc)>()
            + self.loc6.v.capacity() * size_of::<(u64, u64, Loc)>()
            + self.as4.v.capacity() * size_of::<(u32, u32, AsVal)>()
            + self.as6.v.capacity() * size_of::<(u64, u64, AsVal)>();
        let names = self.orgs.iter().map(|o| o.capacity() + size_of::<String>()).sum::<usize>()
            + self.locations.iter().map(|l| l.city.capacity() + size_of::<Location>()).sum::<usize>();
        ranges + names
    }

    /// What to tell when the database takes more than half of the memory the service may
    /// use (`limit`, bytes): a city or commercial database loads within `max_ranges`, but
    /// what is left for everything else (the addresses tracked in a flood, the reports from
    /// the actions log) is then too little, and the kernel ends the service.
    pub fn size_warning(&self, limit: Option<u64>) -> Option<String> {
        let (size, limit) = (self.approx_bytes() as u64, limit?);
        (size > limit / 2).then(|| {
            format!(
                "the geo database takes about {} MB of the {} MB the service may use (MemoryMax): raise the limit \
                 (systemctl edit vpsfort: [Service] MemoryMax=384M), or load less ([geo] max_ranges, a country and network database instead of a city one)",
                size >> 20,
                limit >> 20
            )
        })
    }
}

impl GeoDb {
    /// Loads whichever of `<dir>/country.gz` and `<dir>/asn.gz` exist, each of at most
    /// `max_ranges` ranges.
    pub fn load(dir: &Path, max_ranges: usize) -> Result<GeoDb> {
        let mut db = GeoDb::default();
        let mut parts = Vec::new();
        for (name, is_country) in [("country.gz", true), ("asn.gz", false)] {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            let file = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
            let n = db
                .read_within(BufReader::new(flate2::read::GzDecoder::new(file)), is_country, max_ranges, names_bound(is_country))
                .with_context(|| format!("reading {}", path.display()))?;
            let cities = db.locations.iter().filter(|l| !l.city.is_empty()).count();
            parts.push(match (is_country, cities) {
                (true, 0) => format!("country {n} ranges"),
                (true, c) => format!("country {n} ranges in {c} cities"),
                (false, _) => format!("network {n} ranges"),
            });
        }
        if parts.is_empty() {
            bail!("no geo database in {} yet", dir.display());
        }
        db.summary = parts.join(", ");
        Ok(db)
    }

    /// Reads one database (CSV or iptoasn TSV); returns the number of ranges kept.
    pub fn read(&mut self, r: impl BufRead, is_country: bool) -> Result<usize> {
        self.read_within(r, is_country, MAX_RANGES, names_bound(is_country))
    }

    /// `max_names` bounds a country database's places, a network database's organisation
    /// names.
    fn read_within(&mut self, r: impl BufRead, is_country: bool, max_ranges: usize, max_names: usize) -> Result<usize> {
        let mut org_ids: std::collections::HashMap<String, u32> =
            self.orgs.iter().enumerate().map(|(i, o)| (o.clone(), i as u32)).collect();
        let mut loc_ids: std::collections::HashMap<([u8; 2], String), u32> =
            self.locations.iter().enumerate().map(|(i, l)| ((l.country, l.city.clone()), i as u32)).collect();
        let mut rows = 0usize;
        let mut too_big = false;
        let adjacent = |e: u32, s: u32| e.checked_add(1) == Some(s);
        let adjacent6 = |e: u64, s: u64| e.checked_add(1) == Some(s);
        parse_rows(r, is_country, max_lines(max_ranges), |k, row| {
            if too_big {
                return;
            }
            rows += 1;
            match row {
                Row::Place { country, city, coords } => {
                    // Downloaded text that reaches terminals (TUI), XMPP messages and the digest.
                    let key = (country, crate::event::clean(city, MAX_CITY_LEN));
                    let id = match loc_ids.get(&key) {
                        Some(id) => *id,
                        None => {
                            let id = self.locations.len() as u32;
                            self.locations.push(Location { country, city: key.1.clone() });
                            loc_ids.insert(key, id);
                            id
                        }
                    };
                    let (lat, lon) = coords.unwrap_or(NO_COORDS);
                    match k {
                        Key::V4(a, b) => self.loc4.push(a, b, (id, lat, lon), adjacent),
                        Key::V6(a, b) => self.loc6.push(a, b, (id, lat, lon), adjacent6),
                    }
                }
                Row::Network { country, asn, org } => {
                    let org = crate::event::clean(org, MAX_ORG_LEN);
                    let org = org.as_str();
                    let id = match org_ids.get(org) {
                        Some(id) => *id,
                        None => {
                            let id = self.orgs.len() as u32;
                            self.orgs.push(org.to_string());
                            org_ids.insert(org.to_string(), id);
                            id
                        }
                    };
                    match k {
                        Key::V4(a, b) => self.as4.push(a, b, (country, asn, id), adjacent),
                        Key::V6(a, b) => self.as6.push(a, b, (country, asn, id), adjacent6),
                    }
                }
            }
            // what is kept is bounded, within the service's memory limit
            let (kept, names) = if is_country {
                (self.loc4.v.len() + self.loc6.v.len(), self.locations.len())
            } else {
                (self.as4.v.len() + self.as6.v.len(), self.orgs.len())
            };
            if kept > max_ranges || names > max_names {
                too_big = true;
            }
        })?;
        if too_big {
            bail!("{}", too_big_msg(max_ranges, max_names, is_country));
        }
        if rows == 0 {
            bail!("no address ranges found (not a DB-IP CSV or iptoasn TSV file?)");
        }
        self.orgs.shrink_to_fit();
        self.locations.shrink_to_fit();
        let n = if is_country {
            self.loc4.finish();
            self.loc6.finish();
            self.loc4.v.len() + self.loc6.v.len()
        } else {
            self.as4.finish();
            self.as6.finish();
            self.as4.v.len() + self.as6.v.len()
        };
        Ok(n)
    }

    pub fn lookup(&self, ip: IpAddr) -> Geo {
        let (loc, net) = match ip {
            IpAddr::V4(a) => {
                let k = u32::from(a);
                (self.loc4.get(k), self.as4.get(k))
            }
            IpAddr::V6(a) => {
                let k = (u128::from(a) >> 64) as u64;
                (self.loc6.get(k), self.as6.get(k))
            }
        };
        let loc = loc.and_then(|(i, lat, lon)| Some((self.locations.get(i as usize)?, (lat, lon))));
        // A pinned network first; then the geolocated country; the network's registration
        // country is a fallback.
        let pinned = self.pinned.iter().find(|(n, _)| n.contains(ip)).map(|(_, c)| *c);
        let country = pinned.or(loc.map(|(l, _)| l.country)).or(net.map(|n| n.0).filter(|c| *c != NO_CC));
        // a pinned network's city and coordinates are the database's mistake too
        let loc = loc.filter(|_| pinned.is_none());
        Geo {
            country,
            city: loc.map(|(l, _)| &l.city).filter(|c| !c.is_empty()).cloned(),
            coords: loc.and_then(|(_, (lat, lon))| (lat != NO_COORDS.0).then(|| (f32::from(lat) / 100.0, f32::from(lon) / 100.0))),
            asn: net.map(|n| n.1),
            org: net.and_then(|n| self.orgs.get(n.2 as usize)).filter(|o| !o.is_empty()).cloned(),
        }
    }

    pub fn label(&self, ip: IpAddr) -> Option<String> {
        self.lookup(ip).label()
    }

    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let k = match ip {
            IpAddr::V4(a) => self.as4.get(u32::from(a)),
            IpAddr::V6(a) => self.as6.get((u128::from(a) >> 64) as u64),
        };
        k.map(|v| v.1)
    }

    /// The networks (as CIDRs) the network database gives these ASNs.
    pub fn networks_of(&self, asns: &std::collections::BTreeSet<u32>) -> Vec<Net> {
        let mut out = Vec::new();
        for (lo, hi, v) in &self.as4.v {
            if asns.contains(&v.1) {
                for (a, p) in cidrs(u128::from(*lo), u128::from(*hi), 32) {
                    out.push(Net::new(IpAddr::V4((a as u32).into()), p));
                }
            }
        }
        for (lo, hi, v) in &self.as6.v {
            if asns.contains(&v.1) {
                // kept per /64: the upper 64 bits
                for (a, p) in cidrs(u128::from(*lo), u128::from(*hi), 64) {
                    out.push(Net::new(IpAddr::V6((a << 64).into()), p));
                }
            }
        }
        out
    }

    /// The networks `[geoblock]` drops: the country ranges of `countries` (with
    /// `only_countries`, of every other country) and the network ranges of `asns`, merged,
    /// less `keep` (allowlisted networks, this host, the cluster peers) and special-purpose
    /// ranges, cut out exactly; as few CIDRs as cover the rest.
    pub fn blocked_networks(&self, cfg: &GeoblockCfg, keep: &[Net]) -> Vec<Net> {
        let (block, only) = (GeoblockCfg::codes(&cfg.countries), GeoblockCfg::codes(&cfg.only_countries));
        let blocked = |c: &[u8; 2]| block.contains(c) || (!only.is_empty() && !only.contains(c));
        let placed = |v: &Loc| self.locations.get(v.0 as usize).is_some_and(|l| blocked(&l.country));
        let asns: std::collections::BTreeSet<u32> = cfg.asns.iter().copied().collect();
        let bogons: Vec<Net> = crate::feeds::BOGONS.iter().map(|b| b.parse().expect("valid bogon")).collect();
        let mut out = Vec::new();
        for v6 in [false, true] {
            // each database's ranges are sorted and apart: merged while read, then together
            let (countries, networks) = if v6 {
                (
                    merge_sorted(self.loc6.v.iter().filter(|r| placed(&r.2)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                    merge_sorted(self.as6.v.iter().filter(|r| asns.contains(&r.2 .1)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                )
            } else {
                (
                    merge_sorted(self.loc4.v.iter().filter(|r| placed(&r.2)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                    merge_sorted(self.as4.v.iter().filter(|r| asns.contains(&r.2 .1)).map(|r| (u128::from(r.0), u128::from(r.1)))),
                )
            };
            let ranges = if networks.is_empty() { countries } else { merge_intervals([countries, networks].concat()) };
            let holes: Vec<(u128, u128)> =
                keep.iter().chain(&bogons).map(key_interval).filter(|(is6, ..)| *is6 == v6).map(|(_, lo, hi)| (lo, hi)).collect();
            for (lo, hi) in subtract_intervals(ranges, &merge_intervals(holes)) {
                if v6 {
                    out.extend(cidrs(lo, hi, 64).into_iter().map(|(a, p)| Net::new(IpAddr::V6((a << 64).into()), p)));
                } else {
                    out.extend(cidrs(lo, hi, 32).into_iter().map(|(a, p)| Net::new(IpAddr::V4((a as u32).into()), p)));
                }
            }
        }
        out
    }

    /// Whether the addresses of `net` the network database knows all belong to one network
    /// (ASN): a ban on it then can't reach another provider's customers. True without that
    /// database.
    pub fn one_network(&self, net: &Net) -> bool {
        fn same(mut asns: impl Iterator<Item = u32>) -> bool {
            let first = asns.next();
            asns.all(|a| Some(a) == first)
        }
        match net.addr {
            IpAddr::V4(a) => {
                let lo = u32::from(a);
                same(self.as4.within(lo, lo | u32::MAX.checked_shr(u32::from(net.prefix)).unwrap_or(0)).map(|v| v.1))
            }
            IpAddr::V6(a) => {
                let lo = (u128::from(a) >> 64) as u64;
                same(self.as6.within(lo, lo | u64::MAX.checked_shr(u32::from(net.prefix)).unwrap_or(0)).map(|v| v.1))
            }
        }
    }
}

/// The CIDR blocks covering `lo..=hi` in a `bits`-bit address space: (start, prefix length).
fn cidrs(mut lo: u128, hi: u128, bits: u32) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    while lo <= hi {
        let align = if lo == 0 { bits } else { lo.trailing_zeros().min(bits) };
        let span = hi - lo + 1;
        let fits = 127 - span.leading_zeros().min(127); // floor(log2(span)), span >= 1
        let size = align.min(fits);
        out.push((lo, (bits - size) as u8));
        match lo.checked_add(1u128 << size) {
            Some(next) => lo = next,
            None => break,
        }
    }
    out
}

/// Database lines are short and DB-IP's files have 0.7-8 million of them: a file far beyond
/// is a broken or hostile download, and parsing it would take minutes. `[geo] max_ranges`
/// raised for a big database raises the line bound with it (`max_lines`).
const MAX_LINE: usize = 4096;
const MAX_LINES: usize = 10_000_000;
/// What is kept of one database is bounded too, within the service's memory limit: DB-IP's
/// lite databases hold about 0.5-0.7 million ranges each, ~80,000 network names and one
/// place per country; its city lite 7.8 million ranges (`[geo] max_ranges` can allow them,
/// with the unit's memory) in some 100,000 cities.
pub const MAX_RANGES: usize = 2_000_000;
const MAX_ORGS: usize = 300_000;
const MAX_LOCATIONS: usize = 300_000;

fn max_lines(max_ranges: usize) -> usize {
    MAX_LINES.max(max_ranges.saturating_mul(5))
}

/// The bound on names: a country database's places, a network database's organisations.
fn names_bound(is_country: bool) -> usize {
    if is_country {
        MAX_LOCATIONS
    } else {
        MAX_ORGS
    }
}

fn too_big_msg(max_ranges: usize, max_names: usize, is_country: bool) -> String {
    format!(
        "more than {max_ranges} ranges or {max_names} {}: the database would not fit in memory ([geo] max_ranges and the unit's \
         MemoryMax would have to grow with it; the lite databases and DB-IP's IP to Country fit as they are)",
        if is_country { "places" } else { "network names" }
    )
}

/// Calls `f` for each line, bounded in line length and count.
fn for_each_line(mut r: impl BufRead, max_lines: usize, mut f: impl FnMut(&str)) -> Result<()> {
    let mut buf = Vec::new();
    for _ in 0..max_lines {
        buf.clear();
        let n = std::io::Read::take(&mut r, MAX_LINE as u64 + 1).read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_LINE && buf.last() != Some(&b'\n') {
            bail!("line longer than {MAX_LINE} bytes: not a geo database");
        }
        f(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']));
    }
    bail!("more than {max_lines} lines: not a geo database")
}

/// Counts ranges as `Ranges::push` keeps them (neighbours with the same value merge),
/// holding one at a time: the download check must agree with the loader, without its
/// memory.
struct Tally<K, V> {
    last: Option<(K, V)>,
    n: usize,
}

impl<K, V> Default for Tally<K, V> {
    fn default() -> Self {
        Tally { last: None, n: 0 }
    }
}

impl<K: Ord + Copy, V: PartialEq> Tally<K, V> {
    fn push(&mut self, start: K, end: K, val: V, adjacent: impl Fn(K, K) -> bool) {
        if let Some((e, v)) = &mut self.last {
            if *v == val && adjacent(*e, start) {
                *e = (*e).max(end);
                return;
            }
        }
        self.last = Some((end, val));
        self.n += 1;
    }
}

/// Number of ranges in a database, as `GeoDb::read` would keep them; an error for one too
/// big to load (more than `MAX_RANGES` ranges, or more names than fit).
#[cfg(test)]
fn count_ranges(r: impl BufRead, is_country: bool) -> Result<usize> {
    count_ranges_within(r, is_country, MAX_RANGES, names_bound(is_country))
}

/// `count_ranges` with the bounds given: `refresh` checks each download with `[geo]
/// max_ranges` before it replaces the copy in use.
fn count_ranges_within(r: impl BufRead, is_country: bool, max_ranges: usize, max_names: usize) -> Result<usize> {
    use std::hash::{Hash, Hasher};
    fn digest<T: Hash>(x: T) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        x.hash(&mut h);
        h.finish()
    }
    // names by hash: a few MB at most, and nothing kept of a hostile file's text
    let mut names = std::collections::HashSet::new();
    let (mut p4, mut p6) = (Tally::<u32, (u64, i16, i16)>::default(), Tally::<u64, (u64, i16, i16)>::default());
    let (mut n4, mut n6) = (Tally::<u32, ([u8; 2], u32, u64)>::default(), Tally::<u64, ([u8; 2], u32, u64)>::default());
    let adjacent = |e: u32, s: u32| e.checked_add(1) == Some(s);
    let adjacent6 = |e: u64, s: u64| e.checked_add(1) == Some(s);
    parse_rows(r, is_country, max_lines(max_ranges), |k, row| match row {
        Row::Place { country, city, coords } => {
            let id = digest((country, city));
            if names.len() <= max_names {
                names.insert(id);
            }
            let (lat, lon) = coords.unwrap_or(NO_COORDS);
            match k {
                Key::V4(a, b) => p4.push(a, b, (id, lat, lon), adjacent),
                Key::V6(a, b) => p6.push(a, b, (id, lat, lon), adjacent6),
            }
        }
        Row::Network { country, asn, org } => {
            let id = digest(org);
            if names.len() <= max_names {
                names.insert(id);
            }
            match k {
                Key::V4(a, b) => n4.push(a, b, (country, asn, id), adjacent),
                Key::V6(a, b) => n6.push(a, b, (country, asn, id), adjacent6),
            }
        }
    })?;
    let n = p4.n + p6.n + n4.n + n6.n;
    if n > max_ranges || names.len() > max_names {
        bail!("{n} ranges and {} names: {}", names.len(), too_big_msg(max_ranges, max_names, is_country));
    }
    Ok(n)
}

/// Current and previous `YYYY-MM` (UTC).
fn months(now: crate::time::Micros) -> [String; 2] {
    let (y, m, _) = crate::time::civil_from_days(now.div_euclid(86_400 * crate::time::SEC));
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")]
}

/// Largest compressed database accepted (DB-IP's are ~5-10 MB).
const MAX_DOWNLOAD: u64 = 200 << 20;

/// Downloads the databases that are missing or older than `refresh`. Each download is
/// checked (it must decompress and parse) before it replaces the previous copy.
/// Returns what was downloaded, and the problems met.
pub fn refresh(cfg: &GeoCfg, now: crate::time::Micros) -> (Vec<String>, Vec<String>) {
    let (mut done, mut errors) = (Vec::new(), Vec::new());
    let _ = std::fs::create_dir_all(&cfg.dir);
    for (url, name, is_country) in [(&cfg.country_url, "country.gz", true), (&cfg.asn_url, "asn.gz", false)] {
        if url.is_empty() {
            let _ = std::fs::remove_file(cfg.dir.join(name));
            continue;
        }
        let path = cfg.dir.join(name);
        let age = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if age.is_some_and(|a| a.as_secs() < cfg.refresh.0) {
            continue;
        }
        let mut last_err = None;
        for month in months(now) {
            let u = url.replace("{month}", &month);
            // Streamed to a file and validated from there while decompressing: neither the
            // download nor a second database is ever held in memory (MemoryMax=128M).
            let tmp = path.with_extension("tmp");
            let result = (|| -> Result<usize> {
                let mut file = std::fs::File::create(&tmp)?;
                crate::feeds::fetch_into(&cfg.fetch, &u, &mut file, MAX_DOWNLOAD)?;
                file.sync_all()?;
                let gz = flate2::read::GzDecoder::new(std::fs::File::open(&tmp)?);
                let n = count_ranges_within(BufReader::new(gz), is_country, cfg.max_ranges, names_bound(is_country))
                    .context("checking the download")?;
                if n < 1000 {
                    bail!("only {n} ranges");
                }
                std::fs::rename(&tmp, &path)?;
                Ok(n)
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            match result {
                Ok(n) => {
                    done.push(format!("{u} ({n} ranges)"));
                    last_err = None;
                    break;
                }
                Err(e) => last_err = Some(format!("{u}: {e:#}")),
            }
            if !url.contains("{month}") {
                break;
            }
        }
        if let Some(e) = last_err {
            // the copy in use ages while the downloads fail: say so, before it misplaces much
            let old =
                age.filter(|a| a.as_secs() >= OLD_DATABASE).map(|a| format!(" (the copy in use is {} days old)", a.as_secs() / 86_400));
            errors.push(format!("{e}{}", old.unwrap_or_default()));
        }
    }
    (done, errors)
}

/// A database this old, with the downloads failing, is named in the alert: the lite
/// databases move thousands of networks a month.
const OLD_DATABASE: u64 = 60 * 86_400;

/// Credit line required by DB-IP's CC BY 4.0 licence, for texts that show its free data
/// (the commercial editions, from the same host, need none).
pub fn attribution(cfg: &GeoCfg, loaded: bool) -> String {
    let lite = [&cfg.country_url, &cfg.asn_url].iter().any(|u| u.contains("db-ip.com/free/"));
    if loaded && lite {
        "\nIP locations: DB-IP.com (CC BY 4.0)\n".into()
    } else {
        String::new()
    }
}

/// Bytes a database of up to `max_ranges` ranges may need while it loads (16-24 per range,
/// about twice that while the vectors grow), plus the rest of the daemon and the network
/// database.
pub fn memory_need(max_ranges: usize) -> u64 {
    max_ranges as u64 * 32 + (64 << 20)
}

/// A warning when `[geo] max_ranges` was raised beyond what the unit's memory limit (cgroup
/// v2 `memory.max`) holds; nothing with the default bound, without a limit, or outside a
/// cgroup (not Linux, or run by hand).
pub fn memory_advice(cfg: &GeoCfg) -> Option<String> {
    advice(cfg.max_ranges, cgroup_memory_max()?)
}

fn advice(max_ranges: usize, limit: u64) -> Option<String> {
    let need = memory_need(max_ranges);
    (max_ranges > MAX_RANGES && need > limit).then(|| {
        format!(
            "[geo] max_ranges = {max_ranges} may need about {} MB while a database loads, more than the unit's memory limit of {} MB: \
             raise MemoryHigh and MemoryMax with `systemctl edit vpsfort` (README, \"Memory\"), or the daemon is killed at the limit",
            need >> 20,
            limit >> 20
        )
    })
}

/// The unit's `memory.max` (cgroup v2), found through /proc/self/cgroup; `None` when
/// unlimited ("max") or unknown.
pub fn cgroup_memory_max() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    parse_limit(&std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max")).ok()?)
}

fn parse_limit(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// English short names of ISO 3166-1 alpha-2 codes.
pub fn country_name(code: &[u8; 2]) -> &'static str {
    let code = std::str::from_utf8(code).unwrap_or("??");
    COUNTRIES.split('|').find_map(|e| e.strip_prefix(code).and_then(|n| n.strip_prefix(' '))).unwrap_or(match code {
        "EU" => "European Union",
        "AP" => "Asia/Pacific",
        _ => "unknown country",
    })
}

/// The code of a country as `country_name` spells it ("Germany" -> DE).
pub fn country_code(name: &str) -> Option<[u8; 2]> {
    COUNTRIES.split('|').find_map(|e| {
        let (code, n) = e.split_once(' ')?;
        (n == name && code.len() == 2).then(|| [code.as_bytes()[0], code.as_bytes()[1]])
    })
}

const COUNTRIES: &str = "AD Andorra|AE United Arab Emirates|AF Afghanistan|AG Antigua and Barbuda|AI Anguilla|AL Albania|AM Armenia|\
AO Angola|AQ Antarctica|AR Argentina|AS American Samoa|AT Austria|AU Australia|AW Aruba|AX Åland Islands|AZ Azerbaijan|\
BA Bosnia and Herzegovina|BB Barbados|BD Bangladesh|BE Belgium|BF Burkina Faso|BG Bulgaria|BH Bahrain|BI Burundi|BJ Benin|\
BL Saint Barthélemy|BM Bermuda|BN Brunei|BO Bolivia|BQ Caribbean Netherlands|BR Brazil|BS Bahamas|BT Bhutan|BV Bouvet Island|\
BW Botswana|BY Belarus|BZ Belize|CA Canada|CC Cocos Islands|CD DR Congo|CF Central African Republic|CG Congo|CH Switzerland|\
CI Côte d'Ivoire|CK Cook Islands|CL Chile|CM Cameroon|CN China|CO Colombia|CR Costa Rica|CU Cuba|CV Cape Verde|CW Curaçao|\
CX Christmas Island|CY Cyprus|CZ Czechia|DE Germany|DJ Djibouti|DK Denmark|DM Dominica|DO Dominican Republic|DZ Algeria|\
EC Ecuador|EE Estonia|EG Egypt|EH Western Sahara|ER Eritrea|ES Spain|ET Ethiopia|FI Finland|FJ Fiji|FK Falkland Islands|\
FM Micronesia|FO Faroe Islands|FR France|GA Gabon|GB United Kingdom|GD Grenada|GE Georgia|GF French Guiana|GG Guernsey|GH Ghana|\
GI Gibraltar|GL Greenland|GM Gambia|GN Guinea|GP Guadeloupe|GQ Equatorial Guinea|GR Greece|GS South Georgia|GT Guatemala|GU Guam|\
GW Guinea-Bissau|GY Guyana|HK Hong Kong|HM Heard and McDonald Islands|HN Honduras|HR Croatia|HT Haiti|HU Hungary|ID Indonesia|\
IE Ireland|IL Israel|IM Isle of Man|IN India|IO British Indian Ocean Territory|IQ Iraq|IR Iran|IS Iceland|IT Italy|JE Jersey|\
JM Jamaica|JO Jordan|JP Japan|KE Kenya|KG Kyrgyzstan|KH Cambodia|KI Kiribati|KM Comoros|KN Saint Kitts and Nevis|KP North Korea|\
KR South Korea|KW Kuwait|KY Cayman Islands|KZ Kazakhstan|LA Laos|LB Lebanon|LC Saint Lucia|LI Liechtenstein|LK Sri Lanka|\
LR Liberia|LS Lesotho|LT Lithuania|LU Luxembourg|LV Latvia|LY Libya|MA Morocco|MC Monaco|MD Moldova|ME Montenegro|\
MF Saint Martin|MG Madagascar|MH Marshall Islands|MK North Macedonia|ML Mali|MM Myanmar|MN Mongolia|MO Macao|\
MP Northern Mariana Islands|MQ Martinique|MR Mauritania|MS Montserrat|MT Malta|MU Mauritius|MV Maldives|MW Malawi|MX Mexico|\
MY Malaysia|MZ Mozambique|NA Namibia|NC New Caledonia|NE Niger|NF Norfolk Island|NG Nigeria|NI Nicaragua|NL Netherlands|\
NO Norway|NP Nepal|NR Nauru|NU Niue|NZ New Zealand|OM Oman|PA Panama|PE Peru|PF French Polynesia|PG Papua New Guinea|\
PH Philippines|PK Pakistan|PL Poland|PM Saint Pierre and Miquelon|PN Pitcairn|PR Puerto Rico|PS Palestine|PT Portugal|PW Palau|\
PY Paraguay|QA Qatar|RE Réunion|RO Romania|RS Serbia|RU Russia|RW Rwanda|SA Saudi Arabia|SB Solomon Islands|SC Seychelles|\
SD Sudan|SE Sweden|SG Singapore|SH Saint Helena|SI Slovenia|SJ Svalbard and Jan Mayen|SK Slovakia|SL Sierra Leone|SM San Marino|\
SN Senegal|SO Somalia|SR Suriname|SS South Sudan|ST São Tomé and Príncipe|SV El Salvador|SX Sint Maarten|SY Syria|SZ Eswatini|\
TC Turks and Caicos Islands|TD Chad|TF French Southern Territories|TG Togo|TH Thailand|TJ Tajikistan|TK Tokelau|TL Timor-Leste|\
TM Turkmenistan|TN Tunisia|TO Tonga|TR Türkiye|TT Trinidad and Tobago|TV Tuvalu|TW Taiwan|TZ Tanzania|UA Ukraine|UG Uganda|\
UM US Minor Outlying Islands|US United States|UY Uruguay|UZ Uzbekistan|VA Vatican City|VC Saint Vincent and the Grenadines|\
VE Venezuela|VG British Virgin Islands|VI US Virgin Islands|VN Vietnam|VU Vanuatu|WF Wallis and Futuna|WS Samoa|XK Kosovo|\
YE Yemen|YT Mayotte|ZA South Africa|ZM Zambia|ZW Zimbabwe";

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn ranges_as_cidrs() {
        let c = |lo: u128, hi: u128, bits| super::cidrs(lo, hi, bits);
        assert_eq!(c(0, u128::from(u32::MAX), 32), vec![(0, 0)]);
        // 10.0.0.0 - 10.0.2.255: a /23 and a /24
        let ten = 10u128 << 24;
        assert_eq!(c(ten, ten + 767, 32), vec![(ten, 23), (ten + 512, 24)]);
        assert_eq!(c(5, 5, 32), vec![(5, 32)]);
        assert_eq!(c(1, 6, 32), vec![(1, 32), (2, 31), (4, 31), (6, 32)]);
        assert_eq!(c(u128::from(u64::MAX) - 1, u128::from(u64::MAX), 64), vec![(u128::from(u64::MAX) - 1, 63)]);
    }

    use super::*;

    #[test]
    fn hostile_files_are_rejected() {
        let long = format!("1.0.0.0,1.0.0.255,{}\n", "A".repeat(10_000));
        assert!(count_ranges(long.as_bytes(), true).unwrap_err().to_string().contains("line longer"));
        let ok = "1.0.0.0,1.0.0.255,AU\r\n1.0.1.0,1.0.1.255,CN\n";
        assert_eq!(count_ranges(ok.as_bytes(), true).unwrap(), 2);
        // more ranges or network names than fit in memory: refused when downloaded and when loaded
        let asn: String = (0..20u32).map(|i| format!("1.0.{i}.0,1.0.{i}.255,{},\"Org {i}\"\n", 64500 + i)).collect();
        assert_eq!(count_ranges_within(asn.as_bytes(), false, 20, 20).unwrap(), 20);
        assert!(count_ranges_within(asn.as_bytes(), false, 19, 20).unwrap_err().to_string().contains("not fit in memory"));
        assert!(count_ranges_within(asn.as_bytes(), false, 20, 19).unwrap_err().to_string().contains("not fit in memory"));
        assert!(GeoDb::default().read_within(asn.as_bytes(), false, 19, 20).is_err());
        assert!(GeoDb::default().read_within(asn.as_bytes(), false, 20, 10).is_err());
        assert!(GeoDb::default().read_within(asn.as_bytes(), false, 20, 20).is_ok());
    }

    pub(crate) fn sample() -> GeoDb {
        let mut db = GeoDb::default();
        let country = "0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n5.9.0.0,5.9.127.255,DE\n5.9.128.0,5.9.255.255,DE\n\
                       12.69.0.0,12.69.255.255,FI\n3fff:180::,3fff:180:ffff:ffff:ffff:ffff:ffff:ffff,DE\n";
        let asn = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n5.9.0.0,5.9.255.255,24940,\"Hetzner Online GmbH\"\n\
                   12.69.0.0,12.69.255.255,24940,\"Hetzner Online GmbH\"\n3fff:180::,3fff:180:ffff:ffff:ffff:ffff:ffff:ffff,24940,\"Hetzner Online GmbH\"\n";
        assert_eq!(db.read(country.as_bytes(), true).unwrap(), 4, "ZZ dropped, adjacent DE blocks merged");
        assert_eq!(db.read(asn.as_bytes(), false).unwrap(), 4);
        db
    }

    #[test]
    fn lookups_and_labels() {
        let db = sample();
        let l = |ip: &str| db.label(ip.parse().unwrap());
        assert_eq!(l("5.9.200.1").as_deref(), Some("Germany / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("12.69.3.4").as_deref(), Some("Finland / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("1.0.0.1").as_deref(), Some("Australia / Cloudflare, Inc. (AS13335)"));
        assert_eq!(l("3fff:180:1:2::3").as_deref(), Some("Germany / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("1.0.1.1"), None);
        assert_eq!(l("0.1.2.3"), None);
        assert_eq!(db.asn("12.69.3.4".parse().unwrap()), Some(24940));
    }

    #[test]
    fn places_pin_misplaced_networks() {
        let cfg = GeoCfg {
            places: [("5.9.0.0/16", "GE"), ("5.9.1.0/24", "Armenia"), ("3fff:180:1::/48", "ge")]
                .map(|(n, c)| (n.to_string(), c.to_string()))
                .into(),
            ..Default::default()
        };
        cfg.validate().unwrap();
        let mut db = sample();
        db.pinned = cfg.pinned();
        let l = |ip: &str| db.label(ip.parse().unwrap());
        assert_eq!(l("5.9.200.1").as_deref(), Some("Georgia / Hetzner Online GmbH (AS24940)"), "the owner stays");
        assert_eq!(l("5.9.1.7").as_deref(), Some("Armenia / Hetzner Online GmbH (AS24940)"), "the most specific wins");
        assert_eq!(l("3fff:180:1:2::3").as_deref(), Some("Georgia / Hetzner Online GmbH (AS24940)"));
        assert_eq!(l("12.69.3.4").as_deref(), Some("Finland / Hetzner Online GmbH (AS24940)"), "others as the database says");
        assert_eq!(l("1.0.1.1"), None);

        let bad = |n: &str, c: &str| GeoCfg { places: [(n.to_string(), c.to_string())].into(), ..Default::default() }.validate();
        assert!(bad("5.9.0.0/16", "Atlantis").unwrap_err().to_string().contains("not a country"));
        assert!(bad("5.9.0.0/33", "GE").is_err());
        assert!(bad("example.org", "GE").is_err());
    }

    #[test]
    fn one_network() {
        let mut db = GeoDb::default();
        let asn = "11.145.56.0,11.145.57.255,64501,\"Other\"\n11.145.58.0,11.145.59.127,64500,\"Provider\"\n\
                   11.145.59.128,11.145.63.255,64500,\"Provider (DE)\"\n3fff:180::,3fff:180:0:ffff:ffff:ffff:ffff:ffff,24940,\"H\"\n\
                   3fff:180:1::,3fff:180:1:ffff:ffff:ffff:ffff:ffff,64502,\"V\"\n";
        db.read(asn.as_bytes(), false).unwrap();
        let one = |n: &str| db.one_network(&n.parse().unwrap());
        assert!(one("11.145.58.0/23") && one("11.145.60.0/22"), "one ASN over several ranges");
        assert!(!one("11.145.56.0/22") && !one("11.145.0.0/16"), "two providers");
        assert!(one("11.145.57.7") && one("11.146.0.0/16"), "unknown addresses don't count");
        assert!(one("3fff:180::/48") && one("3fff:180:0:5::/64") && !one("3fff:180::/47"));
        assert!(GeoDb::default().one_network(&"11.145.0.0/16".parse().unwrap()), "no network database");
    }

    #[test]
    fn networks_of_asns() {
        let db = sample();
        let nets: Vec<String> = db.networks_of(&[24940].into_iter().collect()).iter().map(|n| n.to_string()).collect();
        assert_eq!(nets, ["5.9.0.0/16", "12.69.0.0/16", "3fff:180::/32"]);
        assert!(db.networks_of(&[64999].into_iter().collect()).is_empty());
    }

    #[test]
    fn org_names_are_cleaned() {
        let mut db = GeoDb::default();
        let asn =
            format!("1.0.0.0,1.0.0.255,13335,\"Evil\x1b]0;pwned\x07 Corp\u{9b}31m\"\n2.0.0.0,2.0.0.255,64500,\"{}\"\n", "x".repeat(500));
        db.read(asn.as_bytes(), false).unwrap();
        assert_eq!(db.label("1.0.0.1".parse().unwrap()).as_deref(), Some("Evil]0;pwned Corp31m (AS13335)"));
        let long = db.lookup("2.0.0.1".parse().unwrap()).org.unwrap();
        assert_eq!(long.chars().count(), MAX_ORG_LEN + 1, "capped, with an ellipsis");
    }

    #[test]
    fn iptoasn_format() {
        let mut db = GeoDb::default();
        let tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
                   1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM-AS-AP Gtelecom Pty Ltd\n";
        assert_eq!(db.read(tsv.as_bytes(), false).unwrap(), 2, "unrouted ranges skipped");
        let g = db.lookup("1.0.5.5".parse().unwrap());
        assert_eq!(g.label().as_deref(), Some("Australia / Gtelecom Pty Ltd (AS38803)"), "registration country as fallback");
        assert_eq!(db.label("1.0.0.9".parse().unwrap()).as_deref(), Some("United States / CLOUDFLARENET (AS13335)"));
        assert!(db.read("garbage\n".as_bytes(), true).is_err());
        assert_eq!(count_ranges(tsv.as_bytes(), false).unwrap(), 2);
        assert_eq!(count_ranges("1.0.0.0,1.0.0.255,AU\nx,y,z\n".as_bytes(), true).unwrap(), 1);
    }

    #[test]
    fn helpers() {
        assert_eq!(
            fields(r#"1.0.0.0,1.0.0.255,13335,"Cloudflare, ""Inc."""#),
            vec!["1.0.0.0", "1.0.0.255", "13335", "Cloudflare, \"Inc.\""]
        );
        assert_eq!(fields("a\tb c\t"), vec!["a", "b c", ""]);
        assert_eq!(fields("x,\"y,z\",,\"unterminated"), vec!["x", "y,z", "", "unterminated"]);
        assert!(matches!(fields("plain,\"quoted\"")[1], Cow::Borrowed("quoted")), "borrowed unless unescaped");
        assert_eq!(as_number(" AS13335 "), Some(13335));
        assert_eq!(as_number("0"), None);
        assert_eq!(coords("49.4521", "11.0767"), Some((4945, 1108)));
        assert_eq!(coords("91", "0"), None);
        assert_eq!(coords("", "11"), None);
        assert_eq!(country_name(b"DE"), "Germany");
        assert_eq!(country_name(b"ZW"), "Zimbabwe");
        assert_eq!(country_name(b"AD"), "Andorra");
        assert_eq!(country_name(b"QQ"), "unknown country");
        // 2026-01-15: current and previous month
        assert_eq!(months(20_468 * 86_400 * crate::time::SEC), ["2026-01".to_string(), "2025-12".to_string()]);
    }

    #[test]
    fn countries_by_code_or_name() {
        assert_eq!(parse_country("CN"), Some(*b"CN"));
        assert_eq!(parse_country(" cn "), Some(*b"CN"));
        assert_eq!(parse_country("china"), Some(*b"CN"));
        assert_eq!(parse_country("Côte d'Ivoire"), Some(*b"CI"));
        assert_eq!(parse_country("XX"), None);
        assert_eq!(parse_country("Chin"), None);
    }

    #[test]
    fn intervals() {
        assert_eq!(merge_intervals(vec![(5, 9), (1, 3), (4, 4), (12, 20), (15, 16)]), [(1, 9), (12, 20)], "touching ones join");
        assert_eq!(subtract_intervals(vec![(1, 20)], &[(5, 6), (10, 10), (20, 30)]), [(1, 4), (7, 9), (11, 19)]);
        assert_eq!(subtract_intervals(vec![(1, 4), (8, 9)], &[(0, 100)]), []);
        assert_eq!(subtract_intervals(vec![(1, 4), (8, 9)], &[(5, 7)]), [(1, 4), (8, 9)]);
        assert_eq!(subtract_intervals(vec![(0, u128::MAX)], &[(u128::MAX, u128::MAX)]), [(0, u128::MAX - 1)]);
    }

    #[test]
    fn geoblock_networks() {
        let mut db = GeoDb::default();
        let country = "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n1.0.4.0,1.0.7.255,CN\n1.0.8.0,1.0.15.255,CN\n\
                       1.0.16.0,1.0.16.255,JP\n10.0.0.0,10.255.255.255,CN\n\
                       3fff:110::,3fff:110:ffff:ffff:ffff:ffff:ffff:ffff,CN\n3fff:100::,3fff:100:ffff:ffff:ffff:ffff:ffff:ffff,JP\n";
        let asn = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n1.0.16.0,1.0.16.255,2497,\"IIJ\"\n";
        db.read(country.as_bytes(), true).unwrap();
        db.read(asn.as_bytes(), false).unwrap();
        let cfg = |countries: &[&str], only: &[&str], asns: &[u32]| GeoblockCfg {
            enabled: true,
            countries: countries.iter().map(|c| c.to_string()).collect(),
            only_countries: only.iter().map(|c| c.to_string()).collect(),
            asns: asns.to_vec(),
            ..Default::default()
        };
        let names = |nets: Vec<Net>| nets.iter().map(Net::to_string).collect::<Vec<_>>();
        // CN's three adjacent ranges as few CIDRs; 10/8 is private and never blocked; IPv6 per /64
        assert_eq!(
            names(db.blocked_networks(&cfg(&["China"], &[], &[]), &[])),
            ["1.0.1.0/24", "1.0.2.0/23", "1.0.4.0/22", "1.0.8.0/21", "3fff:110::/32"]
        );
        // a protected address inside is cut out exactly, not the whole block
        let kept = db.blocked_networks(&cfg(&["CN"], &[], &[]), &["1.0.2.5".parse().unwrap(), "3fff:110:0:7::1".parse().unwrap()]);
        assert!(kept.iter().all(|n| !n.contains("1.0.2.5".parse().unwrap())), "{kept:?}");
        for still in ["1.0.2.4", "1.0.2.6", "1.0.1.1", "1.0.15.255"] {
            assert!(kept.iter().any(|n| n.contains(still.parse().unwrap())), "{still}: {kept:?}");
        }
        assert!(kept.iter().all(|n| !n.contains("3fff:110:0:7::abcd".parse().unwrap())), "its whole /64 is kept");
        assert!(kept.iter().any(|n| n.contains("3fff:110:0:8::1".parse().unwrap())));
        // all but AU: CN and JP, and the ranges in between merge into larger blocks
        assert_eq!(
            names(db.blocked_networks(&cfg(&[], &["AU"], &[]), &[])),
            ["1.0.1.0/24", "1.0.2.0/23", "1.0.4.0/22", "1.0.8.0/21", "1.0.16.0/24", "3fff:100::/32", "3fff:110::/32"]
        );
        // networks by ASN, together with countries
        assert_eq!(names(db.blocked_networks(&cfg(&[], &[], &[13335]), &[])), ["1.0.0.0/24"]);
        assert_eq!(names(db.blocked_networks(&cfg(&["JP"], &[], &[13335]), &[])), ["1.0.0.0/24", "1.0.16.0/24", "3fff:100::/32"]);
        assert!(db.blocked_networks(&cfg(&[], &[], &[64999]), &[]).is_empty());
        assert_eq!(cfg(&["China", "ru"], &["UA"], &[1, 2]).describe(), "CN, RU; all but UA; 2 networks (ASNs)");
        // for the web console's map: codes, whatever the spelling
        assert_eq!(
            cfg(&["ru", "China", "CN"], &["Ukraine"], &[]).country_codes(),
            (vec!["CN".to_string(), "RU".into()], vec!["UA".to_string()])
        );
    }

    #[test]
    fn geoblock_config() {
        let geo = GeoCfg { enabled: true, ..Default::default() };
        let c = |toml: &str| toml::from_str::<GeoblockCfg>(toml).unwrap();
        assert!(c("enabled = true\ncountries = [\"CN\", \"Russia\"]").validate(&geo).is_ok());
        assert!(c("countries = [\"Narnia\"]").validate(&geo).unwrap_err().to_string().contains("Narnia"), "checked even while disabled");
        assert!(c("enabled = true").validate(&geo).is_err(), "nothing listed");
        assert!(c("enabled = true\nasns = [13335]").validate(&GeoCfg::default()).is_err(), "[geo] off");
        assert!(c("enabled = true\nasns = [13335]").validate(&GeoCfg { asn_url: String::new(), ..geo.clone() }).is_err());
        assert!(c("enabled = true\ncountries = [\"CN\"]\nonly_countries = [\"china\"]").validate(&geo).is_err(), "both");
        assert_eq!(GeoblockCfg::default().max_entries, 200_000);
    }

    #[test]
    fn dbip_commercial_country_layout() {
        // start,end,continent,country: the continent (EU here) is never the country
        let csv = "1.0.0.0,1.0.0.255,OC,AU\n5.9.0.0,5.9.127.255,EU,DE\n5.9.128.0,5.9.255.255,EU,DE\n\
                   3fff:180::,3fff:180:ffff:ffff:ffff:ffff:ffff:ffff,EU,DE\n0.0.0.0,0.255.255.255,ZZ,ZZ\n";
        for text in [csv.to_string(), format!("ip_start,ip_end,continent,country\n{csv}")] {
            let mut db = GeoDb::default();
            assert_eq!(db.read(text.as_bytes(), true).unwrap(), 3, "adjacent DE blocks merged, ZZ dropped");
            assert_eq!(db.label("5.9.200.1".parse().unwrap()).as_deref(), Some("Germany"));
            assert_eq!(db.label("1.0.0.1".parse().unwrap()).as_deref(), Some("Australia"));
            assert_eq!(db.label("3fff:180:1:2::3".parse().unwrap()).as_deref(), Some("Germany"));
            assert_eq!(db.lookup("5.9.200.1".parse().unwrap()).city, None);
            assert_eq!(count_ranges(text.as_bytes(), true).unwrap(), 3, "the download check agrees");
        }
        // in the lite layout the two-letter third column is the country, AF (Afghanistan) included
        let mut db = GeoDb::default();
        db.read("1.0.0.0,1.0.0.255,AF\n1.0.1.0,1.0.1.255,EU\n".as_bytes(), true).unwrap();
        assert_eq!(db.label("1.0.0.1".parse().unwrap()).as_deref(), Some("Afghanistan"));
        assert_eq!(db.label("1.0.1.1".parse().unwrap()).as_deref(), Some("European Union"));
    }

    #[test]
    fn dbip_city_layouts_keep_city_and_coordinates() {
        // the city lite: start,end,continent,country,stateprov,city,latitude,longitude
        let lite = "1.0.0.0,1.0.0.255,OC,AU,Queensland,\"South Brisbane\",-27.4767,153.017\n\
                    5.9.0.0,5.9.127.255,EU,DE,Bavaria,\"Nuremberg, Mittelfranken\",49.4521,11.0767\n\
                    5.9.128.0,5.9.255.255,EU,DE,Bavaria,\"Nuremberg, Mittelfranken\",49.4521,11.0767\n\
                    11.14.0.0,11.14.0.255,EU,DE,Bavaria,\"Nuremberg, Mittelfranken\",49.46,11.08\n\
                    9.9.9.0,9.9.9.255,NA,US,,,0,0\n";
        let mut db = GeoDb::default();
        assert_eq!(db.read(lite.as_bytes(), true).unwrap(), 4, "the same city and coordinates merge; other coordinates don't");
        let g = db.lookup("5.9.200.1".parse().unwrap());
        assert_eq!(g.place().as_deref(), Some("Germany, Nuremberg, Mittelfranken"));
        assert_eq!(g.coords, Some((49.45, 11.08)), "hundredths of a degree");
        assert_eq!(g.label().as_deref(), Some("Germany, Nuremberg, Mittelfranken"));
        assert_eq!(db.lookup("11.14.0.7".parse().unwrap()).coords, Some((49.46, 11.08)));
        let g = db.lookup("9.9.9.9".parse().unwrap());
        assert_eq!((g.country, g.city, g.coords), (Some(*b"US"), None, None), "0,0 and an empty city are nothing");
        assert_eq!(count_ranges(lite.as_bytes(), true).unwrap(), 4, "the download check agrees");
        assert_eq!(db.locations.len(), 3);
        // a pinned network: the database's city and coordinates were wrong too
        db.pinned = vec![("5.9.0.0/16".parse().unwrap(), *b"GE")];
        let g = db.lookup("5.9.200.1".parse().unwrap());
        assert_eq!((g.place().as_deref(), g.coords), (Some("Georgia"), None));

        // IP to Location (15 columns) and IP to Location + ISP (20): country, city, coordinates
        let loc = "8.8.8.0,8.8.8.255,NA,US,CA,California,\"Santa Clara County\",\"Mountain View\",94043,37.4229,-122.085,5375480,-7,America/Los_Angeles,USCA0746";
        let full = format!("{loc},\"Level 3 Communications\",15169,hosting,fttx,\"Google Inc.\"");
        for text in [format!("{loc}\n"), format!("{full}\n")] {
            let mut db = GeoDb::default();
            assert_eq!(db.read(text.as_bytes(), true).unwrap(), 1);
            let g = db.lookup("8.8.8.8".parse().unwrap());
            assert_eq!((g.place().as_deref(), g.coords), (Some("United States, Mountain View"), Some((37.42, -122.09))));
        }
        // the 20-column file as the network database: AS number and organisation
        let mut db = GeoDb::default();
        assert_eq!(db.read(format!("{full}\n").as_bytes(), false).unwrap(), 1);
        assert_eq!(db.label("8.8.8.8".parse().unwrap()).as_deref(), Some("United States / Google Inc. (AS15169)"));
    }

    #[test]
    fn dbip_isp_layout() {
        // start,end,continent,country,isp_name,as_number,usage_type,connection_type,organization_name
        let csv = "8.8.8.0,8.8.8.255,NA,US,\"Level 3 Communications\",15169,hosting,fttx,\"Google Inc.\"\n\
                   1.0.0.0,1.0.0.255,OC,AU,\"Cloudflare, Inc.\",13335,hosting,fttx,\n\
                   5.9.0.0,5.9.255.255,EU,DE,Hetzner,24940,hosting,fttx,\"Hetzner Online GmbH\"\n";
        let header = "ip_start,ip_end,continent,country,isp_name,as_number,usage_type,connection_type,organization_name\n";
        for text in [csv.to_string(), format!("{header}{csv}")] {
            let mut db = GeoDb::default();
            assert_eq!(db.read(text.as_bytes(), false).unwrap(), 3);
            let l = |ip: &str| db.label(ip.parse().unwrap());
            assert_eq!(l("8.8.8.8").as_deref(), Some("United States / Google Inc. (AS15169)"), "the AS organisation, not the ISP");
            assert_eq!(l("1.0.0.1").as_deref(), Some("Australia / Cloudflare, Inc. (AS13335)"), "the ISP without an organisation");
            assert_eq!(db.asn("5.9.1.1".parse().unwrap()), Some(24940));
            assert_eq!(count_ranges(text.as_bytes(), false).unwrap(), 3, "the download check agrees");
        }
    }

    #[test]
    fn header_rows_name_the_columns() {
        // IPinfo-like files: the country's code first, its name and the continent after it
        let country = "start_ip,end_ip,country,country_name,continent,continent_name\n\
                       1.0.0.0,1.0.0.255,AU,Australia,OC,Oceania\n5.9.0.0,5.9.255.255,DE,Germany,EU,Europe\n";
        let mut db = GeoDb::default();
        assert_eq!(db.read(country.as_bytes(), true).unwrap(), 2);
        assert_eq!(db.label("5.9.1.1".parse().unwrap()).as_deref(), Some("Germany"));
        let asn = "\u{feff}start_ip,end_ip,asn,name,domain\n1.0.0.0,1.0.0.255,AS13335,Cloudflare,cloudflare.com\n";
        assert_eq!(db.read(asn.as_bytes(), false).unwrap(), 1, "a BOM, and an AS prefix");
        assert_eq!(db.label("1.0.0.1".parse().unwrap()).as_deref(), Some("Australia / Cloudflare (AS13335)"));
        // a code column beats a name column whatever their order; city and coordinates by name
        let named = "Start,End,Country,Country Code,City,Lat,Long\n1.0.0.0,1.0.0.255,Australia,au,Sydney,-33.87,151.21\n";
        let mut db = GeoDb::default();
        db.read(named.as_bytes(), true).unwrap();
        let g = db.lookup("1.0.0.1".parse().unwrap());
        assert_eq!((g.place().as_deref(), g.coords), (Some("Australia, Sydney"), Some((-33.87, 151.21))));
    }

    #[test]
    fn unknown_layouts_are_refused() {
        // the country file as the network database, and the other way round
        let country = "1.0.0.0,1.0.0.255,OC,AU\n";
        let e = GeoDb::default().read(country.as_bytes(), false).unwrap_err().to_string();
        assert!(e.contains("unknown column layout (4 columns)") && e.contains("header row"), "{e}");
        let asn = "1.0.0.0,1.0.0.255,13335,\"Cloudflare, Inc.\"\n";
        assert!(GeoDb::default().read(asn.as_bytes(), true).unwrap_err().to_string().contains("unknown column layout"));
        assert!(count_ranges(asn.as_bytes(), true).is_err());
        assert!(GeoDb::default().read("garbage\n".as_bytes(), true).unwrap_err().to_string().contains("no address ranges"));
        // a header that names nothing useful, then rows in a known shape
        assert_eq!(GeoDb::default().read("von,bis,land\n1.0.0.0,1.0.0.255,DE\n".as_bytes(), true).unwrap(), 1);
    }

    #[test]
    fn credit_line_for_the_free_data_only() {
        let cfg = GeoCfg::default();
        assert!(attribution(&cfg, true).contains("DB-IP.com"));
        assert!(attribution(&cfg, false).is_empty());
        let paid = GeoCfg {
            country_url: "https://download.db-ip.com/key/0123456789abcdef.csv.gz".into(),
            asn_url: "https://iptoasn.com/data/ip2asn-combined.tsv.gz".into(),
            ..Default::default()
        };
        assert!(attribution(&paid, true).is_empty());
        assert!(GeoCfg { max_ranges: 10, ..Default::default() }.validate().is_err());
    }

    #[test]
    fn memory_advice_for_big_databases() {
        let unit = 128 << 20;
        assert_eq!(advice(MAX_RANGES, unit), None, "the default bound is sized for the unit");
        assert_eq!(advice(MAX_RANGES, 1 << 20), None, "a tight unit with the default is the admin's choice");
        let w = advice(8_000_000, unit).unwrap();
        assert!(w.contains("about 308 MB") && w.contains("limit of 128 MB") && w.contains("systemctl edit vpsfort"), "{w}");
        assert_eq!(advice(8_000_000, 512 << 20), None);
        assert_eq!(parse_limit("134217728\n"), Some(134_217_728));
        assert_eq!(parse_limit("max\n"), None);
    }

    #[test]
    fn labels_with_cities_parse_back() {
        assert_eq!(parse_place("Germany"), Some((*b"DE", None)));
        assert_eq!(parse_place("Germany, Berlin"), Some((*b"DE", Some("Berlin"))));
        assert_eq!(parse_place("Germany, Nuremberg, Mittelfranken"), Some((*b"DE", Some("Nuremberg, Mittelfranken"))));
        assert_eq!(parse_place("Atlantis, X"), None);
        let g = Geo {
            country: Some(*b"DE"),
            city: Some("Berlin".into()),
            asn: Some(24940),
            org: Some("Hetzner Online GmbH".into()),
            ..Default::default()
        };
        assert_eq!(g.label().as_deref(), Some("Germany, Berlin / Hetzner Online GmbH (AS24940)"));
        assert_eq!(
            Geo { country: None, ..g.clone() }.label().as_deref(),
            Some("Hetzner Online GmbH (AS24940)"),
            "no city without a country"
        );
    }

    /// Sizes on the real databases (`VPSFORT_GEO_DIR=<dir with country.gz, asn.gz>
    /// cargo test --release real_geoblock_sizes -- --ignored --nocapture`). With `LOAD_ONLY=1`
    /// it stops after loading: the peak memory of both runs (`/usr/bin/time -l` on the test
    /// binary) tells the computation's share from the database's.
    #[test]
    #[ignore]
    fn real_geoblock_sizes() {
        let dir = std::env::var("VPSFORT_GEO_DIR").expect("VPSFORT_GEO_DIR");
        let db = GeoDb::load(Path::new(&dir), MAX_RANGES).unwrap();
        println!("{}", db.summary);
        if std::env::var_os("LOAD_ONLY").is_some() {
            return;
        }
        let cases: [(&[&str], &[&str], &[u32]); 6] = [
            (&["CN"], &[], &[]),
            (&["RU"], &[], &[]),
            (&["US"], &[], &[]),
            (&["CN", "RU", "IR", "KP"], &[], &[]),
            (&[], &["UA"], &[]),
            (&[], &[], &[13335, 16509]),
        ];
        for (countries, only, asns) in cases {
            let cfg = GeoblockCfg {
                enabled: true,
                countries: countries.iter().map(|c| c.to_string()).collect(),
                only_countries: only.iter().map(|c| c.to_string()).collect(),
                asns: asns.to_vec(),
                ..Default::default()
            };
            let start = std::time::Instant::now();
            let nets = db.blocked_networks(&cfg, &[]);
            let v4 = nets.iter().filter(|n| n.is_v4()).count();
            println!("{:<40} {v4:>7} IPv4 + {:>6} IPv6 networks in {:?}", cfg.describe(), nets.len() - v4, start.elapsed());
        }
    }

    #[test]
    fn a_database_too_big_for_the_service_is_said() {
        let mut db = GeoDb::default();
        for i in 0..100_000u32 {
            db.loc4.v.push((i * 256, i * 256 + 255, Loc::default()));
        }
        let size = db.approx_bytes() as u64;
        assert!(size >= 100_000 * 8, "{size}");
        assert_eq!(db.size_warning(None), None, "no limit: nothing to compare with");
        assert_eq!(db.size_warning(Some(size * 4)), None);
        let w = db.size_warning(Some(size + 1)).expect("more than half");
        assert!(w.contains("MemoryMax") && w.contains("max_ranges"), "{w}");
    }
}
