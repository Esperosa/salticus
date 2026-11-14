//! Metadata aplikačních vrstev (krok 12, impl-krok12.md, část B): TLS, DNS a HTTP.
//!
//! Model pozorování toku nese jen konce, port, bajty a stav. Rozlišit šifrované
//! hromadné stažení od zálohy nebo aktualizace, nebo výčet DNS zóny od běžného
//! překladu z toků nejde; profesionální nástroje čtou pole `ssl.log`, `x509.log`,
//! `dns.log`, `http.log` (Zeek) a události `tls`, `dns`, `http` (Suricata EVE).
//! Pole a jejich názvy jsou ověřené proti dokumentaci (studie 12, oddíl 7).
//!
//! Parsery jsou tolerantní: neznámé, chybějící nebo poškozené pole dá `None`, celý
//! řádek poškozený tak, že nejde použít, dá `None` místo chyby. Žádný parser
//! nepanikuje na libovolném vstupu (fuzz test níže). Vstup je řádek Zeek TSV
//! převedený na mapu polí, řádek Zeek JSON, nebo řádek Suricata EVE JSON.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Nejdelší řetězec, který parser převezme (ochrana paměti proti obřím polím).
const MAX_FIELD: usize = 512;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TlsMeta {
    pub ts: i64,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub alpn: Option<String>,
    pub version: Option<String>,
    /// Platnost certifikátu serveru (epocha), z `x509.log` nebo EVE `notbefore`.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    /// Zeek `cert_chain_fuids` (první = list), pro spojení s `x509.log`.
    pub cert_fuid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DnsMeta {
    pub ts: i64,
    pub src_ip: String,
    pub dst_ip: String,
    /// Dotazované jméno, malými písmeny, bez koncové tečky.
    pub qname: String,
    /// `A`, `AAAA`, `TXT`, `ANY`, `AXFR`, `IXFR` ...
    pub qtype: String,
    /// `NOERROR`, `NXDOMAIN` ... (prázdné u dotazu bez odpovědi).
    pub rcode: Option<String>,
    pub answers: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HttpMeta {
    pub ts: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub host: Option<String>,
    pub method: Option<String>,
    pub uri_len: u32,
    pub user_agent: Option<String>,
    pub status: Option<u16>,
    pub resp_len: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum L7Event {
    Tls(TlsMeta),
    Dns(DnsMeta),
    Http(HttpMeta),
}

impl L7Event {
    pub fn ts(&self) -> i64 {
        match self {
            L7Event::Tls(t) => t.ts,
            L7Event::Dns(d) => d.ts,
            L7Event::Http(h) => h.ts,
        }
    }
}

fn clip(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v == "-" || v == "(empty)" || v == "null" {
        return None;
    }
    Some(v.chars().take(MAX_FIELD).collect())
}

fn field(row: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| row.get(*k).and_then(|v| clip(v)))
}

/// Čas jako epocha (Zeek `ts` desetinné číslo) nebo RFC 3339 (EVE).
fn parse_ts(value: &str) -> Option<i64> {
    let v = value.trim();
    if let Ok(f) = v.parse::<f64>() {
        return (f.is_finite() && f.abs() < 4.0e10).then(|| f.floor() as i64);
    }
    if let Ok(d) = DateTime::parse_from_rfc3339(v) {
        return Some(d.with_timezone(&Utc).timestamp());
    }
    // EVE: `2026-01-05T10:00:01.000000+0000` (offset bez dvojtecky) a `notbefore` bez offsetu
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(d) = DateTime::parse_from_str(v, fmt) {
            return Some(d.with_timezone(&Utc).timestamp());
        }
    }
    chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|n| n.and_utc().timestamp())
}

fn parse_port(value: Option<String>) -> Option<u16> {
    value.and_then(|v| v.trim().parse::<u16>().ok())
}

/// Převede jeden JSON řádek (Zeek JSON nebo EVE) na plochou mapu: vnořené objekty
/// se rozbalí na `a.b`, pole se spojí čárkami. Neplatný JSON dá `None`.
pub fn flatten_json_line(line: &str) -> Option<HashMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let mut out = HashMap::new();
    flatten("", &value, &mut out, 0);
    (!out.is_empty()).then_some(out)
}

fn flatten(prefix: &str, value: &serde_json::Value, out: &mut HashMap<String, String>, depth: u8) {
    if depth > 6 || out.len() > 256 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter().take(128) {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, v, out, depth + 1);
            }
        }
        serde_json::Value::Array(items) => {
            let joined: Vec<String> = items
                .iter()
                .take(32)
                .filter_map(|i| match i {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            if !joined.is_empty() {
                out.insert(prefix.to_string(), joined.join(","));
            }
            // pole objektu (EVE `dns.queries`, `dns.answers`): prvni polozka s prefixem `.0`
            if let Some(first) = items.first().filter(|i| i.is_object()) {
                flatten(&format!("{prefix}.0"), first, out, depth + 1);
            }
            out.insert(format!("{prefix}.#"), items.len().to_string());
        }
        serde_json::Value::String(s) => {
            out.insert(prefix.to_string(), s.chars().take(MAX_FIELD).collect());
        }
        serde_json::Value::Number(n) => {
            out.insert(prefix.to_string(), n.to_string());
        }
        serde_json::Value::Bool(b) => {
            out.insert(prefix.to_string(), b.to_string());
        }
        serde_json::Value::Null => {}
    }
}

/// Zeek `ssl.log` (TSV mapa nebo plochý JSON): `id.orig_h`, `server_name`, `ja3` ...
pub fn tls_from_zeek(row: &HashMap<String, String>) -> Option<TlsMeta> {
    let ts = parse_ts(row.get("ts")?)?;
    Some(TlsMeta {
        ts,
        src_ip: field(row, &["id.orig_h"])?,
        src_port: parse_port(field(row, &["id.orig_p"])),
        dst_ip: field(row, &["id.resp_h"])?,
        dst_port: parse_port(field(row, &["id.resp_p"])),
        sni: field(row, &["server_name"]).map(|s| s.to_ascii_lowercase()),
        ja3: field(row, &["ja3"]),
        ja4: field(row, &["ja4"]),
        alpn: field(row, &["next_protocol"]),
        version: field(row, &["version"]),
        not_before: None,
        not_after: None,
        issuer: field(row, &["issuer"]),
        subject: field(row, &["subject"]),
        cert_fuid: field(row, &["cert_chain_fuids"])
            .and_then(|f| f.split(',').next().map(str::to_string)),
    })
}

/// Doplní platnost certifikátu z `x509.log` podle `fuid` (pole `id`).
pub fn attach_x509(tls: &mut [TlsMeta], x509: &[HashMap<String, String>]) {
    let mut by_id: HashMap<&str, &HashMap<String, String>> = HashMap::new();
    for row in x509.iter().take(500_000) {
        if let Some(id) = row.get("id") {
            by_id.insert(id.as_str(), row);
        }
    }
    for t in tls.iter_mut() {
        let Some(row) = t.cert_fuid.as_deref().and_then(|f| by_id.get(f)) else {
            continue;
        };
        t.not_before = field(row, &["certificate.not_valid_before"])
            .and_then(|v| v.parse::<f64>().ok())
            .map(|f| f as i64);
        t.not_after = field(row, &["certificate.not_valid_after"])
            .and_then(|v| v.parse::<f64>().ok())
            .map(|f| f as i64);
        if t.issuer.is_none() {
            t.issuer = field(row, &["certificate.issuer"]);
        }
        if t.subject.is_none() {
            t.subject = field(row, &["certificate.subject"]);
        }
    }
}

/// Zeek `dns.log`. Jeden řádek = jedna výměna (dotaz s odpovědí, nebo bez ní).
pub fn dns_from_zeek(row: &HashMap<String, String>) -> Option<DnsMeta> {
    let ts = parse_ts(row.get("ts")?)?;
    let qname = field(row, &["query"])?.trim_end_matches('.').to_ascii_lowercase();
    let answers = field(row, &["answers"])
        .map(|a| a.split(',').filter(|s| !s.is_empty()).count() as u32)
        .unwrap_or(0);
    Some(DnsMeta {
        ts,
        src_ip: field(row, &["id.orig_h"])?,
        dst_ip: field(row, &["id.resp_h"])?,
        qname,
        qtype: field(row, &["qtype_name"]).unwrap_or_else(|| "?".into()).to_ascii_uppercase(),
        rcode: field(row, &["rcode_name"]),
        answers,
    })
}

/// Zeek `http.log`.
pub fn http_from_zeek(row: &HashMap<String, String>) -> Option<HttpMeta> {
    let ts = parse_ts(row.get("ts")?)?;
    Some(HttpMeta {
        ts,
        src_ip: field(row, &["id.orig_h"])?,
        dst_ip: field(row, &["id.resp_h"])?,
        host: field(row, &["host"]).map(|s| s.to_ascii_lowercase()),
        method: field(row, &["method"]),
        uri_len: field(row, &["uri"]).map(|u| u.len() as u32).unwrap_or(0),
        user_agent: field(row, &["user_agent"]),
        status: field(row, &["status_code"]).and_then(|s| s.parse().ok()),
        resp_len: field(row, &["response_body_len"]).and_then(|s| s.parse().ok()),
    })
}

/// Jedna udalost Suricata EVE (`tls`, `dns`, `http`). Jine typy a poskozene radky
/// davaji `None`. Starsi i novejsi tvar `dns` (verze 2 a 3): jmeno z `dns.rrname`
/// nebo z `dns.queries.0.rrname`, odpoved z `dns.rcode`.
pub fn from_eve_line(line: &str) -> Option<L7Event> {
    let row = flatten_json_line(line)?;
    let kind = row.get("event_type")?.as_str();
    let ts = parse_ts(row.get("timestamp")?)?;
    let src = field(&row, &["src_ip"])?;
    let dst = field(&row, &["dest_ip"])?;
    match kind {
        "tls" => Some(L7Event::Tls(TlsMeta {
            ts,
            src_ip: src,
            src_port: parse_port(field(&row, &["src_port"])),
            dst_ip: dst,
            dst_port: parse_port(field(&row, &["dest_port"])),
            sni: field(&row, &["tls.sni"]).map(|s| s.to_ascii_lowercase()),
            ja3: field(&row, &["tls.ja3.hash", "tls.ja3"]),
            ja4: field(&row, &["tls.ja4"]),
            alpn: field(&row, &["tls.server_alpns", "tls.client_alpns"]),
            version: field(&row, &["tls.version"]),
            not_before: field(&row, &["tls.notbefore"]).and_then(|v| parse_ts(&v)),
            not_after: field(&row, &["tls.notafter"]).and_then(|v| parse_ts(&v)),
            issuer: field(&row, &["tls.issuerdn"]),
            subject: field(&row, &["tls.subject"]),
            cert_fuid: None,
        })),
        "dns" => {
            let qname = field(&row, &["dns.rrname", "dns.queries.0.rrname"])?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let qtype = field(&row, &["dns.rrtype", "dns.queries.0.rrtype"])
                .unwrap_or_else(|| "?".into())
                .to_ascii_uppercase();
            let answers = field(&row, &["dns.answers.#"])
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            Some(L7Event::Dns(DnsMeta {
                ts,
                src_ip: src,
                dst_ip: dst,
                qname,
                qtype,
                rcode: field(&row, &["dns.rcode"]),
                answers,
            }))
        }
        "http" => Some(L7Event::Http(HttpMeta {
            ts,
            src_ip: src,
            dst_ip: dst,
            host: field(&row, &["http.hostname"]).map(|s| s.to_ascii_lowercase()),
            method: field(&row, &["http.http_method"]),
            uri_len: field(&row, &["http.url"]).map(|u| u.len() as u32).unwrap_or(0),
            user_agent: field(&row, &["http.http_user_agent"]),
            status: field(&row, &["http.status"]).and_then(|s| s.parse().ok()),
            resp_len: field(&row, &["http.length"]).and_then(|s| s.parse().ok()),
        })),
        _ => None,
    }
}

/// Zeek JSON řádek podle druhu logu (`ssl`, `dns`, `http`).
pub fn from_zeek_json_line(log: &str, line: &str) -> Option<L7Event> {
    let row = flatten_json_line(line)?;
    match log {
        "ssl" => tls_from_zeek(&row).map(L7Event::Tls),
        "dns" => dns_from_zeek(&row).map(L7Event::Dns),
        "http" => http_from_zeek(&row).map(L7Event::Http),
        _ => None,
    }
}

/// Registrovatelná doména přibližně (poslední dvě značky; `co.uk` a podobné se nerozlišují,
/// známé omezení bez seznamu veřejných přípon).
pub fn zone_of(name: &str) -> &str {
    let mut dots = name.rmatch_indices('.');
    match (dots.next(), dots.next()) {
        (Some(_), Some((i, _))) => &name[i + 1..],
        _ => name,
    }
}

/// Shannonova entropie znaků jména (bity na znak), pro tunely a DGA.
pub fn name_entropy(name: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in name.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / f64::from(n);
            -p * p.log2()
        })
        .sum()
}

/// Nejvic udalosti nactenych z jednoho zdroje (ochrana pameti).
const MAX_EVENTS: usize = 500_000;

/// Radky logu Zeek (TSV s `#fields`, nebo JSON po radcich) jako ploche mapy. Chybejici
/// nebo necitelny soubor dava prazdny seznam (L7 je volitelny vstup).
fn zeek_rows(path: &std::path::Path) -> Vec<HashMap<String, String>> {
    if !path.exists() {
        return Vec::new();
    }
    if let Ok(rows) = crate::passive::zeek::parse_zeek_log(path) {
        return rows;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .filter_map(flatten_json_line)
        .take(MAX_EVENTS)
        .collect()
}

/// Nacte `ssl.log`, `x509.log`, `dns.log` a `http.log` z adresare Zeeku v case `[start, end]`.
pub fn load_zeek_dir(dir: &std::path::Path, start: i64, end: i64) -> Vec<L7Event> {
    let mut out = Vec::new();
    let in_window = |ts: i64| ts >= start && ts <= end;
    let mut tls: Vec<TlsMeta> = zeek_rows(&dir.join("ssl.log"))
        .iter()
        .filter_map(tls_from_zeek)
        .filter(|t| in_window(t.ts))
        .take(MAX_EVENTS)
        .collect();
    let x509 = zeek_rows(&dir.join("x509.log"));
    attach_x509(&mut tls, &x509);
    out.extend(tls.into_iter().map(L7Event::Tls));
    out.extend(
        zeek_rows(&dir.join("dns.log"))
            .iter()
            .filter_map(dns_from_zeek)
            .filter(|d| in_window(d.ts))
            .take(MAX_EVENTS)
            .map(L7Event::Dns),
    );
    out.extend(
        zeek_rows(&dir.join("http.log"))
            .iter()
            .filter_map(http_from_zeek)
            .filter(|h| in_window(h.ts))
            .take(MAX_EVENTS)
            .map(L7Event::Http),
    );
    out.sort_by_key(L7Event::ts);
    out
}

/// Nacte udalosti `tls`, `dns`, `http` ze souboru Suricata EVE v case `[start, end]`.
pub fn load_eve_file(path: &std::path::Path, start: i64, end: i64) -> Vec<L7Event> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out: Vec<L7Event> = text
        .lines()
        .filter(|l| l.contains("\"event_type\""))
        .filter_map(from_eve_line)
        .filter(|e| e.ts() >= start && e.ts() <= end)
        .take(MAX_EVENTS)
        .collect();
    out.sort_by_key(L7Event::ts);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVE_TLS: &str = r#"{"timestamp":"2026-01-05T10:00:01.000000+0000","event_type":"tls","src_ip":"10.0.0.5","src_port":50000,"dest_ip":"203.0.113.9","dest_port":443,"tls":{"sni":"Files.Example.net","version":"TLS 1.3","notbefore":"2026-01-01T00:00:00","notafter":"2026-04-01T00:00:00","issuerdn":"CN=Test CA","ja3":{"hash":"abcdef"},"ja4":"t13d1516h2_x_y"}}"#;
    const EVE_DNS3: &str = r#"{"timestamp":"2026-01-05T10:00:02+00:00","event_type":"dns","src_ip":"198.51.100.4","dest_ip":"10.0.0.2","dns":{"type":"answer","rcode":"NXDOMAIN","queries":[{"rrname":"A1.corp.example.","rrtype":"AXFR"}],"answers":[]}}"#;

    #[test]
    fn eve_tls_and_dns_are_parsed_in_both_shapes() {
        let Some(L7Event::Tls(t)) = from_eve_line(EVE_TLS) else {
            panic!("tls");
        };
        assert_eq!(t.sni.as_deref(), Some("files.example.net"));
        assert_eq!(t.ja3.as_deref(), Some("abcdef"));
        assert!(t.not_after.unwrap() > t.not_before.unwrap());
        let Some(L7Event::Dns(d)) = from_eve_line(EVE_DNS3) else {
            panic!("dns");
        };
        assert_eq!(d.qname, "a1.corp.example");
        assert_eq!(d.qtype, "AXFR");
        assert_eq!(d.rcode.as_deref(), Some("NXDOMAIN"));
        let old = r#"{"timestamp":"2026-01-05T10:00:02+00:00","event_type":"dns","src_ip":"1.1.1.1","dest_ip":"10.0.0.2","dns":{"rrname":"x.example.com","rrtype":"TXT","rcode":"NOERROR"}}"#;
        let Some(L7Event::Dns(d)) = from_eve_line(old) else {
            panic!("dns2");
        };
        assert_eq!((d.qname.as_str(), d.qtype.as_str()), ("x.example.com", "TXT"));
    }

    #[test]
    fn zeek_rows_and_x509_join() {
        let row = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let ssl = row(&[
            ("ts", "1767607200.5"),
            ("id.orig_h", "10.0.0.5"),
            ("id.orig_p", "51000"),
            ("id.resp_h", "203.0.113.9"),
            ("id.resp_p", "443"),
            ("server_name", "API.Example.com"),
            ("ja3", "-"),
            ("cert_chain_fuids", "Fabc,Fdef"),
        ]);
        let mut tls = vec![tls_from_zeek(&ssl).unwrap()];
        assert_eq!(tls[0].sni.as_deref(), Some("api.example.com"));
        assert_eq!(tls[0].ja3, None);
        let x = row(&[
            ("id", "Fabc"),
            ("certificate.not_valid_before", "1767000000"),
            ("certificate.not_valid_after", "1775000000"),
            ("certificate.issuer", "CN=Amazon"),
        ]);
        attach_x509(&mut tls, &[x]);
        assert_eq!(tls[0].not_before, Some(1767000000));
        assert_eq!(tls[0].issuer.as_deref(), Some("CN=Amazon"));
        let dns = row(&[
            ("ts", "1767607201"),
            ("id.orig_h", "10.0.0.5"),
            ("id.resp_h", "10.0.0.2"),
            ("query", "WWW.Example.com."),
            ("qtype_name", "a"),
            ("rcode_name", "NOERROR"),
            ("answers", "1.2.3.4,5.6.7.8"),
        ]);
        let d = dns_from_zeek(&dns).unwrap();
        assert_eq!((d.qname.as_str(), d.qtype.as_str(), d.answers), ("www.example.com", "A", 2));
    }

    #[test]
    fn helpers() {
        assert_eq!(zone_of("a.b.example.com"), "example.com");
        assert_eq!(zone_of("example"), "example");
        assert!(name_entropy("aaaaaaaa") < 0.01);
        assert!(name_entropy("q8x2kz9pw1ms") > 3.0);
    }

    /// Fuzz: nahodne retezce, useknute a mutovane platne radky nesmi zpusobit paniku.
    #[test]
    fn fuzz_parsers_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds = [EVE_TLS, EVE_DNS3, r#"{"ts":1.5,"id.orig_h":"1.1.1.1"}"#];
        let alphabet: Vec<char> = "{}[]\":,.-_0123456789abcXYZ \t\\\u{e9}\u{4e2d}".chars().collect();
        let mut parsed = 0u32;
        for round in 0..20_000u32 {
            let mut text: Vec<char> = if round % 3 == 0 {
                (0..(next() % 200)).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect()
            } else {
                seeds[(next() % seeds.len() as u64) as usize].chars().collect()
            };
            if round % 3 != 0 && !text.is_empty() {
                for _ in 0..(next() % 6) {
                    let i = (next() % text.len() as u64) as usize;
                    match next() % 3 {
                        0 => text[i] = alphabet[(next() % alphabet.len() as u64) as usize],
                        1 => {
                            text.remove(i);
                            if text.is_empty() {
                                break;
                            }
                        }
                        _ => text.truncate(i),
                    }
                    if text.is_empty() {
                        break;
                    }
                }
            }
            let line: String = text.into_iter().collect();
            if from_eve_line(&line).is_some() {
                parsed += 1;
            }
            for log in ["ssl", "dns", "http"] {
                let _ = from_zeek_json_line(log, &line);
            }
            if let Some(map) = flatten_json_line(&line) {
                let _ = (tls_from_zeek(&map), dns_from_zeek(&map), http_from_zeek(&map));
            }
        }
        assert!(parsed > 0, "fuzz ma obcas zachovat platny radek");
    }
}
