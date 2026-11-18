//! Skryté kanály nad metadaty DNS a toků (krok 17, impl-krok17.md, dodatek D1).
//!
//! - `dns_tunnel_names` v2 (`heuristika-behavior:l7-dns-tunnel@v2`): skupina = (vnitřní
//!   zdroj, základní zóna). Rysy přes **různá jména**: délka a entropie celé části jména před
//!   zónou, podíl typů schopných nést data v odpovědi, objem zakódovaných bajtů a jeho tempo.
//!   Větev T1 = tvar jména + typ záznamu, větev T2 = tvar jména + objem (tunely typu A/AAAA).
//!   mDNS a LLMNR (`.local`, link-local multicast) se vynechají: nemohou opustit segment.
//! - `doh_suspected` (`heuristika-behavior:l7-doh@v1`): DNS přes HTTPS bez dešifrování.
//!   Známý veřejný resolver (IP nebo SNI) nebo DoT (TCP 853) stačí samo; jinak tvar toků na
//!   jeden cíl (mnoho malých spojení, nebo trvalé spojení s malými záznamy) a zároveň mlčení
//!   obyčejného DNS u hosta, který přitom kontaktuje další cíle.
//!
//! Prahy jsou volba autora, ladí se jen na ladicí sadě (seed 17001) a zapisují se do dokumentu
//! kroku před drženým během.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, finding},
    l7::{DnsMeta, L7Event, name_entropy, zone_of},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CovertThresholds {
    /// T1: nejméně různých jmen, podíl různých jmen k dotazům, délka a entropie, podíl typů.
    pub tunnel_names: usize,
    pub tunnel_uniq: f64,
    pub tunnel_label: f64,
    pub tunnel_entropy: f64,
    pub tunnel_types: f64,
    /// T2: nejméně různých jmen, podíl různých jmen, zakódované bajty a jejich tempo (B/s).
    pub tunnel_vol_names: usize,
    pub tunnel_vol_uniq: f64,
    pub tunnel_vol_bytes: f64,
    pub tunnel_vol_rate: f64,
    /// DoH tvar A: nejméně spojení, mediány bajtů klienta a serveru, medián trvání (s).
    pub doh_conns: usize,
    pub doh_med_up: f64,
    pub doh_med_down: f64,
    pub doh_med_dur: f64,
    /// DoH tvar B: trvání (s), pakety klienta, průměrná velikost paketu klienta a serveru.
    pub doh_long_s: f64,
    pub doh_long_pkts: u64,
    pub doh_pkt_up: f64,
    pub doh_pkt_down: f64,
    /// C2: nejméně dalších vnějších cílů hosta v okně.
    pub doh_other_dsts: usize,
}

impl Default for CovertThresholds {
    fn default() -> Self {
        Self {
            tunnel_names: 8,
            tunnel_uniq: 0.3,
            tunnel_label: 24.0,
            tunnel_entropy: 3.0,
            tunnel_types: 0.5,
            tunnel_vol_names: 100,
            tunnel_vol_uniq: 0.5,
            tunnel_vol_bytes: 96_000.0,
            tunnel_vol_rate: 1_000.0,
            doh_conns: 10,
            doh_med_up: 2_500.0,
            doh_med_down: 8_000.0,
            doh_med_dur: 10.0,
            doh_long_s: 30.0,
            doh_long_pkts: 30,
            doh_pkt_up: 300.0,
            doh_pkt_down: 600.0,
            doh_other_dsts: 2,
        }
    }
}

/// Typy dotazu, jejichž odpověď nese libovolná data (TXT, NULL ...). A, AAAA, PTR, SOA a
/// HTTPS/SVCB (prohlížeče je kladou ke každému jménu) se nepočítají.
fn data_type(qtype: &str) -> bool {
    matches!(
        qtype,
        "TXT" | "NULL" | "PRIVATE" | "CNAME" | "MX" | "SRV" | "KEY" | "DNAME"
    ) || qtype.starts_with("TYPE65399")
}

/// mDNS a LLMNR: link-local, tunel přes hranici sítě nimi vést nejde.
fn link_local_dns(d: &DnsMeta) -> bool {
    d.qname.ends_with(".local")
        || d.qname == "local"
        || matches!(
            d.dst_ip.as_str(),
            "224.0.0.251" | "224.0.0.252" | "ff02::fb" | "ff02::1:3"
        )
}

/// Část jména před zónou bez teček (celá zakódovaná část, ne jen první značka).
fn encoded_part<'a>(qname: &'a str, zone: &str) -> String {
    let head: &'a str = qname
        .strip_suffix(zone)
        .map(|h| h.trim_end_matches('.'))
        .unwrap_or("");
    head.chars().filter(|c| *c != '.').collect()
}

/// Rysy jedné skupiny (zdroj, zóna).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TunnelShape {
    pub names: usize,
    pub queries: usize,
    pub uniq: f64,
    pub avg_len: f64,
    pub avg_entropy: f64,
    pub data_types: f64,
    pub bytes: f64,
    pub rate: f64,
}

pub fn tunnel_shape(items: &[&DnsMeta], zone: &str) -> TunnelShape {
    let names: BTreeSet<&str> = items.iter().map(|d| d.qname.as_str()).collect();
    let n = names.len().max(1) as f64;
    let parts: Vec<String> = names.iter().map(|q| encoded_part(q, zone)).collect();
    let bytes: f64 = parts.iter().map(|p| p.len() as f64).sum();
    let ent: f64 = parts.iter().map(|p| name_entropy(p)).sum();
    let typed = items.iter().filter(|d| data_type(&d.qtype)).count() as f64;
    let (lo, hi) = items
        .iter()
        .fold((i64::MAX, i64::MIN), |(a, b), d| (a.min(d.ts), b.max(d.ts)));
    let span = if items.is_empty() { 0 } else { hi - lo };
    TunnelShape {
        names: names.len(),
        queries: items.len(),
        uniq: names.len() as f64 / items.len().max(1) as f64,
        avg_len: bytes / n,
        avg_entropy: ent / n,
        data_types: typed / items.len().max(1) as f64,
        bytes,
        rate: bytes / (span.max(60) as f64),
    }
}

/// Která větev zabrala (T1 typ, T2 objem), nebo žádná.
pub fn tunnel_branch(s: &TunnelShape, t: &CovertThresholds) -> Option<&'static str> {
    let shape = s.avg_len >= t.tunnel_label && s.avg_entropy >= t.tunnel_entropy;
    if !shape {
        return None;
    }
    if s.names >= t.tunnel_names && s.uniq >= t.tunnel_uniq && s.data_types >= t.tunnel_types {
        return Some("T1 tvar jmena a typ zaznamu");
    }
    if s.names >= t.tunnel_vol_names
        && s.uniq >= t.tunnel_vol_uniq
        && s.bytes >= t.tunnel_vol_bytes
        && s.rate >= t.tunnel_vol_rate
    {
        return Some("T2 tvar jmena a objem");
    }
    None
}

pub fn dns_tunnel(
    t: &CovertThresholds,
    events: &[L7Event],
    internal: &dyn Fn(&str) -> bool,
) -> Vec<BehaviorFinding> {
    let mut groups: BTreeMap<(&str, &str), Vec<&DnsMeta>> = BTreeMap::new();
    for ev in events {
        let L7Event::Dns(d) = ev else { continue };
        if link_local_dns(d) || !internal(&d.src_ip) {
            continue;
        }
        groups
            .entry((d.src_ip.as_str(), zone_of(&d.qname)))
            .or_default()
            .push(d);
    }
    let mut out = Vec::new();
    for ((src, zone), items) in groups {
        let s = tunnel_shape(&items, zone);
        let Some(branch) = tunnel_branch(&s, t) else {
            continue;
        };
        let server = items[0].dst_ip.as_str();
        out.push(BehaviorFinding {
            finding: finding(
                "dns_tunnel_names",
                src,
                &format!("dns/{zone}"),
                Severity::Medium,
                Confidence::Medium,
                format!(
                    "Host {src}: {} dlouhych nahodnych jmen pod {zone} ({branch})",
                    s.names
                ),
                format!(
                    "Prumerna delka zakodovane casti {:.0} znaku, entropie {:.1} bitu/znak, \
                     {} ruznych jmen z {} dotazu, podil typu nesoucich data {:.0} %, \
                     {:.0} zakodovanych bajtu ({:.0} B/s). Vetev: {branch}. \
                     Pravidlo heuristika-behavior:l7-dns-tunnel@v2.",
                    s.avg_len,
                    s.avg_entropy,
                    s.names,
                    s.queries,
                    s.data_types * 100.0,
                    s.bytes,
                    s.rate
                ),
                vec![format!("{src} -> {server}: {} jmen pod {zone}", s.names)],
                "Overit proces a ucel dotazu; omezit dotazy klientu mimo firemni resolver a typy TXT/NULL.",
            ),
            sources: vec![server.to_string()],
            targets: vec![(server.to_string(), 53)],
            count: s.names as u32,
            actor: src.to_string(),
        });
    }
    out
}

/// Veřejné DoH resolvery (IP); bez sítě ven se v laboratoři ověřuje jen testem.
const DOH_IPS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "185.228.168.168",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
];
const DOH_SNIS: &[&str] = &[
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.google",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard-dns.com",
    "dns.adguard.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
];

fn known_doh_sni(sni: &str) -> bool {
    DOH_SNIS
        .iter()
        .any(|k| sni == *k || sni.ends_with(&format!(".{k}")))
}

fn median(v: &mut [f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn multicast(ip: &str) -> bool {
    ip.starts_with("ff") || ip.starts_with("224.") || ip.starts_with("239.") || ip == "255.255.255.255"
}

pub fn doh(
    t: &CovertThresholds,
    events: &[L7Event],
    outbound: &[ConnectionObservation],
    internal: &dyn Fn(&str) -> bool,
) -> Vec<BehaviorFinding> {
    // obyčejné DNS dotazy hosta (bez mDNS/LLMNR) a SNI podle cíle
    let mut plain_dns: HashMap<&str, usize> = HashMap::new();
    let mut snis: HashMap<(&str, &str), BTreeSet<&str>> = HashMap::new();
    for ev in events {
        match ev {
            L7Event::Dns(d) if !link_local_dns(d) => *plain_dns.entry(d.src_ip.as_str()).or_default() += 1,
            L7Event::Tls(s) => {
                if let Some(n) = s.sni.as_deref() {
                    snis.entry((s.src_ip.as_str(), s.dst_ip.as_str()))
                        .or_default()
                        .insert(n);
                }
            }
            _ => {}
        }
    }
    // toky vnitřních hostů na vnější cíle (TCP), podle (host, cíl)
    let mut per: BTreeMap<(&str, &str), Vec<&ConnectionObservation>> = BTreeMap::new();
    let mut dsts: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for f in outbound {
        let Some(src) = f.src_ip.as_deref() else { continue };
        if !internal(src) || internal(&f.dst_ip) || multicast(&f.dst_ip) {
            continue;
        }
        let port = f.dst_port.unwrap_or(0);
        if matches!(port, 53 | 5353 | 5355) || f.proto.eq_ignore_ascii_case("icmp") {
            continue;
        }
        dsts.entry(src).or_default().insert(f.dst_ip.as_str());
        if f.proto.eq_ignore_ascii_case("tcp") && matches!(port, 443 | 853) {
            per.entry((src, f.dst_ip.as_str())).or_default().push(f);
        }
    }
    let mut out = Vec::new();
    for ((host, dst), flows) in per {
        let names = snis.get(&(host, dst));
        let sni_known = names.is_some_and(|s| s.iter().any(|n| known_doh_sni(n)));
        let dot = flows.iter().any(|f| f.dst_port == Some(853));
        let known = DOH_IPS.contains(&dst) || sni_known;
        let mut up: Vec<f64> = flows.iter().map(|f| f.orig_bytes.unwrap_or(0) as f64).collect();
        let mut down: Vec<f64> = flows.iter().map(|f| f.resp_bytes.unwrap_or(0) as f64).collect();
        let mut dur: Vec<f64> = flows.iter().map(|f| f.duration_s.unwrap_or(0.0)).collect();
        let n443 = flows.iter().filter(|f| f.dst_port == Some(443)).count();
        let shape_a = n443 >= t.doh_conns
            && median(&mut up) <= t.doh_med_up
            && median(&mut down) <= t.doh_med_down
            && median(&mut dur) <= t.doh_med_dur;
        let shape_b = flows.iter().any(|f| {
            let (op, rp) = (f.orig_pkts.unwrap_or(0), f.resp_pkts.unwrap_or(0));
            f.duration_s.unwrap_or(0.0) >= t.doh_long_s
                && op >= t.doh_long_pkts
                && rp > 0
                && f.orig_bytes.unwrap_or(0) as f64 / op as f64 <= t.doh_pkt_up
                && f.resp_bytes.unwrap_or(0) as f64 / rp as f64 <= t.doh_pkt_down
        });
        let others = dsts
            .get(host)
            .map_or(0, |s| s.iter().filter(|d| **d != dst).count());
        let queries = plain_dns.get(host).copied().unwrap_or(0);
        let silent = others >= t.doh_other_dsts && queries < others;
        let why = if known {
            "znamy verejny DoH resolver".to_string()
        } else if dot {
            "DNS pres TLS (TCP 853)".to_string()
        } else if (shape_a || shape_b) && silent {
            format!(
                "{}; host kontaktoval {others} dalsich cilu a polozil jen {queries} obycejnych DNS dotazu",
                if shape_a {
                    "mnoho malych spojeni na jeden cil"
                } else {
                    "trvale spojeni s malymi zaznamy"
                }
            )
        } else {
            continue;
        };
        let sni = names
            .map(|s| s.iter().copied().collect::<Vec<_>>().join(","))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "bez SNI".into());
        let port = if dot { 853 } else { 443 };
        out.push(BehaviorFinding {
            finding: finding(
                "doh_suspected",
                host,
                &format!("doh/{dst}"),
                Severity::Low,
                if known || dot {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                format!("Host {host}: sifrovane DNS na {dst} ({why})"),
                format!(
                    "{} spojeni na {dst}:{port} ({sni}), median {:.0} B od klienta a {:.0} B od serveru. \
                     Duvod: {why}. Obchazi firemni resolver a jeho kontroly. \
                     Pravidlo heuristika-behavior:l7-doh@v1.",
                    flows.len(),
                    median(&mut up),
                    median(&mut down)
                ),
                vec![format!("{host} -> {dst}:{port}: {} spojeni", flows.len())],
                "Overit aplikaci a nastaveni DNS na hostu; povolit sifrovane DNS jen na firemni resolver.",
            ),
            sources: vec![dst.to_string()],
            targets: vec![(dst.to_string(), port)],
            count: flows.len() as u32,
            actor: host.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::TlsMeta;

    fn dns(src: &str, dst: &str, q: &str, qt: &str, ts: i64) -> L7Event {
        L7Event::Dns(DnsMeta {
            ts,
            src_ip: src.into(),
            dst_ip: dst.into(),
            qname: q.into(),
            qtype: qt.into(),
            rcode: Some("NOERROR".into()),
            answers: 1,
        })
    }

    fn conn(src: &str, dst: &str, port: u16, dur: f64, o: u64, r: u64, op: u64, rp: u64) -> ConnectionObservation {
        use chrono::TimeZone;
        ConnectionObservation {
            timestamp: chrono::Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(40000),
            dst_ip: dst.into(),
            proto: "tcp".into(),
            dst_port: Some(port),
            duration_s: Some(dur),
            orig_bytes: Some(o),
            resp_bytes: Some(r),
            total_bytes: Some(o + r),
            orig_pkts: Some(op),
            resp_pkts: Some(rp),
            total_pkts: Some(op + rp),
            conn_state: Some("SF".into()),
            history: None,
            missed_bytes: None,
        }
    }

    fn hexname(i: u64, len: usize) -> String {
        let mut s = String::new();
        let mut x = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        while s.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push_str(&format!("{x:016x}"));
        }
        s.truncate(len);
        s
    }

    fn int(ip: &str) -> bool {
        ip.starts_with("10.0.")
    }

    #[test]
    fn mixed_txt_cname_mx_tunnel_alarms_t1() {
        // dnscat2: střídání TXT, CNAME a MX, hex 60+ znaků ve více značkách
        let types = ["TXT", "CNAME", "MX"];
        let ev: Vec<L7Event> = (0..40)
            .map(|i| {
                let h = hexname(i, 120);
                dns(
                    "10.0.0.5",
                    "192.0.2.53",
                    &format!("{}.{}.t2.tun.example", &h[..60], &h[60..]),
                    types[i as usize % 3],
                    1_800_000_000 + i as i64,
                )
            })
            .collect();
        let f = dns_tunnel(&CovertThresholds::default(), &ev, &int);
        assert_eq!(f.len(), 1);
        assert!(f[0].finding.title.contains("T1"));
    }

    #[test]
    fn a_type_tunnel_needs_volume_av_reputation_does_not() {
        let t = CovertThresholds::default();
        // AV reputace: 2 dotazy/s, 48 hex znaků, typ A, 150 s
        let av: Vec<L7Event> = (0..300)
            .map(|i| {
                let h = hexname(i, 48);
                dns(
                    "10.0.0.6",
                    "192.0.2.53",
                    &format!("{}.{}.avqs.example", &h[..40], &h[40..]),
                    "A",
                    1_800_000_000 + i as i64 / 2,
                )
            })
            .collect();
        assert!(dns_tunnel(&t, &av, &int).is_empty());
        // tunel typu A: 30 dotazů/s, 100 znaků, 150 s
        let tun: Vec<L7Event> = (0..4500)
            .map(|i| {
                let h = hexname(i + 7, 100);
                dns(
                    "10.0.0.7",
                    "192.0.2.53",
                    &format!("{}.{}.t1.tun.example", &h[..50], &h[50..]),
                    "A",
                    1_800_000_000 + i as i64 / 30,
                )
            })
            .collect();
        let f = dns_tunnel(&t, &tun, &int);
        assert_eq!(f.len(), 1);
        assert!(f[0].finding.title.contains("T2"));
    }

    #[test]
    fn mdns_and_repeated_long_names_are_quiet() {
        let t = CovertThresholds::default();
        // mDNS: dlouhé UUID instance, PTR/SRV/TXT, multicast
        let m: Vec<L7Event> = (0..200)
            .map(|i| {
                dns(
                    "10.0.0.8",
                    "224.0.0.251",
                    &format!("Chromecast-{}._googlecast._tcp.local", hexname(i % 12, 32)),
                    if i % 2 == 0 { "SRV" } else { "TXT" },
                    1_800_000_000 + i as i64,
                )
            })
            .collect();
        assert!(dns_tunnel(&t, &m, &int).is_empty());
        // DKIM/SPF: málo různých jmen, mnoho opakování
        let d: Vec<L7Event> = (0..200)
            .map(|i| {
                dns(
                    "10.0.0.9",
                    "192.0.2.53",
                    &format!("selector{}._domainkey.mail.example", i % 3),
                    "TXT",
                    1_800_000_000 + i as i64,
                )
            })
            .collect();
        assert!(dns_tunnel(&t, &d, &int).is_empty());
    }

    #[test]
    fn encoded_part_joins_labels_before_zone() {
        assert_eq!(encoded_part("ab.cd.t2.tun.example", "tun.example"), "abcdt2");
        assert_eq!(encoded_part("tun.example", "tun.example"), "");
    }

    #[test]
    fn doh_per_lookup_connections_with_dns_silence_alarm() {
        let t = CovertThresholds::default();
        let mut flows: Vec<ConnectionObservation> = (0..40)
            .map(|_| conn("10.0.0.5", "192.0.2.70", 443, 0.01, 2000, 2400, 14, 11))
            .collect();
        flows.push(conn("10.0.0.5", "192.0.2.10", 443, 0.01, 1800, 2200, 13, 9));
        flows.push(conn("10.0.0.5", "192.0.2.11", 443, 0.01, 1800, 2200, 13, 9));
        let ev = vec![L7Event::Tls(TlsMeta {
            ts: 1_800_000_000,
            src_ip: "10.0.0.5".into(),
            dst_ip: "192.0.2.70".into(),
            ..TlsMeta::default()
        })];
        let f = doh(&t, &ev, &flows, &int);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].actor, "10.0.0.5");
        // tentýž tvar, ale host resolvuje obyčejným DNS (API polling): ticho
        let mut ev2 = ev.clone();
        for i in 0..40 {
            ev2.push(dns("10.0.0.5", "192.0.2.53", "api.example", "A", 1_800_000_000 + i));
        }
        assert!(doh(&t, &ev2, &flows, &int).is_empty());
    }

    #[test]
    fn doh_known_resolver_and_dot_alarm_alone() {
        let t = CovertThresholds::default();
        let ev = vec![L7Event::Tls(TlsMeta {
            ts: 1_800_000_000,
            src_ip: "10.0.0.5".into(),
            dst_ip: "203.0.113.9".into(),
            sni: Some("mozilla.cloudflare-dns.com".into()),
            ..TlsMeta::default()
        })];
        let one = vec![conn("10.0.0.5", "203.0.113.9", 443, 120.0, 90_000, 400_000, 600, 500)];
        assert_eq!(doh(&t, &ev, &one, &int).len(), 1);
        let dot = vec![conn("10.0.0.6", "198.51.100.3", 853, 5.0, 900, 1500, 9, 8)];
        assert_eq!(doh(&t, &[], &dot, &int).len(), 1);
        let ip = vec![conn("10.0.0.7", "8.8.8.8", 443, 5.0, 900, 1500, 9, 8)];
        assert_eq!(doh(&t, &[], &ip, &int).len(), 1);
    }

    #[test]
    fn long_small_record_connection_without_silence_is_quiet() {
        let t = CovertThresholds::default();
        // API long-poll v jednom spojení, host resolvuje normálně a nemá další cíle
        let flows = vec![conn("10.0.0.5", "192.0.2.10", 443, 150.0, 7000, 9000, 160, 120)];
        let ev = vec![dns("10.0.0.5", "192.0.2.53", "api.example", "A", 1_800_000_000)];
        assert!(doh(&t, &ev, &flows, &int).is_empty());
        // velké stažení: žádný tvar
        let big: Vec<ConnectionObservation> = (0..20)
            .map(|_| conn("10.0.0.5", "192.0.2.10", 443, 0.5, 400, 5_400_000, 60, 3800))
            .collect();
        assert!(doh(&t, &[], &big, &int).is_empty());
    }
}
