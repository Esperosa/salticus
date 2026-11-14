//! Detektory nad metadaty TLS a DNS (krok 12, impl-krok12.md, část B).
//!
//! Žádné pravidlo nezná port ani rodinu útoku. Každé kombinuje **aspoň dva nezávislé
//! rysy** (studie 12, oddíl 2): novost pro hosta a rys klienta nebo certifikátu nebo
//! rarita v síti. Vstup `L7Event` (Zeek `ssl.log`, `x509.log`, `dns.log`; Suricata EVE)
//! je volitelný: bez něj detektory mlčí a nic se nezavírá ani neztrácí.
//!
//! - `tls_rare_transfer`: zralý host přenesl ≥ `bulk_bytes` (čistě stažení nebo nahrání)
//!   k TLS cíli, který **host dosud nepoužil**, a zároveň aspoň jeden druhý rys:
//!   host nikdy neviděný otisk klienta (JA3 nebo JA4), čerstvý nebo self-signed
//!   certifikát, nebo bez SNI (přímá IP). Rarita cíle v síti (známý nejvýš `fleet_max`
//!   hostům) se do poplachu jen připisuje jako okolnost: v malé síti je málo používané
//!   každé jméno, takže sama o sobě druhým rysem není (měření 2026-11-14: bez tohoto
//!   pravidla zobrazovala 46 až 54 % neškodných aktualizací a pošty).
//! - `tls_novel_burst`: ≥ `burst_flows` TLS spojení do `burst_span_s` na cíl, který host
//!   dosud nepoužil, se stejným druhým rysem.
//! - `dns_zone_enumeration`: jeden zdroj položil ≥ `enum_names` různých jmen pod jednou
//!   zónou a zároveň (podíl NXDOMAIN ≥ `enum_nx` nebo dotaz typu AXFR/IXFR/ANY); nebo
//!   jakýkoli AXFR/IXFR od zdroje mimo rozsah. Směr nerozhoduje (vnější zdroj se
//!   dostává přes `inbound`).
//!
//! Poplachový pár (host, cíl) se neučí do historie (gating, RQ2 Z3). Všechny struktury
//! mají strop velikosti. Prahy jsou volba autora a ladí se jen na ladicích seedech.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, evict_oldest, finding},
    l7::{DnsMeta, L7Event, TlsMeta, name_entropy, zone_of},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

pub const L7_TYPES: &[&str] = &[
    "tls_rare_transfer",
    "tls_novel_burst",
    "dns_zone_enumeration",
    "dns_tunnel_names",
    "icmp_payload_anomaly",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct L7Thresholds {
    pub mature_s: i64,
    pub fleet_max: usize,
    pub bulk_bytes: f64,
    pub burst_flows: usize,
    pub burst_span_s: i64,
    /// Certifikát mladší než tolik sekund je „čerstvý“.
    pub young_cert_s: i64,
    pub enum_names: usize,
    pub enum_nx: f64,
    /// Tunel pres DNS: nejmene ruznych jmen, delka a entropie nejlevejsi znacky a podil TXT/NULL.
    pub tunnel_names: usize,
    pub tunnel_label: f64,
    pub tunnel_entropy: f64,
    pub tunnel_txt: f64,
    pub max_hosts: usize,
    pub max_snis: usize,
    pub per_host_cap: usize,
}

impl Default for L7Thresholds {
    fn default() -> Self {
        Self {
            mature_s: 12 * 3600,
            fleet_max: 2,
            bulk_bytes: 2.0e6,
            burst_flows: 6,
            burst_span_s: 300,
            young_cert_s: 30 * 86_400,
            enum_names: 15,
            enum_nx: 0.3,
            tunnel_names: 8,
            tunnel_label: 24.0,
            tunnel_entropy: 3.0,
            tunnel_txt: 0.6,
            max_hosts: 50_000,
            max_snis: 200_000,
            per_host_cap: 512,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SniInfo {
    last: i64,
    /// (vnitřní host, naposledy), nejvýš 64.
    hosts: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HostL7 {
    last: i64,
    snis: BTreeSet<String>,
    prints: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct L7State {
    snis: HashMap<String, SniInfo>,
    hosts: HashMap<String, HostL7>,
    pub evicted: u64,
}

impl L7State {
    fn fleet(&self, sni: &str, now: i64) -> usize {
        self.snis.get(sni).map_or(0, |i| {
            i.hosts
                .iter()
                .filter(|(_, last)| now - last <= 7 * 86_400)
                .count()
        })
    }
}

fn print_of(t: &TlsMeta) -> Option<&str> {
    t.ja4.as_deref().or(t.ja3.as_deref())
}

/// Dvojice (host, cíl) jednoho okna: cíl = SNI, jinak adresa.
#[derive(Default)]
struct Group {
    flows: Vec<i64>,
    bytes_up: f64,
    bytes_down: f64,
    prints: BTreeSet<String>,
    young: bool,
    selfsigned: bool,
    no_sni: bool,
    dst: String,
    port: u16,
    sni: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn detect(
    state: &mut L7State,
    t: &L7Thresholds,
    events: &[L7Event],
    outbound: &[ConnectionObservation],
    inbound: &[ConnectionObservation],
    first_seen: &dyn Fn(&str) -> Option<i64>,
    internal: &dyn Fn(&str) -> bool,
    now: i64,
    tls_on: bool,
    dns_on: bool,
) -> Vec<BehaviorFinding> {
    let mut out = Vec::new();
    if events.is_empty() {
        return out;
    }
    let mut alarmed: HashSet<(String, String)> = HashSet::new();

    if tls_on {
        // bajty podle pětice (toky odchozí i příchozí: stažení z vnitřního hosta je odchozí tok)
        let mut bytes: HashMap<(&str, u16, &str, u16), (f64, f64)> = HashMap::new();
        for f in outbound.iter().chain(inbound.iter()) {
            if let (Some(s), Some(sp), Some(dp)) = (f.src_ip.as_deref(), f.src_port, f.dst_port) {
                let e = bytes.entry((s, sp, f.dst_ip.as_str(), dp)).or_default();
                e.0 += f.orig_bytes.unwrap_or(0) as f64;
                e.1 += f.resp_bytes.unwrap_or(0) as f64;
            }
        }
        let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
        for ev in events {
            let L7Event::Tls(tls) = ev else { continue };
            if !internal(&tls.src_ip) || internal(&tls.dst_ip) {
                continue; // jen odchozí TLS vnitřních hostů
            }
            let key_dst = tls.sni.clone().unwrap_or_else(|| tls.dst_ip.clone());
            let g = groups
                .entry((tls.src_ip.clone(), key_dst))
                .or_insert_with(|| Group {
                    dst: tls.dst_ip.clone(),
                    port: tls.dst_port.unwrap_or(443),
                    sni: tls.sni.clone(),
                    ..Group::default()
                });
            g.flows.push(tls.ts);
            if let (Some(sp), Some(dp)) = (tls.src_port, tls.dst_port)
                && let Some((o, r)) = bytes.get(&(tls.src_ip.as_str(), sp, tls.dst_ip.as_str(), dp))
            {
                g.bytes_up += (o - r).max(0.0);
                g.bytes_down += (r - o).max(0.0);
            }
            if let Some(p) = print_of(tls) {
                g.prints.insert(p.to_string());
            }
            if let Some(nb) = tls.not_before
                && tls.ts - nb < t.young_cert_s
            {
                g.young = true;
            }
            if let (Some(i), Some(s)) = (&tls.issuer, &tls.subject)
                && i == s
            {
                g.selfsigned = true;
            }
            if tls.sni.is_none() {
                g.no_sni = true;
            }
        }
        for ((host, target), g) in &groups {
            let mature = first_seen(host).is_some_and(|f| now - f >= t.mature_s);
            if !mature {
                continue;
            }
            let known_target = state
                .hosts
                .get(host)
                .is_some_and(|h| h.snis.contains(target));
            if known_target {
                continue;
            }
            let host_prints = state.hosts.get(host);
            let new_print = !g.prints.is_empty()
                && host_prints.is_some_and(|h| !h.prints.is_empty())
                && g.prints
                    .iter()
                    .any(|p| host_prints.is_some_and(|h| !h.prints.contains(p)));
            let fleet = state.fleet(target, now);
            let rare = fleet <= t.fleet_max;
            // druhy rys: nový otisk klienta, rarita v síti, čerstvý či self-signed certifikát, bez SNI
            let mut second: Vec<&str> = Vec::new();
            if new_print {
                second.push("novy otisk klienta");
            }
            if g.young {
                second.push("cerstvy certifikat");
            }
            if g.selfsigned {
                second.push("self-signed certifikat");
            }
            if g.no_sni {
                second.push("bez SNI");
            }
            if second.is_empty() {
                continue; // rarita cile sama o sobe neni druhy rys (v mensich sitich ji ma kazde jmeno)
            }
            if rare {
                second.push("cil zna nejvyse par hostu");
            }
            let transfer = g.bytes_up.max(g.bytes_down);
            let kind = if transfer >= t.bulk_bytes {
                Some("tls_rare_transfer")
            } else if g.flows.len() >= t.burst_flows && {
                let mut ts = g.flows.clone();
                ts.sort_unstable();
                let k = t.burst_flows;
                ts.windows(k).any(|w| w[k - 1] - w[0] <= t.burst_span_s)
            } {
                Some("tls_novel_burst")
            } else {
                None
            };
            let Some(kind) = kind else { continue };
            alarmed.insert((host.clone(), target.clone()));
            let why = second.join(", ");
            let (title, rationale) = if kind == "tls_rare_transfer" {
                (
                    format!(
                        "Host {host} prenesl {:.1} MB k novemu TLS cili {target}",
                        transfer / 1e6
                    ),
                    format!(
                        "Cil host dosud nepouzil; {why}. Cisty prenos {:.1} MB v jednom okne. \
                         Pravidlo heuristika-behavior:l7-tls-transfer@v1.",
                        transfer / 1e6
                    ),
                )
            } else {
                (
                    format!(
                        "Host {host}: {} TLS spojeni na novy cil {target} do {} s",
                        g.flows.len(),
                        t.burst_span_s
                    ),
                    format!(
                        "Cil host dosud nepouzil; {why}. Pravidlo heuristika-behavior:l7-tls-burst@v1."
                    ),
                )
            };
            out.push(BehaviorFinding {
                finding: finding(
                    kind,
                    host,
                    &format!("tls/{target}"),
                    Severity::Medium,
                    Confidence::Low,
                    title,
                    rationale,
                    vec![format!(
                        "{host} -> {target} ({}:{}): {} toku, {:.1} MB, druhy rys: {why}",
                        g.dst,
                        g.port,
                        g.flows.len(),
                        transfer / 1e6
                    )],
                    "Overit proces a ucel spojeni (zamyslena sluzba, aktualizace, zaloha); \
                     nezname a nove se automaticky nezavira.",
                ),
                sources: vec![g.dst.clone()],
                targets: vec![(g.dst.clone(), g.port)],
                count: g.flows.len() as u32,
                actor: host.clone(),
            });
        }
        // učení: jen páry bez poplachu
        for ((host, target), g) in &groups {
            if alarmed.contains(&(host.clone(), target.clone())) {
                continue;
            }
            let h = state.hosts.entry(host.clone()).or_default();
            h.last = now;
            if h.snis.len() < t.per_host_cap {
                h.snis.insert(target.clone());
            }
            for p in &g.prints {
                if h.prints.len() < 32 {
                    h.prints.insert(p.clone());
                }
            }
            let info = state.snis.entry(target.clone()).or_default();
            info.last = now;
            if let Some(e) = info.hosts.iter_mut().find(|(x, _)| x == host) {
                e.1 = now;
            } else if info.hosts.len() < 64 {
                info.hosts.push((host.clone(), now));
            }
        }
        state.evicted += evict_oldest(&mut state.hosts, t.max_hosts, |h| h.last) as u64;
        state.evicted += evict_oldest(&mut state.snis, t.max_snis, |i| i.last) as u64;
    }

    if dns_on {
        let mut by_src: BTreeMap<&str, Vec<&DnsMeta>> = BTreeMap::new();
        for ev in events {
            if let L7Event::Dns(d) = ev {
                by_src.entry(d.src_ip.as_str()).or_default().push(d);
            }
        }
        for (src, list) in &by_src {
            // tunel pres DNS: dva nezavisle rysy, tvar jmena (delka a entropie) a typ zaznamu
            if !internal(src) {
                continue;
            }
            let mut per_zone: BTreeMap<&str, Vec<&DnsMeta>> = BTreeMap::new();
            for d in list {
                per_zone.entry(zone_of(&d.qname)).or_default().push(d);
            }
            for (zone, items) in per_zone {
                let names: BTreeSet<&str> = items.iter().map(|d| d.qname.as_str()).collect();
                if names.len() < t.tunnel_names {
                    continue;
                }
                let label = |d: &&DnsMeta| d.qname.split('.').next().unwrap_or("").to_string();
                let avg_len = items.iter().map(|d| label(d).len() as f64).sum::<f64>() / items.len() as f64;
                let avg_ent = items.iter().map(|d| name_entropy(&label(d))).sum::<f64>() / items.len() as f64;
                let txt = items
                    .iter()
                    .filter(|d| matches!(d.qtype.as_str(), "TXT" | "NULL" | "PRIVATE"))
                    .count() as f64
                    / items.len() as f64;
                if avg_len >= t.tunnel_label && avg_ent >= t.tunnel_entropy && txt >= t.tunnel_txt {
                    let server = items[0].dst_ip.as_str();
                    out.push(BehaviorFinding {
                        finding: finding(
                            "dns_tunnel_names",
                            src,
                            &format!("dns/{zone}"),
                            Severity::Medium,
                            Confidence::Medium,
                            format!("Host {src}: {} dlouhych nahodnych jmen pod {zone} (TXT {:.0} %)", names.len(), txt * 100.0),
                            format!(
                                "Prumerna delka znacky {avg_len:.0}, entropie {avg_ent:.1} bitu/znak, podil TXT/NULL {:.0} %: \
                                 tvar jmen i typ zaznamu odpovidaji DNS tunelu. Pravidlo heuristika-behavior:l7-dns-tunnel@v1.",
                                txt * 100.0
                            ),
                            vec![format!("{src} -> {server}: {} jmen pod {zone}", names.len())],
                            "Overit proces a ucel dotazu; omezit TXT a NULL dotazy z klientu.",
                        ),
                        sources: vec![server.to_string()],
                        targets: vec![(server.to_string(), 53)],
                        count: names.len() as u32,
                        actor: src.to_string(),
                    });
                }
            }
        }
        for (src, list) in by_src {
            let mut zones: BTreeMap<&str, (BTreeSet<&str>, u32, u32, bool, &str)> = BTreeMap::new();
            for d in &list {
                let z = zones
                    .entry(zone_of(&d.qname))
                    .or_insert_with(|| (BTreeSet::new(), 0, 0, false, d.dst_ip.as_str()));
                z.0.insert(d.qname.as_str());
                z.1 += 1;
                z.2 += (d.rcode.as_deref() == Some("NXDOMAIN")) as u32;
                z.3 |= matches!(d.qtype.as_str(), "AXFR" | "IXFR" | "ANY");
            }
            for (zone, (names, total, nx, transfer, server)) in zones {
                let nx_ratio = f64::from(nx) / f64::from(total.max(1));
                let by_names = names.len() >= t.enum_names && (nx_ratio >= t.enum_nx || transfer);
                let external_transfer = transfer && !internal(src);
                if !by_names && !external_transfer {
                    continue;
                }
                out.push(BehaviorFinding {
                    finding: finding(
                        "dns_zone_enumeration",
                        server,
                        &format!("dns/{zone}"),
                        Severity::Medium,
                        Confidence::Medium,
                        format!(
                            "Zdroj {src} vycetl zonu {zone}: {} jmen, NXDOMAIN {:.0} %",
                            names.len(),
                            nx_ratio * 100.0
                        ),
                        format!(
                            "Jeden zdroj polozil {} ruznych jmen pod zonou {zone} ({} dotazu), \
                             podil NXDOMAIN {:.0} %{}. Pravidlo heuristika-behavior:l7-dns-enum@v1.",
                            names.len(),
                            total,
                            nx_ratio * 100.0,
                            if transfer { ", dotazy typu AXFR/IXFR/ANY" } else { "" }
                        ),
                        vec![format!("{src} -> {server}: {} jmen v zone {zone}", names.len())],
                        "Overit, zda zdroj smi dotazovat zonu; omezit prenosy zony a vycet jmen na DNS serveru.",
                    ),
                    sources: vec![src.to_string()],
                    targets: vec![(server.to_string(), 53)],
                    count: names.len() as u32,
                    actor: server.to_string(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(src: &str, dst: &str, sni: Option<&str>, ja3: &str, at: i64, sp: u16) -> L7Event {
        L7Event::Tls(TlsMeta {
            ts: at,
            src_ip: src.into(),
            src_port: Some(sp),
            dst_ip: dst.into(),
            dst_port: Some(443),
            sni: sni.map(str::to_string),
            ja3: Some(ja3.into()),
            ..TlsMeta::default()
        })
    }

    fn flow(src: &str, sp: u16, dst: &str, o: u64, r: u64, at: i64) -> ConnectionObservation {
        use chrono::TimeZone;
        ConnectionObservation {
            timestamp: chrono::Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(sp),
            dst_ip: dst.into(),
            proto: "tcp".into(),
            dst_port: Some(443),
            duration_s: Some(5.0),
            orig_bytes: Some(o),
            resp_bytes: Some(r),
            total_bytes: Some(o + r),
            orig_pkts: None,
            resp_pkts: None,
            total_pkts: None,
            conn_state: Some("SF".into()),
            history: None,
            missed_bytes: None,
        }
    }

    fn run(
        state: &mut L7State,
        ev: &[L7Event],
        fl: &[ConnectionObservation],
        now: i64,
    ) -> Vec<BehaviorFinding> {
        detect(
            state,
            &L7Thresholds::default(),
            ev,
            fl,
            &[],
            &|_| Some(0),
            &|ip| ip.starts_with("10."),
            now,
            true,
            true,
        )
    }

    #[test]
    fn known_target_with_host_print_is_quiet_new_target_with_new_print_alarms() {
        let mut state = L7State::default();
        let now = 1_800_000_000;
        // historie: host zna cil a svuj otisk
        let hist = vec![tls("10.0.0.5", "198.51.100.1", Some("updates.vendor.example"), "browser", now - 9000, 40000)];
        assert!(run(&mut state, &hist, &[], now - 9000).is_empty());
        // znamy cil, velky prenos: ticho (zadny novy cil)
        let known = vec![tls("10.0.0.5", "198.51.100.1", Some("updates.vendor.example"), "browser", now, 40001)];
        let big = vec![flow("10.0.0.5", 40001, "198.51.100.1", 500, 30_000_000, now)];
        assert!(run(&mut state, &known, &big, now).is_empty());
        // novy cil, ale otisk hosta a siroce sdileny cil: ticho (zadny druhy rys)
        for h in 0..6 {
            let other = vec![tls(&format!("10.0.1.{h}"), "198.51.100.7", Some("cdn.popular.example"), "browser", now - 100, 41000)];
            run(&mut state, &other, &[], now - 100);
        }
        let shared = vec![tls("10.0.0.5", "198.51.100.7", Some("cdn.popular.example"), "browser", now, 40002)];
        let big2 = vec![flow("10.0.0.5", 40002, "198.51.100.7", 500, 30_000_000, now)];
        assert!(run(&mut state, &shared, &big2, now).is_empty());
        // novy vzacny cil + novy otisk + velky prenos: poplach
        let evil = vec![tls("10.0.0.5", "203.0.113.50", Some("x8k2.rare.example"), "scripted", now, 40003)];
        let big3 = vec![flow("10.0.0.5", 40003, "203.0.113.50", 500, 30_000_000, now)];
        let found = run(&mut state, &evil, &big3, now);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].finding.finding_type, "tls_rare_transfer");
        // poplachovy par se neuci: dalsi okno znovu hlasi
        assert_eq!(run(&mut state, &evil, &big3, now + 1800).len(), 1);
    }

    #[test]
    fn dns_tunnel_needs_label_shape_and_txt_type() {
        let mk = |qtype: &str, n: usize| -> Vec<L7Event> {
            (0..n)
                .map(|i| {
                    L7Event::Dns(DnsMeta {
                        ts: 1_800_000_000 + i as i64,
                        src_ip: "10.0.0.5".into(),
                        dst_ip: "10.0.0.2".into(),
                        qname: format!("{:x}q8x2kz9pw1msv7b3n5c4d6f0{}.tun.example", 0x5eed_u64 * (i as u64 + 7), i),
                        qtype: qtype.into(),
                        rcode: Some("NOERROR".into()),
                        answers: 1,
                    })
                })
                .collect()
        };
        let mut state = L7State::default();
        let txt = run(&mut state, &mk("TXT", 20), &[], 1_800_000_100);
        assert!(txt.iter().any(|f| f.finding.finding_type == "dns_tunnel_names"));
        // dlouha hashovana jmena typu A (CDN) nejsou tunel
        assert!(run(&mut state, &mk("A", 20), &[], 1_800_000_100).is_empty());
        // malo jmen
        assert!(run(&mut state, &mk("TXT", 4), &[], 1_800_000_100).is_empty());
    }

    #[test]
    fn dns_enumeration_needs_names_and_nxdomain_or_transfer() {
        let mk = |n: usize, nx: bool, qtype: &str| -> Vec<L7Event> {
            (0..n)
                .map(|i| {
                    L7Event::Dns(DnsMeta {
                        ts: 1_800_000_000 + i as i64,
                        src_ip: "198.51.100.4".into(),
                        dst_ip: "10.0.0.2".into(),
                        qname: format!("h{i}.corp.example"),
                        qtype: qtype.into(),
                        rcode: Some(if nx { "NXDOMAIN" } else { "NOERROR" }.into()),
                        answers: 0,
                    })
                })
                .collect()
        };
        let mut state = L7State::default();
        assert_eq!(run(&mut state, &mk(30, true, "A"), &[], 1_800_000_100).len(), 1);
        // mnoho jmen bez NXDOMAIN a bez prenosu: bezny prekladac
        assert!(run(&mut state, &mk(30, false, "A"), &[], 1_800_000_100).is_empty());
        // malo jmen: ticho
        assert!(run(&mut state, &mk(5, true, "A"), &[], 1_800_000_100).is_empty());
        // AXFR od vnejsiho zdroje: poplach i s jednim dotazem
        assert_eq!(run(&mut state, &mk(1, false, "AXFR"), &[], 1_800_000_100).len(), 1);
    }
}
