//! Obecné detektory rysů provozu (krok 9, impl-krok9.md, C1).
//!
//! Žádný detektor nezná rodinu útoku ani poruchy. Každý měří jednu vlastnost okna a
//! porovnává ji s historií téhož hostu nebo téže sítě:
//! - `broadcast_storm`: počet toků na broadcast, multicast a link-local adresy proti
//!   historii okna (porucha smyčky, mDNS/SSDP bouře, DHCP bouře; ale i skenování
//!   zdrojů, které tyto adresy zneužívají),
//! - `ingest_volume_anomaly`: stažený objem hostu (odchozí i vnitřní toky) proti
//!   historii hostu; hromadné stahování, sběr dat, záloha mimo okno,
//! - `slow_egress`: kumulovaný nahraný přebytek dvojice zdroj-cíl-port přes mnoho oken
//!   bez protiváhy ve stahování; pomalý únik pod prahem jednoho okna,
//! - `link_saturation`: celkový objem odchozího provozu sítě v okně proti historii
//!   sítě (zaplněná linka, hromadná záloha, distribuovaný únik).
//!
//! Prahy jsou autorova volba a ladí se jen na ladicích seedech (impl-krok9.md, B).
//! Nález nikdy nevzniká z prázdného okna (chybějící telemetrie není důkaz klidu ani
//! poplachu) a poplachové okno se do historie neučí (RQ2 Z3).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, evict_oldest, finding, median_mad},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

pub const BREADTH_TYPES: &[&str] = &[
    "broadcast_storm",
    "ingest_volume_anomaly",
    "slow_egress",
    "link_saturation",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BreadthThresholds {
    /// Minimální počet toků na zvláštní adresy v okně a bez historie.
    pub storm_min: f64,
    pub storm_cold: f64,
    /// Minimální stažený objem hostu v okně (B) a bez historie.
    pub down_min: f64,
    pub down_cold: f64,
    /// Kumulace pomalého úniku: oken, nahraný přebytek (B), poměr nahráno:staženo.
    pub slow_windows: u32,
    pub slow_bytes: f64,
    pub slow_ratio: f64,
    /// Nejmenší celkový objem sítě v okně (B) pro `link_saturation`.
    pub link_min: f64,
    pub link_cold: f64,
    pub z: f64,
    pub ratio: f64,
    pub min_history: usize,
    pub history: usize,
    pub max_hosts: usize,
    pub max_pairs: usize,
}

impl Default for BreadthThresholds {
    fn default() -> Self {
        Self {
            storm_min: 150.0,
            storm_cold: 600.0,
            down_min: 10.0e6,
            down_cold: 300.0e6,
            slow_windows: 6,
            slow_bytes: 4.0e6,
            slow_ratio: 8.0,
            link_min: 200.0e6,
            link_cold: 2.0e9,
            z: 6.0,
            ratio: 4.0,
            min_history: 6,
            history: 96,
            max_hosts: 50_000,
            max_pairs: 100_000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Series {
    history: Vec<f32>,
    last: i64,
}

impl Series {
    fn learn(&mut self, x: f64, cap: usize, now: i64) {
        self.last = now;
        self.history.push(x as f32);
        if self.history.len() > cap {
            let drop = self.history.len() - cap;
            self.history.drain(..drop);
        }
    }

    /// Robustní test odlehlosti; `None` = málo historie.
    fn outlier(&self, x: f64, t: &BreadthThresholds) -> Option<(f64, f64)> {
        if self.history.len() < t.min_history {
            return None;
        }
        let mut h: Vec<f64> = self.history.iter().map(|v| *v as f64).collect();
        let (median, mad) = median_mad(&mut h);
        let z = 0.6745 * (x - median) / mad.max(0.25);
        let ratio = (x - median).exp();
        (z >= t.z && ratio >= t.ratio).then_some((z, ratio))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PairAcc {
    first: i64,
    last: i64,
    windows: u32,
    up: f64,
    down: f64,
    alarmed_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BreadthState {
    storm: Series,
    link: Series,
    down: HashMap<String, Series>,
    pairs: HashMap<(String, String, u16), PairAcc>,
    pub evicted: u64,
}

/// Broadcast, multicast, link-local, nespecifikovaná adresa (IPv4 i IPv6).
pub fn is_special_dst(ip: &str) -> bool {
    if ip == "255.255.255.255" || ip == "0.0.0.0" {
        return true;
    }
    if let Some(first) = ip.split('.').next().and_then(|o| o.parse::<u8>().ok())
        && ip.matches('.').count() == 3
    {
        return (224..=239).contains(&first) || ip.starts_with("169.254.");
    }
    let lower = ip.to_ascii_lowercase();
    lower.starts_with("ff") || lower.starts_with("fe80:")
}

fn is_directed_broadcast(ip: &str) -> bool {
    ip.ends_with(".255") && ip.matches('.').count() == 3
}

fn bytes_of(f: &ConnectionObservation) -> (f64, f64) {
    (
        f.orig_bytes.unwrap_or(0) as f64,
        f.resp_bytes.unwrap_or(0) as f64,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn detect(
    state: &mut BreadthState,
    t: &BreadthThresholds,
    outbound: &[ConnectionObservation],
    internal: &[ConnectionObservation],
    now: i64,
    habit: &dyn Fn(&str, &str, &str, u16) -> bool,
) -> Vec<BehaviorFinding> {
    let mut out = Vec::new();
    // prazdne okno nic neuci a nic nehlasi
    if outbound.is_empty() && internal.is_empty() {
        return out;
    }

    // --- broadcast_storm ---
    let mut by_src: BTreeMap<&str, u32> = BTreeMap::new();
    let mut storm_total = 0u32;
    for flow in outbound.iter().chain(internal.iter()) {
        if is_special_dst(&flow.dst_ip) || is_directed_broadcast(&flow.dst_ip) {
            storm_total += 1;
            *by_src.entry(flow.src_ip.as_deref().unwrap_or("?")).or_default() += 1;
        }
    }
    let x = (1.0 + storm_total as f64).ln();
    let storm_alarm = f64::from(storm_total) >= t.storm_min
        && match state.storm.outlier(x, t) {
            Some(_) => true,
            None => {
                state.storm.history.len() < t.min_history && f64::from(storm_total) >= t.storm_cold
            }
        };
    if storm_alarm {
        let mut top: Vec<(&&str, &u32)> = by_src.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let actor = top.first().map(|(s, _)| (**s).to_string()).unwrap_or_default();
        let evidence: Vec<String> = top
            .iter()
            .take(6)
            .map(|(s, n)| format!("{s} -> broadcast/multicast: {n} toku"))
            .collect();
        let port = outbound
            .iter()
            .chain(internal.iter())
            .find(|f| is_special_dst(&f.dst_ip))
            .and_then(|f| f.dst_port)
            .unwrap_or(0);
        let f = finding(
            "broadcast_storm",
            &actor,
            &format!("special/{port}"),
            Severity::Medium,
            Confidence::Medium,
            format!("{storm_total} toku na broadcast a multicast v jednom okne"),
            "Pocet toku na zvlastni adresy v okne vybocuje z historie site; typicky smycka \
             v prepinani, chybna konfigurace zarizeni nebo zdroj, ktery adresy zneuziva. \
             Pravidlo heuristika-behavior:breadth_storm@v1."
                .to_string(),
            evidence,
            "Zjistit puvodce (zdroje v dukazech), overit smycku v prepinaci a nedavne zmeny konfigurace.",
        );
        out.push(BehaviorFinding {
            finding: f,
            sources: top.iter().take(6).map(|(s, _)| (**s).to_string()).collect(),
            targets: vec![("255.255.255.255".into(), port)],
            count: storm_total,
            actor,
        });
    } else if storm_total > 0 || !state.storm.history.is_empty() {
        state.storm.learn(x, t.history, now);
    }

    // --- ingest_volume_anomaly (stazeny objem na hosta) ---
    let mut down: BTreeMap<&str, (f64, BTreeMap<&str, f64>)> = BTreeMap::new();
    for flow in outbound.iter().chain(internal.iter()) {
        let Some(src) = flow.src_ip.as_deref() else {
            continue;
        };
        let (o, r) = bytes_of(flow);
        let net = (r - o).max(0.0);
        if net > 0.0 {
            let e = down.entry(src).or_default();
            e.0 += net;
            *e.1.entry(flow.dst_ip.as_str()).or_default() += net;
        }
    }
    for (host, (bytes, by_peer)) in &down {
        let entry = state.down.entry((*host).to_string()).or_default();
        let x = (1.0 + bytes).ln();
        let alarm = if *bytes < t.down_min {
            None
        } else if entry.history.len() < t.min_history {
            (*bytes >= t.down_cold).then(|| "bez historie, absolutni mez".to_string())
        } else {
            entry
                .outlier(x, t)
                .map(|(z, r)| format!("{r:.0}x median historie hostu, z = {z:.1}"))
        };
        match alarm {
            Some(basis) => {
                entry.last = now;
                let (peer, peer_bytes) = by_peer
                    .iter()
                    .max_by(|a, b| a.1.total_cmp(b.1).then(b.0.cmp(a.0)))
                    .map(|(p, b)| ((*p).to_string(), *b))
                    .unwrap_or_default();
                let port = outbound
                    .iter()
                    .chain(internal.iter())
                    .find(|f| f.src_ip.as_deref() == Some(host) && f.dst_ip == peer)
                    .and_then(|f| f.dst_port)
                    .unwrap_or(0);
                let f = finding(
                    "ingest_volume_anomaly",
                    host,
                    "in/download",
                    Severity::Medium,
                    Confidence::Medium,
                    format!("Host {host} stahl {:.0} MB, hlavne z {peer}", bytes / 1e6),
                    format!(
                        "Stazeny objem okna vybocuje z historie hostu ({basis}); {:.0} % z {peer}:{port}. \
                         Pravidlo heuristika-behavior:breadth_ingest@v1.",
                        peer_bytes * 100.0 / bytes.max(1.0)
                    ),
                    by_peer
                        .iter()
                        .take(5)
                        .map(|(p, b)| format!("{host} <- {p}: {:.1} MB", b / 1e6))
                        .collect(),
                    "Overit, zda jde o aktualizaci, zalohu nebo obnovu (kalendar, profil hostu); jinak proverit hromadne stahovani dat.",
                );
                out.push(BehaviorFinding {
                    finding: f,
                    sources: vec![peer.clone()],
                    targets: vec![(peer, port)],
                    count: (bytes / 1e6).min(f64::from(u32::MAX)) as u32,
                    actor: (*host).to_string(),
                });
            }
            None => entry.learn(x, t.history, now),
        }
    }

    // --- slow_egress (kumulace pomaleho uniku na dvojici) ---
    let mut pair_now: BTreeMap<(&str, &str, u16), (f64, f64)> = BTreeMap::new();
    for flow in outbound {
        let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
            continue;
        };
        let (o, r) = bytes_of(flow);
        let e = pair_now
            .entry((src, flow.dst_ip.as_str(), port))
            .or_default();
        e.0 += o;
        e.1 += r;
    }
    for ((src, dst, port), (up, dn)) in pair_now {
        // jen male a stredni objemy: velke jdou pres egress_volume_anomaly
        let key = (src.to_string(), dst.to_string(), port);
        let acc = state.pairs.entry(key).or_default();
        if acc.windows == 0 || now - acc.last > 12 * 1800 {
            *acc = PairAcc {
                first: now,
                ..PairAcc::default()
            };
        }
        acc.last = now;
        acc.windows += 1;
        acc.up += up;
        acc.down += dn;
        let proto = "tcp";
        if acc.windows >= t.slow_windows
            && acc.up - acc.down >= t.slow_bytes
            && acc.up >= t.slow_ratio * acc.down.max(1.0)
            && (acc.alarmed_at == 0 || now - acc.alarmed_at > 48 * 1800)
            && !habit(src, dst, proto, port)
        {
            acc.alarmed_at = now;
            let f = finding(
                "slow_egress",
                src,
                &format!("out/{dst}:{port}"),
                Severity::Medium,
                Confidence::Low,
                format!(
                    "Host {src} odeslal na {dst}:{port} za {} oken {:.1} MB bez protihodnoty",
                    acc.windows,
                    acc.up / 1e6
                ),
                format!(
                    "Kumulovany nahrany prebytek dvojice {:.1} MB ve {} oknech, stazeno {:.2} MB; \
                     pomaly unik pod prahem jednoho okna. Pravidlo heuristika-behavior:breadth_slow@v1.",
                    (acc.up - acc.down) / 1e6,
                    acc.windows,
                    acc.down / 1e6
                ),
                vec![format!("{src} -> {dst}:{port}: {:.1} MB", acc.up / 1e6)],
                "Overit, zda je cil zamyslenou sluzbou (profil hostu, kalendar); jinak proverit proces a obsah prenosu.",
            );
            out.push(BehaviorFinding {
                finding: f,
                sources: vec![dst.to_string()],
                targets: vec![(dst.to_string(), port)],
                count: acc.windows,
                actor: src.to_string(),
            });
        }
    }
    // omezeni stavu: dvojice mimo posledni hodiny pryc, pak strop
    state.pairs.retain(|_, a| now - a.last <= 24 * 3600);
    state.evicted += evict_oldest(&mut state.pairs, t.max_pairs, |a| a.last) as u64;
    state.evicted += evict_oldest(&mut state.down, t.max_hosts, |s| s.last) as u64;

    // --- link_saturation (celkovy odchozi objem site) ---
    let total: f64 = outbound
        .iter()
        .map(|f| {
            let (o, r) = bytes_of(f);
            o + r
        })
        .sum();
    let x = (1.0 + total).ln();
    let alarm = if total < t.link_min {
        None
    } else if state.link.history.len() < t.min_history {
        (total >= t.link_cold).then(|| "bez historie, absolutni mez".to_string())
    } else {
        state
            .link
            .outlier(x, t)
            .map(|(z, r)| format!("{r:.1}x median historie site, z = {z:.1}"))
    };
    match alarm {
        Some(basis) => {
            let mut by_host: BTreeMap<&str, f64> = BTreeMap::new();
            for f in outbound {
                let (o, r) = bytes_of(f);
                *by_host.entry(f.src_ip.as_deref().unwrap_or("?")).or_default() += o + r;
            }
            let mut top: Vec<(&&str, &f64)> = by_host.iter().collect();
            top.sort_by(|a, b| b.1.total_cmp(a.1).then(a.0.cmp(b.0)));
            let actor = top.first().map(|(h, _)| (**h).to_string()).unwrap_or_default();
            let port = outbound.iter().find_map(|f| f.dst_port).unwrap_or(0);
            let f = finding(
                "link_saturation",
                &actor,
                "link/egress",
                Severity::Medium,
                Confidence::Low,
                format!("Odchozi objem site {:.0} MB v jednom okne", total / 1e6),
                format!(
                    "Celkovy objem odchoziho provozu vybocuje z historie site ({basis}); \
                     nejvetsi prispevatel {actor}. Pravidlo heuristika-behavior:breadth_link@v1."
                ),
                top.iter()
                    .take(8)
                    .map(|(h, b)| format!("{h}: {:.0} MB", **b / 1e6))
                    .collect(),
                "Rozlisit zalohu a aktualizace (kalendar) od neplanovaneho zaplneni linky; zjistit, zda je pricinou jeden host nebo vice.",
            );
            out.push(BehaviorFinding {
                finding: f,
                sources: top.iter().take(8).map(|(h, _)| (**h).to_string()).collect(),
                targets: vec![("0.0.0.0".into(), port)],
                count: (total / 1e6).min(f64::from(u32::MAX)) as u32,
                actor,
            });
        }
        None => state.link.learn(x, t.history, now),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn flow(src: &str, dst: &str, port: u16, ob: u64, rb: u64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(40000),
            dst_ip: dst.into(),
            dst_port: Some(port),
            proto: "tcp".into(),
            duration_s: Some(1.0),
            orig_bytes: Some(ob),
            resp_bytes: Some(rb),
            total_bytes: None,
            orig_pkts: None,
            resp_pkts: None,
            total_pkts: None,
            conn_state: Some("SF".into()),
            history: None,
            missed_bytes: None,
        }
    }

    fn no_habit(_: &str, _: &str, _: &str, _: u16) -> bool {
        false
    }

    #[test]
    fn special_addresses_recognised() {
        assert!(is_special_dst("255.255.255.255"));
        assert!(is_special_dst("224.0.0.251"));
        assert!(is_special_dst("169.254.1.2"));
        assert!(is_special_dst("ff02::fb"));
        assert!(!is_special_dst("10.0.0.5"));
        assert!(!is_special_dst("8.8.8.8"));
    }

    #[test]
    fn empty_window_neither_learns_nor_reports() {
        let mut state = BreadthState::default();
        let out = detect(&mut state, &BreadthThresholds::default(), &[], &[], 100, &no_habit);
        assert!(out.is_empty() && state.link.history.is_empty());
    }

    #[test]
    fn storm_after_quiet_history_is_reported_once_and_not_learned() {
        let t = BreadthThresholds::default();
        let mut state = BreadthState::default();
        let quiet: Vec<_> = (0..20)
            .map(|_| flow("10.0.0.5", "224.0.0.251", 5353, 100, 0))
            .collect();
        for w in 0..10 {
            let out = detect(&mut state, &t, &quiet, &[], 1800 * w, &no_habit);
            assert!(out.is_empty());
        }
        let burst: Vec<_> = (0..900)
            .map(|_| flow("10.0.0.9", "255.255.255.255", 137, 90, 0))
            .collect();
        let before = state.storm.history.len();
        let out = detect(&mut state, &t, &burst, &[], 1800 * 11, &no_habit);
        assert!(out.iter().any(|f| f.finding.finding_type == "broadcast_storm"));
        assert_eq!(state.storm.history.len(), before, "poplach se neuci");
        assert!(
            out[0]
                .finding
                .evidence
                .iter()
                .any(|e| e.contains("10.0.0.9"))
        );
    }

    #[test]
    fn slow_egress_accumulates_over_windows_but_not_habit() {
        let t = BreadthThresholds::default();
        let mut state = BreadthState::default();
        let mut got = 0;
        for w in 0..10 {
            let flows = vec![flow("10.0.0.7", "203.0.113.9", 443, 900_000, 1_000)];
            got += detect(&mut state, &t, &flows, &[], 1800 * w, &no_habit)
                .iter()
                .filter(|f| f.finding.finding_type == "slow_egress")
                .count();
        }
        assert_eq!(got, 1);
        let mut habitual = BreadthState::default();
        let mut got = 0;
        for w in 0..10 {
            let flows = vec![flow("10.0.0.7", "203.0.113.9", 443, 900_000, 1_000)];
            got += detect(&mut habitual, &t, &flows, &[], 1800 * w, &|_, _, _, _| true)
                .len();
        }
        assert_eq!(got, 0);
    }

    #[test]
    fn symmetric_transfer_is_not_slow_egress() {
        let t = BreadthThresholds::default();
        let mut state = BreadthState::default();
        for w in 0..20 {
            let flows = vec![flow("10.0.0.7", "203.0.113.9", 443, 900_000, 800_000)];
            let out = detect(&mut state, &t, &flows, &[], 1800 * w, &no_habit);
            assert!(out.iter().all(|f| f.finding.finding_type != "slow_egress"));
        }
    }

    #[test]
    fn ingest_outlier_needs_history_or_cold_limit() {
        let t = BreadthThresholds::default();
        let mut state = BreadthState::default();
        let small = vec![flow("10.0.0.5", "203.0.113.1", 443, 1_000, 200_000)];
        for w in 0..10 {
            assert!(detect(&mut state, &t, &small, &[], 1800 * w, &no_habit).is_empty());
        }
        let big = vec![flow("10.0.0.5", "203.0.113.1", 443, 1_000, 60_000_000)];
        let out = detect(&mut state, &t, &big, &[], 1800 * 11, &no_habit);
        assert!(
            out.iter()
                .any(|f| f.finding.finding_type == "ingest_volume_anomaly")
        );
    }
}
