//! Odchozí skenování a rozesílání (krok 31): vnitřní host, který navazuje spojení na mnoho
//! různých vnějších cílů a většina pokusů selže (SYN bez odpovědi nebo odmítnutí).
//!
//! Měření kroku 30 na skutečných botnetech CTU-13 ukázalo, že infikovaný host, který hned po
//! infekci skenuje internet (desítky tisíc SYN na stovky cílů), nemá v produktu žádný nález:
//! pokusy bez odpovědi se jako `scan_attempts` počítají jen u toků s cílem v rozsahu a
//! behaviorální detektory odchozího provozu vyžadují zralý profil hosta.
//!
//! Pravidlo nezávisí na historii hosta: aspoň `min_targets` různých vnějších cílů s neúspěšným
//! TCP spojením na stejný port během `span_s` sekund a podíl neúspěšných spojení na tento port
//! v úseku aspoň `min_failed_ratio`. Prahy 25 cílů a 5 minut jsou výchozí hodnoty skriptu
//! `scan.zeek` v Zeeku (`addr_scan_threshold`, `scan_interval`); podmínka většiny neúspěšných
//! odlišuje sken od hostu s mnoha spojeními, z nichž část selhala (měřeno na domácí síti).
//! Prahy se nelaďily na pravdě testovacích scénářů.
//!
//! Neškodně ho může vyrobit peer-to-peer klient s mnoha mrtvými peery, pomalé nebo
//! blokované cíle a vlastní skener správce. Nález je chráněný typ (nikdy se neuzavře
//! automaticky).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, finding},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

pub const OUTSCAN_TYPES: &[&str] = &["outbound_scan"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutscanThresholds {
    /// Nejmenší počet různých cílů s neúspěšným spojením na stejný port v úseku.
    pub min_targets: usize,
    /// Délka úseku (s).
    pub span_s: i64,
    /// Nejmenší podíl neúspěšných spojení na (host, port) v úseku.
    pub min_failed_ratio: f64,
    /// Od tolika cílů je závažnost High.
    pub high_targets: usize,
}

impl Default for OutscanThresholds {
    fn default() -> Self {
        Self {
            min_targets: 25,
            span_s: 300,
            min_failed_ratio: 0.5,
            high_targets: 100,
        }
    }
}

fn failed(flow: &ConnectionObservation) -> bool {
    matches!(flow.conn_state.as_deref(), Some("S0" | "REJ" | "RSTOS0"))
}

pub fn detect(t: &OutscanThresholds, outbound: &[ConnectionObservation]) -> Vec<BehaviorFinding> {
    // (zdroj, port) -> (čas, cíl, neúspěšné)
    let mut by: BTreeMap<(&str, u16), Vec<(i64, &str, bool)>> = BTreeMap::new();
    for flow in outbound {
        let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
            continue;
        };
        if flow.proto != "tcp" {
            continue;
        }
        by.entry((src, port)).or_default().push((
            flow.timestamp.timestamp(),
            flow.dst_ip.as_str(),
            failed(flow),
        ));
    }
    let mut out = Vec::new();
    for ((src, port), mut flows) in by {
        if flows.iter().filter(|f| f.2).count() < t.min_targets {
            continue;
        }
        flows.sort_by_key(|f| f.0);
        let mut dst_failed: HashMap<&str, usize> = HashMap::new();
        let (mut total, mut fails, mut left) = (0usize, 0usize, 0usize);
        let mut best: Option<(usize, i64)> = None;
        for i in 0..flows.len() {
            let (at, dst, is_failed) = flows[i];
            total += 1;
            if is_failed {
                fails += 1;
                *dst_failed.entry(dst).or_default() += 1;
            }
            while at - flows[left].0 > t.span_s {
                let (_, old_dst, old_failed) = flows[left];
                total -= 1;
                if old_failed {
                    fails -= 1;
                    if let Some(count) = dst_failed.get_mut(old_dst) {
                        *count -= 1;
                        if *count == 0 {
                            dst_failed.remove(old_dst);
                        }
                    }
                }
                left += 1;
            }
            if dst_failed.len() >= t.min_targets
                && fails as f64 / total as f64 >= t.min_failed_ratio
                && best.is_none_or(|(n, _)| dst_failed.len() > n)
            {
                best = Some((dst_failed.len(), flows[left].0));
            }
        }
        let Some((targets, started)) = best else {
            continue;
        };
        let sample: Vec<String> = {
            let mut seen: Vec<&str> = Vec::new();
            for (at, dst, is_failed) in &flows {
                if *is_failed && *at >= started && *at <= started + t.span_s && !seen.contains(dst)
                {
                    seen.push(dst);
                    if seen.len() == 3 {
                        break;
                    }
                }
            }
            seen.into_iter().map(str::to_string).collect()
        };
        out.push(BehaviorFinding {
            finding: finding(
                "outbound_scan",
                src,
                &format!("scan/ext/tcp/{port}"),
                if targets >= t.high_targets {
                    Severity::High
                } else {
                    Severity::Medium
                },
                Confidence::Low,
                format!(
                    "Host {src} se pokusil o spojení na {targets} různých vnějších cílů na port {port}, většina bez odpovědi, do {} s",
                    t.span_s
                ),
                format!(
                    "Vnitřní host {src} měl v jednom úseku aspoň {targets} různých vnějších cílů s neúspěšným \\
                     TCP spojením na port {port} a většina jeho pokusů na tento port selhala. Takový vzor odpovídá \\
                     skenování nebo rozesílání (typicky infikovaný host). Neškodně ho může vyrobit peer-to-peer \\
                     klient s mnoha mrtvými peery, blokovaný nebo pomalý cíl a vlastní skener správce."
                ),
                vec![format!(
                    "{src} -> *:{port}/tcp: {targets} různých cílů bez odpovědi do {} s (např. {})",
                    t.span_s,
                    sample.join(", ")
                )],
                "Ověřit, zda host skenování zamýšlí (správce, monitorování); jinak izolovat host a zkontrolovat jeho procesy.",
            ),
            sources: sample.clone(),
            targets: sample.iter().map(|d| (d.clone(), port)).collect(),
            count: u32::try_from(targets).unwrap_or(u32::MAX),
            actor: src.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::*;

    fn flow(src: &str, dst: &str, port: u16, at: i64, state: &str) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: DateTime::from_timestamp(1_800_000_000 + at, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: None,
            orig_bytes: Some(0),
            resp_bytes: Some(0),
            total_bytes: None,
            orig_pkts: Some(1),
            resp_pkts: Some(0),
            total_pkts: None,
            conn_state: Some(state.to_string()),
            history: None,
            missed_bytes: None,
        }
    }

    fn scan(n: usize, step: i64, port: u16) -> Vec<ConnectionObservation> {
        (0..n)
            .map(|i| {
                flow(
                    "192.168.1.9",
                    &format!("203.0.113.{}", i % 250 + 1),
                    port,
                    i as i64 * step,
                    "S0",
                )
            })
            .collect()
    }

    #[test]
    fn many_unanswered_syns_to_distinct_hosts_are_reported() {
        let found = detect(&OutscanThresholds::default(), &scan(60, 2, 80));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].finding.finding_type, "outbound_scan");
        assert_eq!(found[0].actor, "192.168.1.9");
        assert_eq!(found[0].finding.severity, Severity::Medium);
        assert_eq!(found[0].sources.len(), 3);
    }

    #[test]
    fn high_severity_from_one_hundred_targets() {
        let found = detect(&OutscanThresholds::default(), &scan(150, 1, 25));
        assert_eq!(found[0].finding.severity, Severity::High);
    }

    #[test]
    fn boundaries_for_target_count_and_span() {
        let t = OutscanThresholds::default();
        assert!(detect(&t, &scan(24, 1, 80)).is_empty());
        assert_eq!(detect(&t, &scan(25, 1, 80)).len(), 1);
        // 25 cílů přesně za 300 s a za 301 s
        let mut edge = scan(25, 12, 80); // 24 * 12 = 288 s
        edge[24].timestamp += chrono::Duration::seconds(12); // 300 s
        assert_eq!(detect(&t, &edge).len(), 1);
        edge[24].timestamp += chrono::Duration::seconds(1); // 301 s
        assert!(detect(&t, &edge).is_empty());
    }

    #[test]
    fn host_with_mostly_successful_connections_is_not_a_scanner() {
        // 30 neúspěšných cílů, ale 100 úspěšných spojení na stejný port: podíl < 0,5
        let mut flows = scan(30, 2, 443);
        flows.extend((0..100).map(|i| flow("192.168.1.9", "198.51.100.7", 443, i, "SF")));
        assert!(detect(&OutscanThresholds::default(), &flows).is_empty());
    }

    #[test]
    fn repeated_failures_to_one_target_are_not_a_scan() {
        let flows: Vec<_> = (0..200)
            .map(|i| flow("192.168.1.9", "203.0.113.5", 80, i, "S0"))
            .collect();
        assert!(detect(&OutscanThresholds::default(), &flows).is_empty());
    }

    #[test]
    fn rejected_and_reset_attempts_count_as_failed() {
        let flows: Vec<_> = (0..30)
            .map(|i| {
                let state = if i % 2 == 0 { "REJ" } else { "RSTOS0" };
                flow(
                    "192.168.1.9",
                    &format!("203.0.113.{}", i + 1),
                    23,
                    i as i64,
                    state,
                )
            })
            .collect();
        assert_eq!(detect(&OutscanThresholds::default(), &flows).len(), 1);
    }

    #[test]
    fn udp_and_missing_port_are_ignored() {
        let mut flows = scan(60, 2, 80);
        for f in &mut flows {
            f.proto = "udp".to_string();
        }
        assert!(detect(&OutscanThresholds::default(), &flows).is_empty());
        let mut no_port = scan(60, 2, 80);
        for f in &mut no_port {
            f.dst_port = None;
        }
        assert!(detect(&OutscanThresholds::default(), &no_port).is_empty());
    }

    #[test]
    fn slow_scan_spread_over_hours_is_not_reported() {
        // 60 cílů po 200 s: v 300 s jsou nejvýš 2
        assert!(detect(&OutscanThresholds::default(), &scan(60, 200, 80)).is_empty());
    }

    #[test]
    fn two_hosts_and_two_ports_give_separate_findings() {
        let mut flows = scan(40, 1, 80);
        flows.extend(scan(40, 1, 25));
        let found = detect(&OutscanThresholds::default(), &flows);
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].finding.finding_id, found[1].finding.finding_id);
    }

    #[test]
    fn type_is_protected_and_switch_is_off_in_presets() {
        use crate::engine::V3Features;
        assert!(crate::protection::is_protected_type("outbound_scan"));
        assert!(crate::behavior::is_behavior_type("outbound_scan"));
        assert!(!V3Features::recommended().outscan);
        assert!(!V3Features::all().outscan);
        assert!(!V3Features::none().outscan);
        assert!(!V3Features::step6().outscan);
    }
}
