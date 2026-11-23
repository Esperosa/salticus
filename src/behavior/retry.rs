//! Opakované neúspěšné pokusy na stejný vnější cíl (krok 32): vnitřní host se stále znovu
//! pokouší o TCP spojení na stejný (cíl, port), které nikdy neodpoví (mrtvé nebo blokované C&C,
//! chybná konfigurace, zablokovaná služba).
//!
//! Měření kroku 31 na IoT-23 (scénář 8-1) ukázalo infikovaný host s 8 222 pokusy SYN bez
//! odpovědi na dva vnější cíle a port 50; skenovací pravidlo ho nezachytí (jen dva cíle) a
//! beaconing vyžaduje zahřátého hosta. Pravidlo nezávisí na historii hosta.
//!
//! Pravidlo: aspoň `min_attempts` neúspěšných TCP pokusů (`S0`, `REJ`, `RSTOS0`) z vnitřního
//! hosta na stejný vnější (cíl, port) během `span_s` sekund a **žádné úspěšné spojení** na tento
//! (cíl, port) v tomtéž úseku. Prahy jsem stanovil předem; na skutečné domácí síti (3 dny) dávaly
//! 0 zásahů.
//!
//! Neškodně ho může vyrobit služba, která je chvíli nedostupná, zablokovaná brána firewall nebo
//! pokus o spojení na vypnuté zařízení. Nález je chráněný typ (nikdy se neuzavře automaticky).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, finding},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

pub const RETRY_TYPES: &[&str] = &["unanswered_retry"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryThresholds {
    /// Nejmenší počet neúspěšných pokusů na (cíl, port) v úseku.
    pub min_attempts: usize,
    /// Délka úseku (s).
    pub span_s: i64,
}

impl Default for RetryThresholds {
    fn default() -> Self {
        Self {
            min_attempts: 20,
            span_s: 600,
        }
    }
}

fn failed(flow: &ConnectionObservation) -> bool {
    matches!(flow.conn_state.as_deref(), Some("S0" | "REJ" | "RSTOS0"))
}

pub fn detect(t: &RetryThresholds, outbound: &[ConnectionObservation]) -> Vec<BehaviorFinding> {
    // (zdroj, cíl, port) -> (čas, neúspěšné)
    let mut by: BTreeMap<(&str, &str, u16), Vec<(i64, bool)>> = BTreeMap::new();
    for flow in outbound {
        let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
            continue;
        };
        if flow.proto != "tcp" {
            continue;
        }
        by.entry((src, flow.dst_ip.as_str(), port))
            .or_default()
            .push((flow.timestamp.timestamp(), failed(flow)));
    }
    let mut out = Vec::new();
    for ((src, dst, port), mut flows) in by {
        if flows.iter().filter(|f| f.1).count() < t.min_attempts {
            continue;
        }
        flows.sort_by_key(|f| f.0);
        let (mut fails, mut oks, mut left) = (0usize, 0usize, 0usize);
        let mut best = 0usize;
        for i in 0..flows.len() {
            if flows[i].1 {
                fails += 1;
            } else {
                oks += 1;
            }
            while flows[i].0 - flows[left].0 > t.span_s {
                if flows[left].1 {
                    fails -= 1;
                } else {
                    oks -= 1;
                }
                left += 1;
            }
            if fails >= t.min_attempts && oks == 0 {
                best = best.max(fails);
            }
        }
        if best == 0 {
            continue;
        }
        out.push(BehaviorFinding {
            finding: finding(
                "unanswered_retry",
                src,
                &format!("retry/{dst}/tcp/{port}"),
                Severity::Medium,
                Confidence::Low,
                format!(
                    "Host {src} se {best}krát za {} s marně pokusil o spojení na {dst}:{port}",
                    t.span_s
                ),
                format!(
                    "Vnitřní host {src} opakoval aspoň {best} neúspěšných TCP spojení na vnější cíl {dst}:{port} \\
                     a žádné spojení tam neuspělo. Takový vzor odpovídá mrtvému nebo blokovanému řídicímu \\
                     serveru (infikované zařízení), ale i vypnuté službě, chybné konfiguraci nebo firewallu."
                ),
                vec![format!(
                    "{src} -> {dst}:{port}/tcp: {best} neúspěšných pokusů do {} s, žádný úspěšný",
                    t.span_s
                )],
                "Ověřit, co host na cíl očekává (služba, aktualizace); jinak zkontrolovat procesy hosta a cíl v reputaci.",
            ),
            sources: vec![dst.to_string()],
            targets: vec![(dst.to_string(), port)],
            count: u32::try_from(best).unwrap_or(u32::MAX),
            actor: src.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::*;

    fn flow(dst: &str, at: i64, state: &str) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: DateTime::from_timestamp(1_800_000_000 + at, 0).unwrap(),
            src_ip: Some("192.168.1.9".to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(50),
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

    fn retries(n: usize, step: i64) -> Vec<ConnectionObservation> {
        (0..n)
            .map(|i| flow("203.0.113.5", i as i64 * step, "S0"))
            .collect()
    }

    #[test]
    fn repeated_unanswered_attempts_to_one_target_are_reported() {
        let found = detect(&RetryThresholds::default(), &retries(30, 5));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].finding.finding_type, "unanswered_retry");
        assert_eq!(found[0].actor, "192.168.1.9");
        assert_eq!(found[0].targets, vec![("203.0.113.5".to_string(), 50)]);
    }

    #[test]
    fn boundaries_for_count_and_span() {
        let t = RetryThresholds::default();
        assert!(detect(&t, &retries(19, 1)).is_empty());
        assert_eq!(detect(&t, &retries(20, 1)).len(), 1);
        let mut edge = retries(20, 30); // 19 * 30 = 570 s
        edge[19].timestamp += chrono::Duration::seconds(30); // 600 s
        assert_eq!(detect(&t, &edge).len(), 1);
        edge[19].timestamp += chrono::Duration::seconds(1); // 601 s
        assert!(detect(&t, &edge).is_empty());
    }

    #[test]
    fn a_successful_connection_in_the_span_means_target_is_alive() {
        let mut flows = retries(30, 5);
        flows.push(flow("203.0.113.5", 60, "SF"));
        assert!(detect(&RetryThresholds::default(), &flows).is_empty());
    }

    #[test]
    fn success_long_before_the_burst_does_not_hide_it() {
        let mut flows = vec![flow("203.0.113.5", 0, "SF")];
        flows.extend((0..30).map(|i| flow("203.0.113.5", 5_000 + i * 5, "S0")));
        assert_eq!(detect(&RetryThresholds::default(), &flows).len(), 1);
    }

    #[test]
    fn rejected_and_reset_count_as_failed() {
        let flows: Vec<_> = (0..24)
            .map(|i| flow("203.0.113.5", i, if i % 2 == 0 { "REJ" } else { "RSTOS0" }))
            .collect();
        assert_eq!(detect(&RetryThresholds::default(), &flows).len(), 1);
    }

    #[test]
    fn attempts_spread_over_many_targets_are_not_a_retry() {
        let flows: Vec<_> = (0..60)
            .map(|i| flow(&format!("203.0.113.{}", i + 1), i, "S0"))
            .collect();
        assert!(detect(&RetryThresholds::default(), &flows).is_empty());
    }

    #[test]
    fn udp_and_missing_port_are_ignored() {
        let mut udp = retries(30, 5);
        for f in &mut udp {
            f.proto = "udp".to_string();
        }
        assert!(detect(&RetryThresholds::default(), &udp).is_empty());
        let mut no_port = retries(30, 5);
        for f in &mut no_port {
            f.dst_port = None;
        }
        assert!(detect(&RetryThresholds::default(), &no_port).is_empty());
    }

    #[test]
    fn unsorted_input_is_handled() {
        let mut flows = retries(30, 5);
        flows.reverse();
        assert_eq!(detect(&RetryThresholds::default(), &flows).len(), 1);
    }

    #[test]
    fn type_is_protected_and_switch_is_off_in_presets() {
        use crate::engine::V3Features;
        assert!(crate::protection::is_protected_type("unanswered_retry"));
        assert!(crate::behavior::is_behavior_type("unanswered_retry"));
        assert!(!V3Features::recommended().retry);
        assert!(!V3Features::all().retry);
        assert!(!V3Features::none().retry);
        assert!(!V3Features::step6().retry);
    }
}
