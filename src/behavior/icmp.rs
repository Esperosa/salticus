//! ICMP s neobvyklou užitečnou částí (krok 12, studie 12, tunel a únik přes ICMP).
//!
//! Obyčejný echo má desítky bajtů (56 u Linuxu, 32 u Windows). Trvalý proud ICMP toků
//! od vnitřního hosta ven, kde medián odeslaných bajtů přesahuje `min_payload`, je
//! jeden rys (velikost) a opakování `min_flows` krát v okně druhý (trvání). Dva
//! nezávislé rysy: samotný jeden velký ping (MTU test) nebo pár drobných echo
//! (monitoring) nález nedá. Nález je chráněný typ (nezavírá se).

use std::collections::BTreeMap;

use crate::{
    behavior::{BehaviorFinding, finding},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

pub const ICMP_TYPES: &[&str] = &["icmp_payload_anomaly"];

pub fn detect(
    outbound: &[ConnectionObservation],
    min_flows: usize,
    min_payload: u64,
) -> Vec<BehaviorFinding> {
    let mut by_pair: BTreeMap<(&str, &str), Vec<u64>> = BTreeMap::new();
    for f in outbound {
        if !f.proto.eq_ignore_ascii_case("icmp") {
            continue;
        }
        let Some(src) = f.src_ip.as_deref() else {
            continue;
        };
        by_pair
            .entry((src, f.dst_ip.as_str()))
            .or_default()
            .push(f.orig_bytes.unwrap_or(0));
    }
    let mut out = Vec::new();
    for ((src, dst), mut sizes) in by_pair {
        if sizes.len() < min_flows {
            continue;
        }
        sizes.sort_unstable();
        let median = sizes[sizes.len() / 2];
        if median < min_payload {
            continue;
        }
        out.push(BehaviorFinding {
            finding: finding(
                "icmp_payload_anomaly",
                src,
                &format!("icmp/{dst}"),
                Severity::Medium,
                Confidence::Medium,
                format!(
                    "Host {src} posila na {dst} ICMP s velkou uzitecnou casti ({} toku, median {median} B)",
                    sizes.len()
                ),
                format!(
                    "Obycejny echo ma desitky bajtu; {} toku s medianem {median} B v jednom okne je tunel \
                     nebo unik pres ICMP. Pravidlo heuristika-behavior:icmp-payload@v1.",
                    sizes.len()
                ),
                vec![format!(
                    "{src} -> {dst}: {} ICMP toku, median {median} B",
                    sizes.len()
                )],
                "Overit proces a ucel; blokovat ICMP ven mimo nutne diagnostiky.",
            ),
            sources: vec![dst.to_string()],
            targets: vec![(dst.to_string(), 0)],
            count: sizes.len() as u32,
            actor: src.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn icmp(src: &str, dst: &str, bytes: u64, at: i64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: chrono::Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: None,
            dst_ip: dst.into(),
            proto: "icmp".into(),
            dst_port: None,
            duration_s: Some(0.1),
            orig_bytes: Some(bytes),
            resp_bytes: Some(bytes),
            total_bytes: Some(2 * bytes),
            orig_pkts: None,
            resp_pkts: None,
            total_pkts: None,
            conn_state: Some("SF".into()),
            history: None,
            missed_bytes: None,
        }
    }

    #[test]
    fn needs_both_large_payload_and_repetition() {
        let big: Vec<_> = (0..12)
            .map(|i| icmp("10.0.0.5", "198.51.100.9", 900, i))
            .collect();
        assert_eq!(detect(&big, 8, 200).len(), 1);
        let pings: Vec<_> = (0..40)
            .map(|i| icmp("10.0.0.5", "198.51.100.9", 64, i))
            .collect();
        assert!(detect(&pings, 8, 200).is_empty(), "monitoring echo");
        assert!(
            detect(&big[..3], 8, 200).is_empty(),
            "jeden velky ping nebo par"
        );
    }
}
