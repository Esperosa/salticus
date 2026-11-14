//! Detektory prvního vidění protějšku (krok 11, impl-krok11.md, oprava 1).
//!
//! Nezávislé na rodině útoku. Obě pravidla vycházejí z jednoho abstraktního rysu:
//! zralý vnitřní host navázal vztah s vnějším protějškem, který jeho profil nikdy
//! neviděl ani jako kandidáta, a ten vztah je hned při prvním okně nápadný:
//! - `novel_bulk_transfer`: čistý přenos (stažení nebo nahrání, rozdíl `orig` a `resp`)
//!   nad `bulk_bytes` na první vztah; hromadné stažení, sběr dat, únik jednou dávkou,
//! - `novel_peer_burst`: aspoň `burst_flows` toků na stejný první vztah během
//!   `burst_span_s` sekund; shluk požadavků na nový cíl (kliknutí, výčet API).
//!
//! Okno je rozhodnuto před učením profilu, takže po prvním okně je vztah kandidátem a
//! pravidlo mlčí; trvalou komunikaci s novým cílem hlásí `novel_persistent_peer`.
//! Flotila (cíl zná víc než `fleet_max` vnitřních hostů) je software, ne novost.
//! Pojistky: host mladší než `mature_s` se nehodnotí. Nález nikdy nevzniká z prázdného
//! okna. Prahy jsou volba autora a ladí se jen na ladicích seedech.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{
        BehaviorFinding, beacon::Prevalence, beacon::target_key, finding, profile::HostProfiles,
    },
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

/// Porty, po kterych se data prenasi bez sifrovani (FTP, Telnet, SMTP, HTTP).
const CLEARTEXT_PORTS: &[u16] = &[21, 23, 25, 80, 8080];

pub const ONESHOT_TYPES: &[&str] = &["novel_bulk_transfer", "novel_peer_burst"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OneshotThresholds {
    /// Host je zralý po tolika sekundách pozorování.
    pub mature_s: i64,
    /// Cíl zná nejvýš tolik vnitřních hostů (víc = flotila).
    pub fleet_max: usize,
    /// Čistý přenos na první vztah v okně (B).
    pub bulk_bytes: f64,
    /// Počet toků na první vztah a rozpětí (s) shluku.
    pub burst_flows: usize,
    pub burst_span_s: i64,
}

impl Default for OneshotThresholds {
    fn default() -> Self {
        Self {
            mature_s: 12 * 3600,
            fleet_max: 2,
            bulk_bytes: 2.0e6,
            burst_flows: 6,
            burst_span_s: 300,
        }
    }
}

#[derive(Default)]
struct Rel {
    up: f64,
    down: f64,
    times: Vec<i64>,
}

/// Jedno okno. Volá se před učením profilu z tohoto okna.
pub fn detect(
    profile: &HostProfiles,
    prevalence: &Prevalence,
    t: &OneshotThresholds,
    outbound: &[ConnectionObservation],
    now: i64,
    bulk: bool,
    bulk_clear: bool,
    burst: bool,
) -> Vec<BehaviorFinding> {
    let mut out = Vec::new();
    let mut rels: BTreeMap<(String, String, String, u16), Rel> = BTreeMap::new();
    for flow in outbound {
        let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
            continue;
        };
        let rel = rels
            .entry((src.to_string(), flow.dst_ip.clone(), flow.proto.clone(), port))
            .or_default();
        let o = flow.orig_bytes.unwrap_or(0) as f64;
        let r = flow.resp_bytes.unwrap_or(0) as f64;
        rel.up += (o - r).max(0.0);
        rel.down += (r - o).max(0.0);
        rel.times.push(flow.timestamp.timestamp());
    }
    for ((src, dst, proto, port), mut rel) in rels {
        if profile.knows(&src, &dst, &proto, port)
            || !profile
                .host_first(&src)
                .is_some_and(|first| now - first >= t.mature_s)
        {
            continue;
        }
        let (fleet, _) = prevalence.of(&target_key(&dst, &proto, port), now);
        if fleet > t.fleet_max {
            continue;
        }
        let transfer = rel.up.max(rel.down);
        let clear = CLEARTEXT_PORTS.contains(&port);
        if (bulk || (bulk_clear && clear)) && transfer >= t.bulk_bytes {
            let (direction, verb) = if rel.up >= rel.down {
                ("nahrani", "nahral")
            } else {
                ("stazeni", "stahl")
            };
            out.push(BehaviorFinding {
                finding: finding(
                    "novel_bulk_transfer",
                    &src,
                    &format!("bulk/{dst}/{proto}/{port}"),
                    Severity::Medium,
                    Confidence::Low,
                    format!(
                        "Host {src} {verb} {:.1} MB na prvni vztah s {dst}:{port}",
                        transfer / 1e6
                    ),
                    format!(
                        "Protejsek neni v profilu hostu a flotila ho nezna; cisty prenos ({direction}) \
                         {:.1} MB v jednom okne. Pravidlo heuristika-behavior:oneshot-bulk@v1.",
                        transfer / 1e6
                    ),
                    vec![format!(
                        "{src} <-> {dst}:{port}/{proto}: {:.1} MB",
                        transfer / 1e6
                    )],
                    "Overit, zda jde o zamyslenou sluzbu (aktualizace, zaloha, cloud); jinak proverit hromadny prenos dat.",
                ),
                sources: vec![dst.clone()],
                targets: vec![(dst.clone(), port)],
                count: (transfer / 1e6).min(f64::from(u32::MAX)) as u32,
                actor: src.clone(),
            });
            continue;
        }
        if burst && rel.times.len() >= t.burst_flows {
            rel.times.sort_unstable();
            let k = t.burst_flows;
            let tight = rel
                .times
                .windows(k)
                .any(|w| w[k - 1] - w[0] <= t.burst_span_s);
            if tight {
                out.push(BehaviorFinding {
                    finding: finding(
                        "novel_peer_burst",
                        &src,
                        &format!("burst/{dst}/{proto}/{port}"),
                        Severity::Low,
                        Confidence::Low,
                        format!(
                            "Host {src} poslal {} toku na prvni vztah s {dst}:{port} do {} s",
                            rel.times.len(),
                            t.burst_span_s
                        ),
                        format!(
                            "Protejsek neni v profilu hostu a flotila ho nezna; shluk {} toku v okne. \
                             Pravidlo heuristika-behavior:oneshot-burst@v1.",
                            rel.times.len()
                        ),
                        vec![format!(
                            "{src} -> {dst}:{port}/{proto}: {} toku",
                            rel.times.len()
                        )],
                        "Overit, jakou sluzbu host nove pouziva; nezname a nove se automaticky nezavira.",
                    ),
                    sources: vec![dst.clone()],
                    targets: vec![(dst.clone(), port)],
                    count: rel.times.len() as u32,
                    actor: src.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn flow(src: &str, dst: &str, port: u16, at: i64, o: u64, r: u64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(40000),
            dst_ip: dst.into(),
            proto: "tcp".into(),
            dst_port: Some(port),
            duration_s: Some(1.0),
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

    fn mature_profile(host: &str, now: i64) -> HostProfiles {
        let mut p = HostProfiles::default();
        let old = flow(host, "8.8.8.8", 443, now - 48 * 3600, 100, 100);
        p.learn(
            std::iter::once(&old),
            &Default::default(),
            now - 48 * 3600,
            &Default::default(),
        );
        p
    }

    #[test]
    fn bulk_and_burst_fire_only_on_first_contact_of_mature_host() {
        let now = 1_800_000_000;
        let profile = mature_profile("10.0.0.5", now);
        let prevalence = Prevalence::default();
        let t = OneshotThresholds::default();
        let big = vec![flow("10.0.0.5", "203.0.113.9", 80, now, 800, 4_000_000)];
        let found = detect(&profile, &prevalence, &t, &big, now, true, false, true);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].finding.finding_type, "novel_bulk_transfer");
        // vypnuto = ticho
        assert!(detect(&profile, &prevalence, &t, &big, now, false, false, false).is_empty());
        // jen nesifrovane porty: 80 ano, 443 ne
        let tls = vec![flow("10.0.0.5", "203.0.113.9", 443, now, 800, 4_000_000)];
        assert_eq!(
            detect(&profile, &prevalence, &t, &big, now, false, true, false).len(),
            1
        );
        assert!(detect(&profile, &prevalence, &t, &tls, now, false, true, false).is_empty());
        // shluk malych toku
        let many: Vec<_> = (0..8)
            .map(|i| flow("10.0.0.5", "203.0.113.9", 443, now + i * 10, 900, 3000))
            .collect();
        let found = detect(&profile, &prevalence, &t, &many, now, true, false, true);
        assert_eq!(found[0].finding.finding_type, "novel_peer_burst");
        // zname vztah mlci
        let mut learned = profile.clone();
        learned.learn(many.iter(), &Default::default(), now, &Default::default());
        assert!(detect(&learned, &prevalence, &t, &many, now + 1800, true, false, true).is_empty());
        // mlady host se nehodnoti
        let young = HostProfiles::default();
        assert!(detect(&young, &prevalence, &t, &big, now, true, false, true).is_empty());
    }
}
