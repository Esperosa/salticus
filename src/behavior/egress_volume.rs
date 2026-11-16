//! Odchozí objem a odchozí IDS alerty (krok 3A).
//!
//! `egress_volume_anomaly`: nahraný objem (`orig_bytes` toků ven) hostu v okně proti
//! jeho vlastní historii (robustní z-skóre z mediánu a MAD v log prostoru) a poměru
//! k mediánu. Bez historie jen absolutní mez (studený start). D3FEND „Per Host
//! Download-Upload Ratio Analysis“ (studie 03 §10) popisuje stejný princip; recenzovanou
//! kvantifikaci z toků RQ4 nenašla (§3c), takže prahy jsou volba autora a výsledek je
//! hypotéza. Alarmové okno se do historie neučí (RQ2 Z3).
//!
//! Krok 4: počítá se NAHRANÝ PŘEBYTEK toku, `max(0, orig − resp)` (poměr nahraných
//! a stažených bajtů, D3FEND „Per Host Download-Upload Ratio Analysis“). Symetrická
//! relace (videohovor přes TURN, sdílení obrazovky) nahraje stovky MB, ale stejně tolik
//! stáhne; exfiltrace a záloha jsou jednosměrné. Krok 3 D ukázal videohovory jako
//! největší zdroj FP vrstvy při hustém neškodném provozu (25,3 na síť-den při šumu 50×).
//! Riziko: útočník, který stahování uměle dorovná, detekci objemem obejde; cenou je
//! dvojnásobný provoz.
//!
//! `egress_ids_alert`: Suricata alert se zdrojem uvnitř a cílem venku (C2, miner),
//! jeden nález na (vnitřní host, signatura). Dřív ho parser zahodil (A10).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, evict_oldest, finding, median_mad},
    model::{Confidence, NormalizedEvent, Severity},
    passive::ConnectionObservation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressThresholds {
    /// Minimální nahraný objem okna pro poplach (B).
    pub min_bytes: f64,
    /// Bez historie (méně než `min_history` oken): absolutní mez (B).
    pub cold_bytes: f64,
    pub min_history: usize,
    pub z: f64,
    pub ratio: f64,
    /// Délka historie hostu (okna).
    pub history: usize,
    pub max_hosts: usize,
    /// Od tohoto objemu závažnost High (B).
    pub high_bytes: f64,
    /// Krok 4: počítat jen nahraný přebytek toku (bez symetrických relací).
    pub net_upload: bool,
}

impl Default for EgressThresholds {
    fn default() -> Self {
        Self {
            min_bytes: 50.0e6,
            cold_bytes: 1.0e9,
            min_history: 4,
            z: 6.0,
            ratio: 10.0,
            history: 48,
            max_hosts: 50_000,
            high_bytes: 1.0e9,
            net_upload: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HostUpload {
    /// log1p(nahrané bajty) posledních oken bez poplachu.
    history: Vec<f32>,
    last: i64,
    /// Krok 15 (P2): nahrané bajty posledních `HORIZON` oken (včetně poplachových),
    /// klouzavý horizont pro `detect_horizon`.
    #[serde(default)]
    recent: Vec<f32>,
    /// Čas posledního poplachu horizontu (jednou na horizont).
    #[serde(default)]
    horizon_alarmed: i64,
    /// Kolik oken horizontu uplynulo od posledního poplachu horizontu.
    #[serde(default)]
    since_horizon_alarm: u32,
}

/// Krok 15 (P2): délka klouzavého horizontu v oknech (6 oken po 30 min = 3 h).
pub const HORIZON: usize = 6;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressVolumeState {
    hosts: HashMap<String, HostUpload>,
    pub evicted: u64,
}

/// Nahraný objem hostů v okně: host -> (bajty, cíl -> bajty).
fn uploads(
    outbound: &[ConnectionObservation],
    net_upload: bool,
) -> BTreeMap<&str, (f64, BTreeMap<&str, f64>)> {
    let mut by_host: BTreeMap<&str, (f64, BTreeMap<&str, f64>)> = BTreeMap::new();
    for flow in outbound {
        let Some(src) = flow.src_ip.as_deref() else {
            continue;
        };
        let orig = flow.orig_bytes.unwrap_or(0);
        let bytes = if net_upload {
            orig.saturating_sub(flow.resp_bytes.unwrap_or(0)) as f64
        } else {
            orig as f64
        };
        let entry = by_host.entry(src).or_default();
        entry.0 += bytes;
        *entry.1.entry(flow.dst_ip.as_str()).or_default() += bytes;
    }
    by_host
}

pub fn detect(
    state: &mut EgressVolumeState,
    t: &EgressThresholds,
    outbound: &[ConnectionObservation],
    now: i64,
) -> Vec<BehaviorFinding> {
    let mut out = Vec::new();
    for (host, (bytes, by_dst)) in uploads(outbound, t.net_upload) {
        let entry = state.hosts.entry(host.to_string()).or_default();
        entry.last = now;
        entry.recent.push(bytes as f32);
        if entry.recent.len() > HORIZON {
            let drop = entry.recent.len() - HORIZON;
            entry.recent.drain(..drop);
        }
        entry.since_horizon_alarm = entry.since_horizon_alarm.saturating_add(1);
        let x = bytes.ln_1p();
        let mut history: Vec<f64> = entry.history.iter().map(|v| *v as f64).collect();
        let alarm = if bytes < t.min_bytes {
            None
        } else if history.len() < t.min_history {
            (bytes >= t.cold_bytes).then(|| "bez historie, absolutni mez".to_string())
        } else {
            let (median, mad) = median_mad(&mut history);
            let z = 0.6745 * (x - median) / mad.max(0.25);
            let ratio = (x - median).exp();
            (z >= t.z && ratio >= t.ratio).then(|| {
                format!(
                    "{:.0}x median historie hostu ({} oken), z = {z:.1}",
                    ratio,
                    entry.history.len()
                )
            })
        };
        match alarm {
            Some(basis) => {
                let (top, top_bytes) = by_dst
                    .iter()
                    .max_by(|a, b| a.1.total_cmp(b.1).then(b.0.cmp(a.0)))
                    .map(|(d, b)| (d.to_string(), *b))
                    .unwrap_or_default();
                let port = outbound
                    .iter()
                    .find(|f| f.src_ip.as_deref() == Some(host) && f.dst_ip == top)
                    .and_then(|f| f.dst_port)
                    .unwrap_or(0);
                let severity = if bytes >= t.high_bytes {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let mut f = finding(
                    "egress_volume_anomaly",
                    host,
                    "out/upload",
                    severity,
                    Confidence::Medium,
                    format!(
                        "Host {host} odeslal ven {:.0} MB, hlavne na {top}",
                        bytes / 1e6
                    ),
                    format!(
                        "Nahrany objem okna vybocuje z historie hostu ({basis}); {:.0} % na {top}:{port}.",
                        top_bytes * 100.0 / bytes.max(1.0)
                    ),
                    by_dst
                        .iter()
                        .take(5)
                        .map(|(d, b)| format!("{host} -> {d}: {:.1} MB", b / 1e6))
                        .collect(),
                    "Overit, zda jde o zalohu nebo synchronizaci (kalendar, profil hostu); jinak omezit odchozi provoz hostu a proverit proces.",
                );
                f.rationale
                    .push_str(" Pravidlo heuristika-behavior:egress_volume@v1.");
                out.push(BehaviorFinding {
                    finding: f,
                    sources: vec![top.clone()],
                    targets: vec![(top, port)],
                    count: (bytes / 1e6).min(u32::MAX as f64) as u32,
                    actor: host.to_string(),
                });
            }
            None => {
                // jen okno bez poplachu se uci (RQ2 Z3)
                entry.history.push(x as f32);
                if entry.history.len() > t.history {
                    let drop = entry.history.len() - t.history;
                    entry.history.drain(..drop);
                }
            }
        }
    }
    state.evicted += evict_oldest(&mut state.hosts, t.max_hosts, |h| h.last) as u64;
    out
}

/// Krok 15 (P2, `upload_horizon`): tentýž test jako `detect`, ale nad součtem nahraného
/// přebytku posledních `HORIZON` oken proti historii stejně dlouhých horizontů hostu.
/// Zaplňuje mezeru mezi jedním oknem (`min_bytes`) a pomalým únikem (`slow_egress`:
/// ≥ 6 oken s malým průměrem): nahrání desítek MB za 2 až 5 oken nemělo žádný detektor.
/// Prahy jsou tytéž (`min_bytes`, `cold_bytes`, `z`, `ratio`); poplach nejvýš jednou na
/// horizont. Volá se po `detect` v témže okně (čte `recent`, nic se neučí navíc).
pub fn detect_horizon(
    state: &mut EgressVolumeState,
    t: &EgressThresholds,
    now: i64,
) -> Vec<BehaviorFinding> {
    let mut out = Vec::new();
    for (host, entry) in state.hosts.iter_mut() {
        if entry.last != now || entry.recent.len() < 2 {
            continue;
        }
        if entry.since_horizon_alarm < HORIZON as u32 && entry.horizon_alarmed > 0 {
            continue;
        }
        let sum: f64 = entry.recent.iter().map(|b| *b as f64).sum();
        if sum < t.min_bytes {
            continue;
        }
        // historie horizontů: klouzavé součty `HORIZON` po sobě jdoucích oken historie
        let windows: Vec<f64> = entry.history.iter().map(|v| (*v as f64).exp_m1()).collect();
        let mut sums: Vec<f64> = windows
            .windows(HORIZON.min(windows.len().max(1)))
            .map(|w| w.iter().sum::<f64>().ln_1p())
            .collect();
        let x = sum.ln_1p();
        let alarm = if sums.len() < t.min_history {
            (sum >= t.cold_bytes).then(|| "bez historie, absolutni mez horizontu".to_string())
        } else {
            let (median, mad) = median_mad(&mut sums);
            let z = 0.6745 * (x - median) / mad.max(0.25);
            let ratio = (x - median).exp();
            (z >= t.z && ratio >= t.ratio).then(|| {
                format!(
                    "{:.0}x median horizontu {} oken ({} horizontu historie), z = {z:.1}",
                    ratio,
                    entry.recent.len(),
                    sums.len()
                )
            })
        };
        let Some(basis) = alarm else { continue };
        entry.horizon_alarmed = now;
        entry.since_horizon_alarm = 0;
        let severity = if sum >= t.high_bytes {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut f = finding(
            "egress_volume_anomaly",
            host,
            "out/upload",
            severity,
            Confidence::Medium,
            format!(
                "Host {host} odeslal ven {:.0} MB za {} oken",
                sum / 1e6,
                entry.recent.len()
            ),
            format!(
                "Nahrany objem klouzaveho horizontu vybocuje z historie hostu ({basis}); jednotliva okna pod prahem."
            ),
            vec![format!(
                "{host}: {} MB za posledni okna",
                entry
                    .recent
                    .iter()
                    .map(|b| format!("{:.1}", *b as f64 / 1e6))
                    .collect::<Vec<_>>()
                    .join(" + ")
            )],
            "Overit, zda jde o zalohu nebo synchronizaci (kalendar, profil hostu); jinak omezit odchozi provoz hostu a proverit proces.",
        );
        f.rationale
            .push_str(" Pravidlo heuristika-behavior:egress_volume_horizon@v1.");
        out.push(BehaviorFinding {
            finding: f,
            sources: Vec::new(),
            targets: Vec::new(),
            count: (sum / 1e6).min(u32::MAX as f64) as u32,
            actor: host.clone(),
        });
    }
    out
}

/// Odchozí IDS alerty: jeden nález na (vnitřní zdroj, signatura).
pub fn ids_findings(alerts: &[NormalizedEvent]) -> Vec<BehaviorFinding> {
    let mut groups: BTreeMap<(String, String), Vec<&NormalizedEvent>> = BTreeMap::new();
    for alert in alerts {
        let Some(src) = alert.src_ip.clone() else {
            continue;
        };
        let sid = alert.rule_id.clone().unwrap_or_else(|| "0".into());
        groups.entry((src, sid)).or_default().push(alert);
    }
    groups
        .into_iter()
        .map(|((host, sid), items)| {
            let strongest = items
                .iter()
                .max_by_key(|a| a.severity)
                .expect("neprazdna skupina");
            let mut peers: Vec<String> = items.iter().map(|a| a.dst_ip.clone()).collect();
            peers.sort();
            peers.dedup();
            let targets: Vec<(String, u16)> = items
                .iter()
                .filter_map(|a| a.dst_port.map(|p| (a.dst_ip.clone(), p)))
                .collect();
            let f = finding(
                "egress_ids_alert",
                &host,
                &format!("out/ids#{sid}"),
                strongest.severity.max(Severity::Medium),
                Confidence::High,
                format!("IDS: {} (z {host} ven)", strongest.message),
                format!(
                    "Suricata signatura {sid} ({} vyskytu) na odchozim provozu z {host} na: {}.",
                    items.len(),
                    peers.join(", ")
                ),
                items
                    .iter()
                    .take(5)
                    .map(|a| {
                        format!(
                            "{} {host} -> {}:{} sid={sid}",
                            a.timestamp.to_rfc3339(),
                            a.dst_ip,
                            a.dst_port.map(|p| p.to_string()).unwrap_or_default()
                        )
                    })
                    .collect(),
                "Izolovat host a proverit proces, ktery spojeni navazal; overit reputaci cile.",
            );
            BehaviorFinding {
                finding: f,
                sources: peers,
                targets,
                count: items.len() as u32,
                actor: host,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn up(src: &str, dst: &str, bytes: u64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(443),
            duration_s: Some(600.0),
            orig_bytes: Some(bytes),
            resp_bytes: Some(4000),
            total_bytes: Some(bytes + 4000),
            orig_pkts: Some(bytes / 1400 + 1),
            resp_pkts: Some(10),
            total_pkts: Some(bytes / 1400 + 11),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    /// Krok 15 (P2): nahrani 30 MB za okno po tri okna je pod prahem jednoho okna (50 MB)
    /// a nad prumerem pomaleho uniku; bez horizontu zadny nalez, s horizontem jeden
    /// (drzene seedy: exfil_cloud_storage_upload 20 az 29 MB za okno bez nalezu).
    #[test]
    fn upload_spread_over_a_few_windows_is_caught_only_by_the_horizon() {
        let t = EgressThresholds::default();
        for horizon in [false, true] {
            let mut state = EgressVolumeState::default();
            let mut found = Vec::new();
            for w in 0..24 {
                let bytes = if w >= 21 { 30_000_000 } else { 1_000_000 + w * 1000 };
                let now = w as i64 * 1800;
                let single = detect(&mut state, &t, &[up("10.0.0.5", "203.0.113.9", bytes)], now);
                assert!(single.is_empty(), "okno {w}: jednotlive okno pod prahem");
                if horizon {
                    found.extend(detect_horizon(&mut state, &t, now));
                }
            }
            if horizon {
                assert_eq!(found.len(), 1, "{found:?}");
                assert_eq!(found[0].finding.finding_type, "egress_volume_anomaly");
                assert_eq!(found[0].actor, "10.0.0.5");
                assert!(found[0].finding.rationale.contains("horizon"));
            } else {
                assert!(found.is_empty());
            }
        }
    }

    #[test]
    fn upload_spike_against_own_history_alarms_and_is_not_learned() {
        let mut state = EgressVolumeState::default();
        let t = EgressThresholds::default();
        for w in 0..10 {
            let found = detect(
                &mut state,
                &t,
                &[up("10.0.0.5", "203.0.113.9", 20_000 + w * 100)],
                w as i64 * 1800,
            );
            assert!(found.is_empty());
        }
        let found = detect(
            &mut state,
            &t,
            &[up("10.0.0.5", "198.51.100.77", 400_000_000)],
            20 * 1800,
        );
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!(f.finding.finding_type, "egress_volume_anomaly");
        assert_eq!(f.actor, "10.0.0.5");
        assert_eq!(f.sources, vec!["198.51.100.77".to_string()]);
        assert_eq!(f.finding.severity, Severity::Medium);
        // alarmove okno se neucilo: stejny objem znovu alarmuje
        assert_eq!(
            detect(
                &mut state,
                &t,
                &[up("10.0.0.5", "198.51.100.77", 400_000_000)],
                21 * 1800
            )
            .len(),
            1
        );
    }

    #[test]
    fn cold_start_needs_absolute_volume_and_regular_large_uploads_stop_alarming() {
        let mut state = EgressVolumeState::default();
        let t = EgressThresholds::default();
        assert!(detect(&mut state, &t, &[up("10.0.0.6", "x", 300_000_000)], 0).is_empty());
        assert_eq!(
            detect(&mut state, &t, &[up("10.0.0.7", "x", 2_000_000_000)], 0)[0]
                .finding
                .severity,
            Severity::High
        );
        // host, ktery pravidelne nahrava stovky MB (zaloha), neni anomalie proti sobe
        let mut state = EgressVolumeState::default();
        for w in 0..8 {
            detect(
                &mut state,
                &t,
                &[up("10.0.0.8", "x", 300_000_000 + w * 1_000_000)],
                w as i64,
            );
        }
        assert!(detect(&mut state, &t, &[up("10.0.0.8", "x", 320_000_000)], 9).is_empty());
    }

    /// Krok 4: symetrický videohovor (stejně nahráno i staženo) není anomálie, stejný
    /// objem jednosměrně ano.
    #[test]
    fn symmetric_session_is_not_upload_but_one_way_is() {
        let t = EgressThresholds::default();
        let mut state = EgressVolumeState::default();
        for w in 0..10 {
            detect(&mut state, &t, &[up("10.0.0.5", "x", 30_000)], w * 1800);
        }
        let mut call = up("10.0.0.5", "198.51.100.3", 900_000_000);
        call.resp_bytes = Some(900_000_000);
        assert!(detect(&mut state, &t, &[call.clone()], 20 * 1800).is_empty());
        let exfil = up("10.0.0.5", "198.51.100.3", 900_000_000);
        assert_eq!(detect(&mut state, &t, &[exfil], 21 * 1800).len(), 1);
        // puvodni pocitani nahranych bajtu hlasi i hovor
        let raw = EgressThresholds {
            net_upload: false,
            ..Default::default()
        };
        let mut state = EgressVolumeState::default();
        for w in 0..10 {
            detect(&mut state, &raw, &[up("10.0.0.5", "x", 30_000)], w * 1800);
        }
        assert_eq!(detect(&mut state, &raw, &[call], 20 * 1800).len(), 1);
    }

    #[test]
    fn host_map_is_capped() {
        let mut state = EgressVolumeState::default();
        let t = EgressThresholds {
            max_hosts: 100,
            ..Default::default()
        };
        let flows: Vec<_> = (0..300)
            .map(|i| up(&format!("10.0.{}.{}", i / 250, i % 250), "x", 1000))
            .collect();
        detect(&mut state, &t, &flows, 0);
        assert!(state.hosts.len() <= 100);
        assert!(state.evicted >= 200);
    }

    #[test]
    fn outbound_ids_alerts_group_per_host_and_signature() {
        let alert = |src: &str, dst: &str, sid: &str| NormalizedEvent {
            event_id: format!("s:{src}:{dst}:{sid}"),
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(1),
            dst_ip: dst.into(),
            proto: "tcp".into(),
            dst_port: Some(443),
            event_type: "suricata_alert".into(),
            severity: Severity::High,
            source: "suricata".into(),
            rule_id: Some(sid.into()),
            message: "ET MALWARE Known C2 beacon pattern".into(),
            raw_ref: None,
            count: 1,
        };
        let found = ids_findings(&[
            alert("10.0.0.5", "203.0.113.1", "2027865"),
            alert("10.0.0.5", "203.0.113.2", "2027865"),
            alert("10.0.0.6", "203.0.113.1", "2027865"),
        ]);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].count, 2);
        assert_eq!(found[0].sources.len(), 2);
        assert_eq!(found[0].finding.host_key.as_deref(), Some("10.0.0.5"));
    }
}
