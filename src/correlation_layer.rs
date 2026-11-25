//! Napojení modulů kroku 12 na běh (pipeline v3): spisy případů, incidenty z historie,
//! zápis a přehodnocení rozhodnutí s auditem (přepínač `case_files`).
//!
//! Vstupem je výsledek ověřování (rozhodnutí žebříku s kroky) a nálezy běhu; výstupem
//! jsou pole `caseFiles`, `incidents` a `reassessAudit` v reportu (stávající API
//! `/runs/{id}` je vydá beze změny UI). Nic se nespouští ani nezavírá; modul jen
//! popisuje a zaznamenává. Stav (`retro` a `ledger`) se drží v `engine-state.sqlite`.

use serde::{Deserialize, Serialize};

use crate::{
    case_file::{self, CaseFile},
    competing::{self, Costs, Obs, Result3},
    coverage_status::CoverageStatus,
    model::Finding,
    reassess::{AuditEntry, Ledger},
    retro::{Cause, Event, History, Incident},
    verification_chain::CheckKind,
    verify_ladder::{CheckId, Decision, Status, competing_kind},
};

/// Strop spisů a incidentů v jednom reportu (ochrana velikosti reportu).
pub const MAX_CASE_FILES: usize = 200;
pub const MAX_INCIDENTS: usize = 200;
/// Odstup nálezů téhož hosta nebo indikátoru, který je ještě jeden incident.
pub const INCIDENT_GAP_S: i64 = 6 * 3600;
/// Krok 34: klíč, který by spojil víc nálezů, je hub (server, brána) a dál nespojuje.
pub const MAX_KEY_DEGREE: usize = 25;
/// Krok 35: aktér s víc útočnými nálezy v jednom okně už dál nespojuje (beacon z jednoho hosta
/// na stovky cílů); u skutečného aktéra řetězce je nálezů málo.
pub const MAX_ACTOR_DEGREE: usize = 100;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Correlation {
    #[serde(default, rename = "caseFiles")]
    pub case_files: Vec<CaseFile>,
    #[serde(default)]
    pub incidents: Vec<Incident>,
    #[serde(default, rename = "reassessAudit")]
    pub reassess_audit: Vec<AuditEntry>,
    /// Krok 16: případové složky (přepínač `case_folder`; bez něj prázdné a nevypisuje se).
    #[serde(default, rename = "caseFolders", skip_serializing_if = "Vec::is_empty")]
    pub case_folders: Vec<crate::case_folder::CaseFolder>,
    /// Krok 16: složky, které se nevešly pod strop (K16-2 hlásí počet; cíl 0).
    #[serde(
        default,
        rename = "caseFoldersDropped",
        skip_serializing_if = "is_zero"
    )]
    pub case_folders_dropped: usize,
    /// Krok 33: co korelace nezařadila (viditelná ztráta; prázdné a nevypisuje se).
    #[serde(default, skip_serializing_if = "CorrStats::is_empty")]
    pub stats: CorrStats,
}

/// Čítače nálezů, které korelace nezařadila do incidentu (krok 33, `corr_v2`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CorrStats {
    /// Nálezy bez `host_key` (do historie se nedostaly).
    pub without_host: usize,
    /// Skupiny s jediným různým nálezem (nejsou incident, jen osamělý nález).
    pub single_finding_groups: usize,
    /// Incidenty nad strop `MAX_INCIDENTS`.
    pub truncated: usize,
}

impl CorrStats {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Nastavení běhu korelace. `Default` = původní chování (v1, čas běhu).
#[derive(Debug, Clone, Default)]
pub struct Options<'a> {
    /// Krok 33: čas nálezu místo času běhu, jedna událost na nález, seskupení v2,
    /// počet různých nálezů, čítače zahozených.
    pub v2: bool,
    /// Krok 34: kauzální seskupení (`incidents_v3`) a nálezy bez hosta jako oběť; vyžaduje `v2`.
    pub v3: bool,
    /// `finding_id` -> čas prvního výskytu (z paměti nálezů).
    pub first_seen: Option<&'a std::collections::BTreeMap<String, i64>>,
}

/// Ponechá nejvýš `max` nejnovějších incidentů (podle posledního nálezu), v pořadí vzniku.
fn keep_newest(all: &mut Vec<Incident>, max: usize) {
    if all.len() <= max {
        return;
    }
    all.sort_by_key(|i| std::cmp::Reverse((i.last_ts, i.first_ts)));
    all.truncate(max);
    all.sort_by_key(|i| (i.first_ts, i.first_finding.clone()));
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Strop případových složek v jednom reportu (každá ≤ 16 KiB, tedy nejvýš asi 32 MiB).
pub const MAX_CASE_FOLDERS: usize = 2000;

/// Taktika ATT&CK podle typu nálezu (hrubé mapování; nezná-li typ, `None`).
pub fn tactic_of(finding_type: &str) -> Option<&'static str> {
    Some(match finding_type {
        "scan_attempts" | "port_scan" | "dns_zone_enumeration" | "network_discovery" => "discovery",
        "beacon_periodic" | "dns_tunnel_names" | "doh_suspected" | "icmp_payload_anomaly" => {
            "command-and-control"
        }
        "tls_rare_transfer"
        | "novel_bulk_transfer"
        | "egress_volume_anomaly"
        | "novel_persistent_peer" => "exfiltration",
        "lateral_movement" | "novel_fanout" => "lateral-movement",
        "exploit_attempt" | "suricata_alert" | "ids_alert" => "initial-access",
        "credential_stuffing" | "ssh_bruteforce" => "credential-access",
        _ => return None,
    })
}

/// Provozní porucha (ne útok) podle typu nálezu.
pub fn is_fault(finding_type: &str) -> bool {
    matches!(
        finding_type,
        "service_unreachable"
            | "connection_timeout_burst"
            | "service_overload_risk"
            | "identification_gap"
    )
}

/// Indikatory nalezu (IPv4 z titulku a dukazu), nejvyse 8.
pub fn indicators_of(f: &Finding) -> Vec<String> {
    let mut indicators = ips_in(&f.title);
    for e in &f.evidence {
        for ip in ips_in(e) {
            if !indicators.contains(&ip) {
                indicators.push(ip);
            }
        }
    }
    indicators.truncate(8);
    indicators
}

fn ips_in(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if token.parse::<std::net::Ipv4Addr>().is_ok() && !out.iter().any(|t| t == token) {
            out.push(token.to_string());
        }
    }
    out.truncate(6);
    out
}

fn result_of(tag: &str) -> Result3 {
    match tag {
        "malicious" => Result3::Suspicious,
        "benign" => Result3::Benign,
        _ => Result3::Nothing,
    }
}

fn obs_of(steps: &[(CheckId, &'static str)]) -> Vec<Obs> {
    steps
        .iter()
        .filter_map(|(check, tag)| {
            competing_kind(*check).map(|kind| Obs {
                kind,
                result: result_of(tag),
            })
        })
        .collect()
}

/// Jeden běh: zapíše nálezy do historie, rozhodnutí do účetní knihy, spojí incidenty a
/// sestaví spisy nerozhodnutých případů.
#[allow(clippy::too_many_arguments)]
pub fn run(
    history: &mut History,
    ledger: &mut Ledger,
    findings: &[Finding],
    decisions: &[Decision],
    coverage: &CoverageStatus,
    prior: f64,
    now: i64,
    opts: &Options,
) -> Correlation {
    let lik = competing::measured_static();
    let costs = Costs::default();
    let mut stats = CorrStats::default();
    for f in findings {
        let mut hostless = false;
        let host = match f.host_key.clone() {
            Some(h) => h,
            None if opts.v2 && opts.v3 => {
                // nespárovaná pasivní událost: první adresa v důkazu je oběť
                match f.evidence.iter().find_map(|e| ips_in(e).into_iter().next()) {
                    Some(v) => {
                        hostless = true;
                        v
                    }
                    None => {
                        stats.without_host += 1;
                        continue;
                    }
                }
            }
            None => {
                stats.without_host += 1;
                continue;
            }
        };
        if opts.v2 && history.has_finding(&f.finding_id) {
            // nové důkazy (další protějšky) se do existující události doplní, událost nepřibývá
            let mut extra = ips_in(&f.title);
            for e in &f.evidence {
                extra.extend(ips_in(e));
            }
            history.merge_indicators(&f.finding_id, &extra);
            continue;
        }
        let ts = if opts.v2 {
            opts.first_seen
                .and_then(|m| m.get(&f.finding_id).copied())
                .unwrap_or(now)
        } else {
            now
        };
        let mut indicators = ips_in(&f.title);
        for e in &f.evidence {
            for ip in ips_in(e) {
                if !indicators.contains(&ip) {
                    indicators.push(ip);
                }
            }
        }
        indicators.truncate(8);
        history.add(Event {
            ts,
            host,
            finding_id: f.finding_id.clone(),
            indicators,
            tactic: tactic_of(&f.finding_type).map(str::to_string),
            cause: if is_fault(&f.finding_type) {
                Cause::Fault
            } else {
                Cause::Attack
            },
            kind: f.finding_type.clone(),
            hostless,
        });
    }
    let mut out = Correlation::default();
    for d in decisions {
        let evidence = obs_of(&d.steps);
        // nova rozhodnuti se zapisuji, pozdejsi se starsim rozhodnutim se prehodnoti
        if ledger.get(&d.finding_id).is_some() {
            let known = ledger.get(&d.finding_id).map_or(0, |r| r.evidence.len());
            let added: Vec<Obs> = evidence
                .iter()
                .skip(known.min(evidence.len()))
                .copied()
                .collect();
            if let Some(entry) = ledger.reassess(
                &d.finding_id,
                &added,
                &format!("nove kroky zebriku ({})", d.reason),
                lik,
                &costs,
                now,
            ) {
                out.reassess_audit.push(entry);
            }
        } else {
            ledger.record(&d.finding_id, prior, evidence.clone(), lik, &costs, now);
        }
        if d.status == Status::Escalated && out.case_files.len() < MAX_CASE_FILES {
            let observations: Vec<(CheckKind, Result3, String)> = d
                .steps
                .iter()
                .filter_map(|(c, tag)| {
                    competing_kind(*c).map(|k| (k, result_of(tag), format!("{} {tag}", c.label())))
                })
                .collect();
            let all_kinds: Vec<CheckKind> = CheckKind::ALL.to_vec();
            let tried: Vec<CheckKind> = observations.iter().map(|o| o.0).collect();
            let unavailable: Vec<(CheckKind, String)> = all_kinds
                .into_iter()
                .filter(|k| {
                    !tried.contains(k)
                        && matches!(
                            k,
                            CheckKind::TlsFingerprint
                                | CheckKind::DnsPivot
                                | CheckKind::EndpointTelemetry
                        )
                })
                .map(|k| {
                    (
                        k,
                        "bez dat (zdroj neni pripojen nebo nema pokryti)".to_string(),
                    )
                })
                .collect();
            let obs: Vec<Obs> = obs_of(&d.steps);
            let assessment = competing::assess(prior, &obs, &|_| true, lik, &costs, None);
            let blind = coverage.silent_hosts.iter().any(|h| *h == d.host_ip)
                || coverage.dark_segments.iter().any(|s| {
                    d.host_ip
                        .rsplit_once('.')
                        .is_some_and(|(p, _)| s.starts_with(p))
                });
            out.case_files.push(case_file::build(
                &d.finding_id,
                &d.host_ip,
                vec![
                    (d.opened as i64, "nalez otevren k overeni".to_string()),
                    (d.decided as i64, format!("predano cloveku: {}", d.reason)),
                ],
                &observations,
                &unavailable,
                &assessment,
                coverage,
                blind,
            ));
        }
    }
    if opts.v2 {
        let mut all = if opts.v3 {
            history.incidents_v3(INCIDENT_GAP_S, MAX_KEY_DEGREE, MAX_ACTOR_DEGREE)
        } else {
            history.incidents_v2(INCIDENT_GAP_S)
        };
        for i in &mut all {
            i.findings.sort();
            i.findings.dedup();
        }
        stats.single_finding_groups = all.iter().filter(|i| i.findings.len() <= 1).count();
        all.retain(|i| i.findings.len() > 1);
        stats.truncated = all.len().saturating_sub(MAX_INCIDENTS);
        keep_newest(&mut all, MAX_INCIDENTS);
        out.incidents = all;
        out.stats = stats;
        return out;
    }
    out.incidents = history.incidents(INCIDENT_GAP_S);
    out.incidents.retain(|i| i.findings.len() > 1);
    out.incidents.truncate(MAX_INCIDENTS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Severity};

    fn finding(id: &str, kind: &str, host: &str, ev: &str) -> Finding {
        Finding {
            finding_id: id.into(),
            finding_type: kind.into(),
            title: format!("t {ev}"),
            severity: Severity::Medium,
            confidence: Confidence::Low,
            host_key: Some(host.into()),
            service_key: None,
            rationale: String::new(),
            evidence: vec![ev.into()],
            recommendation: String::new(),
        }
    }

    #[test]
    fn findings_sharing_an_indicator_form_one_incident_with_phases_and_cause() {
        let mut h = History::new(100);
        let mut l = Ledger::new();
        let f = vec![
            finding("a", "scan_attempts", "10.0.0.5", "z 198.51.100.4"),
            finding("b", "beacon_periodic", "10.0.0.7", "na 198.51.100.4"),
            finding("c", "service_unreachable", "10.0.9.9", "cil 10.0.9.1"),
        ];
        let out = run(
            &mut h,
            &mut l,
            &f,
            &[],
            &CoverageStatus::default(),
            0.2,
            1000,
            &Options::default(),
        );
        assert_eq!(
            out.incidents.len(),
            1,
            "porucha na jinem hostu bez sdileni je mimo"
        );
        assert_eq!(
            out.incidents[0].phases,
            vec!["discovery", "command-and-control"]
        );
        assert_eq!(out.incidents[0].cause, Cause::Attack);
    }

    #[test]
    fn corr_v2_counts_distinct_findings_and_uses_finding_time() {
        use std::collections::BTreeMap;
        let mut h = History::new(100);
        let mut l = Ledger::new();
        let f = vec![
            finding("a", "scan_attempts", "10.0.0.5", "z 198.51.100.4"),
            finding("b", "beacon_periodic", "10.0.0.5", "na 198.51.100.4"),
        ];
        let seen: BTreeMap<String, i64> = [("a".to_string(), 100), ("b".to_string(), 700)].into();
        let o = Options {
            v2: true,
            first_seen: Some(&seen),
            ..Default::default()
        };
        let cov = CoverageStatus::default();
        // stejny nalez ve dvou bezich nesmi vytvorit incident ani druhou udalost
        let out = run(&mut h, &mut l, &f[..1], &[], &cov, 0.2, 9000, &o);
        assert!(out.incidents.is_empty());
        let out = run(&mut h, &mut l, &f[..1], &[], &cov, 0.2, 9500, &o);
        assert!(out.incidents.is_empty(), "opakovany nalez neni incident");
        assert_eq!(h.events().len(), 1);
        let out = run(&mut h, &mut l, &f, &[], &cov, 0.2, 9600, &o);
        assert_eq!(h.events().len(), 2);
        assert_eq!(h.events()[0].ts, 100);
        assert_eq!(h.events()[1].ts, 700);
        assert_eq!(out.incidents.len(), 1);
        assert_eq!(out.incidents[0].findings, vec!["a", "b"]);
        // stabilni klic nezavisi na poradi
        assert_eq!(out.incidents[0].key, crate::retro::stable_key("a"));
    }

    #[test]
    fn corr_v2_reports_dropped_findings() {
        let mut h = History::new(100);
        let mut l = Ledger::new();
        let mut nohost = finding("x", "scan_attempts", "h", "e");
        nohost.host_key = None;
        let f = vec![nohost, finding("y", "scan_attempts", "10.0.0.5", "1.1.1.1")];
        let o = Options {
            v2: true,
            first_seen: None,
            ..Default::default()
        };
        let out = run(
            &mut h,
            &mut l,
            &f,
            &[],
            &CoverageStatus::default(),
            0.2,
            5,
            &o,
        );
        assert_eq!(out.stats.without_host, 1);
        assert_eq!(out.stats.single_finding_groups, 1);
    }

    #[test]
    fn corr_v3_links_causal_chain_but_not_shared_peers() {
        use std::collections::BTreeMap;
        let mut f_scan = finding(
            "scan1",
            "unmapped_passive_event",
            "x",
            "event_id=anomaly-v3:scan:10.0.0.9/tcp/19",
        );
        f_scan.host_key = None;
        let brute = finding(
            "brute1",
            "bruteforce_attempts",
            "10.0.0.5",
            "10.0.0.5 -> 10.0.0.9:22",
        );
        let exfil = finding(
            "exfil1",
            "egress_volume_anomaly",
            "10.0.0.9",
            "10.0.0.9 -> 198.51.100.7: 1500 MB",
        );
        // druhy, nesouvisejici utok na stejny vnejsi cil
        let exfil2 = finding(
            "exfil2",
            "egress_volume_anomaly",
            "10.0.0.20",
            "10.0.0.20 -> 198.51.100.7: 1500 MB",
        );
        let seen: BTreeMap<String, i64> = [
            ("scan1", 0),
            ("brute1", 900),
            ("exfil1", 2400),
            ("exfil2", 2500),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let o = Options {
            v2: true,
            v3: true,
            first_seen: Some(&seen),
        };
        let mut h = History::new(100);
        let mut l = Ledger::new();
        let all = vec![f_scan, brute, exfil, exfil2];
        let out = run(
            &mut h,
            &mut l,
            &all,
            &[],
            &CoverageStatus::default(),
            0.2,
            9000,
            &o,
        );
        assert_eq!(out.incidents.len(), 1, "{:?}", out.incidents);
        let mut got = out.incidents[0].findings.clone();
        got.sort();
        assert_eq!(
            got,
            vec!["brute1", "exfil1", "scan1"],
            "exfil2 sdili jen vnejsi cil"
        );
    }

    #[test]
    fn corr_v3_keeps_newest_incidents_when_over_cap() {
        let mut v: Vec<Incident> = (0..5)
            .map(|k| Incident {
                id: k,
                findings: vec![format!("f{k}"), format!("g{k}")],
                hosts: vec![],
                first_ts: k as i64 * 10,
                last_ts: k as i64 * 10 + 5,
                phases: vec![],
                cause: Cause::Attack,
                first_finding: format!("f{k}"),
                key: String::new(),
            })
            .collect();
        keep_newest(&mut v, 2);
        let ids: Vec<usize> = v.iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![3, 4], "ponechat nejnovejsi, ne nejstarsi");
    }

    #[test]
    fn corr_v3_hub_releases_after_gap_and_does_not_split_active_host() {
        // jeden aktér s 40 nálezy v čase 0..39 s: nad stropem aktéra (100) se nerozpadne;
        // po dlouhé pauze se čítač klíče uvolní
        let mut h = History::new(1000);
        for k in 0..40 {
            h.add(Event {
                ts: k,
                host: "10.0.0.9".into(),
                finding_id: format!("e{k}"),
                indicators: vec!["10.0.0.9".into(), format!("198.51.100.{k}")],
                tactic: Some("command-and-control".into()),
                cause: Cause::Attack,
                kind: "beacon_periodic".into(),
                hostless: false,
            });
        }
        let inc = h.incidents_v3(3600, 25, 100);
        assert_eq!(
            inc.len(),
            1,
            "aktér pod stropem aktéra zůstane jeden incident"
        );
        assert_eq!(inc[0].findings.len(), 40);
    }

    #[test]
    fn corr_v3_shared_victim_scans_do_not_merge_and_same_window_order_is_stable() {
        use std::collections::BTreeMap;
        let mk = |id: &str, ev: &str| {
            let mut f = finding(id, "unmapped_passive_event", "x", ev);
            f.host_key = None;
            f
        };
        let s1 = mk("scan_s_1", "event_id=anomaly-v3:scan:10.0.0.50/tcp/19");
        let s2 = mk("scan_s_2", "event_id=anomaly-v3:scan:10.0.0.50/tcp/20");
        let seen: BTreeMap<String, i64> = [("scan_s_1", 0), ("scan_s_2", 10)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let o = Options {
            v2: true,
            v3: true,
            first_seen: Some(&seen),
        };
        let mut h = History::new(100);
        let mut l = Ledger::new();
        let out = run(
            &mut h,
            &mut l,
            &[s1, s2],
            &[],
            &CoverageStatus::default(),
            0.2,
            99,
            &o,
        );
        assert!(
            out.incidents.is_empty(),
            "dva skeny téže oběti nejsou jeden incident"
        );
    }

    #[test]
    fn corr_v3_same_window_phases_link_in_any_insertion_order() {
        use std::collections::BTreeMap;
        let mut scan = finding(
            "sc",
            "unmapped_passive_event",
            "x",
            "event_id=anomaly-v3:scan:10.0.0.9/tcp/19",
        );
        scan.host_key = None;
        let brute = finding(
            "br",
            "bruteforce_attempts",
            "10.0.0.5",
            "10.0.0.5 -> 10.0.0.9:22",
        );
        let exfil = finding(
            "ex",
            "egress_volume_anomaly",
            "10.0.0.9",
            "10.0.0.9 -> 198.51.100.7: 1500 MB",
        );
        // všechny nálezy mají tentýž čas (jedno okno)
        let seen: BTreeMap<String, i64> = ["sc", "br", "ex"]
            .iter()
            .map(|k| (k.to_string(), 500))
            .collect();
        let o = Options {
            v2: true,
            v3: true,
            first_seen: Some(&seen),
        };
        for perm in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let base = [scan.clone(), brute.clone(), exfil.clone()];
            let all: Vec<Finding> = perm.iter().map(|k| base[*k].clone()).collect();
            let mut h = History::new(100);
            let mut l = Ledger::new();
            let out = run(
                &mut h,
                &mut l,
                &all,
                &[],
                &CoverageStatus::default(),
                0.2,
                600,
                &o,
            );
            assert_eq!(out.incidents.len(), 1, "perm {perm:?}: {:?}", out.incidents);
            assert_eq!(out.incidents[0].findings.len(), 3, "perm {perm:?}");
        }
    }

    #[test]
    fn history_index_survives_cap_drain_and_updates_indicators() {
        let mut h = History::new(3);
        for k in 0..5 {
            h.add(Event {
                ts: k,
                host: "h".into(),
                finding_id: format!("f{k}"),
                indicators: vec!["h".into()],
                tactic: None,
                cause: Cause::Attack,
                kind: String::new(),
                hostless: false,
            });
        }
        assert!(!h.has_finding("f0") && !h.has_finding("f1"));
        assert!(h.has_finding("f4"));
        h.merge_indicators("f4", &["1.2.3.4".to_string()]);
        assert!(
            h.events()
                .last()
                .unwrap()
                .indicators
                .contains(&"1.2.3.4".to_string())
        );
        let json = serde_json::to_string(&h).unwrap();
        let mut back: History = serde_json::from_str(&json).unwrap();
        assert!(!back.has_finding("f4"), "index se neukládá");
        back.reindex();
        assert!(back.has_finding("f4") && !back.has_finding("f0"));
    }
}
