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
) -> Correlation {
    let lik = competing::measured_static();
    let costs = Costs::default();
    for f in findings {
        let Some(host) = f.host_key.clone() else {
            continue;
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
            ts: now,
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
}
