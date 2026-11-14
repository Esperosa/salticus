//! Spis případu a žádosti o chybějící data (krok 12, studie 12b, oddíl 2 body 3 a 7).
//!
//! Spis nese: časovou osu, ověřené kontroly s výsledkem, neověřené kontroly s důvodem,
//! proč je případ nerozhodnutý a co by ho rozhodlo (milníky, Heuer krok 8). Když rozhodnutí
//! brzdí chybějící telemetrie, spis obsahuje konkrétní žádost: jaký log, který segment,
//! jaký senzor. Zvlášť u případů, jejichž nález zmizel kvůli slepému místu. Čistá funkce,
//! výstup je serializovatelný pro stávající API; nic se nespouští.

use serde::{Deserialize, Serialize};

use crate::{
    competing::{Action, Assessment, Result3},
    coverage_status::CoverageStatus,
    verification_chain::CheckKind,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRequest {
    /// Např. `ssl.log` (Zeek), `tls` (Suricata EVE), `dns.log`, `conn.log`, `sysmon`.
    pub log: String,
    /// Segment (/24) nebo host.
    pub scope: String,
    /// Kde sbírat: `tap/SPAN na uplinku`, `agent na hostu`, ...
    pub sensor: String,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verified {
    pub check: CheckKind,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseFile {
    pub finding_id: String,
    pub host: String,
    pub timeline: Vec<(i64, String)>,
    pub verified: Vec<Verified>,
    pub unverified: Vec<(CheckKind, String)>,
    pub posterior_attack: f64,
    pub action: String,
    /// Proč případ nerozhodl program sám (prázdné, pokud rozhodl).
    pub why_undecided: Vec<String>,
    /// Co by případ rozhodlo (nejlepší další kontrola a očekávaný výsledek).
    pub would_decide: Vec<String>,
    pub data_requests: Vec<DataRequest>,
}

/// Kontrola → log a senzor, které potřebuje (k žádosti o chybějící data).
fn log_for(kind: CheckKind) -> Option<(&'static str, &'static str)> {
    match kind {
        CheckKind::TlsFingerprint => Some(("ssl.log, x509.log (Zeek) nebo tls (Suricata EVE)", "tap nebo SPAN na uplinku, vidi oba smery")),
        CheckKind::DnsPivot => Some(("dns.log (Zeek) nebo dns (Suricata EVE)", "tap nebo SPAN u resolveru a na uplinku")),
        CheckKind::EndpointTelemetry => Some(("Sysmon, Wazuh nebo osquery", "agent na hostu")),
        CheckKind::GeoAsn | CheckKind::Reputation => Some(("zdroj reputace a ASN", "konfigurace zdroje znalosti, ne senzor")),
        CheckKind::Timing | CheckKind::RepeatMeasure => Some(("conn.log (Zeek)", "tap nebo SPAN v segmentu hosta")),
        _ => None,
    }
}

/// Žádosti o chybějící data podle nedostupných kontrol a stavu pokrytí. `blind` = nález
/// zmizel nebo se nedá vyhodnotit, protože host nebo segment nemá telemetrii.
pub fn data_requests(
    host: &str,
    unavailable: &[CheckKind],
    coverage: &CoverageStatus,
    blind: bool,
) -> Vec<DataRequest> {
    let mut out: Vec<DataRequest> = Vec::new();
    let segment = host
        .parse::<std::net::Ipv4Addr>()
        .map(|a| {
            let o = a.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        })
        .unwrap_or_else(|_| host.to_string());
    if blind || coverage.silent_hosts.iter().any(|h| h == host) || coverage.dark_segments.contains(&segment) {
        out.push(DataRequest {
            log: "conn.log (Zeek) nebo flow (Suricata EVE)".into(),
            scope: if coverage.dark_segments.contains(&segment) {
                segment.clone()
            } else {
                host.to_string()
            },
            sensor: "tap nebo SPAN na uplinku a na prepinaci segmentu".into(),
            why: "host nebo segment nema telemetrii; detekce zde neni garantovana".into(),
        });
    }
    for kind in unavailable {
        if let Some((log, sensor)) = log_for(*kind) {
            let req = DataRequest {
                log: log.into(),
                scope: segment.clone(),
                sensor: sensor.into(),
                why: format!("kontrola {kind:?} nema vstup; bez ni nelze pripad rozhodnout"),
            };
            if !out.contains(&req) {
                out.push(req);
            }
        }
    }
    out
}

pub fn build(
    finding_id: &str,
    host: &str,
    timeline: Vec<(i64, String)>,
    observations: &[(CheckKind, Result3, String)],
    unavailable: &[(CheckKind, String)],
    assessment: &Assessment,
    coverage: &CoverageStatus,
    blind: bool,
) -> CaseFile {
    let verified = observations
        .iter()
        .filter(|(_, r, _)| *r != Result3::Nothing)
        .map(|(k, r, text)| Verified {
            check: *k,
            result: format!("{r:?}: {text}"),
        })
        .collect();
    let mut unverified: Vec<(CheckKind, String)> = observations
        .iter()
        .filter(|(_, r, _)| *r == Result3::Nothing)
        .map(|(k, _, text)| (*k, text.clone()))
        .collect();
    unverified.extend(unavailable.iter().cloned());
    let mut why = Vec::new();
    if assessment.action == Action::Human {
        why.push(format!(
            "ocekavana ztrata automatickeho rozhodnuti je vyssi nez predani cloveku (P(utok) = {:.3})",
            assessment.posterior_attack
        ));
        if !unverified.is_empty() {
            why.push(format!("{} kontrol bez vysledku (chybi data)", unverified.len()));
        }
        if blind {
            why.push("slepe misto: host nebo segment nema telemetrii".into());
        }
    }
    let mut would = Vec::new();
    if let Some(next) = assessment.next_check {
        would.push(format!("dalsi kontrola s nejvyssi ocekavanou informaci na cenu: {next:?}"));
    }
    for (h, p) in assessment.hypotheses.iter().take(3) {
        would.push(format!("hypoteza {} ({:.2}): {}", h.label(), p, h.prediction()));
    }
    let unavailable_kinds: Vec<CheckKind> = unverified.iter().map(|(k, _)| *k).collect();
    CaseFile {
        finding_id: finding_id.into(),
        host: host.into(),
        timeline,
        verified,
        unverified,
        posterior_attack: assessment.posterior_attack,
        action: format!("{:?}", assessment.action),
        why_undecided: why,
        would_decide: would,
        data_requests: data_requests(host, &unavailable_kinds, coverage, blind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::competing::{Costs, Likelihoods, assess};

    #[test]
    fn undecided_case_names_missing_logs_segment_and_sensor() {
        let lik = Likelihoods::measured();
        let a = assess(0.2, &[], &|_| true, &lik, &Costs::default(), None);
        let coverage = CoverageStatus {
            dark_segments: vec!["10.0.4.0/24".into()],
            silent_hosts: vec!["10.0.4.7".into()],
            ..Default::default()
        };
        let file = build(
            "f1",
            "10.0.4.7",
            vec![(1, "nalez vznikl".into())],
            &[(CheckKind::CaseHistory, Result3::Benign, "videno 3 dny".into())],
            &[(CheckKind::TlsFingerprint, "bez ssl.log".into())],
            &a,
            &coverage,
            true,
        );
        assert_eq!(file.verified.len(), 1);
        assert_eq!(file.unverified.len(), 1);
        assert!(!file.why_undecided.is_empty());
        assert!(file.data_requests.iter().any(|r| r.scope == "10.0.4.0/24" && r.log.contains("conn.log")));
        assert!(file.data_requests.iter().any(|r| r.log.contains("ssl.log") && r.sensor.contains("tap")));
        assert!(!file.would_decide.is_empty());
    }

    #[test]
    fn full_coverage_and_available_checks_give_no_requests() {
        let reqs = data_requests("10.0.0.5", &[], &CoverageStatus::default(), false);
        assert!(reqs.is_empty());
    }
}
