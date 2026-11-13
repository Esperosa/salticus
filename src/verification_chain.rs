//! Řetěz nezávislých kontrol při nejistotě (krok 9, impl-krok9.md, C2).
//!
//! Postup vychází z rešerše (studie 09, sekce 4): nález se při nejistotě neuzavírá
//! ani nezahazuje. Nabídne se další NEZÁVISLÁ kontrola (pivot na DNS, TLS a JA3,
//! časování, GeoIP a ASN, srovnání s baseline hosta a peerů, koncová telemetrie,
//! historie případu, reputace a konfigurační kontext, opakované měření, aktivní čtecí
//! ověření v povoleném rozsahu), dokud se nepřekročí práh jistoty nebo nevyčerpá
//! rozpočet.
//!
//! Čistá funkce bez I/O a bez náhody: stejný stav a katalog dávají stejný další krok.
//! Tvrdá pravidla (testovaná):
//! - kontrola bez dat (`NoData`) nemá žádnou váhu, ani pro, ani proti (O6: prázdná
//!   telemetrie neznamená „v pořádku“);
//! - důkazy ze stejné skupiny (stejný zdroj dat) se nesčítají naplno, druhý a další
//!   z téže skupiny mají poloviční, třetí čtvrtinovou váhu (závislost, studie H2);
//! - „vyvráceno“ vyžaduje aspoň dvě různé skupiny s neškodným důkazem a nikdy
//!   nenastane u chráněného případu; jinak zůstává „nerozhodnuto“;
//! - „potvrzeno“ vyžaduje aspoň dvě různé skupiny s podezřelým důkazem;
//! - vyčerpaný rozpočet nebo katalog dává „nerozhodnuto“, nikdy zavření;
//! - kontrola vyžadující schválení se nabídne, ale sama se neprovede (`needs_approval`).

use serde::{Deserialize, Serialize};

/// Druh kontroly (pivoty a kontext podle studie 09, tabulka znalostí).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    DnsPivot,
    TlsFingerprint,
    Timing,
    GeoAsn,
    HostBaseline,
    PeerCompare,
    EndpointTelemetry,
    CaseHistory,
    Reputation,
    ConfigContext,
    RepeatMeasure,
    ActiveReadOnly,
}

/// Zdroj dat kontroly: důkazy ze stejné skupiny nejsou nezávislé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Metadata téhož spojení a související záznamy (DNS, TLS, časování).
    FlowMetadata,
    /// Vnější znalost (GeoIP, ASN, reputace).
    External,
    /// Chování hosta a skupiny (baseline, peery, historie).
    Behaviour,
    /// Koncová telemetrie.
    Endpoint,
    /// Schválený kontext a konfigurace.
    Context,
    /// Aktivní čtecí ověření.
    Active,
}

impl CheckKind {
    pub const ALL: [CheckKind; 12] = [
        CheckKind::DnsPivot,
        CheckKind::TlsFingerprint,
        CheckKind::Timing,
        CheckKind::GeoAsn,
        CheckKind::HostBaseline,
        CheckKind::PeerCompare,
        CheckKind::EndpointTelemetry,
        CheckKind::CaseHistory,
        CheckKind::Reputation,
        CheckKind::ConfigContext,
        CheckKind::RepeatMeasure,
        CheckKind::ActiveReadOnly,
    ];

    pub fn group(self) -> Group {
        match self {
            CheckKind::DnsPivot | CheckKind::TlsFingerprint | CheckKind::Timing => {
                Group::FlowMetadata
            }
            CheckKind::GeoAsn | CheckKind::Reputation => Group::External,
            CheckKind::HostBaseline
            | CheckKind::PeerCompare
            | CheckKind::CaseHistory
            | CheckKind::RepeatMeasure => Group::Behaviour,
            CheckKind::EndpointTelemetry => Group::Endpoint,
            CheckKind::ConfigContext => Group::Context,
            CheckKind::ActiveReadOnly => Group::Active,
        }
    }

    /// Relativní cena (0 = zdarma, 1 = drahá) a nutnost schválení.
    pub fn cost(self) -> (f64, bool) {
        match self {
            CheckKind::CaseHistory | CheckKind::ConfigContext => (0.02, false),
            CheckKind::HostBaseline | CheckKind::PeerCompare => (0.05, false),
            CheckKind::DnsPivot | CheckKind::TlsFingerprint | CheckKind::Timing => (0.1, false),
            CheckKind::GeoAsn | CheckKind::Reputation => (0.1, false),
            CheckKind::EndpointTelemetry => (0.15, false),
            CheckKind::RepeatMeasure => (0.3, false),
            CheckKind::ActiveReadOnly => (0.6, true),
        }
    }

    /// Typická informativnost (|ln LR|) kontroly; slouží jen k pořadí nabídky, váha
    /// skutečného výsledku přichází s výsledkem (`Observation::log_lr`).
    fn prior_gain(self) -> f64 {
        match self {
            CheckKind::EndpointTelemetry => 2.5,
            CheckKind::TlsFingerprint | CheckKind::DnsPivot => 1.8,
            CheckKind::Timing | CheckKind::HostBaseline => 1.5,
            CheckKind::PeerCompare | CheckKind::CaseHistory => 1.2,
            CheckKind::GeoAsn | CheckKind::Reputation => 1.0,
            CheckKind::ConfigContext => 1.3,
            CheckKind::RepeatMeasure => 1.1,
            CheckKind::ActiveReadOnly => 2.0,
        }
    }
}

/// Výsledek provedené kontroly.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CheckResult {
    /// Data nebyla k dispozici: žádná váha (O6).
    NoData,
    /// Podezřelý (`log_lr` > 0) nebo neškodný (`log_lr` < 0) důkaz, přirozený log věrohodnostního poměru.
    Evidence { log_lr: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub kind: CheckKind,
    pub result: CheckResult,
}

/// Prahy a rozpočet řetězu.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ChainPolicy {
    /// Počáteční pravděpodobnost, že jde o skutečný problém.
    pub prior: f64,
    pub confirm_at: f64,
    pub refute_at: f64,
    /// Rozpočet cyklu (součet cen kontrol).
    pub budget: f64,
    /// Chráněný případ se nikdy nevyvrací automaticky.
    pub protected: bool,
}

impl Default for ChainPolicy {
    fn default() -> Self {
        Self {
            prior: 0.3,
            confirm_at: 0.9,
            refute_at: 0.05,
            budget: 1.0,
            protected: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Confirmed,
    Refuted,
    /// Nerozhodnuto, s důvodem (nikdy se nezavírá).
    Undetermined(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub verdict: Verdict,
    pub posterior: f64,
    pub spent: f64,
    pub suspicious_groups: usize,
    pub benign_groups: usize,
    pub no_data: usize,
}

fn logit(p: f64) -> f64 {
    let p = p.clamp(1e-6, 1.0 - 1e-6);
    (p / (1.0 - p)).ln()
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Posterior, počty nezávislých skupin a útrata z dosavadních pozorování.
pub fn assess(observations: &[Observation], policy: &ChainPolicy) -> Assessment {
    let mut per_group: std::collections::BTreeMap<Group, usize> = Default::default();
    let mut log_odds = logit(policy.prior);
    let (mut sus, mut ben, mut no_data) = (
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
        0usize,
    );
    let mut spent = 0.0;
    for obs in observations {
        spent += obs.kind.cost().0;
        match obs.result {
            CheckResult::NoData => no_data += 1,
            CheckResult::Evidence { log_lr } => {
                let group = obs.kind.group();
                let seen = per_group.entry(group).or_default();
                // stejná skupina: 1, 1/2, 1/4, ...
                let weight = 0.5f64.powi((*seen).min(8) as i32);
                *seen += 1;
                log_odds += weight * log_lr;
                if log_lr > 0.0 {
                    sus.insert(group);
                } else if log_lr < 0.0 {
                    ben.insert(group);
                }
            }
        }
    }
    let posterior = sigmoid(log_odds);
    let verdict = if posterior >= policy.confirm_at && sus.len() >= 2 {
        Verdict::Confirmed
    } else if posterior <= policy.refute_at && ben.len() >= 2 && !policy.protected {
        Verdict::Refuted
    } else if posterior <= policy.refute_at && policy.protected {
        Verdict::Undetermined("chraneny pripad se nevyvraci automaticky".into())
    } else if posterior <= policy.refute_at {
        Verdict::Undetermined("neskodny dukaz jen z jedne skupiny".into())
    } else if posterior >= policy.confirm_at {
        Verdict::Undetermined("podezrely dukaz jen z jedne skupiny".into())
    } else {
        Verdict::Undetermined("jistota nedosazena".into())
    };
    Assessment {
        verdict,
        posterior,
        spent,
        suspicious_groups: sus.len(),
        benign_groups: ben.len(),
        no_data,
    }
}

/// Dostupnost kontroly pro daný případ (rozhoduje volající podle dat a rozsahu).
pub trait Availability {
    fn available(&self, kind: CheckKind) -> bool;
}

impl<F: Fn(CheckKind) -> bool> Availability for F {
    fn available(&self, kind: CheckKind) -> bool {
        self(kind)
    }
}

/// Další kontrola, nebo `None`, když je případ rozhodnutý, rozpočet vyčerpán nebo
/// není co nabídnout. Pořadí: nejvyšší očekávaná informace na cenu, s přednostní
/// skupinou, která ještě nebyla použita (nezávislost).
pub fn next_check(
    observations: &[Observation],
    policy: &ChainPolicy,
    availability: &dyn Availability,
) -> Option<CheckKind> {
    let current = assess(observations, policy);
    if !matches!(current.verdict, Verdict::Undetermined(_)) {
        return None;
    }
    let done: std::collections::BTreeSet<CheckKind> =
        observations.iter().map(|o| o.kind).collect();
    let used_groups: std::collections::BTreeSet<Group> = observations
        .iter()
        .filter(|o| matches!(o.result, CheckResult::Evidence { .. }))
        .map(|o| o.kind.group())
        .collect();
    CheckKind::ALL
        .iter()
        .copied()
        .filter(|k| !done.contains(k) && availability.available(*k))
        .filter(|k| current.spent + k.cost().0 <= policy.budget + 1e-9)
        .map(|k| {
            let novelty = if used_groups.contains(&k.group()) { 0.5 } else { 1.0 };
            (k, novelty * k.prior_gain() / (k.cost().0 + 0.05))
        })
        .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|(k, _)| k)
}

/// Kontrola, která se sama neprovede (vyžaduje schválení).
pub fn needs_approval(kind: CheckKind) -> bool {
    kind.cost().1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: CheckKind, log_lr: f64) -> Observation {
        Observation {
            kind,
            result: CheckResult::Evidence { log_lr },
        }
    }

    fn nod(kind: CheckKind) -> Observation {
        Observation {
            kind,
            result: CheckResult::NoData,
        }
    }

    #[test]
    fn no_data_carries_no_weight_and_never_refutes() {
        let policy = ChainPolicy::default();
        let obs: Vec<_> = CheckKind::ALL.iter().map(|k| nod(*k)).collect();
        let a = assess(&obs, &policy);
        assert!((a.posterior - policy.prior).abs() < 1e-9);
        assert!(matches!(a.verdict, Verdict::Undetermined(_)));
        assert_eq!(a.no_data, 12);
    }

    #[test]
    fn one_group_is_never_enough_to_close_or_confirm() {
        let policy = ChainPolicy::default();
        let benign = [
            ev(CheckKind::DnsPivot, -4.0),
            ev(CheckKind::TlsFingerprint, -4.0),
            ev(CheckKind::Timing, -4.0),
        ];
        let a = assess(&benign, &policy);
        assert!(a.posterior < 0.05, "{}", a.posterior);
        assert!(matches!(a.verdict, Verdict::Undetermined(_)));
        let suspicious = [
            ev(CheckKind::DnsPivot, 5.0),
            ev(CheckKind::TlsFingerprint, 5.0),
        ];
        assert!(matches!(
            assess(&suspicious, &policy).verdict,
            Verdict::Undetermined(_)
        ));
    }

    #[test]
    fn two_independent_groups_decide() {
        let policy = ChainPolicy::default();
        let sus = [ev(CheckKind::DnsPivot, 3.0), ev(CheckKind::EndpointTelemetry, 3.0)];
        assert_eq!(assess(&sus, &policy).verdict, Verdict::Confirmed);
        let ben = [ev(CheckKind::HostBaseline, -4.0), ev(CheckKind::ConfigContext, -4.0)];
        assert_eq!(assess(&ben, &policy).verdict, Verdict::Refuted);
    }

    #[test]
    fn protected_case_is_never_refuted() {
        let policy = ChainPolicy {
            protected: true,
            ..ChainPolicy::default()
        };
        let ben = [
            ev(CheckKind::HostBaseline, -6.0),
            ev(CheckKind::ConfigContext, -6.0),
            ev(CheckKind::CaseHistory, -6.0),
        ];
        let a = assess(&ben, &policy);
        assert!(matches!(a.verdict, Verdict::Undetermined(_)));
    }

    #[test]
    fn same_group_evidence_is_discounted() {
        let policy = ChainPolicy::default();
        let one = assess(&[ev(CheckKind::DnsPivot, 2.0)], &policy).posterior;
        let two = assess(
            &[ev(CheckKind::DnsPivot, 2.0), ev(CheckKind::Timing, 2.0)],
            &policy,
        )
        .posterior;
        let cross = assess(
            &[ev(CheckKind::DnsPivot, 2.0), ev(CheckKind::GeoAsn, 2.0)],
            &policy,
        )
        .posterior;
        assert!(one < two && two < cross);
    }

    #[test]
    fn next_check_respects_budget_availability_and_done() {
        let policy = ChainPolicy::default();
        let all = |_: CheckKind| true;
        let first = next_check(&[], &policy, &all).unwrap();
        // totez podruhe (determinismus)
        assert_eq!(Some(first), next_check(&[], &policy, &all));
        let only_active = |k: CheckKind| k == CheckKind::ActiveReadOnly;
        assert_eq!(
            next_check(&[], &policy, &only_active),
            Some(CheckKind::ActiveReadOnly)
        );
        assert!(needs_approval(CheckKind::ActiveReadOnly));
        // vycerpany rozpocet: nic dalsiho
        let tight = ChainPolicy {
            budget: 0.01,
            ..policy
        };
        assert_eq!(next_check(&[], &tight, &all), None);
        // provedena kontrola se nenabidne znovu
        let done = [nod(first)];
        assert_ne!(next_check(&done, &policy, &all), Some(first));
    }

    #[test]
    fn chain_terminates_without_closing_when_nothing_is_available() {
        let policy = ChainPolicy::default();
        let none = |_: CheckKind| false;
        assert_eq!(next_check(&[], &policy, &none), None);
        assert!(matches!(
            assess(&[], &policy).verdict,
            Verdict::Undetermined(_)
        ));
    }

    #[test]
    fn a_run_through_all_checks_stays_within_budget() {
        let policy = ChainPolicy::default();
        let all = |_: CheckKind| true;
        let mut obs: Vec<Observation> = Vec::new();
        while let Some(kind) = next_check(&obs, &policy, &all) {
            obs.push(nod(kind));
            assert!(obs.len() <= 12);
        }
        assert!(assess(&obs, &policy).spent <= policy.budget + 1e-9);
    }
}
