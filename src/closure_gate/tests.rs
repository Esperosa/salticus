use super::*;
use crate::context_gate::{ContextKind, Explanation};
use crate::finding_memory::{
    Disposition, FindingKey, FindingMemory, FindingState, MemoryConfig, Observation,
};
use crate::model::Severity;

fn at(minutes: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000 + minutes * 60, 0).unwrap()
}

fn note(check: CheckId, lr: f64, detail: &str) -> StepNote {
    StepNote {
        check,
        cycle: 0,
        tag: if lr < 1.0 { "benign" } else { "malicious" },
        lr: Some(lr),
        detail: detail.to_string(),
    }
}

fn decision(kind: &str, notes: Vec<StepNote>) -> Decision {
    Decision {
        key: FindingKey::new("10.0.0.5", kind, "tcp/80"),
        finding_id: format!("finding:{kind}"),
        finding_type: kind.to_string(),
        status: Status::Refuted,
        host_ip: "10.0.0.5".into(),
        posterior: 0.01,
        raw_posterior: 0.01,
        opened: 0,
        decided: 1,
        reason: "test".into(),
        checks: notes.len(),
        budget_escalation: false,
        high_impact: false,
        protected: false,
        steps: Vec::new(),
        notes,
        prior_hold: false,
        pending_check: None,
    }
}

fn history() -> StepNote {
    note(CheckId::History, 0.25, "stejny jev uz 3 dny")
}
fn context() -> StepNote {
    note(
        CheckId::Context,
        0.1,
        "schvaleny kontext: backup_window (schvalil spravce)",
    )
}
fn allow() -> StepNote {
    note(
        CheckId::Endpoint,
        0.1,
        "seznam povolenych: 10.0.0.9: backup.exe (vlastnik it-ops, do 2027-01-01)",
    )
}

/// R1: závislý důkaz (historie, profil), peeři, agent „vše v pořádku“ a výpadek služby
/// samy nezavřou; pozitivní důkaz s vlastníkem a druhá skupina ano.
#[test]
fn ladder_needs_positive_evidence_with_owner_and_two_groups() {
    let kind = "unexpected_traffic";
    let refused = [
        vec![history(), note(CheckId::Profile, 0.2, "zvyk")],
        vec![history(), note(CheckId::Peers, 0.25, "2 z 4")],
        vec![
            history(),
            note(CheckId::Endpoint, 0.3, "koncova telemetrie: vse v poradku"),
        ],
        vec![history(), note(CheckId::Liveness, 0.15, "vypadek")],
        vec![allow()],
        vec![context()],
        vec![
            history(),
            note(
                CheckId::Context,
                0.1,
                "schvaleny kontext: sensor_outage (schvalil spravce)",
            ),
        ],
        vec![
            history(),
            note(CheckId::Context, 0.1, "schvaleny kontext: backup"),
        ],
    ];
    for notes in refused {
        let d = decision(kind, notes.clone());
        assert!(admit_ladder(&d).is_err(), "{notes:?}");
    }
    let ok = admit_ladder(&decision(kind, vec![history(), context()])).unwrap();
    assert_eq!(ok.owner(), "spravce");
    assert_eq!(ok.groups(), &[1, 3]);
    let ok = admit_ladder(&decision(kind, vec![allow(), history()])).unwrap();
    assert_eq!(ok.owner(), "it-ops");
    assert!(ok.is_positive());
}

/// R2: vysoký dopad a chráněný typ se nezavírají ani s nejsilnějším důkazem; P nad mezí taky ne.
#[test]
fn ladder_never_closes_high_impact_protected_or_high_posterior() {
    let strong = vec![history(), context(), allow()];
    let mut high = decision("packet_rate_spike", strong.clone());
    high.high_impact = true;
    assert_eq!(admit_ladder(&high), Err(Refusal::HighImpact));
    let protected = decision("pivot_chain", strong.clone());
    assert_eq!(admit_ladder(&protected), Err(Refusal::Protected));
    let mut flagged = decision("unexpected_traffic", strong.clone());
    flagged.protected = true;
    assert_eq!(admit_ladder(&flagged), Err(Refusal::Protected));
    let mut unsure = decision("unexpected_traffic", strong);
    unsure.posterior = 0.2;
    assert_eq!(admit_ladder(&unsure), Err(Refusal::NotLowEnough));
}

fn explanation(kind: ContextKind, owner: &str, proven: bool) -> Explanation {
    Explanation {
        kind,
        reason: format!("{} (schvalil {owner})", kind.label()),
        approved_by: owner.to_string(),
        expires: at(600),
        sources_proven: proven,
    }
}

fn easy() -> Subject {
    Subject {
        protected: false,
        high_impact: false,
    }
}

type ContextCase<'a> = (
    Explanation,
    &'a str,
    &'a [String],
    DateTime<Utc>,
    Subject,
    Refusal,
);

/// Kontext: výpadek senzoru (R5), záznam bez vlastníka, prošlý, se zdrojem mimo záznam,
/// nález bez zdroje, vysoký dopad a chráněný typ se nezavřou.
#[test]
fn context_claim_needs_owner_expiry_and_proven_sources() {
    let src = vec!["10.0.0.9".to_string()];
    let ok = admit_explanation(
        &explanation(ContextKind::AuthorizedScanner, "secops", true),
        "scan_attempts",
        &src,
        at(0),
        easy(),
    )
    .unwrap();
    assert_eq!(ok.owner(), "secops");
    assert_eq!(ok.sources(), &src[..]);
    let cases: [ContextCase<'_>; 7] = [
        (
            explanation(ContextKind::SensorOutage, "secops", true),
            "packet_rate_spike",
            &src,
            at(0),
            easy(),
            Refusal::SensorOutage,
        ),
        (
            explanation(ContextKind::AuthorizedScanner, " ", true),
            "scan_attempts",
            &src,
            at(0),
            easy(),
            Refusal::NoOwner,
        ),
        (
            explanation(ContextKind::AuthorizedScanner, "secops", true),
            "scan_attempts",
            &src,
            at(700),
            easy(),
            Refusal::Expired,
        ),
        (
            explanation(ContextKind::AuthorizedScanner, "secops", false),
            "scan_attempts",
            &src,
            at(0),
            easy(),
            Refusal::SourceNotProven,
        ),
        (
            explanation(ContextKind::Backup, "secops", true),
            "inductive_volume_anomaly",
            &[],
            at(0),
            easy(),
            Refusal::SourceNotProven,
        ),
        (
            explanation(ContextKind::AuthorizedScanner, "secops", true),
            "scan_attempts",
            &src,
            at(0),
            Subject {
                protected: false,
                high_impact: true,
            },
            Refusal::HighImpact,
        ),
        (
            explanation(ContextKind::Maintenance, "secops", true),
            "suricata_alert",
            &src,
            at(0),
            easy(),
            Refusal::Protected,
        ),
    ];
    for (e, kind, sources, when, subject, why) in cases {
        assert_eq!(
            admit_explanation(&e, kind, sources, when, subject),
            Err(why),
            "{kind} {:?}",
            e.kind
        );
    }
}

fn gate_memory() -> FindingMemory {
    FindingMemory::new(MemoryConfig {
        gate: true,
        protect: true,
        refute_episode_s: 3600,
        escalate_first_source: true,
        ..MemoryConfig::default()
    })
}

fn obs<'a>(
    key: &FindingKey,
    minute: i64,
    severity: Severity,
    sources: &'a [String],
) -> Observation<'a> {
    Observation {
        key: key.clone(),
        severity,
        count: 3,
        sources,
        at: at(minute),
        volume_explained: false,
        protected: false,
    }
}

/// Obchvat: v režimu brány textové vysvětlení ani `refute` bez lístku nic nezavřou.
#[test]
fn legacy_inputs_cannot_close_in_gate_mode() {
    let mut memory = gate_memory();
    let key = FindingKey::new("10.0.0.5", "scan_attempts", "-");
    let none: Vec<String> = Vec::new();
    let d = memory.observe(&obs(&key, 0, Severity::Low, &none), Some("kalendar"));
    assert_eq!(d, Disposition::First);
    assert!(!memory.refute(&key, "stary zebrik", at(1)));
    assert_eq!(memory.get(&key).unwrap().state, FindingState::New);
    assert_eq!(memory.stats.gate_bypass, 2);
    assert!(memory.gate_violations().is_empty());
}

/// Zámek podezření: potvrzený klíč i klíč předaný jako nepotvrzené podezření se nevyvrátí
/// (dříve jen 48 cyklů v `Ladder::held`); po zavření klidem (TTL) zámek padá.
#[test]
fn suspected_or_confirmed_key_is_locked_until_closed() {
    let mut memory = gate_memory();
    let none: Vec<String> = Vec::new();
    let ticket =
        || admit_ladder(&decision("unexpected_traffic", vec![history(), context()])).unwrap();
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    memory.observe_gated(&obs(&key, 0, Severity::Low, &none), None);
    memory.mark_suspected(&key, at(1));
    assert!(!memory.refute_gated(&key, ticket(), at(2000)));
    let other = FindingKey::new("10.0.0.6", "unexpected_traffic", "tcp/80");
    memory.observe_gated(&obs(&other, 0, Severity::Low, &none), None);
    memory.confirm(&other, "verify_ladder", at(1));
    assert!(!memory.refute_gated(&other, ticket(), at(2)));
    // settle prevede odmitnute vyvraceni na eskalaci
    let mut d = decision("unexpected_traffic", vec![history(), context()]);
    d.key = key.clone();
    let settled = settle(&mut memory, d, &none, at(3));
    assert_eq!(settled.status, Status::Escalated, "{}", settled.reason);
    memory.sweep(at(3 + 25 * 60));
    assert_eq!(memory.get(&key).unwrap().state, FindingState::Closed);
    memory.observe_gated(&obs(&key, 3 + 26 * 60, Severity::Low, &none), None);
    assert!(memory.refute_gated(&key, ticket(), at(3 + 26 * 60 + 1)));
    assert!(memory.gate_violations().is_empty());
}

/// Rozsah epizody: zavřený klíč pohltí jen souvislé pokračování se zdroji z lístku; nový
/// zdroj nebo odmlka ≥ 1 h jde znovu k ověření (eskalace, zobrazí se).
#[test]
fn closed_key_absorbs_only_continuous_episode_with_ticket_sources() {
    let mut memory = gate_memory();
    let src = vec!["10.0.0.9".to_string()];
    let other = vec!["10.0.0.66".to_string()];
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    memory.observe_gated(&obs(&key, 0, Severity::Low, &src), None);
    let d = settle(&mut memory, FindingKeyDecision::with_key(&key), &src, at(1));
    assert_eq!(d.status, Status::Refuted, "{}", d.reason);
    assert_eq!(
        memory.observe_gated(&obs(&key, 30, Severity::Low, &src), None),
        Disposition::Suppressed
    );
    assert!(matches!(
        memory.observe_gated(&obs(&key, 60, Severity::Low, &other), None),
        Disposition::Escalated(_)
    ));
    // znovu zavrit a pak odmlka
    let d = settle(
        &mut memory,
        FindingKeyDecision::with_key(&key),
        &src,
        at(61),
    );
    assert_eq!(d.status, Status::Refuted);
    assert!(matches!(
        memory.observe_gated(&obs(&key, 61 + 90, Severity::Low, &src), None),
        Disposition::Escalated(_)
    ));
}

struct FindingKeyDecision;
impl FindingKeyDecision {
    fn with_key(key: &FindingKey) -> Decision {
        let mut d = decision(&key.finding_type, vec![history(), context()]);
        d.key = key.clone();
        d
    }
}

/// K20-5: property/fuzz test invariantu na 20 000 náhodných posloupnostech operací paměti a
/// rozhodnutí žebříku v režimu brány (včetně obchvatů starými vstupy): zavřený stav ⇒ lístek
/// s pozitivním důkazem a vlastníkem; chráněný typ a nález s vysokým dopadem nikdy zavřen;
/// podezřelý klíč nikdy zavřen. 0 porušení, 0 paniků.
#[test]
fn gate_invariant_holds_under_random_operations_fuzz() {
    let mut state = 0x2020_1119u64;
    let mut next = |n: u64| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) % n.max(1)
    };
    // typ, vysoky dopad
    let kinds = [
        ("unexpected_traffic", false),
        ("scan_attempts", false),
        ("packet_rate_spike", true),
        ("pivot_chain", false),
        ("suricata_alert", false),
        ("inductive_volume_anomaly", false),
    ];
    let pool: Vec<String> = ["10.0.0.9", "10.0.0.66", "203.0.113.7"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let notes_pool = || {
        vec![
            history(),
            context(),
            allow(),
            note(CheckId::Profile, 0.2, "zvyk"),
            note(CheckId::Peers, 0.25, "peeri"),
            note(CheckId::Liveness, 0.15, "vypadek"),
            note(CheckId::Endpoint, 0.3, "koncova telemetrie: vse v poradku"),
            note(
                CheckId::Context,
                0.1,
                "schvaleny kontext: sensor_outage (schvalil x)",
            ),
            note(CheckId::Reputation, 3.0, "zly zdroj"),
        ]
    };
    let mut closures = 0u64;
    for run in 0..20_000u64 {
        let mut memory = gate_memory();
        let (kind, high) = kinds[next(kinds.len() as u64) as usize];
        let key = FindingKey::new(&format!("10.0.{}.{}", run % 7, 1 + next(3)), kind, "tcp/80");
        let severity = if high { Severity::High } else { Severity::Low };
        let mut minute = 0i64;
        for _ in 0..(3 + next(12)) {
            minute += 1 + next(120) as i64;
            let k = next(pool.len() as u64 + 1) as usize;
            let sources: Vec<String> = pool.iter().take(k).cloned().collect();
            match next(9) {
                0 | 1 => {
                    let e = explanation(
                        [
                            ContextKind::AuthorizedScanner,
                            ContextKind::Backup,
                            ContextKind::SensorOutage,
                        ][next(3) as usize],
                        ["secops", "", " "][next(3) as usize],
                        next(2) == 0,
                    );
                    let ticket = admit_explanation(
                        &e,
                        kind,
                        &sources,
                        at(minute),
                        Subject {
                            protected: next(5) == 0,
                            high_impact: high,
                        },
                    )
                    .ok();
                    let d = memory.observe_gated(&obs(&key, minute, severity, &sources), ticket);
                    if matches!(d, Disposition::AutoResolved(_)) {
                        closures += 1;
                        assert!(!high, "{run}: vysoky dopad zavren kontextem");
                    }
                }
                2 => {
                    memory.observe(&obs(&key, minute, severity, &sources), Some("obchvat"));
                }
                3 => {
                    memory.refute(&key, "obchvat", at(minute));
                }
                4 | 5 => {
                    let all = notes_pool();
                    let picked: Vec<StepNote> = all.into_iter().filter(|_| next(2) == 0).collect();
                    let mut d = decision(kind, picked);
                    d.key = key.clone();
                    d.high_impact = high;
                    d.protected = next(6) == 0;
                    d.posterior = next(100) as f64 / 1000.0;
                    d.status =
                        [Status::Refuted, Status::Confirmed, Status::Escalated][next(3) as usize];
                    d.prior_hold = d.status == Status::Escalated && next(2) == 0;
                    let settled = settle(&mut memory, d, &sources, at(minute));
                    if settled.status == Status::Refuted {
                        closures += 1;
                        assert!(!high, "{run}: vysoky dopad zavren");
                    }
                }
                6 => memory.sweep(at(minute)),
                7 => {
                    memory.observe_gated(&obs(&key, minute, severity, &sources), None);
                }
                _ => {
                    memory.mark_suspected(&key, at(minute));
                }
            }
            let violations = memory.gate_violations();
            assert!(violations.is_empty(), "{run}: {violations:?}");
            if let Some(e) = memory.get(&key)
                && matches!(e.state, FindingState::AutoResolved | FindingState::Refuted)
            {
                assert!(!high, "{run}: vysoky dopad v zavrenem stavu");
                assert!(
                    !crate::protection::is_protected_type(kind),
                    "{run}: chraneny typ"
                );
            }
        }
    }
    // generator musi zavirani skutecne pokryt, jinak test nic nedokazuje
    assert!(closures > 500, "zavreno jen {closures}");
}

/// Krok 22 (B1, K22-N1): rekonstrukce dvou příčinně omylem vyvrácených případů ramene R,
/// seed 20270207, síť 0, cykly 636 a 637 (`F:\work-tmp\k22\trace`). Jediný neškodný výsledek
/// je schválený kontext autorizovaného skeneru bez rozsahu cílů; nález má smíšené zdroje
/// (skener a cizí zdroj). Brána žebříku vyvrácení odmítne (jen jedna skupina) a s přísným
/// doložením zdroje (`close_gate` zapíná `strict_close`) kontext ani nepodpoří.
#[test]
fn k22_b1_scanner_context_without_scope_alone_is_refused() {
    let undetermined = |check: CheckId, detail: &str| StepNote {
        check,
        cycle: 0,
        tag: "undetermined",
        lr: None,
        detail: detail.to_string(),
    };
    let mut d = decision(
        "unexpected_traffic",
        vec![
            undetermined(CheckId::History, "historie jen 0 dny"),
            undetermined(CheckId::Profile, "pripad nema jednu dvojici host-cil"),
            note(
                CheckId::Context,
                0.30,
                "schvaleny kontext: authorized_scanner (schvalil sim-spravce)",
            ),
        ],
    );
    d.posterior = 0.026_372;
    assert_eq!(admit_ladder(&d), Err(Refusal::TooFewGroups));

    use crate::context_gate::{ContextEntry, ContextGate, GateInput, GatePolicy, StaticCalendar};
    let scanner = ContextEntry {
        kind: ContextKind::AuthorizedScanner,
        hosts: Vec::new(),
        sources: vec!["192.168.33.119".to_string()],
        start: at(0),
        end: at(30),
        covers: Vec::new(),
        approved_by: "sim-spravce".to_string(),
        expires: at(60),
    };
    let calendar = StaticCalendar::new(vec![scanner]);
    let host = vec!["192.168.33.1".to_string()];
    let mixed = vec!["192.168.34.234".to_string(), "192.168.33.119".to_string()];
    let case = GateInput {
        finding_type: "unexpected_traffic",
        host_ids: &host,
        targets: &[],
        sources: &mixed,
        severity: Severity::Low,
        at: at(10),
        protected: false,
    };
    // rameno R (bez prisnosti): castecna shoda zdroje staci, kontext podpori vyvraceni
    let loose = ContextGate::new(GatePolicy::default());
    assert!(loose.supporting_context(&calendar, &case).is_some());
    // s branou: skener bez rozsahu a cizi zdroj = nedolozeno, zadny podpurny dukaz
    let strict = ContextGate::new(GatePolicy {
        strict_close: true,
        ..GatePolicy::default()
    });
    assert!(strict.supporting_context(&calendar, &case).is_none());
}
