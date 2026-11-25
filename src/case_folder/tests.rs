use super::*;
use crate::{
    context_gate::ContextKind,
    finding_memory::FindingKey,
    model::{Confidence, Severity},
};

fn note(check: CheckId, tag: &'static str, lr: Option<f64>, detail: &str) -> StepNote {
    StepNote {
        check,
        cycle: 3,
        tag,
        lr,
        detail: detail.into(),
    }
}

fn decision(status: Status, posterior: f64, notes: Vec<StepNote>) -> Decision {
    Decision {
        key: FindingKey::new("asset:1", "beacon_periodic", "tcp/443"),
        finding_id: "f-1".into(),
        finding_type: "beacon_periodic".into(),
        status,
        host_ip: "10.0.4.7".into(),
        posterior,
        raw_posterior: posterior,
        opened: 1,
        decided: 4,
        reason: String::new(),
        checks: notes.len(),
        budget_escalation: false,
        high_impact: false,
        protected: false,
        steps: notes.iter().map(|n| (n.check, n.tag)).collect(),
        notes,
        prior_hold: false,
        pending_check: None,
    }
}

fn input(d: &Decision) -> FolderInput<'_> {
    FolderInput {
        decision: d,
        finding: None,
        lifecycle: None,
        ops: None,
        coverage: None,
        endpoint_covered: None,
        contexts: &[],
        incidents: None,
        pseudonymize_users: true,
        endpoint_weak: false,
        endpoint_users: None,
    }
}

#[test]
fn escalated_case_is_complete_consistent_and_names_what_is_missing() {
    let d = decision(
        Status::Escalated,
        0.4,
        vec![
            note(CheckId::History, "malicious", Some(2.0), "novy jev"),
            note(CheckId::L7, "unavailable", None, "bez ssl.log"),
            note(CheckId::Profile, "benign", Some(0.5), "zvyk hosta"),
        ],
    );
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    assert_eq!(f.verdict.level, "L3");
    assert_eq!(f.evidence_for.len(), 1);
    assert_eq!(f.evidence_against.len(), 1);
    assert!(f.handoff.iter().any(|h| h.contains("konflikt")));
    assert!(
        f.handoff
            .iter()
            .any(|h| h.contains("chybi pozitivni dukaz"))
    );
    assert!(
        f.blind_spots
            .iter()
            .any(|b| b.starts_with("l7: nelze provest"))
    );
    assert!(f.actors_missing.iter().any(|a| a.starts_with("uzivatel")));
    assert_eq!(f.uncertainty.observation.value, Some(1.0 / 3.0));
    assert!(f.closure.is_none());
    // P(utok) hypotezy je presne verdikt enginu
    assert_eq!(
        f.hypotheses
            .iter()
            .find(|h| h.hypothesis == "utok")
            .unwrap()
            .probability,
        0.4
    );
}

#[test]
fn closed_case_carries_proof_owner_and_expiry() {
    let d = decision(
        Status::Refuted,
        0.01,
        vec![
            note(
                CheckId::Context,
                "benign",
                Some(0.3),
                "schvaleny kontext: authorized_scanner (schvalil spravce)",
            ),
            note(CheckId::History, "benign", Some(0.25), "stejny jev 3 dny"),
        ],
    );
    let at = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let ctx = [ContextEntry {
        kind: ContextKind::AuthorizedScanner,
        hosts: vec![],
        sources: vec!["10.0.0.9".into()],
        start: at - chrono::Duration::days(30),
        end: at,
        covers: vec![],
        approved_by: "spravce".into(),
        expires: at,
    }];
    let mut i = input(&d);
    i.contexts = &ctx;
    let f = build(&i);
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    let c = f.closure.as_ref().unwrap();
    assert_eq!(c.owner, "spravce");
    assert!(c.expires.starts_with("2026-12-01"));
    assert!(c.proof.iter().all(|e| e.strong));
    assert!(f.handoff.is_empty());
    assert_eq!(f.verdict.level, "L1");
    assert_eq!(f.hypotheses[0].hypothesis, "planovany_skener");
}

#[test]
fn closure_by_outage_says_owner_cannot_be_determined() {
    let d = decision(
        Status::Refuted,
        0.02,
        vec![
            note(
                CheckId::Liveness,
                "benign",
                Some(0.15),
                "sluzba neodpovida, bez dominantniho zdroje: vypadek",
            ),
            note(CheckId::History, "benign", Some(0.25), "stejny jev 2 dny"),
        ],
    );
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty());
    let c = f.closure.unwrap();
    assert_eq!(c.owner, UNKNOWN);
    assert_eq!(c.expires, UNKNOWN);
    assert!(c.note.contains("vlastnik: nelze urcit"));
}

#[test]
fn allowlist_detail_gives_owner_and_expiry() {
    let d = decision(
        Status::Refuted,
        0.01,
        vec![
            note(
                CheckId::Endpoint,
                "benign",
                Some(0.2),
                "seznam povolenych: backup.exe (vlastnik it-provoz, do 2027-01-01T00:00:00Z)",
            ),
            note(CheckId::History, "benign", Some(0.25), "zvyk"),
        ],
    );
    let f = build(&input(&d));
    let c = f.closure.as_ref().unwrap();
    assert_eq!(c.owner, "it-provoz");
    assert_eq!(c.expires, "2027-01-01T00:00:00Z");
    assert!(f.actors.iter().any(|a| a.role == "proces"));
}

#[test]
fn validator_rejects_overclaim_and_inconsistency() {
    let d = decision(
        Status::Escalated,
        0.3,
        vec![note(CheckId::History, "benign", Some(0.25), "x")],
    );
    let mut f = build(&input(&d));
    assert!(validate(&f, &d).is_empty());
    f.summary = "Utok potvrdil zebrik".into();
    f.verdict.posterior_attack = 0.9;
    f.evidence_for.push(Evidence {
        check: "reputation".into(),
        level: "L1".into(),
        origin: "externi".into(),
        group: "external".into(),
        independent: true,
        strong: false,
        lr: 8.0,
        detail: "vymysleno".into(),
    });
    let v = validate(&f, &d);
    assert!(v.iter().any(|x| x.contains("P(utok) se lisi")));
    assert!(v.iter().any(|x| x.contains("bez provedeneho kroku")));
    assert!(v.iter().any(|x| x.contains("tvrdi")));
}

#[test]
fn weak_endpoint_signal_is_not_strong_proof() {
    let d = decision(
        Status::Escalated,
        0.05,
        vec![note(
            CheckId::Endpoint,
            "benign",
            Some(0.3),
            "koncova telemetrie: podepsany proces",
        )],
    );
    let mut i = input(&d);
    i.endpoint_weak = true;
    let f = build(&i);
    assert!(f.evidence_against.iter().all(|e| !e.strong));
    assert!(
        f.handoff
            .iter()
            .any(|h| h.contains("chybi pozitivni dukaz"))
    );
}

/// Pevná množina klíčů schématu (K16-5): změna = nová verze schématu.
#[test]
fn schema_keys_are_stable_and_roundtrip_is_lossless() {
    let d = decision(
        Status::Confirmed,
        0.97,
        vec![note(
            CheckId::Reputation,
            "malicious",
            Some(8.0),
            "spatna reputace",
        )],
    );
    let f = build(&input(&d));
    let json = serde_json::to_value(&f).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "schema",
            "case_id",
            "finding_type",
            "host",
            "summary",
            "recommended_step",
            "verdict",
            "timeline",
            "actors",
            "actors_missing",
            "hypotheses",
            "uncertainty",
            "evidence_for",
            "evidence_against",
            "verified",
            "to_verify",
            "blind_spots",
            "data_requests",
            "related",
            "handoff",
            "closure"
        ]
    );
    let text = serde_json::to_string(&f).unwrap();
    let back: CaseFolder = serde_json::from_str(&text).unwrap();
    assert_eq!(back, f);
    assert_eq!(serde_json::to_string(&back).unwrap(), text);
    assert!(validate(&f, &d).is_empty());
    assert!(render_text(&f).contains("Doporuceny krok"));
    assert!(render_html(std::slice::from_ref(&f)).contains("<pre>"));
}

/// Krok 16 (held seedy): žebřík potvrdí i jen podle apriorní pravděpodobnosti z paměti
/// případů; složka to nesmí podat jako doložené podezření.
#[test]
fn confirmation_without_suspicious_evidence_is_reported_as_prior_only() {
    let d = decision(
        Status::Confirmed,
        0.91,
        vec![note(CheckId::History, "undetermined", None, "bez historie")],
    );
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    assert!(f.summary.contains("bez podezreleho dukazu"));
    assert!(!f.summary.contains("potvrdil"));
    assert!(f.handoff[0].starts_with("potvrzeno bez dukazu z kontrol"));
    assert!(f.recommended_step.starts_with("Pred zasahem"));
}

/// Krok 18: nepotvrzený případ (vysoká apriorní P bez nezávislého důkazu) je eskalovaný,
/// složka netvrdí útok a jako první důvod předání uvádí kontrolu, na kterou čeká.
#[test]
fn prior_hold_is_reported_as_unconfirmed_with_pending_check() {
    let mut d = decision(
        Status::Escalated,
        0.93,
        vec![note(
            CheckId::Profile,
            "undetermined",
            None,
            "profil nezraly",
        )],
    );
    d.prior_hold = true;
    d.pending_check = Some(CheckId::Reputation);
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    assert_eq!(f.verdict.level, "L3");
    assert!(f.handoff[0].starts_with("nepotvrzeno"), "{:?}", f.handoff);
    assert!(f.handoff[0].contains("reputation"), "{:?}", f.handoff);
    assert!(
        f.summary.starts_with("Nerozhodnuty pripad"),
        "{}",
        f.summary
    );
    assert!(!f.summary.contains("potvrdil"));
    d.pending_check = None;
    let f = build(&input(&d));
    assert!(f.handoff[0].contains("rucni overeni"), "{:?}", f.handoff);
}

/// Senior review (held seedy): složka doporučovala znovu kontrolu, která už proběhla bez dat.
#[test]
fn recommendation_skips_checks_that_already_ran_without_data() {
    let mut d = decision(
        Status::Escalated,
        0.3,
        vec![
            note(CheckId::History, "undetermined", None, "historie jen 0 dny"),
            note(
                CheckId::Context,
                "undetermined",
                None,
                "zadny zaznam kontextu",
            ),
        ],
    );
    d.protected = true;
    let f = build(&input(&d));
    assert!(!f.recommended_step.contains("CaseHistory"));
    assert!(!f.recommended_step.contains("ConfigContext"));
    assert!(
        f.to_verify
            .iter()
            .all(|c| c.check != "ConfigContext" && c.check != "OpsTelemetry")
    );
    let last = f.to_verify.last().unwrap();
    assert!(last.why.starts_with("provedeno"), "{last:?}");
    // neškodné druhy bez rozlišujícího důkazu nesou jen rovnoměrný podíl
    assert!(
        f.hypotheses
            .iter()
            .filter(|h| h.hypothesis != "utok")
            .all(|h| h.status == "nerozlisena")
    );
}

#[test]
fn html_escapes_untrusted_text() {
    let d = decision(
        Status::Escalated,
        0.3,
        vec![note(
            CheckId::History,
            "malicious",
            Some(2.0),
            "<script>x</script>",
        )],
    );
    let f = build(&input(&d));
    let html = render_html(&[f]);
    assert!(!html.contains("<script>"));
}

/// Property/fuzz test (K16-5): náhodné kroky, stavy, texty a hodnoty včetně NaN a extrémů;
/// žádná panika, validátor bez porušení, determinismus.
#[test]
fn fuzz_random_decisions_never_panic_and_always_validate() {
    let mut s: u64 = 0x16_2026_1116;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let checks = [
        CheckId::History,
        CheckId::Context,
        CheckId::Reputation,
        CheckId::Intel,
        CheckId::DeviceProfile,
        CheckId::Peers,
        CheckId::Persistence,
        CheckId::Liveness,
        CheckId::Pivot,
        CheckId::Profile,
        CheckId::Endpoint,
        CheckId::L7,
        CheckId::Ops,
    ];
    let tags = ["malicious", "benign", "undetermined", "unavailable", "wait"];
    let texts = [
        "",
        "schvalil ",
        "vlastnik x, do ",
        "seznam povolenych: a",
        "ěščř\u{0}<>&\"",
        "do , ;)",
        "x",
    ];
    let cov = CoverageStatus {
        silent_hosts: vec!["10.0.4.7".into()],
        dark_segments: vec!["10.0.4.0/24".into()],
        ..Default::default()
    };
    let finding = Finding {
        finding_id: "f-1".into(),
        finding_type: "beacon_periodic".into(),
        title: "Beacon z 10.0.4.7 na 1.2.3.4".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        host_key: Some("10.0.4.7".into()),
        service_key: Some("tcp/443".into()),
        rationale: String::new(),
        evidence: vec!["5.6.7.8".into()],
        recommendation: String::new(),
    };
    let incidents = [Incident {
        id: 1,
        findings: vec!["f-1".into(), "f-2".into()],
        hosts: vec!["10.0.4.7".into()],
        first_ts: 0,
        last_ts: 1,
        phases: vec!["discovery".into()],
        cause: crate::retro::Cause::Attack,
        first_finding: "f-2".into(),
        key: String::new(),
        related: Vec::new(),
    }];
    for i in 0..20_000u32 {
        let n = (next() % 9) as usize;
        let mut notes = Vec::new();
        for _ in 0..n {
            let tag = tags[(next() % 5) as usize];
            let lr = match tag {
                "malicious" => Some(1.0 + (next() % 1000) as f64 / 10.0),
                "benign" => Some((next() % 99 + 1) as f64 / 100.0),
                _ => None,
            };
            let mut detail =
                texts[(next() % texts.len() as u64) as usize].repeat((next() % 80) as usize);
            detail.push_str(texts[(next() % texts.len() as u64) as usize]);
            notes.push(StepNote {
                check: checks[(next() % checks.len() as u64) as usize],
                cycle: next() % 1000,
                tag,
                lr,
                detail,
            });
        }
        let raw = match next() % 6 {
            0 => f64::NAN,
            1 => -1.0,
            2 => 2.0,
            _ => (next() % 1001) as f64 / 1000.0,
        };
        let has_strong = notes
            .iter()
            .any(|n| n.tag == "benign" && matches!(benign_group(n.check), Some(1 | 2 | 4)));
        let status = match next() % 4 {
            // engine vyvraci jen se silnym dukazem (strict_close); jinak eskaluje
            0 if has_strong => Status::Refuted,
            1 => Status::Confirmed,
            2 => Status::Open,
            _ => Status::Escalated,
        };
        let mut d = decision(status, raw, notes);
        d.protected = next() % 5 == 0 && status != Status::Refuted;
        d.high_impact = next() % 7 == 0;
        d.budget_escalation = next() % 9 == 0;
        if next() % 3 == 0 {
            d.host_ip = String::new();
        }
        let mut inp = input(&d);
        if i % 2 == 0 {
            inp.finding = Some(&finding);
            inp.coverage = Some(&cov);
            inp.incidents = Some(&incidents);
            inp.endpoint_covered = Some(next() % 2 == 0);
            inp.endpoint_users = match next() % 3 {
                0 => None,
                1 => Some(Vec::new()),
                _ => Some(
                    (0..next() % 6)
                        .map(|k| texts[(k % texts.len() as u64) as usize].repeat(40))
                        .collect(),
                ),
            };
        }
        let f = build(&inp);
        let v = validate(&f, &d);
        assert!(v.is_empty(), "iterace {i}: {v:?}");
        let again = build(&inp);
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            serde_json::to_string(&again).unwrap()
        );
        let size = serde_json::to_vec(&f).unwrap().len();
        assert!(size <= 16 * 1024, "iterace {i}: {size} B");
        let _ = render_text(&f);
    }
}

/// Krok 19 (slabina kroku 16: „slepé místo“ u 99 % předaných): kontrola, která proběhla a nic
/// nerozlišila, není slepé místo; slepé místo je jen kontrola, kterou nešlo provést.
#[test]
fn inconclusive_check_is_not_a_blind_spot() {
    let d = decision(
        Status::Escalated,
        0.3,
        vec![
            note(CheckId::Liveness, "undetermined", None, "sluzba odpovida"),
            note(
                CheckId::Reputation,
                "undetermined",
                None,
                "zdroj bez reputace",
            ),
        ],
    );
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    assert!(
        f.blind_spots.iter().all(|b| b.starts_with("stav pokryti")),
        "{:?}",
        f.blind_spots
    );
    assert!(!f.handoff.iter().any(|h| h.starts_with("slepa mista")));
    let d = decision(
        Status::Escalated,
        0.3,
        vec![
            note(CheckId::Liveness, "undetermined", None, "sluzba odpovida"),
            note(
                CheckId::Endpoint,
                "unavailable",
                None,
                "host 10.0.4.7 nema zivou koncovou telemetrii",
            ),
        ],
    );
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    assert_eq!(
        f.blind_spots
            .iter()
            .filter(|b| !b.starts_with("stav pokryti"))
            .count(),
        1,
        "{:?}",
        f.blind_spots
    );
    assert!(f.handoff.iter().any(|h| h.starts_with("slepa mista: 1")));
    // validátor odmítne slepé místo vyrobené z kontroly, která proběhla
    let mut bad = f.clone();
    bad.blind_spots
        .push("liveness: nelze provest, sluzba odpovida".into());
    assert!(
        validate(&bad, &d)
            .iter()
            .any(|v| v.starts_with("slepe misto liveness"))
    );
}

/// Krok 19 (slabina kroku 16: obecný doporučený krok): doporučí se jen kontrola se změřenou
/// rozlišovací schopností, s ručním postupem a s tím, jak by výsledek posunul P(útok).
#[test]
fn recommendation_names_a_discriminating_check_and_its_effect() {
    let d = decision(Status::Escalated, 0.3, Vec::new());
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    for neutral in ["DnsPivot", "Timing", "GeoAsn", "TlsFingerprint"] {
        assert!(
            !f.recommended_step.contains(neutral),
            "{}",
            f.recommended_step
        );
        let entry = f.to_verify.iter().find(|c| c.check == neutral).unwrap();
        assert!(!entry.why.starts_with(DISCRIMINATES), "{entry:?}");
    }
    assert!(
        f.recommended_step.starts_with("Rucne"),
        "{}",
        f.recommended_step
    );
    assert!(
        f.recommended_step
            .contains("vysledek posune P(utok) z 0.30 na")
    );
    // první v seznamu je kontrola, která rozlišuje
    assert!(
        f.to_verify[0].why.starts_with(DISCRIMINATES),
        "{:?}",
        f.to_verify[0]
    );
    // validátor odmítne doporučení kontroly bez rozlišovací schopnosti
    let mut bad = f.clone();
    bad.recommended_step = "Rucne projit DNS (DnsPivot, cena 0.10).".into();
    assert!(
        validate(&bad, &d)
            .iter()
            .any(|v| v.contains("DnsPivot nerozlisuje"))
    );
}

/// Krok 19 (ladicí seedy): kontrola dostupnosti služby se nedoporučuje u nálezu, pro jehož typ
/// ji žebřík nepoužívá (únik dat); u výpadku služby ano.
#[test]
fn recommendation_respects_checks_applicable_to_finding_type() {
    let mut d = decision(Status::Escalated, 0.5, Vec::new());
    d.finding_type = "egress_volume_anomaly".into();
    let f = build(&input(&d));
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    let active = f
        .to_verify
        .iter()
        .find(|c| c.check == "ActiveReadOnly")
        .unwrap();
    assert!(active.why.contains("nema smysl"), "{active:?}");
    assert!(!f.recommended_step.contains("ActiveReadOnly"));
    d.finding_type = "service_unreachable".into();
    let f = build(&input(&d));
    let active = f
        .to_verify
        .iter()
        .find(|c| c.check == "ActiveReadOnly")
        .unwrap();
    assert!(active.why.starts_with(DISCRIMINATES), "{active:?}");
}

/// Krok 19 (slabina kroku 16: uživatel vždy „nelze určit“): uživatel z koncové telemetrie.
#[test]
fn user_actor_comes_from_endpoint_telemetry() {
    let d = decision(Status::Escalated, 0.3, Vec::new());
    let mut i = input(&d);
    i.endpoint_covered = Some(true);
    i.endpoint_users = Some(vec!["u-1a2b3c4d".into(), "SYSTEM".into()]);
    let f = build(&i);
    assert!(validate(&f, &d).is_empty(), "{:?}", validate(&f, &d));
    let users: Vec<&Actor> = f.actors.iter().filter(|a| a.role == "uzivatel").collect();
    assert_eq!(users.len(), 2);
    assert!(
        users
            .iter()
            .all(|a| a.source == "endpoint" && a.pseudonymized)
    );
    assert!(!f.actors_missing.iter().any(|a| a.starts_with("uzivatel")));
    i.endpoint_users = Some(Vec::new());
    let f = build(&i);
    assert!(
        f.actors_missing
            .iter()
            .any(|a| a.starts_with("uzivatel") && a.contains("neuvadi"))
    );
    i.endpoint_users = None;
    i.endpoint_covered = Some(false);
    let f = build(&i);
    assert!(
        f.actors_missing
            .iter()
            .any(|a| a.starts_with("uzivatel") && a.contains("nema zivou"))
    );
    let mut bad = f.clone();
    bad.actors.push(Actor {
        role: "uzivatel".into(),
        id: "x".into(),
        pseudonymized: false,
        source: "nalez".into(),
    });
    assert!(
        validate(&bad, &d)
            .iter()
            .any(|v| v.contains("uzivatel mimo"))
    );
}
