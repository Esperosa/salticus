//! Krok 21: nezávislé sondy proti bráně zavření (`docs/diplomka/eval/impl-krok21.md`).
//!
//! Sondy netestují to, co autor brány kódoval, ale pravdivý invariant pravidel R1 a R2
//! (`docs/diplomka/rozsah-autonomie.md`) na úrovni klíče a v čase:
//! - klíč, který byl kdykoli pozorován s vysokou závažností, se automaticky nezavře;
//! - klíč s aktivním signálem ochrany (P4/P5) se automaticky nezavře;
//! - zámek podezření přežije restart procesu;
//! - zavření vzniká jen z rozhodnutí s pozitivním důkazem s vlastníkem.
//!
//! Testy `known_gap_*` popisují zjištěný stav, který krok 21 neopravuje (návrh v registru
//! `docs/diplomka/eval/rozhodnuti-jadra.md`); selžou, až se mezera zavře, a pak se mají otočit.

use super::*;
use crate::finding_memory::{
    Disposition, FindingKey, FindingMemory, FindingState, MemoryConfig, Observation,
};
use crate::model::Severity;
use rusqlite::Connection;

fn at(minutes: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_800_000_000 + minutes * 60, 0).unwrap()
}

fn cfg() -> MemoryConfig {
    MemoryConfig {
        gate: true,
        protect: true,
        refute_episode_s: 3600,
        escalate_first_source: true,
        ..MemoryConfig::default()
    }
}

fn step(check: CheckId, lr: f64, detail: &str) -> StepNote {
    StepNote {
        check,
        cycle: 0,
        tag: if lr < 1.0 { "benign" } else { "malicious" },
        lr: Some(lr),
        detail: detail.to_string(),
    }
}

fn approved_context() -> StepNote {
    step(
        CheckId::Context,
        0.1,
        "schvaleny kontext: [zdroj dolozen] backup (schvalil spravce)",
    )
}

fn habit() -> StepNote {
    step(
        CheckId::History,
        0.25,
        "stejny jev uz 4 dny ve stejne hodine",
    )
}

/// Rozhodnutí žebříku tak, jak ho žebřík vydá: vysoký dopad a ochrana z prvního otevření
/// případu (viz `verify_ladder::tests::audit_k21_merge_keeps_stale_high_impact_and_protection`).
fn refuted(key: &FindingKey, notes: Vec<StepNote>) -> Decision {
    Decision {
        key: key.clone(),
        finding_id: format!("finding:{}", key.finding_type),
        finding_type: key.finding_type.clone(),
        status: Status::Refuted,
        host_ip: key.entity.clone(),
        posterior: 0.01,
        raw_posterior: 0.01,
        opened: 0,
        decided: 1,
        reason: "sonda k21".into(),
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

fn observe<'a>(
    key: &FindingKey,
    minute: i64,
    severity: Severity,
    sources: &'a [String],
    protected: bool,
) -> Observation<'a> {
    Observation {
        key: key.clone(),
        severity,
        count: 3,
        sources,
        at: at(minute),
        volume_explained: false,
        protected,
    }
}

fn closed(memory: &FindingMemory, key: &FindingKey) -> bool {
    memory
        .get(key)
        .is_some_and(|e| matches!(e.state, FindingState::AutoResolved | FindingState::Refuted))
}

fn src(ip: &str) -> Vec<String> {
    vec![ip.to_string()]
}

/// N1 (R2): případ otevřený při nízké závažnosti, pak eskalace téhož klíče na High. Žebřík
/// nese `high_impact` z otevření, brána ho čte z rozhodnutí. Klíč s High se nesmí zavřít.
#[test]
fn k21_severity_escalated_key_is_not_refuted() {
    let mut memory = FindingMemory::new(cfg());
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None);
    let d = memory.observe_gated(&observe(&key, 30, Severity::High, &s, false), None);
    assert!(matches!(d, Disposition::Escalated(_)), "{d:?}");
    let settled = settle(
        &mut memory,
        refuted(&key, vec![habit(), approved_context()]),
        &s,
        at(31),
    );
    assert_ne!(settled.status, Status::Refuted, "{}", settled.reason);
    assert!(!closed(&memory, &key));
    assert!(memory.gate_violations().is_empty());
}

/// N1 (R2): kontext nesmí automaticky vyřešit klíč, který byl dřív pozorován s High, jen
/// proto, že aktuální výskyt má nízkou závažnost.
#[test]
fn k21_context_does_not_resolve_key_seen_high() {
    let mut memory = FindingMemory::new(cfg());
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    memory.observe_gated(&observe(&key, 0, Severity::High, &s, false), None);
    let e = crate::context_gate::Explanation {
        kind: crate::context_gate::ContextKind::Backup,
        reason: "backup (schvalil spravce)".into(),
        approved_by: "spravce".into(),
        expires: at(600),
        sources_proven: true,
    };
    let ticket = admit_explanation(
        &e,
        &key.finding_type,
        &s,
        at(30),
        Subject {
            protected: false,
            high_impact: false, // aktualni vyskyt je Low
        },
    )
    .expect("brana sama vysoky dopad z historie klice nevidi");
    let d = memory.observe_gated(&observe(&key, 30, Severity::Low, &s, false), Some(ticket));
    assert!(!matches!(d, Disposition::AutoResolved(_)), "{d:?}");
    assert!(!closed(&memory, &key));
}

/// N2 (R2): signál ochrany (P4 degradace, P5 nejednoznačná identita) přijde až po otevření
/// případu; žebřík ho nevidí (sloučení), paměť ho dostala v pozorování. Nezavřít.
#[test]
fn k21_protection_signal_after_open_blocks_refute() {
    let mut memory = FindingMemory::new(cfg());
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None);
    memory.observe_gated(&observe(&key, 30, Severity::Low, &s, true), None);
    let settled = settle(
        &mut memory,
        refuted(&key, vec![habit(), approved_context()]),
        &s,
        at(31),
    );
    assert_ne!(settled.status, Status::Refuted, "{}", settled.reason);
    assert!(!closed(&memory, &key));
}

/// N3: zámek podezření přežije restart (produkce načítá paměť z SQLite v každém běhu).
#[test]
fn k21_suspicion_lock_survives_restart() {
    let mut conn = Connection::open_in_memory().unwrap();
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    {
        let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
        memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None);
        memory.mark_suspected(&key, at(1));
        memory.flush(&mut conn).unwrap();
    }
    let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
    assert!(memory.get(&key).unwrap().suspected, "zamek po restartu");
    let settled = settle(
        &mut memory,
        refuted(&key, vec![habit(), approved_context()]),
        &s,
        at(31),
    );
    assert_ne!(settled.status, Status::Refuted, "{}", settled.reason);
}

/// O3: databáze se schématem 1 (před krokem 21) se migruje na 2 bez ztráty řádků; nové sloupce
/// mají výchozí 0 a uloží se.
#[test]
fn k21_schema_v1_database_migrates() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE finding_state (entity TEXT NOT NULL, finding_type TEXT NOT NULL,
            service TEXT NOT NULL, state TEXT NOT NULL, first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL, last_displayed INTEGER, occurrences INTEGER NOT NULL,
            max_severity INTEGER NOT NULL, max_count INTEGER NOT NULL, sources TEXT NOT NULL,
            auto_reason TEXT, PRIMARY KEY (entity, finding_type, service));
         CREATE TABLE finding_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL,
            finding_type TEXT NOT NULL, service TEXT NOT NULL, detail TEXT NOT NULL);
         INSERT INTO finding_state VALUES ('10.0.0.5','unexpected_traffic','tcp/80','open',
            1800000000,1800000060,NULL,2,1,3,'[]',NULL);
         PRAGMA user_version = 1;",
    )
    .unwrap();
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
    let e = memory.get(&key).unwrap();
    assert_eq!(e.state, FindingState::Open);
    assert!(!e.suspected && !e.shield);
    memory.mark_suspected(&key, at(2));
    memory.flush(&mut conn).unwrap();
    let back = FindingMemory::load(&conn, cfg()).unwrap();
    assert!(back.get(&key).unwrap().suspected);
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, crate::finding_memory::SCHEMA_VERSION);
}

/// N2 a N1 po restartu: signál ochrany ani High se restartem neztratí.
#[test]
fn k21_shield_survives_restart() {
    let mut conn = Connection::open_in_memory().unwrap();
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    {
        let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
        memory.observe_gated(&observe(&key, 0, Severity::Low, &s, true), None);
        memory.flush(&mut conn).unwrap();
    }
    let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
    let settled = settle(
        &mut memory,
        refuted(&key, vec![habit(), approved_context()]),
        &s,
        at(31),
    );
    assert_ne!(settled.status, Status::Refuted, "{}", settled.reason);
}

/// N4 (známá mezera, bezpečný směr): lístek se do SQLite neukládá, takže v produkci (paměť se
/// načítá v každém běhu) vyvrácení platí jen do konce běhu; další výskyt se znovu zobrazí.
/// Soak paměť mezi cykly nenačítá, takže tenhle rozdíl neměří.
#[test]
fn known_gap_ticket_is_not_persisted_closure_lasts_one_run() {
    let mut conn = Connection::open_in_memory().unwrap();
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    {
        let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
        memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None);
        let d = settle(
            &mut memory,
            refuted(&key, vec![habit(), approved_context()]),
            &s,
            at(1),
        );
        assert_eq!(d.status, Status::Refuted, "{}", d.reason);
        memory.flush(&mut conn).unwrap();
    }
    let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
    assert_eq!(memory.get(&key).unwrap().state, FindingState::Closed);
    assert_eq!(
        memory.observe_gated(&observe(&key, 30, Severity::Low, &s, false), None),
        Disposition::Reopened
    );
}

/// N5 (známá mezera): dva souběžné běhy nad toutéž databází. Běh A potvrdí klíč, běh B (načten
/// dřív) ho vyvrátí s lístkem a zapíše později; upsert „poslední vyhrává“ přepíše potvrzení a
/// po načtení je klíč `Closed` (bez lístku), potvrzení se ztratilo.
#[test]
fn known_gap_concurrent_runs_lose_confirmation() {
    let dir = std::env::temp_dir().join(format!("k21-race-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.db");
    let _ = std::fs::remove_file(&path);
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    {
        let mut conn = Connection::open(&path).unwrap();
        let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
        memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None);
        memory.flush(&mut conn).unwrap();
    }
    let mut conn_a = Connection::open(&path).unwrap();
    let mut conn_b = Connection::open(&path).unwrap();
    let mut a = FindingMemory::load(&conn_a, cfg()).unwrap();
    let mut b = FindingMemory::load(&conn_b, cfg()).unwrap();
    assert!(a.confirm(&key, "verify_ladder", at(1)));
    a.flush(&mut conn_a).unwrap();
    // B o potvrzeni nevi; vyvraceni s pozitivnim dukazem projde branou i pameti
    b.observe_gated(&observe(&key, 2, Severity::Low, &s, false), None);
    let d = settle(
        &mut b,
        refuted(&key, vec![habit(), approved_context()]),
        &s,
        at(2),
    );
    assert_eq!(d.status, Status::Refuted, "{}", d.reason);
    b.flush(&mut conn_b).unwrap();
    let back = FindingMemory::load(&conn_a, cfg()).unwrap();
    assert_eq!(
        back.get(&key).unwrap().state,
        FindingState::Closed,
        "potvrzeni prepsano soubeznym behem"
    );
    drop((conn_a, conn_b));
    let _ = std::fs::remove_dir_all(&dir);
}

/// N6 (riziko, ne chyba kódu): pozitivní důkaz „seznam povolených“ pochází z hlášení agenta na
/// hostu. Lhoucí agent, který nahlásí povolený proces, spolu s historií (závislý důkaz) splní
/// bránu. R1 tím stojí na poctivosti agenta, ne na nezávislém zdroji.
#[test]
fn known_gap_lying_agent_allowlist_plus_history_passes_gate() {
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let lie = step(
        CheckId::Endpoint,
        0.1,
        "seznam povolenych: 10.0.0.5: backup.exe (vlastnik it-ops, do 2027-01-01)",
    );
    let ticket = admit_ladder(&refuted(&key, vec![lie, habit()])).unwrap();
    assert_eq!(ticket.owner(), "it-ops");
    assert_eq!(ticket.groups(), &[3, 4]);
}

/// N7 (API): lístek není svázán s klíčem; `refute_gated` přijme lístek vydaný pro jiný nález.
/// Ve stávajícím kódu volá `refute_gated` jen `settle` s lístkem z téhož rozhodnutí.
#[test]
fn known_gap_ticket_is_not_bound_to_key() {
    let mut memory = FindingMemory::new(cfg());
    let a = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let b = FindingKey::new("10.0.0.77", "unexpected_traffic", "tcp/443");
    let none: Vec<String> = Vec::new();
    memory.observe_gated(&observe(&b, 0, Severity::Low, &none, false), None);
    let ticket = admit_ladder(&refuted(&a, vec![habit(), approved_context()])).unwrap();
    assert!(memory.refute_gated(&b, ticket, at(1)));
}

/// C7 (otevřený bod 1, známá mezera): otevřený klíč pohltí nový výskyt po odmlce, která je u
/// zavřeného klíče už novou epizodou (1 h). Bez změny závažnosti, zdroje nebo objemu ×4 se
/// nová epizoda útoku pod týmž klíčem nezobrazí ani nejde do žebříku.
#[test]
fn known_gap_open_key_absorbs_new_episode_silently() {
    let mut memory = FindingMemory::new(cfg());
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    assert_eq!(
        memory.observe_gated(&observe(&key, 0, Severity::Medium, &s, false), None),
        Disposition::First
    );
    // odmlka 6 h (< 24 h zavreni klidem), tataz adresa, nova epizoda
    assert_eq!(
        memory.observe_gated(&observe(&key, 6 * 60, Severity::Medium, &s, false), None),
        Disposition::Suppressed
    );
    assert_eq!(memory.get(&key).unwrap().state, FindingState::Open);
}

/// N8 (hodiny): skok hodin dopředu o > 24 h uzavře klidem i potvrzený a podezřelý klíč a
/// zámek padá; skok dozadu (výskyt starší než poslední) neprodlouží epizodu.
#[test]
fn known_gap_clock_jump_forward_drops_lock() {
    let mut memory = FindingMemory::new(cfg());
    let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
    let s = src("203.0.113.9");
    memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None);
    memory.mark_suspected(&key, at(1));
    memory.sweep(at(1 + 25 * 60)); // hodiny poskocily
    let e = memory.get(&key).unwrap();
    assert_eq!(e.state, FindingState::Closed);
    assert!(!e.suspected, "zamek podezreni po skoku hodin neplati");
    // skok dozadu: vyskyt s casem pred poslednim videnim se pocita jako souvisla epizoda
    memory.observe_gated(&observe(&key, 2 + 25 * 60, Severity::Low, &s, false), None);
    let d = settle(
        &mut memory,
        refuted(&key, vec![habit(), approved_context()]),
        &s,
        at(3 + 25 * 60),
    );
    assert_eq!(d.status, Status::Refuted);
    assert_eq!(
        memory.observe_gated(&observe(&key, 0, Severity::Low, &s, false), None),
        Disposition::Suppressed
    );
}

/// Fuzz proti pravdivému invariantu (ne proti tomu, co brána kóduje). Stínový model sleduje
/// u klíče: byl kdy pozorován High, byl v aktivním životě pozorován chráněný, byl podezřelý nebo
/// potvrzený (do zavření klidem). Rozhodnutí žebříku nese vysoký dopad a ochranu jen z prvního
/// otevření (jako skutečný žebřík). Operace zahrnují restart (flush + load). Zavřený stav smí
/// nastat jen bez High, bez ochrany a bez zámku a jen z rozhodnutí s pozitivním důkazem.
#[test]
fn k21_true_invariant_fuzz_with_restarts_and_stale_decisions() {
    let mut state = 0x2027_0201u64;
    let mut next = |n: u64| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) % n.max(1)
    };
    let pool: Vec<String> = ["10.0.0.9", "10.0.0.66", "203.0.113.7"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut closures = 0u64;
    let mut violations: Vec<String> = Vec::new();
    for run in 0..5_000u64 {
        let mut conn = Connection::open_in_memory().unwrap();
        let mut memory = FindingMemory::load(&conn, cfg()).unwrap();
        let key = FindingKey::new("10.0.0.5", "unexpected_traffic", "tcp/80");
        // stinovy model
        let (mut ever_high, mut shield, mut lock) = (false, false, false);
        let (mut open_high, mut open_protected): (Option<bool>, Option<bool>) = (None, None);
        let mut minute = 0i64;
        for _ in 0..(4 + next(14)) {
            minute += 1 + next(90) as i64;
            let k = next(pool.len() as u64 + 1) as usize;
            let sources: Vec<String> = pool.iter().take(k).cloned().collect();
            match next(8) {
                0..=2 => {
                    let severity =
                        [Severity::Low, Severity::Medium, Severity::High][next(3) as usize];
                    let protected = next(6) == 0;
                    memory
                        .observe_gated(&observe(&key, minute, severity, &sources, protected), None);
                    ever_high |= severity == Severity::High;
                    shield |= protected;
                    open_high.get_or_insert(severity == Severity::High);
                    open_protected.get_or_insert(protected);
                }
                3 | 4 => {
                    let mut notes = vec![habit()];
                    let positive = next(2) == 0;
                    if positive {
                        notes.push(approved_context());
                    }
                    let mut d = refuted(&key, notes);
                    d.high_impact = open_high.unwrap_or(false);
                    d.protected = open_protected.unwrap_or(false);
                    let settled = settle(&mut memory, d, &sources, at(minute));
                    if settled.status == Status::Refuted {
                        closures += 1;
                        if !positive {
                            violations.push(format!("{run}: zavreno bez pozitivniho dukazu"));
                        }
                    }
                }
                5 => {
                    if memory.get(&key).is_some() {
                        memory.mark_suspected(&key, at(minute));
                        lock = true;
                    }
                }
                6 => {
                    memory.flush(&mut conn).unwrap();
                    memory = FindingMemory::load(&conn, cfg()).unwrap();
                }
                _ => {
                    let before = memory.get(&key).map(|e| e.state);
                    memory.sweep(at(minute));
                    let after = memory.get(&key).map(|e| e.state);
                    if before != after && after == Some(FindingState::Closed) {
                        // zavreni klidem konci aktivni zivot klice (zamek a ochrana)
                        lock = false;
                        shield = false;
                        open_high = None;
                        open_protected = None;
                    }
                }
            }
            if closed(&memory, &key) {
                if ever_high {
                    violations.push(format!("{run}: klic s High zavren"));
                }
                if shield {
                    violations.push(format!("{run}: chraneny klic zavren"));
                }
                if lock {
                    violations.push(format!("{run}: podezrely klic zavren"));
                }
            }
            if memory.get(&key).is_none() {
                // smazano retenci: novy zivot klice
                (ever_high, shield, lock) = (false, false, false);
            }
        }
    }
    assert!(closures > 300, "generator zavrel jen {closures}");
    let mut kinds: std::collections::BTreeMap<String, (u64, String)> = Default::default();
    for v in violations {
        let (run, what) = v.split_once(": ").unwrap();
        let slot = kinds
            .entry(what.to_string())
            .or_insert((0, run.to_string()));
        slot.0 += 1;
    }
    assert!(kinds.is_empty(), "poruseni (pocet, prvni beh): {kinds:?}");
}
