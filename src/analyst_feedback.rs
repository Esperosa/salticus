//! Zpětná vazba analytika včetně zmeškaných útoků (krok 10, impl-krok10.md, B).
//!
//! Dřív šel verdikt jen k existujícímu nálezu (`potvrzeno` / `vyvráceno`). Chyba, kterou
//! systém neviděl („tohle jsem měl vidět“), a chybná klasifikace (útok vs. porucha)
//! neměly kam jít. Záznam je tady ABSTRAKTNÍ POPIS CHOVÁNÍ (třídy tempa, objemu,
//! topologie, protokolu, taktika ATT&CK, selhaná kontrola), nikdy adresa, seed ani
//! snímek provozu: validace odmítne cokoli mimo uzavřené slovníky, takže nelze uložit
//! IP ani identifikátor sítě.
//!
//! Úložiště je append-only (SQLite triggery). Vratnost: řádek `revoke` odkazuje na
//! původní záznam, původní řádek zůstává (audit). Aktivní jsou záznamy bez odvolání.
//! Projekce do provozu je jen doporučení (`Summary`): kalibrační přirážka pro druh
//! nálezu a návrh vypnutí automatického zavírání druhu; samotné vypnutí provádí
//! stávající `closure_audit` (člověk ho vrací), tady se nic automaticky nezapíná.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SalticusError};

fn db_error(error: rusqlite::Error) -> SalticusError {
    SalticusError::Processing(format!("analyst_feedback SQLite chyba: {error}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Útok nebo porucha, kterou systém nenahlásil.
    MissedAttack,
    /// Nález byl zavřen a neměl být.
    WrongClosed,
    /// Nález byl správně zachycen, ale špatně zařazen (bezpečnostní vs. provozní).
    Misclassified,
    /// Potvrzení správného zachycení a zařazení (pro kalibraci).
    ConfirmedOk,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::MissedAttack => "missed_attack",
            Kind::WrongClosed => "wrong_closed",
            Kind::Misclassified => "misclassified",
            Kind::ConfirmedOk => "confirmed_ok",
        }
    }
}

pub const CLASSES: &[&str] = &["security", "ops_fault", "benign_change", "unknown"];
pub const PROTOS: &[&str] = &["tcp", "udp", "icmp", "other"];
pub const PORT_CLASSES: &[&str] = &[
    "web",
    "dns",
    "mail",
    "remote_admin",
    "file_share",
    "database",
    "ics",
    "iot_messaging",
    "high",
    "other",
    "none",
];
pub const TEMPOS: &[&str] = &[
    "instant",
    "burst",
    "periodic_fast",
    "periodic_slow",
    "sustained",
    "trickle",
];
pub const VOLUMES: &[&str] = &["tiny", "small", "medium", "large", "huge"];
pub const TOPOLOGIES: &[&str] = &[
    "one_to_one",
    "one_to_many",
    "many_to_one",
    "many_to_many",
    "internal_chain",
];
pub const TACTICS: &[&str] = &[
    "reconnaissance",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    "none",
];
pub const CHECKS: &[&str] = &[
    "none",
    "dns_pivot",
    "tls_fingerprint",
    "timing",
    "geo_asn",
    "host_baseline",
    "peer_compare",
    "endpoint_telemetry",
    "case_history",
    "reputation",
    "config_context",
    "repeat_measure",
    "active_read_only",
];

/// Abstraktní poučení: jen uzavřené slovníky a volitelný druh nálezu.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Lesson {
    pub kind: Kind,
    pub expected_class: String,
    pub observed_class: String,
    /// Druh nálezu (např. `beacon_periodic`), pokud existoval; jen `[a-z0-9_:]`.
    pub finding_type: Option<String>,
    pub tactic: String,
    pub proto: String,
    pub port_class: String,
    pub tempo: String,
    pub volume: String,
    pub topology: String,
    /// Počet zdrojů: 1, 2-5, 6+ (třídy `1`, `few`, `many`).
    pub sources: String,
    pub failed_check: String,
}

fn one_of(value: &str, allowed: &[&str], field: &str) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(SalticusError::Processing(format!(
            "pole {field} mimo slovnik"
        )))
    }
}

impl Lesson {
    /// Uzavřené slovníky: nelze uložit adresu, seed ani volný text.
    pub fn validate(&self) -> Result<()> {
        one_of(&self.expected_class, CLASSES, "expected_class")?;
        one_of(&self.observed_class, CLASSES, "observed_class")?;
        one_of(&self.tactic, TACTICS, "tactic")?;
        one_of(&self.proto, PROTOS, "proto")?;
        one_of(&self.port_class, PORT_CLASSES, "port_class")?;
        one_of(&self.tempo, TEMPOS, "tempo")?;
        one_of(&self.volume, VOLUMES, "volume")?;
        one_of(&self.topology, TOPOLOGIES, "topology")?;
        one_of(&self.sources, &["1", "few", "many"], "sources")?;
        one_of(&self.failed_check, CHECKS, "failed_check")?;
        if let Some(kind) = &self.finding_type
            && (kind.is_empty()
                || kind.len() > 64
                || !kind.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b':'
                }))
        {
            return Err(SalticusError::Processing(
                "finding_type ma neplatny tvar".into(),
            ));
        }
        Ok(())
    }

    /// Klíč shluku: všechny rysy chování kromě druhu a třídy zachycení.
    pub fn behaviour_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.tactic,
            self.proto,
            self.port_class,
            self.tempo,
            self.volume,
            self.topology,
            self.sources
        )
    }
}

/// Třída portu (jen pro abstrakci; číslo portu se neukládá).
pub fn port_class(proto: &str, port: u16) -> &'static str {
    if proto == "icmp" {
        return "none";
    }
    match port {
        80 | 443 | 8080 | 8443 => "web",
        53 | 853 => "dns",
        25 | 110 | 143 | 465 | 587 | 993 | 995 => "mail",
        22 | 23 | 3389 | 5900 | 5985 | 5986 => "remote_admin",
        139 | 445 | 21 | 2049 => "file_share",
        1433 | 1521 | 3306 | 5432 | 6379 | 27017 => "database",
        102 | 502 | 20000 | 44818 | 47808 | 4840 => "ics",
        1883 | 8883 | 5683 => "iot_messaging",
        1024..=65535 => "high",
        _ => "other",
    }
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS analyst_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at INTEGER NOT NULL,
            action TEXT NOT NULL,
            ref_id INTEGER,
            actor TEXT NOT NULL,
            lesson TEXT,
            note TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS analyst_feedback_no_update BEFORE UPDATE ON analyst_feedback
        BEGIN SELECT RAISE(ABORT, 'analyst_feedback je append-only'); END;
        CREATE TRIGGER IF NOT EXISTS analyst_feedback_no_delete BEFORE DELETE ON analyst_feedback
        BEGIN SELECT RAISE(ABORT, 'analyst_feedback je append-only'); END;",
    )
    .map_err(db_error)
}

/// Přidá poučení (po validaci). Volný text se omezí na 500 znaků a do učení nejde.
pub fn submit(
    conn: &Connection,
    lesson: &Lesson,
    actor: &str,
    note: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<i64> {
    lesson.validate()?;
    migrate(conn)?;
    let json = serde_json::to_string(lesson)
        .map_err(|e| SalticusError::Processing(format!("serializace poucení: {e}")))?;
    conn.execute(
        "INSERT INTO analyst_feedback (at, action, ref_id, actor, lesson, note)
         VALUES (?1, 'add', NULL, ?2, ?3, ?4)",
        params![
            at.timestamp(),
            actor,
            json,
            note.chars().take(500).collect::<String>()
        ],
    )
    .map_err(db_error)?;
    Ok(conn.last_insert_rowid())
}

/// Odvolání záznamu (vratnost). Původní řádek zůstává. Vrací `false`, když záznam
/// neexistuje nebo už je odvolaný.
pub fn revoke(
    conn: &Connection,
    id: i64,
    actor: &str,
    note: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    migrate(conn)?;
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM analyst_feedback WHERE id = ?1 AND action = 'add'
             AND NOT EXISTS (SELECT 1 FROM analyst_feedback r WHERE r.action = 'revoke' AND r.ref_id = ?1)",
            params![id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if exists == 0 {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO analyst_feedback (at, action, ref_id, actor, lesson, note)
         VALUES (?1, 'revoke', ?2, ?3, NULL, ?4)",
        params![
            at.timestamp(),
            id,
            actor,
            note.chars().take(500).collect::<String>()
        ],
    )
    .map_err(db_error)?;
    Ok(true)
}

/// Aktivní (neodvolaná) poučení v pořadí vzniku.
pub fn active(conn: &Connection) -> Result<Vec<(i64, Lesson)>> {
    migrate(conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, lesson FROM analyst_feedback a WHERE action = 'add'
             AND NOT EXISTS (SELECT 1 FROM analyst_feedback r WHERE r.action = 'revoke' AND r.ref_id = a.id)
             ORDER BY id",
        )
        .map_err(db_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(db_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, json) = row.map_err(db_error)?;
        if let Ok(lesson) = serde_json::from_str::<Lesson>(&json)
            && lesson.validate().is_ok()
        {
            out.push((id, lesson));
        }
    }
    Ok(out)
}

/// Projekce poučení do provozu (jen doporučení, žádné automatické zapnutí).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub missed: usize,
    pub wrong_closed: usize,
    pub misclassified: usize,
    pub confirmed_ok: usize,
    /// Druhy nálezů, u kterých se doporučuje zakázat automatické zavření
    /// (aspoň `DISABLE_AT` omylem zavřených).
    pub disable_auto_close: Vec<String>,
    /// Kalibrační přirážka nejistoty druhu (≥ 1; 1 = beze změny).
    pub uncertainty_boost: Vec<(String, f64)>,
}

pub const DISABLE_AT: usize = 3;

pub fn summarize(lessons: &[Lesson]) -> Summary {
    let mut s = Summary::default();
    let mut wrong: std::collections::BTreeMap<String, usize> = Default::default();
    let mut mis: std::collections::BTreeMap<String, usize> = Default::default();
    for l in lessons {
        match l.kind {
            Kind::MissedAttack => s.missed += 1,
            Kind::WrongClosed => {
                s.wrong_closed += 1;
                if let Some(t) = &l.finding_type {
                    *wrong.entry(t.clone()).or_default() += 1;
                }
            }
            Kind::Misclassified => {
                s.misclassified += 1;
                if let Some(t) = &l.finding_type {
                    *mis.entry(t.clone()).or_default() += 1;
                }
            }
            Kind::ConfirmedOk => s.confirmed_ok += 1,
        }
    }
    s.disable_auto_close = wrong
        .iter()
        .filter(|(_, n)| **n >= DISABLE_AT)
        .map(|(t, _)| t.clone())
        .collect();
    let mut kinds: std::collections::BTreeSet<&String> = wrong.keys().collect();
    kinds.extend(mis.keys());
    s.uncertainty_boost = kinds
        .into_iter()
        .map(|t| {
            let n = wrong.get(t).copied().unwrap_or(0) + mis.get(t).copied().unwrap_or(0);
            (t.clone(), 1.0 + 0.25 * n.min(8) as f64)
        })
        .collect();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn lesson(kind: Kind, finding: Option<&str>) -> Lesson {
        Lesson {
            kind,
            expected_class: "security".into(),
            observed_class: "unknown".into(),
            finding_type: finding.map(str::to_string),
            tactic: "command-and-control".into(),
            proto: "tcp".into(),
            port_class: "web".into(),
            tempo: "periodic_slow".into(),
            volume: "tiny".into(),
            topology: "one_to_one".into(),
            sources: "1".into(),
            failed_check: "tls_fingerprint".into(),
        }
    }

    fn conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn rejects_addresses_and_free_text_in_fields() {
        let mut l = lesson(Kind::MissedAttack, None);
        l.tempo = "10.0.0.5".into();
        assert!(l.validate().is_err());
        let mut l = lesson(Kind::MissedAttack, None);
        l.port_class = "20261102".into();
        assert!(l.validate().is_err());
        let l = lesson(Kind::WrongClosed, Some("beacon periodic; DROP"));
        assert!(l.validate().is_err());
        assert!(
            lesson(Kind::WrongClosed, Some("beacon_periodic"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn append_only_and_revocable() {
        let c = conn();
        let id = submit(
            &c,
            &lesson(Kind::MissedAttack, None),
            "ana",
            "poznamka",
            Utc::now(),
        )
        .unwrap();
        assert!(c.execute("DELETE FROM analyst_feedback", []).is_err());
        assert!(
            c.execute("UPDATE analyst_feedback SET note='x'", [])
                .is_err()
        );
        assert_eq!(active(&c).unwrap().len(), 1);
        assert!(revoke(&c, id, "ana", "omyl", Utc::now()).unwrap());
        assert!(!revoke(&c, id, "ana", "podruhe", Utc::now()).unwrap());
        assert!(active(&c).unwrap().is_empty());
        // puvodni radek zustava pro audit
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM analyst_feedback", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn summary_recommends_disable_only_from_repeated_wrong_closures() {
        let mut v = Vec::new();
        for _ in 0..2 {
            v.push(lesson(Kind::WrongClosed, Some("beacon_periodic")));
        }
        assert!(summarize(&v).disable_auto_close.is_empty());
        v.push(lesson(Kind::WrongClosed, Some("beacon_periodic")));
        let s = summarize(&v);
        assert_eq!(s.disable_auto_close, vec!["beacon_periodic".to_string()]);
        assert!(s.uncertainty_boost[0].1 > 1.0);
        // chybějící nález (zmeškaný útok) nikoho nevypíná
        let missed = vec![lesson(Kind::MissedAttack, None); 10];
        assert!(summarize(&missed).disable_auto_close.is_empty());
    }

    #[test]
    fn port_classes_cover_common_services() {
        assert_eq!(port_class("tcp", 443), "web");
        assert_eq!(port_class("tcp", 502), "ics");
        assert_eq!(port_class("icmp", 0), "none");
        assert_eq!(port_class("udp", 53), "dns");
    }
}
