//! Ruční zásahy analytika do seskupení incidentů (krok 38, K14).
//!
//! Dva druhy: `link` (nálezy `a` a `b` patří do jednoho incidentu) a `detach` (nález `a` do
//! incidentu nepatří). Zásahy se ukládají append-only (odvolání je nový řádek, původní zůstává
//! pro audit) a přežijí restart i přepočet incidentů. Mění **jen seskupení**: nikdy ne
//! závažnost, stav ani zavření nálezu, takže nemůžou zavřít chráněný nález.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, SalticusError},
    retro::Incident,
};

fn db_error(error: rusqlite::Error) -> SalticusError {
    SalticusError::Processing(format!("incident_overrides SQLite chyba: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Override {
    Link { a: String, b: String },
    Detach { a: String },
}

/// Identifikátor nálezu: neprázdný, rozumně dlouhý, bez řídicích znaků (ochrana databáze).
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control)
}

fn validate(over: &Override) -> Result<()> {
    let ok = match over {
        Override::Link { a, b } => valid_id(a) && valid_id(b) && a != b,
        Override::Detach { a } => valid_id(a),
    };
    if ok {
        Ok(())
    } else {
        Err(SalticusError::Processing(
            "incident_overrides: neplatný identifikátor nálezu".into(),
        ))
    }
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS incident_overrides (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            body TEXT NOT NULL,
            actor TEXT NOT NULL,
            note TEXT NOT NULL,
            at TEXT NOT NULL,
            revokes INTEGER
        );
        CREATE TRIGGER IF NOT EXISTS incident_overrides_no_update
            BEFORE UPDATE ON incident_overrides BEGIN SELECT RAISE(ABORT, 'append-only'); END;
        CREATE TRIGGER IF NOT EXISTS incident_overrides_no_delete
            BEFORE DELETE ON incident_overrides BEGIN SELECT RAISE(ABORT, 'append-only'); END;",
    )
    .map_err(db_error)
}

pub fn submit(
    conn: &Connection,
    over: &Override,
    actor: &str,
    note: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<i64> {
    migrate(conn)?;
    validate(over)?;
    let body = serde_json::to_string(over).map_err(SalticusError::Json)?;
    conn.execute(
        "INSERT INTO incident_overrides (body, actor, note, at, revokes) VALUES (?1, ?2, ?3, ?4, NULL)",
        params![body, actor, note, at.to_rfc3339()],
    )
    .map_err(db_error)?;
    Ok(conn.last_insert_rowid())
}

/// Odvolá zásah (nový řádek); `false`, když neexistuje nebo už je odvolaný.
pub fn revoke(
    conn: &Connection,
    id: i64,
    actor: &str,
    note: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    migrate(conn)?;
    let live: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incident_overrides o WHERE o.id = ?1 AND o.revokes IS NULL
             AND NOT EXISTS (SELECT 1 FROM incident_overrides r WHERE r.revokes = o.id)",
            params![id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if live == 0 {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO incident_overrides (body, actor, note, at, revokes) VALUES ('{}', ?1, ?2, ?3, ?4)",
        params![actor, note, at.to_rfc3339(), id],
    )
    .map_err(db_error)?;
    Ok(true)
}

/// Aktivní zásahy (neodvolané) v pořadí vzniku.
pub fn active(conn: &Connection) -> Result<Vec<(i64, Override)>> {
    migrate(conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT o.id, o.body FROM incident_overrides o
             WHERE o.revokes IS NULL
             AND NOT EXISTS (SELECT 1 FROM incident_overrides r WHERE r.revokes = o.id)
             ORDER BY o.id",
        )
        .map_err(db_error)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .map_err(db_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, body) = row.map_err(db_error)?;
        if let Ok(o) = serde_json::from_str::<Override>(&body) {
            out.push((id, o));
        }
    }
    Ok(out)
}

/// Uplatní zásahy na hotové incidenty: `detach` odebere nález z incidentu, `link` slije incidenty
/// obsahující oba nálezy. Incident s jediným nálezem po zásahu zaniká (není incident).
pub fn apply(incidents: &mut Vec<Incident>, overrides: &[Override]) {
    for o in overrides {
        match o {
            Override::Detach { a } => {
                for inc in incidents.iter_mut() {
                    inc.findings.retain(|f| f != a);
                    // hrany odpojeného nálezu zanikají; zbylé hrany zůstanou (kostra může být
                    // nesouvislá, důvod hrany se neumyslně nevymýšlí)
                    inc.links.retain(|l| l.a != *a && l.b != *a);
                }
            }
            Override::Link { a, b } => {
                let ia = incidents.iter().position(|i| i.findings.contains(a));
                let ib = incidents.iter().position(|i| i.findings.contains(b));
                if let (Some(x), Some(y)) = (ia, ib)
                    && x != y
                {
                    let (keep, drop) = if x < y { (x, y) } else { (y, x) };
                    let moved = incidents.remove(drop);
                    let target = &mut incidents[keep];
                    target.links.extend(moved.links);
                    target.links.push(crate::retro::Link {
                        a: a.clone(),
                        b: b.clone(),
                        rule: "manual".into(),
                        via: "zásah analytika".into(),
                        dt_s: 0,
                    });
                    for f in moved.findings {
                        if !target.findings.contains(&f) {
                            target.findings.push(f);
                        }
                    }
                    for h in moved.hosts {
                        if !target.hosts.contains(&h) {
                            target.hosts.push(h);
                        }
                    }
                    target.first_ts = target.first_ts.min(moved.first_ts);
                    target.last_ts = target.last_ts.max(moved.last_ts);
                    for p in moved.phases {
                        if !target.phases.contains(&p) {
                            target.phases.push(p);
                        }
                    }
                }
            }
        }
    }
    incidents.retain(|i| i.findings.len() > 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retro::Cause;

    fn inc(fs: &[&str]) -> Incident {
        Incident {
            id: 0,
            findings: fs.iter().map(|f| f.to_string()).collect(),
            hosts: vec![],
            first_ts: 0,
            last_ts: 1,
            phases: vec![],
            cause: Cause::Attack,
            first_finding: fs[0].to_string(),
            key: String::new(),
            related: vec![],
            links: Vec::new(),
        }
    }

    #[test]
    fn link_and_detach_change_only_grouping() {
        let mut v = vec![inc(&["a", "b"]), inc(&["c", "d", "e"])];
        apply(
            &mut v,
            &[Override::Link {
                a: "b".into(),
                b: "c".into(),
            }],
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].findings.len(), 5);
        apply(&mut v, &[Override::Detach { a: "a".into() }]);
        assert_eq!(v[0].findings.len(), 4);
        // incident s jedním nálezem zaniká
        let mut w = vec![inc(&["x", "y"])];
        apply(&mut w, &[Override::Detach { a: "x".into() }]);
        assert!(w.is_empty());
    }

    #[test]
    fn overrides_are_append_only_and_revocable() {
        let conn = Connection::open_in_memory().unwrap();
        let at = chrono::Utc::now();
        let id = submit(
            &conn,
            &Override::Detach { a: "f1".into() },
            "analytik",
            "chyba",
            at,
        )
        .unwrap();
        assert_eq!(active(&conn).unwrap().len(), 1);
        assert!(conn.execute("DELETE FROM incident_overrides", []).is_err());
        assert!(
            conn.execute("UPDATE incident_overrides SET note = 'x'", [])
                .is_err()
        );
        assert!(revoke(&conn, id, "analytik", "omyl", at).unwrap());
        assert!(active(&conn).unwrap().is_empty());
        assert!(
            !revoke(&conn, id, "analytik", "znovu", at).unwrap(),
            "druhé odvolání nic nedělá"
        );
    }

    #[test]
    fn manual_link_keeps_spanning_links_and_ids_are_validated() {
        let mut v = vec![inc(&["a", "b"]), inc(&["c", "d"])];
        v[0].links.push(crate::retro::Link {
            a: "a".into(),
            b: "b".into(),
            rule: "pair".into(),
            via: "x".into(),
            dt_s: 1,
        });
        v[1].links.push(crate::retro::Link {
            a: "c".into(),
            b: "d".into(),
            rule: "pair".into(),
            via: "y".into(),
            dt_s: 1,
        });
        apply(
            &mut v,
            &[Override::Link {
                a: "b".into(),
                b: "c".into(),
            }],
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].links.len(), 3, "kostra: 4 nálezů, 3 hrany");
        assert!(v[0].links.iter().any(|l| l.rule == "manual"));
        let conn = Connection::open_in_memory().unwrap();
        let at = chrono::Utc::now();
        assert!(submit(&conn, &Override::Detach { a: String::new() }, "x", "", at).is_err());
        assert!(
            submit(
                &conn,
                &Override::Link {
                    a: "z".into(),
                    b: "z".into()
                },
                "x",
                "",
                at
            )
            .is_err()
        );
        assert!(submit(&conn, &Override::Detach { a: "a\nb".into() }, "x", "", at).is_err());
    }
}
