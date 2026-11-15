//! Perzistence provozních signálů v `engine-state.sqlite` (krok 14, C2).
//!
//! Příjem (CLI `ops ingest`, REST `POST /api/ops/ingest`) jen parsuje, omezuje a ukládá.
//! Každá přijatá dávka je zároveň heartbeat zdrojů formátu (i když neobsahuje žádný signál):
//! zdroj, který dávky posílá a nic nehlásí, je živý; zdroj bez dávek je tichý.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use super::{
    OpsSignal, OpsSource, OpsStore,
    adapters::{self, Format},
};
use crate::error::{Result, SalticusError};

pub const MAX_ROWS: i64 = 200_000;
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_AGE_S: i64 = 24 * 3600;
pub const MAX_FUTURE_S: i64 = 3600;

fn db_error(error: rusqlite::Error) -> SalticusError {
    SalticusError::Processing(format!("ops_signals SQLite chyba: {error}"))
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ops_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fp TEXT NOT NULL UNIQUE,
            ts INTEGER NOT NULL,
            received INTEGER NOT NULL,
            body TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ops_signals_ts ON ops_signals (ts);
        CREATE TABLE IF NOT EXISTS ops_sources (
            source TEXT PRIMARY KEY,
            last_seen INTEGER NOT NULL
        );",
    )
    .map_err(db_error)
}

/// Zdroje, které formát pokrývá (heartbeat při přijetí dávky).
pub fn sources_of(format: Format) -> &'static [OpsSource] {
    match format {
        Format::Syslog => &[OpsSource::Syslog],
        Format::Snmp => &[OpsSource::Snmp],
        Format::Prometheus => &[OpsSource::Snmp, OpsSource::Probe],
        Format::Nagios => &[OpsSource::Probe],
        Format::Dhcp => &[OpsSource::Dhcp],
        Format::Arp => &[OpsSource::Arp],
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IngestSummary {
    pub lines: usize,
    pub signals: usize,
    pub stored: usize,
    pub duplicates: usize,
    pub rejected: usize,
    pub truncated: bool,
}

fn fingerprint(s: &OpsSignal) -> String {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h = (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3);
        }
    };
    feed(&s.at.to_le_bytes());
    feed(s.key.as_bytes());
    for t in &s.scope {
        feed(t.as_bytes());
    }
    format!("{h:016x}")
}

pub fn ingest_text(
    conn: &mut Connection,
    format: Format,
    text: &str,
    now: DateTime<Utc>,
) -> Result<IngestSummary> {
    migrate(conn)?;
    let mut summary = IngestSummary::default();
    let text = if text.len() > MAX_BATCH_BYTES {
        summary.truncated = true;
        let mut cut = MAX_BATCH_BYTES;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        &text[..cut]
    } else {
        text
    };
    summary.lines = text.lines().count();
    let now_s = now.timestamp();
    let signals = adapters::parse_lines(format, text, now_s);
    summary.signals = signals.len();
    let tx = conn.transaction().map_err(db_error)?;
    {
        let mut stmt = tx
            .prepare(
                "INSERT OR IGNORE INTO ops_signals (fp, ts, received, body) VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(db_error)?;
        for s in &signals {
            if s.at > now_s + MAX_FUTURE_S || s.at < now_s - MAX_AGE_S {
                summary.rejected += 1;
                continue;
            }
            // stejné meze jako sklad: neplatný klíč nebo hodnota se odmítne už tady
            let mut probe = OpsStore::default();
            if !probe.ingest(s.clone(), now_s) {
                summary.rejected += 1;
                continue;
            }
            let body = serde_json::to_string(s).map_err(SalticusError::Json)?;
            let changed = stmt
                .execute(params![fingerprint(s), s.at, now_s, body])
                .map_err(db_error)?;
            if changed == 0 {
                summary.duplicates += 1;
            } else {
                summary.stored += 1;
            }
        }
        // každá přijatá dávka je heartbeat zdrojů formátu
        for src in sources_of(format) {
            tx.execute(
                "INSERT INTO ops_sources (source, last_seen) VALUES (?1, ?2)
                 ON CONFLICT(source) DO UPDATE SET last_seen = MAX(last_seen, ?2)",
                params![src.label(), now_s],
            )
            .map_err(db_error)?;
        }
    }
    tx.execute(
        "DELETE FROM ops_signals WHERE ts < ?1",
        params![now_s - MAX_AGE_S],
    )
    .map_err(db_error)?;
    tx.execute(
        "DELETE FROM ops_signals WHERE id <= (SELECT MAX(id) FROM ops_signals) - ?1",
        params![MAX_ROWS],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(summary)
}

/// Sklad pro běh enginu: poslední signály a heartbeaty zdrojů.
pub fn load_store(conn: &Connection, now: DateTime<Utc>) -> Result<OpsStore> {
    migrate(conn)?;
    let now_s = now.timestamp();
    let mut store = OpsStore::default();
    let mut stmt = conn
        .prepare("SELECT body FROM ops_signals WHERE ts >= ?1 ORDER BY ts LIMIT ?2")
        .map_err(db_error)?;
    let rows = stmt
        .query_map(params![now_s - MAX_AGE_S, MAX_ROWS], |r| {
            r.get::<_, String>(0)
        })
        .map_err(db_error)?;
    for row in rows {
        let body = row.map_err(db_error)?;
        if let Ok(s) = serde_json::from_str::<OpsSignal>(&body) {
            store.ingest(s, now_s);
        }
    }
    let mut stmt = conn
        .prepare("SELECT source, last_seen FROM ops_sources")
        .map_err(db_error)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(db_error)?;
    for row in rows {
        let (name, at) = row.map_err(db_error)?;
        if let Some(src) = OpsSource::ALL.iter().find(|s| s.label() == name) {
            store.heartbeat(*src, at);
        }
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_is_idempotent_bounded_and_marks_sources_alive() {
        let mut conn = Connection::open_in_memory().unwrap();
        let now = DateTime::parse_from_rfc3339("2026-11-15T10:05:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let text = "<189>Nov 15 10:00:01 sw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\nsmetí\n";
        let a = ingest_text(&mut conn, Format::Syslog, text, now).unwrap();
        assert_eq!((a.signals, a.stored), (1, 1), "{a:?}");
        let b = ingest_text(&mut conn, Format::Syslog, text, now).unwrap();
        assert_eq!((b.stored, b.duplicates), (0, 1));
        let store = load_store(&conn, now).unwrap();
        assert_eq!(store.len(), 1);
        let silent = store.silent_sources(now.timestamp());
        assert!(!silent.contains(&OpsSource::Syslog));
        assert!(silent.contains(&OpsSource::Dhcp));
        // dávka bez signálu je dál heartbeat
        let c = ingest_text(&mut conn, Format::Dhcp, "nic zajimaveho\n", now).unwrap();
        assert_eq!(c.signals, 0);
        let store = load_store(&conn, now).unwrap();
        assert!(
            !store
                .silent_sources(now.timestamp())
                .contains(&OpsSource::Dhcp)
        );
        // dávný signál se odmítne
        let later = now + chrono::Duration::days(3);
        let dated = "<34>1 2026-11-15T10:00:00Z db1 postgres - - - FATAL: too many open files\n";
        let d = ingest_text(&mut conn, Format::Syslog, dated, later).unwrap();
        assert_eq!((d.stored, d.rejected), (0, 1));
    }
}
