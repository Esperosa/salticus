//! Čtení souborů EVTX (Windows Event Log) produkční cestou: soubor -> JSON záznam -> adaptér
//! (`sysmon`) -> `EndpointEvent` (krok 14, A; reálná data EVTX-ATTACK-SAMPLES).
//!
//! Parser binárního XML je crate `evtx` (MIT/Apache-2.0, omerbenamram/EVTX). Soubor je
//! nedůvěryhodný vstup: velikost ≤ 64 MiB, záznamů nejvýš 200 000, chybný záznam se přeskočí a
//! spočítá, nikdy panika (parser běží uvnitř `catch_unwind`).

use std::path::Path;

use super::{EndpointEvent, ParseError, sysmon};

pub const MAX_FILE: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 200_000;

/// Souhrn čtení jednoho souboru.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvtxSummary {
    pub records: usize,
    /// Záznamy, které adaptér přeložil na událost.
    pub parsed: usize,
    /// Záznamy s ID, které adaptér nepodporuje (ne chyba).
    pub unsupported: usize,
    /// Poškozené záznamy nebo záznamy bez povinných polí.
    pub errors: usize,
    /// Počty podle EventID (řazeno podle ID).
    pub by_id: std::collections::BTreeMap<u32, usize>,
    /// První chyby adaptéru (nejvýš 5; pro diagnostiku).
    pub first_errors: Vec<String>,
}

/// Přečte soubor EVTX a vrátí události a souhrn. `host_override` doplní hostitele, když záznam
/// nemá `Computer` (u vzorků je vždy).
pub fn read_file(path: &Path) -> Result<(Vec<EndpointEvent>, EvtxSummary), ParseError> {
    let meta = std::fs::metadata(path).map_err(|e| ParseError(format!("EVTX: {e}")))?;
    if meta.len() > MAX_FILE {
        return Err(ParseError(format!(
            "EVTX: soubor {} B je nad limit {MAX_FILE}",
            meta.len()
        )));
    }
    let data = std::fs::read(path).map_err(|e| ParseError(format!("EVTX: {e}")))?;
    read_bytes(&data)
}

pub fn read_bytes(data: &[u8]) -> Result<(Vec<EndpointEvent>, EvtxSummary), ParseError> {
    if data.len() as u64 > MAX_FILE {
        return Err(ParseError("EVTX: soubor je nad limit".into()));
    }
    let owned = data.to_vec();
    // parser je cizí kód nad nedůvěryhodným vstupem: panika se změní na chybu
    let result = std::panic::catch_unwind(move || {
        let mut out: Vec<String> = Vec::new();
        let mut parser = evtx::EvtxParser::from_buffer(owned)
            .map_err(|e| ParseError(format!("EVTX: hlavička: {e}")))?;
        let mut bad = 0usize;
        for record in parser.records_json() {
            if out.len() >= MAX_RECORDS {
                break;
            }
            match record {
                Ok(r) => out.push(r.data),
                Err(_) => bad += 1,
            }
        }
        Ok::<_, ParseError>((out, bad))
    });
    let (records, bad) = match result {
        Ok(r) => r?,
        Err(_) => {
            return Err(ParseError(
                "EVTX: parser selhal na poškozeném souboru".into(),
            ));
        }
    };
    let mut summary = EvtxSummary {
        records: records.len() + bad,
        errors: bad,
        ..Default::default()
    };
    let mut events = Vec::new();
    for json in &records {
        if let Some(id) = event_id(json) {
            *summary.by_id.entry(id).or_default() += 1;
        }
        let map = match serde_json::from_str::<serde_json::Value>(json) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => {
                summary.errors += 1;
                continue;
            }
        };
        match sysmon::parse(&map) {
            Ok(Some(e)) => {
                summary.parsed += 1;
                events.push(e);
            }
            Ok(None) => summary.unsupported += 1,
            Err(e) => {
                summary.errors += 1;
                if summary.first_errors.len() < 5 {
                    summary.first_errors.push(e.0);
                }
            }
        }
    }
    Ok((events, summary))
}

/// EventID z JSON záznamu (číslo nebo objekt s `#text`).
fn event_id(json: &str) -> Option<u32> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let id = v.pointer("/Event/System/EventID")?;
    id.as_u64()
        .or_else(|| id.pointer("/#text").and_then(|t| t.as_u64()))
        .or_else(|| id.as_str().and_then(|s| s.trim().parse().ok()))
        .map(|n| n as u32)
}

/// Výsledek přehrání jednoho souboru produkční cestou (evtx -> adaptér -> sklad -> verdikt -> graf).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplayFile {
    pub file: String,
    pub records: usize,
    pub parsed: usize,
    pub unsupported: usize,
    pub errors: usize,
    pub by_id: std::collections::BTreeMap<u32, usize>,
    pub hosts: Vec<String>,
    /// Skóre verdiktu a kódy indikátorů nejvyššího hosta.
    pub score: u32,
    pub indicators: Vec<String>,
    /// Verdikt by vyústil v nález `endpoint_alert` (host je podezřelý a pokrytý).
    pub would_alert: bool,
    pub graph_nodes: usize,
    pub graph_edges: usize,
}

/// Přehraje soubory EVTX: čas „teď“ se klade za poslední událost, aby stáří nebylo důvod odmítnutí.
pub fn replay(files: &[std::path::PathBuf], extended: bool) -> Vec<Result<ReplayFile, String>> {
    use super::correlate::{
        EndpointStore, EndpointView, HostDirectory, Limits, Policy, Resolution,
    };
    files
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let (events, summary) = read_file(path).map_err(|e| format!("{name}: {}", e.0))?;
            let now = events.iter().map(|e| e.ts).max().unwrap_or(0) + 1;
            let mut dir = HostDirectory::default();
            let mut store = EndpointStore::new(Limits {
                max_per_host_cycle: u32::MAX / 2,
                ..Limits::default()
            });
            let mut hosts: std::collections::BTreeSet<String> = Default::default();
            for e in &events {
                if let Some(h) = &e.host.hostname {
                    hosts.insert(h.clone());
                    dir.add(h, Some(h), &[], None);
                }
            }
            for e in events {
                let res = match &e.host.hostname {
                    Some(h) => Resolution::Unique(h.clone()),
                    None => Resolution::Unknown,
                };
                store.ingest(e, &res, now);
            }
            let mut policy = Policy::default();
            policy.extended = extended;
            policy.lookback_s = 10 * 365 * 86_400;
            policy.alive_s = 10 * 365 * 86_400;
            let view = EndpointView::build(&store, &dir, now, &policy);
            let best = hosts
                .iter()
                .filter_map(|h| view.assessment(h))
                .max_by_key(|a| a.score);
            let host_list: Vec<String> = hosts.iter().cloned().collect();
            let graph = super::graph::Graph::build(
                &store,
                &host_list,
                0,
                now,
                &super::graph::Privacy::default(),
            );
            Ok(ReplayFile {
                file: name,
                records: summary.records,
                parsed: summary.parsed,
                unsupported: summary.unsupported,
                errors: summary.errors,
                by_id: summary.by_id,
                hosts: host_list,
                score: best.map_or(0, |a| a.score),
                indicators: best
                    .map(|a| a.indicators.iter().map(|i| i.code.to_string()).collect())
                    .unwrap_or_default(),
                would_alert: !view.suspicious_hosts().is_empty(),
                graph_nodes: graph.nodes.len(),
                graph_edges: graph.edges.len(),
            })
        })
        .collect()
}

/// Přehrání JSON řádků (OTRF Security-Datasets, winlogbeat) po hodinových oknech na hosta.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplayWindows {
    pub file: String,
    pub lines: usize,
    pub parsed: usize,
    pub unsupported: usize,
    pub errors: usize,
    /// Počty podle druhu události po překladu.
    pub kinds: std::collections::BTreeMap<String, usize>,
    pub hosts: Vec<String>,
    pub windows_total: usize,
    pub windows_alert: usize,
    /// Kódy indikátorů -> počet oken, kde se objevily.
    pub indicators: std::collections::BTreeMap<String, usize>,
    /// První a poslední událost a první okno s výstrahou (epocha).
    pub first_event: i64,
    pub first_alert_window: Option<i64>,
}

pub fn replay_jsonl(
    path: &std::path::Path,
    format: super::Format,
    extended: bool,
    window_s: i64,
    graph_out: Option<&std::path::Path>,
) -> Result<ReplayWindows, String> {
    use super::correlate::{Policy, assess};
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let meta = std::fs::metadata(path).map_err(|e| format!("{name}: {e}"))?;
    if meta.len() > 256 * 1024 * 1024 {
        return Err(format!("{name}: soubor je nad limit 256 MiB"));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
    let mut out = ReplayWindows {
        file: name,
        lines: 0,
        parsed: 0,
        unsupported: 0,
        errors: 0,
        kinds: Default::default(),
        hosts: Vec::new(),
        windows_total: 0,
        windows_alert: 0,
        indicators: Default::default(),
        first_event: 0,
        first_alert_window: None,
    };
    let mut by_host: std::collections::BTreeMap<String, Vec<EndpointEvent>> = Default::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.len() > 64 * 1024 {
            continue;
        }
        out.lines += 1;
        match format.parse_line(line) {
            Ok(Some(e)) => {
                out.parsed += 1;
                *out.kinds.entry(e.kind.label().to_string()).or_default() += 1;
                let host = e.host.hostname.clone().unwrap_or_default();
                by_host.entry(host).or_default().push(e);
            }
            Ok(None) => out.unsupported += 1,
            Err(_) => out.errors += 1,
        }
    }
    let mut policy = Policy::default();
    policy.extended = extended;
    policy.lookback_s = window_s;
    out.hosts = by_host.keys().cloned().collect();
    out.first_event = by_host
        .values()
        .flat_map(|v| v.iter().map(|e| e.ts))
        .min()
        .unwrap_or(0);
    for (host, events) in &mut by_host {
        events.sort_by_key(|e| e.ts);
        let (Some(first), Some(last)) = (events.first().map(|e| e.ts), events.last().map(|e| e.ts))
        else {
            continue;
        };
        let mut w = first - first.rem_euclid(window_s);
        while w <= last {
            let slice: Vec<&EndpointEvent> = events
                .iter()
                .filter(|e| e.ts >= w && e.ts < w + window_s)
                .collect();
            out.windows_total += 1;
            if !slice.is_empty() {
                let a = assess(host, slice.iter().copied(), w + window_s - 1, &policy);
                if a.suspicious(&policy) {
                    out.windows_alert += 1;
                    out.first_alert_window = Some(out.first_alert_window.map_or(w, |f| f.min(w)));
                    let mut seen: std::collections::BTreeSet<&str> = Default::default();
                    for i in &a.indicators {
                        if seen.insert(i.code) {
                            *out.indicators.entry(i.code.to_string()).or_default() += 1;
                        }
                    }
                }
            }
            w += window_s;
        }
    }
    // graf okna s prvním nálezem (kauzální řetěz, uživatelé pseudonymizovaní)
    if let (Some(path), Some(w)) = (graph_out, out.first_alert_window) {
        use super::correlate::{EndpointStore, Limits, Resolution};
        let mut store = EndpointStore::new(Limits {
            max_per_host_cycle: u32::MAX / 2,
            max_events_per_host: 200_000,
            ..Limits::default()
        });
        let hosts: Vec<String> = by_host.keys().cloned().collect();
        for (host, events) in &by_host {
            for e in events.iter().filter(|e| e.ts >= w && e.ts < w + window_s) {
                store.ingest(e.clone(), &Resolution::Unique(host.clone()), w + window_s);
            }
        }
        let g = super::graph::Graph::build(
            &store,
            &hosts,
            w,
            w + window_s,
            &super::graph::Privacy::default(),
        );
        let json = serde_json::to_string_pretty(&g).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset(name: &str) -> Option<std::path::PathBuf> {
        let root = std::env::var("SALTICUS_EXTERNAL_DATASETS")
            .unwrap_or_else(|_| "F:/Projekty/bakula-datasets".into());
        let p = std::path::Path::new(&root)
            .join("evtx-attack-samples")
            .join(name);
        p.exists().then_some(p)
    }

    #[test]
    fn garbage_and_truncated_files_are_errors_not_panics() {
        assert!(read_bytes(b"not an evtx file").is_err());
        assert!(read_bytes(&[]).is_err());
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..200 {
            let n = (x % 4096) as usize;
            let mut data: Vec<u8> = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            if data.len() > 8 {
                data[..8].copy_from_slice(b"ElfFile\0");
            }
            let _ = read_bytes(&data);
        }
    }

    #[test]
    fn real_samples_parse_when_available() {
        let Some(p) = dataset("CA_DCSync_4662.evtx") else {
            return; // vzorky nejsou v repu (licence GPL-3.0, jen mimo git)
        };
        let (events, summary) = read_file(&p).unwrap();
        assert!(summary.records > 0, "{summary:?}");
        assert_eq!(summary.errors, 0, "{summary:?}");
        // DCSync (4662 s replikačními právy od ne-řadiče domény) je zobrazený jako výstraha
        assert!(
            events.iter().any(|e| matches!(&e.kind, super::super::EventKind::Alert { rule_id, .. } if rule_id == "win-4662-dcsync")),
            "{summary:?}"
        );
    }
}
