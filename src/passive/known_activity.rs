//! Krok 25: znamá činnost sítě (vlastní sken, běžné vyhledávání služeb).
//!
//! Detektory ve `passive` rozhodují jen podle tvaru provozu. Nevědí, že sken pustil
//! majitel sítě, ani že UDP odpovědi mířily na dotaz, který příjemce sám poslal. Tenhle
//! modul to dodá jako kontext, ale ne jako mlčenlivé zahazování: vysvětlené toky se z
//! detekce vyjmou, každá skupina ale nechá jednu souhrnnou událost `explained_activity`
//! (Low, "vysvětleno, ne uzavřeno"). Nic se tu nezavírá a chráněné nálezy se nemění.
//!
//! Zapíná se jen souborem z proměnné prostředí `SALTICUS_KNOWN_ACTIVITY` (JSON). Bez ní
//! (nebo s nečitelným souborem) se chování neliší od dosavadního.
//!
//! Poctivě k mezím: z hlaviček paketů nejde dokázat, že tok je skutečná odpověď. Pravidla
//! proto zužují prostor, ve kterém by se mohl útočník schovat:
//! - vlastní sken jen z deklarované IP, v deklarovaném okně a jen na deklarované cíle,
//! - jednotlivý vysvětlený tok musí být malý (nejvýš 64 paketů a 16 KB), takže vysoké
//!   tempo nebo objem zůstanou v detekci,
//! - odpověď musí mít dotaz příjemce na multicast SSDP/mDNS předtím (do 600 s) a počet
//!   odpovědí je omezen násobkem počtu dotazů (na odpovídajícího i celkem),
//! - broadcast jen na skutečné broadcast adresy deklarovaných podsítí a na tři známé
//!   discovery skupiny; strop toků za hodinu na zdroj.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use ipnet::IpNet;
use serde::Deserialize;

use crate::model::{NormalizedEvent, Severity};

use super::ConnectionObservation;
use super::detector::ConnectionDetector;
use super::thresholds::{HIGH_BPS_THRESHOLD, HIGH_PPS_THRESHOLD};

type ServiceKey = (String, String, u16);

/// Nejvýš tolik paketů a bajtů smí mít jeden vysvětlený tok (vyšší tempo/objem zůstane v detekci).
const MAX_FLOW_PKTS: u64 = 64;
const MAX_FLOW_BYTES: u64 = 16 * 1024;

/// Odpověď musí přijít nejpozději tolik sekund po dotazu.
const REPLY_WINDOW_S: i64 = 600;

/// Nejvýš tolik odpovědí na jeden dotaz od jednoho odpovídajícího a celkem od všech
/// (stanoveno z logiky protokolu: odpověď nemůže být početnější než dotazy, které ji vyvolaly).
/// Na datech domácí sítě bylo maximum 8 odpovědí na dotaz od jednoho zařízení.
const MAX_REPLIES_PER_QUERY_RESPONDER: usize = 10;
const MAX_REPLIES_PER_QUERY_TOTAL: usize = 30;

/// Rozpoznané discovery multicast skupiny (SSDP, mDNS, LLMNR).
fn is_discovery_group(ip: &str) -> bool {
    matches!(ip, "239.255.255.250" | "224.0.0.251" | "224.0.0.252")
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DeclaredScanner {
    pub(crate) ip: String,
    pub(crate) from: DateTime<Utc>,
    pub(crate) to: DateTime<Utc>,
    /// Cíle deklarovaného skenu (CIDR nebo IP). Prázdné = sken se nevysvětluje.
    #[serde(default)]
    pub(crate) targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KnownActivityConfig {
    #[serde(default)]
    pub(crate) own_scanners: Vec<DeclaredScanner>,
    /// Vysvětlovat odpovědi na vlastní dotazy a broadcast/mDNS v deklarovaných podsítích.
    #[serde(default)]
    pub(crate) discovery: bool,
    /// Podsítě LAN (CIDR): jejich broadcast adresy se berou jako broadcast.
    #[serde(default)]
    pub(crate) lan_cidrs: Vec<String>,
    /// Strop toků za hodinu na jeden zdroj pro broadcast/mDNS.
    #[serde(default = "default_cap")]
    pub(crate) max_flows_per_src_hour: usize,
    /// Záznam má jen hlavičky paketů; `missed_bytes` je tedy artefakt záznamu (platí pro celý záznam).
    #[serde(default)]
    pub(crate) headers_only_capture: bool,
}

fn default_cap() -> usize {
    1000
}

impl KnownActivityConfig {
    /// Neplatná politika nesmí tiše vypnout jen část pravidel: celá konfigurace se odmítne.
    fn validate(&self) -> Result<(), String> {
        for cidr in &self.lan_cidrs {
            cidr.parse::<IpNet>()
                .map_err(|_| format!("lan_cidrs: neplatna podsit '{cidr}'"))?;
        }
        for scanner in &self.own_scanners {
            scanner
                .ip
                .parse::<std::net::IpAddr>()
                .map_err(|_| format!("own_scanners: neplatna IP '{}'", scanner.ip))?;
            if scanner.from > scanner.to {
                return Err(format!(
                    "own_scanners: okno {} konci pred zacatkem",
                    scanner.ip
                ));
            }
            for target in &scanner.targets {
                let ok =
                    target.parse::<IpNet>().is_ok() || target.parse::<std::net::IpAddr>().is_ok();
                if !ok {
                    return Err(format!("own_scanners: neplatny cil '{target}'"));
                }
            }
        }
        Ok(())
    }
}

static CONFIG: OnceLock<Option<KnownActivityConfig>> = OnceLock::new();

/// Nastaví pipeline, jakmile obálka skutečně běží (jen s legacy detektorem). Parser smí
/// ponechat dotazy SSDP/mDNS jen tehdy.
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub(crate) fn activate() {
    ACTIVE.store(true, AtomicOrdering::Relaxed);
}

/// Načte konfiguraci jednou za proces. `None`, pokud proměnná chybí nebo soubor nejde
/// přečíst či naparsovat (chování zůstane beze změny).
pub(crate) fn config() -> Option<&'static KnownActivityConfig> {
    CONFIG
        .get_or_init(|| {
            let path = std::env::var_os("SALTICUS_KNOWN_ACTIVITY")?;
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(error) => {
                    tracing::warn!(%error, "SALTICUS_KNOWN_ACTIVITY se nenacetl, znama cinnost vypnuta");
                    return None;
                }
            };
            match serde_json::from_str::<KnownActivityConfig>(&text) {
                Ok(config) => match config.validate() {
                    Ok(()) => Some(config),
                    Err(error) => {
                        tracing::warn!(%error, "SALTICUS_KNOWN_ACTIVITY ma neplatnou politiku, znama cinnost vypnuta");
                        None
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "SALTICUS_KNOWN_ACTIVITY neni platny JSON, znama cinnost vypnuta");
                    None
                }
            }
        })
        .as_ref()
}

/// Má parser ponechat multicast dotazy SSDP/mDNS, ze kterých se pozná jejich odpověď?
/// Pravda jen s platnou konfigurací, `discovery: true` a jen když obálka skutečně běží.
pub(crate) fn wants_discovery_queries() -> bool {
    ACTIVE.load(AtomicOrdering::Relaxed) && config().is_some_and(|config| config.discovery)
}

/// Je tok jedním z dotazů, které chce `known_activity` vidět (UDP na SSDP/mDNS multicast)?
pub(crate) fn is_query_flow(proto: &str, dst: &str, dst_port: Option<u16>) -> bool {
    proto == "udp"
        && matches!(
            (dst, dst_port),
            ("239.255.255.250", Some(1900)) | ("224.0.0.251", Some(5353))
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Explanation {
    OwnScan,
    Multicast,
    Broadcast,
    SolicitedReply,
}

impl Explanation {
    fn rule(self) -> &'static str {
        match self {
            Self::OwnScan => "kontext:own-scan",
            Self::Multicast => "kontext:discovery-multicast",
            Self::Broadcast => "kontext:broadcast",
            Self::SolicitedReply => "kontext:solicited-reply",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OwnScan => "vlastni deklarovany sken",
            Self::Multicast => "discovery multicast (SSDP/mDNS/LLMNR)",
            Self::Broadcast => "UDP broadcast v deklarovane podsiti",
            Self::SolicitedReply => "odpovedi na vlastni multicast dotazy",
        }
    }
}

fn private(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok_and(|a| a.is_private())
}

fn small_flow(conn: &ConnectionObservation) -> bool {
    // musí být známý počet paketů a všechny uvedené součty pod stropem
    if !conn.orig_pkts.is_some_and(|p| p <= MAX_FLOW_PKTS) {
        return false;
    }
    let pkts_ok = [conn.resp_pkts, conn.total_pkts]
        .into_iter()
        .flatten()
        .all(|p| p <= MAX_FLOW_PKTS);
    let bytes_ok = [conn.orig_bytes, conn.resp_bytes, conn.total_bytes]
        .into_iter()
        .flatten()
        .all(|b| b <= MAX_FLOW_BYTES);
    // tempo podle stejných kritérií jako dosavadní detektor (celkové pakety a bity za sekundu)
    let rate_ok = match conn.duration_s {
        Some(d) if d > 0.0 => {
            let pkts = conn.total_pkts.or(conn.orig_pkts).unwrap_or(0) as f64;
            let bytes = conn.total_bytes.or(conn.orig_bytes).unwrap_or(0) as f64;
            pkts / d < HIGH_PPS_THRESHOLD && bytes * 8.0 / d < HIGH_BPS_THRESHOLD
        }
        _ => true,
    };
    pkts_ok && bytes_ok && rate_ok
}

fn is_lan_broadcast(ip: &str, config: &KnownActivityConfig) -> bool {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    if addr.is_broadcast() {
        return true;
    }
    config
        .lan_cidrs
        .iter()
        .any(|cidr| matches!(cidr.parse::<IpNet>(), Ok(IpNet::V4(net)) if net.prefix_len() <= 30 && net.broadcast() == addr))
}

fn own_scan(conn: &ConnectionObservation, src: &str, config: &KnownActivityConfig) -> bool {
    config.own_scanners.iter().any(|scanner| {
        scanner.ip == src
            && conn.timestamp >= scanner.from
            && conn.timestamp <= scanner.to
            && scanner
                .targets
                .iter()
                .any(|target| target_contains(target, &conn.dst_ip))
    })
}

fn target_contains(target: &str, ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match target.parse::<IpNet>() {
        Ok(net) => net.contains(&addr),
        Err(_) => target.parse::<std::net::IpAddr>().is_ok_and(|t| t == addr),
    }
}

/// Dotazy, které si zařízení samo poslalo na multicast SSDP/mDNS: (IP, zdrojový port) → časy
/// seřazené vzestupně.
type Queries = HashMap<(String, u16), Vec<DateTime<Utc>>>;

fn collect_queries(connections: &[ConnectionObservation]) -> Queries {
    let mut queries: Queries = HashMap::new();
    for conn in connections {
        let (Some(src), Some(port)) = (conn.src_ip.as_ref(), conn.src_port) else {
            continue;
        };
        if is_query_flow(&conn.proto, &conn.dst_ip, conn.dst_port) {
            queries
                .entry((src.clone(), port))
                .or_default()
                .push(conn.timestamp);
        }
    }
    for times in queries.values_mut() {
        times.sort_unstable();
    }
    queries
}

/// Index posledního dotazu příjemce na tomto portu, který byl ostře PŘED odpovědí a nejvýš
/// `REPLY_WINDOW_S` před ní (přesný čas). Dotaz je jediný, který smí odpověď "financovat".
fn matching_query(conn: &ConnectionObservation, queries: &Queries) -> Option<usize> {
    let port = conn.dst_port?;
    let times = queries.get(&(conn.dst_ip.clone(), port))?;
    let idx = times.partition_point(|t| *t < conn.timestamp);
    (idx > 0 && conn.timestamp - times[idx - 1] <= Duration::seconds(REPLY_WINDOW_S))
        .then(|| idx - 1)
}

fn candidate(
    conn: &ConnectionObservation,
    config: &KnownActivityConfig,
    queries: &Queries,
) -> Option<(Explanation, usize)> {
    let src = conn.src_ip.as_deref()?;
    if own_scan(conn, src, config) {
        return Some((Explanation::OwnScan, 0));
    }
    if !config.discovery || conn.proto != "udp" || !private(src) || !small_flow(conn) {
        return None;
    }
    if is_discovery_group(&conn.dst_ip) {
        return Some((Explanation::Multicast, 0));
    }
    if is_lan_broadcast(&conn.dst_ip, config) {
        return Some((Explanation::Broadcast, 0));
    }
    if private(&conn.dst_ip)
        && let Some(query) = matching_query(conn, queries)
    {
        return Some((Explanation::SolicitedReply, query));
    }
    None
}

fn hour_key(ip: &str, at: DateTime<Utc>) -> (String, i32, u32) {
    (
        ip.to_string(),
        at.date_naive().num_days_from_ce(),
        at.hour(),
    )
}

/// Rozdělí toky na ty, které jdou dál do detekce, a souhrn vysvětlených.
pub(crate) fn split(
    mut connections: Vec<ConnectionObservation>,
    config: &KnownActivityConfig,
) -> (Vec<ConnectionObservation>, Vec<NormalizedEvent>) {
    if config.headers_only_capture {
        for conn in &mut connections {
            conn.missed_bytes = None;
        }
    }
    let queries = if config.discovery {
        collect_queries(&connections)
    } else {
        Queries::new()
    };
    let marks: Vec<Option<(Explanation, usize)>> = connections
        .iter()
        .map(|conn| candidate(conn, config, &queries))
        .collect();

    // Počty pro stropy: broadcast/multicast za hodinu na zdroj; odpovědi v klouzavém okně
    // `REPLY_WINDOW_S` (dotazy z okna před odpovědí financují omezený počet odpovědí od
    // jednoho odpovídajícího i od všech; budoucí a vypršené dotazy nefinancují nic).
    let mut per_hour: HashMap<(String, i32, u32), usize> = HashMap::new();
    let mut by_responder: HashMap<(String, String, u16), Vec<DateTime<Utc>>> = HashMap::new();
    let mut by_receiver: HashMap<(String, u16), Vec<DateTime<Utc>>> = HashMap::new();
    for (conn, mark) in connections.iter().zip(&marks) {
        let src = conn.src_ip.as_deref().unwrap_or_default();
        match mark {
            Some((Explanation::OwnScan, _)) | None => {}
            Some((Explanation::SolicitedReply, _)) => {
                let port = conn.dst_port.unwrap_or_default();
                by_responder
                    .entry((src.to_string(), conn.dst_ip.clone(), port))
                    .or_default()
                    .push(conn.timestamp);
                by_receiver
                    .entry((conn.dst_ip.clone(), port))
                    .or_default()
                    .push(conn.timestamp);
            }
            Some(_) => {
                *per_hour.entry(hour_key(src, conn.timestamp)).or_default() += 1;
            }
        }
    }
    for times in by_responder.values_mut().chain(by_receiver.values_mut()) {
        times.sort_unstable();
    }
    let window = Duration::seconds(REPLY_WINDOW_S);

    let mut kept = Vec::new();
    let mut explained: BTreeMap<(Explanation, String), Group> = BTreeMap::new();
    for (conn, mark) in connections.into_iter().zip(marks) {
        let src = conn.src_ip.clone().unwrap_or_default();
        let over_cap = match mark {
            Some((Explanation::OwnScan, _)) | None => false,
            Some((Explanation::SolicitedReply, _)) => {
                let port = conn.dst_port.unwrap_or_default();
                let ts = conn.timestamp;
                // dotazy ostře před odpovědí a ne starší než okno
                let funded = queries.get(&(conn.dst_ip.clone(), port)).map_or(0, |q| {
                    q.partition_point(|t| *t < ts) - q.partition_point(|t| *t < ts - window)
                });
                // odpovědi v okně končícím touto odpovědí (včetně ní)
                let in_window = |times: Option<&Vec<DateTime<Utc>>>| {
                    times.map_or(0, |v| {
                        v.partition_point(|t| *t <= ts) - v.partition_point(|t| *t < ts - window)
                    })
                };
                in_window(by_responder.get(&(src.clone(), conn.dst_ip.clone(), port)))
                    > MAX_REPLIES_PER_QUERY_RESPONDER * funded
                    || in_window(by_receiver.get(&(conn.dst_ip.clone(), port)))
                        > MAX_REPLIES_PER_QUERY_TOTAL * funded
            }
            Some(_) => {
                per_hour
                    .get(&hour_key(&src, conn.timestamp))
                    .copied()
                    .unwrap_or(0)
                    > config.max_flows_per_src_hour
            }
        };
        match mark {
            Some((kind, _)) if !over_cap => {
                let group = explained.entry((kind, src)).or_insert_with(|| Group {
                    count: 0,
                    first: conn.timestamp,
                    targets: HashMap::new(),
                });
                group.count += 1;
                if conn.timestamp < group.first {
                    group.first = conn.timestamp;
                }
                let target = format!("{}:{}", conn.dst_ip, conn.dst_port.unwrap_or_default());
                *group.targets.entry(target).or_default() += 1;
            }
            _ => kept.push(conn),
        }
    }

    let events = explained
        .into_iter()
        .map(|((kind, src), group)| {
            let mut top: Vec<_> = group.targets.iter().collect();
            top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let targets = top
                .iter()
                .take(3)
                .map(|(target, n)| format!("{target} x{n}"))
                .collect::<Vec<_>>()
                .join(", ");
            NormalizedEvent {
                event_id: format!("explained:{}:{src}", kind.rule()),
                timestamp: group.first,
                src_ip: Some(src.clone()),
                src_port: None,
                // souhrn patří zdroji (informace o jeho činnosti), ne libovolnému cíli
                dst_ip: src.clone(),
                proto: "udp".to_string(),
                dst_port: None,
                event_type: "explained_activity".to_string(),
                severity: Severity::Low,
                source: "known-activity".to_string(),
                rule_id: Some(kind.rule().to_string()),
                message: format!(
                    "Vysvetleno, ne uzavreno: {} z {src} ({} toku vyjmuto z detekce; nejcastejsi cile: {targets})",
                    kind.label(),
                    group.count
                ),
                raw_ref: None,
                count: u32::try_from(group.count).unwrap_or(u32::MAX),
            }
        })
        .collect();
    (kept, events)
}

struct Group {
    count: usize,
    first: DateTime<Utc>,
    targets: HashMap<String, usize>,
}

/// Obálka kolem libovolného detektoru: znamou činnost vysvětlí, zbytek pošle vnitřnímu.
pub(crate) struct KnownActivityDetector<'a> {
    pub(crate) inner: &'a (dyn ConnectionDetector + Sync),
    pub(crate) config: &'a KnownActivityConfig,
}

impl ConnectionDetector for KnownActivityDetector<'_> {
    fn id(&self) -> &'static str {
        "known-activity"
    }

    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent> {
        let (kept, mut summary) = split(connections, self.config);
        let mut events = self.inner.detect(kept, known_services);
        events.append(&mut summary);
        events.sort_by_key(|event| event.timestamp);
        events
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::passive::LegacyAnomalyDetector;

    fn at(h: u32, m: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 20, h, m, s).unwrap()
    }

    fn conn(
        src: &str,
        sport: u16,
        dst: &str,
        dport: u16,
        proto: &str,
        when: DateTime<Utc>,
    ) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: when,
            src_ip: Some(src.to_string()),
            src_port: Some(sport),
            dst_ip: dst.to_string(),
            proto: proto.to_string(),
            dst_port: Some(dport),
            duration_s: None,
            orig_bytes: Some(300),
            resp_bytes: None,
            total_bytes: None,
            orig_pkts: Some(1),
            resp_pkts: None,
            total_pkts: None,
            conn_state: Some("S0".to_string()),
            history: None,
            missed_bytes: Some(5000),
        }
    }

    fn config() -> KnownActivityConfig {
        KnownActivityConfig {
            own_scanners: vec![DeclaredScanner {
                ip: "192.168.1.133".to_string(),
                from: at(9, 0, 0),
                to: at(13, 0, 0),
                targets: vec!["192.168.1.0/24".to_string()],
            }],
            discovery: true,
            lan_cidrs: vec!["192.168.1.0/24".to_string()],
            max_flows_per_src_hour: 5,
            headers_only_capture: true,
        }
    }

    fn query(port: u16, when: DateTime<Utc>) -> ConnectionObservation {
        conn("192.168.1.133", port, "239.255.255.250", 1900, "udp", when)
    }

    fn reply(from: &str, to_port: u16, when: DateTime<Utc>) -> ConnectionObservation {
        conn(from, 42822, "192.168.1.133", to_port, "udp", when)
    }

    #[test]
    fn declared_scanner_in_window_on_declared_target_is_explained() {
        let c = conn(
            "192.168.1.133",
            40000,
            "192.168.1.146",
            22,
            "tcp",
            at(10, 0, 0),
        );
        let (kept, events) = split(vec![c], &config());
        assert!(kept.is_empty());
        assert_eq!(events[0].rule_id.as_deref(), Some("kontext:own-scan"));
        // souhrn nepatri libovolnemu cili, ale zdroji
        assert_eq!(events[0].dst_ip, "192.168.1.133");
    }

    #[test]
    fn scanner_traffic_to_undeclared_target_or_without_targets_stays() {
        let outside = conn("192.168.1.133", 40000, "8.8.8.8", 22, "tcp", at(10, 0, 0));
        let mut no_targets = config();
        no_targets.own_scanners[0].targets.clear();
        let inside = conn(
            "192.168.1.133",
            40000,
            "192.168.1.146",
            22,
            "tcp",
            at(10, 0, 0),
        );
        assert_eq!(split(vec![outside], &config()).0.len(), 1);
        assert_eq!(split(vec![inside], &no_targets).0.len(), 1);
    }

    #[test]
    fn undeclared_scanner_stays_in_detection() {
        let c = conn(
            "192.168.1.99",
            40000,
            "192.168.1.146",
            22,
            "tcp",
            at(10, 0, 0),
        );
        let (kept, events) = split(vec![c], &config());
        assert_eq!(kept.len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn declared_scanner_outside_window_stays() {
        let c = conn(
            "192.168.1.133",
            40000,
            "192.168.1.146",
            22,
            "tcp",
            at(14, 0, 0),
        );
        assert_eq!(split(vec![c], &config()).0.len(), 1);
    }

    #[test]
    fn reply_to_own_multicast_query_from_random_port_is_explained() {
        let conns = vec![
            query(62183, at(10, 0, 0)),
            reply("192.168.1.232", 62183, at(10, 0, 5)),
        ];
        let (kept, events) = split(conns, &config());
        assert!(
            kept.iter()
                .all(|c| c.src_ip.as_deref() != Some("192.168.1.232"))
        );
        assert!(
            events
                .iter()
                .any(|e| e.rule_id.as_deref() == Some("kontext:solicited-reply"))
        );
    }

    #[test]
    fn reply_without_prior_query_is_not_explained_even_from_port_1900() {
        let c = conn(
            "192.168.1.83",
            1900,
            "192.168.1.133",
            50000,
            "udp",
            at(10, 0, 0),
        );
        assert_eq!(split(vec![c], &config()).0.len(), 1);
    }

    #[test]
    fn reply_before_the_query_is_not_explained() {
        let conns = vec![
            reply("192.168.1.232", 62183, at(10, 0, 0)),
            query(62183, at(10, 0, 5)),
        ];
        let (kept, _) = split(conns, &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn reply_window_boundary_uses_full_precision() {
        let q = query(62183, at(10, 0, 0));
        let inside = reply("192.168.1.232", 62183, at(10, 10, 0));
        let mut just_over = reply("192.168.1.232", 62183, at(10, 10, 0));
        just_over.timestamp += Duration::milliseconds(1);
        let (kept_in, _) = split(vec![q.clone(), inside], &config());
        let (kept_over, _) = split(vec![q, just_over], &config());
        assert!(
            kept_in
                .iter()
                .all(|c| c.src_ip.as_deref() != Some("192.168.1.232"))
        );
        assert!(
            kept_over
                .iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn replies_above_budget_from_one_responder_stay_in_detection() {
        // 1 dotaz => nejvyse 10 odpovedi od jednoho zarizeni
        let mut conns = vec![query(62183, at(10, 0, 0))];
        for i in 0..50 {
            conns.push(reply("192.168.1.232", 62183, at(10, 0, 1 + i % 50)));
        }
        let (kept, _) = split(conns, &config());
        // prvnich 10 financuje jediny dotaz, zbylych 40 zustava v detekci
        assert_eq!(
            kept.iter()
                .filter(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
                .count(),
            40
        );
    }

    #[test]
    fn zero_queries_give_zero_reply_budget() {
        // dotaz na jinem portu: odpoved na port bez dotazu se nevysvetli
        let conns = vec![
            query(11111, at(10, 0, 0)),
            reply("192.168.1.232", 62183, at(10, 0, 5)),
        ];
        let (kept, _) = split(conns, &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn oversized_or_high_rate_flow_is_not_explained() {
        let q = query(62183, at(10, 0, 0));
        let mut big = reply("192.168.1.232", 62183, at(10, 0, 5));
        big.orig_pkts = Some(5000);
        let mut heavy = reply("192.168.1.232", 62183, at(10, 0, 6));
        heavy.orig_bytes = Some(10_000_000);
        let (kept, _) = split(vec![q, big, heavy], &config());
        assert_eq!(
            kept.iter()
                .filter(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
                .count(),
            2
        );
    }

    #[test]
    fn ssdp_toward_external_or_from_public_source_is_not_explained() {
        let q = query(62183, at(10, 0, 0));
        let from_public = conn(
            "203.0.113.5",
            1900,
            "192.168.1.133",
            62183,
            "udp",
            at(10, 0, 5),
        );
        let (kept, _) = split(vec![q, from_public], &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("203.0.113.5"))
        );
    }

    #[test]
    fn only_real_subnet_broadcast_and_known_groups_are_explained() {
        let real = conn(
            "192.168.1.88",
            57621,
            "192.168.1.255",
            57621,
            "udp",
            at(10, 0, 0),
        );
        let fake255 = conn("192.168.1.88", 40000, "10.1.2.255", 80, "udp", at(10, 0, 0));
        let other_group = conn(
            "192.168.1.88",
            40000,
            "239.1.2.3",
            9000,
            "udp",
            at(10, 0, 0),
        );
        let group = conn(
            "192.168.1.88",
            5353,
            "224.0.0.251",
            5353,
            "udp",
            at(10, 0, 0),
        );
        let tcp = conn(
            "192.168.1.88",
            40000,
            "192.168.1.255",
            80,
            "tcp",
            at(10, 0, 0),
        );
        let (kept, events) = split(vec![real, fake255, other_group, group, tcp], &config());
        assert_eq!(kept.len(), 3);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn unicast_port_5353_between_private_hosts_is_not_explained() {
        let c = conn(
            "192.168.1.88",
            5353,
            "192.168.1.146",
            5353,
            "udp",
            at(10, 0, 0),
        );
        assert_eq!(split(vec![c], &config()).0.len(), 1);
    }

    #[test]
    fn broadcast_above_hourly_cap_stays_in_detection() {
        let conns: Vec<_> = (0..10)
            .map(|i| {
                conn(
                    "192.168.1.88",
                    57621,
                    "192.168.1.255",
                    57621,
                    "udp",
                    at(10, 0, i),
                )
            })
            .collect();
        let (kept, events) = split(conns, &config());
        assert_eq!(kept.len(), 10);
        assert!(events.is_empty());
    }

    #[test]
    fn broadcast_cap_is_per_utc_hour() {
        // 5 toku v jedne hodine a 5 v nasledujici: kazda hodina je pod stropem 5
        let mut conns = Vec::new();
        for i in 0..5 {
            conns.push(conn(
                "192.168.1.88",
                57621,
                "192.168.1.255",
                57621,
                "udp",
                at(10, 59, 50 + i),
            ));
            conns.push(conn(
                "192.168.1.88",
                57621,
                "192.168.1.255",
                57621,
                "udp",
                at(11, 0, i),
            ));
        }
        let (kept, _) = split(conns, &config());
        assert!(kept.is_empty());
    }

    #[test]
    fn headers_only_capture_strips_missed_bytes() {
        let c = conn(
            "192.168.1.99",
            40000,
            "192.168.1.146",
            22,
            "tcp",
            at(10, 0, 0),
        );
        assert_eq!(split(vec![c], &config()).0[0].missed_bytes, None);
    }

    #[test]
    fn discovery_off_explains_only_declared_scan() {
        let mut off = config();
        off.discovery = false;
        let conns = vec![
            query(62183, at(10, 0, 0)),
            reply("192.168.1.232", 62183, at(10, 0, 5)),
        ];
        assert_eq!(split(conns, &off).0.len(), 2);
    }

    #[test]
    fn wrapper_forwards_unexplained_flows_to_inner_detector() {
        let cfg = config();
        let detector = KnownActivityDetector {
            inner: &LegacyAnomalyDetector,
            config: &cfg,
        };
        // 30 vlastnich skenovacich toku (vysvetleno) + 30 toku z nedeklarovane IP na jednu sluzbu
        let mut conns: Vec<_> = (0..30u16)
            .map(|i| {
                conn(
                    "192.168.1.133",
                    40000 + i,
                    "192.168.1.146",
                    1000 + i,
                    "tcp",
                    at(10, 0, 1),
                )
            })
            .collect();
        conns.extend((0..30u16).map(|i| {
            conn(
                "192.168.1.250",
                41000 + i,
                "192.168.1.146",
                2222,
                "tcp",
                at(10, 0, 2),
            )
        }));
        let events = detector.detect(conns, &HashSet::new());
        assert!(events.iter().any(|e| e.event_type == "explained_activity"));
        assert!(
            events
                .iter()
                .any(|e| e.event_type != "explained_activity" && e.dst_port == Some(2222))
        );
        assert!(events.iter().all(|e| e.event_type == "explained_activity"
            || e.src_ip.as_deref() != Some("192.168.1.133")));
    }

    #[test]
    fn future_and_expired_queries_do_not_fund_replies() {
        // 11 odpovedi (nad limit 10 na dotaz) po dotazu v 10:00; druhy dotaz v 10:30 je
        // budoucnost, treti v 09:00 je expirovany: nesmi navysit rozpocet
        let mut conns = vec![
            query(62183, at(9, 0, 0)),
            query(62183, at(10, 0, 0)),
            query(62183, at(10, 30, 0)),
        ];
        for i in 0..11 {
            conns.push(reply("192.168.1.232", 62183, at(10, 0, 1 + i)));
        }
        let (kept, _) = split(conns, &config());
        // financuje jen dotaz v 10:00 (10 odpovedi); budouci ani expirovany nepomohou
        assert_eq!(
            kept.iter()
                .filter(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
                .count(),
            1
        );
    }

    #[test]
    fn query_with_the_same_timestamp_is_not_a_prior_query() {
        let conns = vec![
            query(62183, at(10, 0, 0)),
            reply("192.168.1.232", 62183, at(10, 0, 0)),
        ];
        let (kept, _) = split(conns, &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn slash_31_and_32_networks_have_no_directed_broadcast() {
        let mut cfg = config();
        cfg.lan_cidrs = vec!["192.168.1.7/32".to_string(), "192.168.1.8/31".to_string()];
        let a = conn(
            "192.168.1.88",
            40000,
            "192.168.1.7",
            80,
            "udp",
            at(10, 0, 0),
        );
        let b = conn(
            "192.168.1.88",
            40000,
            "192.168.1.9",
            80,
            "udp",
            at(10, 0, 0),
        );
        assert_eq!(split(vec![a, b], &cfg).0.len(), 2);
    }

    #[test]
    fn flow_with_high_packet_rate_stays_even_when_totals_are_small() {
        let q = query(62183, at(10, 0, 0));
        let mut fast = reply("192.168.1.232", 62183, at(10, 0, 5));
        fast.orig_pkts = Some(60);
        fast.total_pkts = Some(60);
        fast.duration_s = Some(0.001); // 60 000 pps
        let (kept, _) = split(vec![q, fast], &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn bidirectional_totals_above_cap_stay() {
        let q = query(62183, at(10, 0, 0));
        let mut chatty = reply("192.168.1.232", 62183, at(10, 0, 5));
        chatty.resp_pkts = Some(500);
        let (kept, _) = split(vec![q, chatty], &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn invalid_policy_is_rejected() {
        let mut bad_cidr = config();
        bad_cidr.lan_cidrs = vec!["not-a-cidr".to_string()];
        let mut bad_target = config();
        bad_target.own_scanners[0].targets = vec!["999.1.1.1/8".to_string()];
        let mut bad_window = config();
        bad_window.own_scanners[0].to = at(8, 0, 0);
        assert!(config().validate().is_ok());
        assert!(bad_cidr.validate().is_err());
        assert!(bad_target.validate().is_err());
        assert!(bad_window.validate().is_err());
    }

    #[test]
    fn summary_lists_top_targets_for_visibility() {
        let c = conn(
            "192.168.1.133",
            40000,
            "192.168.1.146",
            22,
            "tcp",
            at(10, 0, 0),
        );
        let (_, events) = split(vec![c], &config());
        assert!(events[0].message.contains("192.168.1.146:22 x1"));
    }

    #[test]
    fn query_import_is_off_until_the_wrapper_is_activated() {
        // bez activate() (a bez konfigurace) parser dotazy nepridava
        assert!(!wants_discovery_queries());
    }
}
