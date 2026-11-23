//! Krok 25: znamá činnost sítě (vlastní sken, běžné vyhledávání služeb).
//!
//! Detektory ve `passive` rozhodují jen podle tvaru provozu. Nevědí, že sken pustil
//! majitel sítě, ani že UDP z portu 1900 jsou odpovědi SSDP. Tenhle modul to dodá jako
//! kontext, ale ne jako mlčenlivé zahazování: vysvětlené toky se z detekce vyjmou, každá
//! skupina ale nechá jednu souhrnnou událost `explained_activity` (Low, "vysvětleno, ne
//! uzavřeno"). Nic se tu nezavírá a chráněné nálezy se nemění.
//!
//! Zapíná se jen souborem z proměnné prostředí `SALTICUS_KNOWN_ACTIVITY` (JSON). Bez ní se
//! chování neliší od dosavadního.
//!
//! Meze, které drží proti zneužití (útočník by se jinak mohl schovat za vysvětlenou
//! kategorii):
//! - vlastní sken platí jen pro deklarovanou IP a deklarované časové okno,
//! - vyhledávání služeb se vysvětlí jen mezi soukromými adresami a jen do stropu toků za
//!   hodinu na zdroj (SSDP zesilovací útok má řádově vyšší tempo),
//! - cokoli nad strop nebo mimo soukromé adresy zůstává v detekci.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use chrono::{DateTime, Timelike, Utc};
use serde::Deserialize;

use crate::model::{NormalizedEvent, Severity};

use super::ConnectionObservation;
use super::detector::ConnectionDetector;

type ServiceKey = (String, String, u16);

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DeclaredScanner {
    pub(crate) ip: String,
    pub(crate) from: DateTime<Utc>,
    pub(crate) to: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KnownActivityConfig {
    #[serde(default)]
    pub(crate) own_scanners: Vec<DeclaredScanner>,
    /// Vysvětlovat SSDP/mDNS/broadcast mezi soukromými adresami.
    #[serde(default)]
    pub(crate) discovery: bool,
    /// Strop toků za hodinu na jeden zdroj, nad který se vyhledávání už nevysvětluje.
    #[serde(default = "default_cap")]
    pub(crate) max_flows_per_src_hour: usize,
    /// Záznam má jen hlavičky paketů (snaplen), `missed_bytes` je tedy artefakt záznamu.
    #[serde(default)]
    pub(crate) headers_only_capture: bool,
}

fn default_cap() -> usize {
    1000
}

/// Je znamá činnost zapnutá (proměnná prostředí nastavená)? Řídí i to, zda parser ponechá
/// multicast dotazy SSDP/mDNS, ze kterých se pozná jejich odpověď.
pub(crate) fn enabled() -> bool {
    std::env::var_os("SALTICUS_KNOWN_ACTIVITY").is_some()
}

impl KnownActivityConfig {
    /// `None`, pokud proměnná není nastavená nebo soubor nejde přečíst (chování beze změny).
    pub(crate) fn from_env() -> Option<Self> {
        let path = std::env::var_os("SALTICUS_KNOWN_ACTIVITY")?;
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<Self>(&text) {
            Ok(config) => Some(config),
            Err(error) => {
                tracing::warn!(%error, "SALTICUS_KNOWN_ACTIVITY se nenacetl, znama cinnost vypnuta");
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Explanation {
    OwnScan,
    Mdns,
    Broadcast,
    SolicitedReply,
}

impl Explanation {
    fn rule(self) -> &'static str {
        match self {
            Self::OwnScan => "kontext:own-scan",
            Self::Mdns => "kontext:mdns",
            Self::Broadcast => "kontext:broadcast",
            Self::SolicitedReply => "kontext:solicited-reply",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::OwnScan => "vlastni deklarovany sken",
            Self::Mdns => "mDNS (UDP port 5353)",
            Self::Broadcast => "UDP broadcast/multicast v LAN",
            Self::SolicitedReply => "odpovedi na vlastni multicast dotazy SSDP/mDNS",
        }
    }
}

fn private(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok_and(|a| a.is_private())
}

fn broadcast_or_multicast(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>()
        .is_ok_and(|a| a.is_broadcast() || a.is_multicast() || a.octets()[3] == 255)
}

/// Dotazy, které si zařízení samo poslalo na multicast SSDP/mDNS: (IP, zdrojový port) → časy.
type Queries = HashMap<(String, u16), Vec<DateTime<Utc>>>;

/// Odpověď musí přijít do tohoto počtu sekund po dotazu.
const REPLY_WINDOW_S: i64 = 600;

/// Nejvýš tolik odpovědí na jeden dotaz za hodinu (stanoveno předem z logiky protokolu).
const MAX_REPLIES_PER_QUERY: usize = 10;

fn collect_queries(connections: &[ConnectionObservation]) -> Queries {
    let mut queries: Queries = HashMap::new();
    for conn in connections {
        let (Some(src), Some(port)) = (conn.src_ip.as_ref(), conn.src_port) else {
            continue;
        };
        let group = matches!(
            (conn.dst_ip.as_str(), conn.dst_port),
            ("239.255.255.250", Some(1900)) | ("224.0.0.251", Some(5353))
        );
        if conn.proto == "udp" && group {
            queries
                .entry((src.clone(), port))
                .or_default()
                .push(conn.timestamp);
        }
    }
    queries
}

fn is_reply_to_own_query(conn: &ConnectionObservation, queries: &Queries) -> bool {
    let Some(port) = conn.dst_port else {
        return false;
    };
    queries
        .get(&(conn.dst_ip.clone(), port))
        .is_some_and(|times| {
            times.iter().any(|t| {
                let delta = (conn.timestamp - *t).num_seconds();
                (0..=REPLY_WINDOW_S).contains(&delta)
            })
        })
}

fn candidate(
    conn: &ConnectionObservation,
    config: &KnownActivityConfig,
    queries: &Queries,
) -> Option<Explanation> {
    let src = conn.src_ip.as_deref()?;
    if config
        .own_scanners
        .iter()
        .any(|s| s.ip == src && conn.timestamp >= s.from && conn.timestamp <= s.to)
    {
        return Some(Explanation::OwnScan);
    }
    if !config.discovery || conn.proto != "udp" || !private(src) {
        return None;
    }
    let dst_ok = private(&conn.dst_ip) || broadcast_or_multicast(&conn.dst_ip);
    if !dst_ok {
        return None;
    }
    // Odpověď na dotaz, který příjemce sám poslal na SSDP/mDNS multicast (zdrojový port
    // odpovědi je libovolný, zařízení často odpovídá z náhodného portu).
    if private(&conn.dst_ip) && is_reply_to_own_query(conn, queries) {
        return Some(Explanation::SolicitedReply);
    }
    if conn.src_port == Some(5353) || conn.dst_port == Some(5353) {
        return Some(Explanation::Mdns);
    }
    if broadcast_or_multicast(&conn.dst_ip) {
        return Some(Explanation::Broadcast);
    }
    None
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
    let queries = collect_queries(&connections);
    let marks: Vec<Option<Explanation>> = connections
        .iter()
        .map(|conn| candidate(conn, config, &queries))
        .collect();

    // Stropy proti zneužití kategorie. Vlastní deklarovaný sken strop nemá.
    // - vyhledávání: nejvýš `max_flows_per_src_hour` toků za hodinu na zdroj,
    // - odpovědi na vlastní dotaz: nejvýš `MAX_REPLIES_PER_QUERY` odpovědí na dotaz za hodinu
    //   u daného příjemce (odpověď nemůže být početnější než dotazy, které ji vyvolaly).
    let hour_key = |ip: &str, at: DateTime<Utc>| {
        (
            ip.to_string(),
            at.date_naive().num_days_from_ce_i64(),
            at.hour(),
        )
    };
    let mut per_hour: HashMap<(String, i64, u32), usize> = HashMap::new();
    let mut replies_hour: HashMap<(String, i64, u32), usize> = HashMap::new();
    for (conn, mark) in connections.iter().zip(&marks) {
        match mark {
            Some(Explanation::OwnScan) | None => {}
            Some(Explanation::SolicitedReply) => {
                *replies_hour
                    .entry(hour_key(&conn.dst_ip, conn.timestamp))
                    .or_default() += 1;
            }
            Some(_) => {
                *per_hour
                    .entry(hour_key(
                        conn.src_ip.as_deref().unwrap_or_default(),
                        conn.timestamp,
                    ))
                    .or_default() += 1;
            }
        }
    }
    let mut queries_hour: HashMap<(String, i64, u32), usize> = HashMap::new();
    for ((ip, _), times) in &queries {
        for at in times {
            *queries_hour.entry(hour_key(ip, *at)).or_default() += 1;
        }
    }

    let mut kept = Vec::new();
    let mut explained: BTreeMap<(Explanation, String), (usize, DateTime<Utc>, String)> =
        BTreeMap::new();
    for (conn, mark) in connections.into_iter().zip(marks) {
        let over_cap = match mark {
            Some(Explanation::OwnScan) | None => false,
            Some(Explanation::SolicitedReply) => {
                let key = hour_key(&conn.dst_ip, conn.timestamp);
                let sent = queries_hour.get(&key).copied().unwrap_or(0).max(1);
                replies_hour.get(&key).copied().unwrap_or(0) > MAX_REPLIES_PER_QUERY * sent
            }
            Some(_) => {
                let key = hour_key(conn.src_ip.as_deref().unwrap_or_default(), conn.timestamp);
                per_hour.get(&key).copied().unwrap_or(0) > config.max_flows_per_src_hour
            }
        };
        match mark {
            Some(e) if !over_cap => {
                let entry = explained
                    .entry((e, conn.src_ip.clone().unwrap_or_default()))
                    .or_insert((0, conn.timestamp, conn.dst_ip.clone()));
                entry.0 += 1;
                if conn.timestamp < entry.1 {
                    entry.1 = conn.timestamp;
                }
            }
            _ => kept.push(conn),
        }
    }

    let events = explained
        .into_iter()
        .map(|((kind, src), (count, first, dst))| NormalizedEvent {
            event_id: format!("explained:{}:{src}", kind.rule()),
            timestamp: first,
            src_ip: Some(src.clone()),
            src_port: None,
            dst_ip: dst,
            proto: "udp".to_string(),
            dst_port: None,
            event_type: "explained_activity".to_string(),
            severity: Severity::Low,
            source: "known-activity".to_string(),
            rule_id: Some(kind.rule().to_string()),
            message: format!(
                "Vysvetleno, ne uzavreno: {} z {src} ({count} toku vyjmuto z detekce)",
                kind.label()
            ),
            raw_ref: None,
            count: u32::try_from(count).unwrap_or(u32::MAX),
        })
        .collect();
    (kept, events)
}

/// Obálka kolem libovolného detektoru: znamou činnost vysvětlí, zbytek pošle vnitřnímu.
pub(crate) struct KnownActivityDetector<'a> {
    pub(crate) inner: &'a (dyn ConnectionDetector + Sync),
    pub(crate) config: KnownActivityConfig,
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
        let (kept, mut summary) = split(connections, &self.config);
        let mut events = self.inner.detect(kept, known_services);
        events.append(&mut summary);
        events.sort_by_key(|event| event.timestamp);
        events
    }
}

trait DaysCe {
    fn num_days_from_ce_i64(&self) -> i64;
}

impl DaysCe for chrono::NaiveDate {
    fn num_days_from_ce_i64(&self) -> i64 {
        i64::from(chrono::Datelike::num_days_from_ce(self))
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::passive::LegacyAnomalyDetector;

    fn conn(
        src: &str,
        sport: u16,
        dst: &str,
        dport: u16,
        proto: &str,
        minute: u32,
    ) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc
                .with_ymd_and_hms(2026, 11, 20, 10, minute % 60, 0)
                .unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(sport),
            dst_ip: dst.to_string(),
            proto: proto.to_string(),
            dst_port: Some(dport),
            duration_s: None,
            orig_bytes: None,
            resp_bytes: None,
            total_bytes: None,
            orig_pkts: None,
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
                from: Utc.with_ymd_and_hms(2026, 11, 20, 9, 0, 0).unwrap(),
                to: Utc.with_ymd_and_hms(2026, 11, 20, 13, 0, 0).unwrap(),
            }],
            discovery: true,
            max_flows_per_src_hour: 5,
            headers_only_capture: true,
        }
    }

    #[test]
    fn declared_scanner_in_window_is_explained() {
        let conns = vec![conn("192.168.1.133", 40000, "192.168.1.146", 22, "tcp", 1)];
        let (kept, events) = split(conns, &config());
        assert!(kept.is_empty());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule_id.as_deref(), Some("kontext:own-scan"));
    }

    #[test]
    fn undeclared_scanner_stays_in_detection() {
        // kladna kontrola: stejny sken z jine IP se nesmi vysvetlit
        let conns = vec![conn("192.168.1.99", 40000, "192.168.1.146", 22, "tcp", 1)];
        let (kept, events) = split(conns, &config());
        assert_eq!(kept.len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn declared_scanner_outside_window_stays() {
        let mut c = conn("192.168.1.133", 40000, "192.168.1.146", 22, "tcp", 1);
        c.timestamp = Utc.with_ymd_and_hms(2026, 11, 21, 10, 0, 0).unwrap();
        let (kept, _) = split(vec![c], &config());
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn ssdp_port_without_own_query_is_not_explained() {
        // UDP ze zdrojoveho portu 1900 bez dotazu prijemce se NEvysvetluje (mohl by to byt utok)
        let c = conn("192.168.1.83", 1900, "192.168.1.133", 50000, "udp", 1);
        let (kept, events) = split(vec![c], &config());
        assert_eq!(kept.len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn ssdp_toward_external_victim_is_not_explained() {
        // zesilovaci utok: zdroj 1900 smerem ven nebo z verejne adresy
        let out = conn("192.168.1.83", 1900, "8.8.8.8", 50000, "udp", 1);
        let from_public = conn("203.0.113.5", 1900, "192.168.1.133", 50000, "udp", 1);
        let (kept, events) = split(vec![out, from_public], &config());
        assert_eq!(kept.len(), 2);
        assert!(events.is_empty());
    }

    #[test]
    fn discovery_above_hourly_cap_stays_in_detection() {
        let conns: Vec<_> = (0..10)
            .map(|i| conn("192.168.1.83", 1900, "192.168.1.133", 50000 + i, "udp", 1))
            .collect();
        let (kept, events) = split(conns, &config());
        assert_eq!(kept.len(), 10);
        assert!(events.is_empty());
    }

    #[test]
    fn broadcast_is_explained_but_tcp_to_broadcast_is_not() {
        let udp = conn("192.168.1.88", 57621, "192.168.1.255", 57621, "udp", 1);
        let tcp = conn("192.168.1.88", 40000, "192.168.1.255", 80, "tcp", 1);
        let (kept, events) = split(vec![udp, tcp], &config());
        assert_eq!(kept.len(), 1);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn reply_from_random_port_to_own_multicast_query_is_explained() {
        let query = conn("192.168.1.133", 62183, "239.255.255.250", 1900, "udp", 1);
        let reply = conn("192.168.1.232", 42822, "192.168.1.133", 62183, "udp", 2);
        let (kept, events) = split(vec![query, reply], &config());
        // dotaz na multicast je broadcast/multicast sam o sobe; odpoved je vysvetlena pres dotaz
        assert!(
            kept.iter()
                .all(|c| c.src_ip.as_deref() != Some("192.168.1.232"))
        );
        assert!(
            events
                .iter()
                .any(|e| e.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn reply_flood_far_above_query_count_is_not_explained() {
        let mut conns = vec![conn(
            "192.168.1.133",
            62183,
            "239.255.255.250",
            1900,
            "udp",
            1,
        )];
        for i in 0..50u16 {
            conns.push(conn(
                "192.168.1.232",
                40000 + i,
                "192.168.1.133",
                62183,
                "udp",
                2,
            ));
        }
        let (kept, _) = split(conns, &config());
        assert!(
            kept.iter()
                .filter(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
                .count()
                == 50
        );
    }

    #[test]
    fn udp_to_port_without_prior_query_is_not_explained_as_reply() {
        let reply = conn("192.168.1.232", 42822, "192.168.1.133", 62183, "udp", 2);
        let (kept, events) = split(vec![reply], &config());
        assert_eq!(kept.len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn reply_long_after_query_is_not_explained() {
        let query = conn("192.168.1.133", 62183, "239.255.255.250", 1900, "udp", 1);
        let mut late = conn("192.168.1.232", 42822, "192.168.1.133", 62183, "udp", 2);
        late.timestamp = Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap();
        let (kept, _) = split(vec![query, late], &config());
        assert!(
            kept.iter()
                .any(|c| c.src_ip.as_deref() == Some("192.168.1.232"))
        );
    }

    #[test]
    fn headers_only_capture_strips_missed_bytes() {
        let c = conn("192.168.1.99", 40000, "192.168.1.146", 22, "tcp", 1);
        let (kept, _) = split(vec![c], &config());
        assert_eq!(kept[0].missed_bytes, None);
    }

    #[test]
    fn wrapper_keeps_unexplained_for_inner_detector_and_adds_summary() {
        let detector = KnownActivityDetector {
            inner: &LegacyAnomalyDetector,
            config: config(),
        };
        let own: Vec<_> = (0..30)
            .map(|i| {
                conn(
                    "192.168.1.133",
                    40000 + i,
                    "192.168.1.146",
                    1000 + i,
                    "tcp",
                    1,
                )
            })
            .collect();
        let events = detector.detect(own, &HashSet::new());
        assert!(events.iter().all(|e| e.event_type == "explained_activity"));
        assert_eq!(events.len(), 1);
    }
}
