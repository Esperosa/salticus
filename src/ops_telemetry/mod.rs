//! Krok 14, část C2: provozní telemetrie jako vstup enginu (docs/diplomka/eval/impl-krok14.md).
//!
//! Engine dosud poznal poruchu jen ze vzoru v tocích (E1 až E3 v `ops_evidence`). Profesionální
//! NMS poznává poruchu z veličin, které síť sama neukazuje: SNMP (IF-MIB, EtherLike-MIB),
//! syslog, DHCP a DNS logy, NTP offset, health-check, certifikáty, zálohy a replikace.
//! Tento modul:
//! - `OpsSignal`: normalizovaný signál (klíč, váha, rozsah platnosti, čas),
//! - `adapters`: odolné parsery nedůvěryhodného vstupu (syslog, SNMP, Prometheus, Nagios, DHCP, chrony, ARP),
//! - `OpsStore`: okenní sklad s limity a evidencí pokrytí zdrojů,
//! - `diagnose`: shoda signálů s typy katalogu (`data/incident-catalog.json`, pole `ops_signals`).
//!
//! Pravidla (předregistrace C1 až C13): porucha se nikdy nezavírá jen proto, že není útok;
//! diagnóza je anotace a zařazení do fronty, ne uzavření; bez telemetrie se hlásí „nelze určit,
//! chybí telemetrie X“; útokové typy nálezů se na poruchu nepřeřazují (jen se poznamená, že
//! signály poruchy v okně existují).

pub mod adapters;
pub mod persist;

use std::collections::{HashMap, HashSet, VecDeque};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::incident_catalog::Catalog;

/// Zdroj telemetrie (kvůli pokrytí a hlášení „chybí telemetrie X“).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OpsSource {
    Snmp,
    Syslog,
    Dhcp,
    Dns,
    Arp,
    Ntp,
    Probe,
}

impl OpsSource {
    pub const ALL: [OpsSource; 7] = [
        OpsSource::Snmp,
        OpsSource::Syslog,
        OpsSource::Dhcp,
        OpsSource::Dns,
        OpsSource::Arp,
        OpsSource::Ntp,
        OpsSource::Probe,
    ];

    pub fn label(self) -> &'static str {
        match self {
            OpsSource::Snmp => "snmp",
            OpsSource::Syslog => "syslog",
            OpsSource::Dhcp => "dhcp",
            OpsSource::Dns => "dns",
            OpsSource::Arp => "arp",
            OpsSource::Ntp => "ntp",
            OpsSource::Probe => "probe",
        }
    }
}

/// Zdroj, který signál nese, podle klíče (slovník katalogu).
pub fn source_of(key: &str) -> OpsSource {
    if key.starts_with("dhcp_") {
        OpsSource::Dhcp
    } else if key.starts_with("dns_") {
        OpsSource::Dns
    } else if key.starts_with("arp_") {
        OpsSource::Arp
    } else if key.starts_with("ntp_") {
        OpsSource::Ntp
    } else if key.starts_with("probe_") || key == "cert_new_issuer" {
        OpsSource::Probe
    } else if key.starts_with("sys_") || key == "backup_running_long" {
        OpsSource::Syslog
    } else {
        OpsSource::Snmp
    }
}

/// Jeden normalizovaný signál. `scope` jsou IP adresy nebo CIDR, jichž se týká; `*` = celá síť.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpsSignal {
    pub at: i64,
    pub key: String,
    pub value: f64,
    pub scope: Vec<String>,
}

/// Meze nedůvěryhodného vstupu.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_signals: usize,
    pub max_scope: usize,
    pub max_key: usize,
    pub future_s: i64,
    pub max_age_s: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_signals: 50_000,
            max_scope: 16,
            max_key: 48,
            future_s: 3600,
            max_age_s: 24 * 3600,
        }
    }
}

fn valid_key(key: &str, max: usize) -> bool {
    !key.is_empty()
        && key.len() <= max
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Okenní sklad signálů s evidencí pokrytí zdrojů.
#[derive(Debug, Clone, Default)]
pub struct OpsStore {
    limits: Limits,
    signals: VecDeque<OpsSignal>,
    last_seen: HashMap<OpsSource, i64>,
    pub rejected: u64,
    pub evicted: u64,
}

impl OpsStore {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Doba, po kterou zdroj platí za živý (bez heartbeatu = tichý).
    pub const ALIVE_S: i64 = 3 * 3600;

    /// Signál zdroje „vše v pořádku“: jen eviduje pokrytí.
    pub fn heartbeat(&mut self, source: OpsSource, at: i64) {
        let e = self.last_seen.entry(source).or_insert(at);
        if at > *e {
            *e = at;
        }
    }

    pub fn ingest(&mut self, signal: OpsSignal, now: i64) -> bool {
        if !valid_key(&signal.key, self.limits.max_key)
            || !signal.value.is_finite()
            || signal.scope.len() > self.limits.max_scope
            || signal.at > now + self.limits.future_s
            || signal.at < now - self.limits.max_age_s
        {
            self.rejected += 1;
            return false;
        }
        self.heartbeat(source_of(&signal.key), signal.at);
        if self.signals.len() >= self.limits.max_signals {
            self.signals.pop_front();
            self.evicted += 1;
        }
        self.signals.push_back(signal);
        true
    }

    pub fn prune(&mut self, now: i64) {
        let cut = now - self.limits.max_age_s;
        while self.signals.front().is_some_and(|s| s.at < cut) {
            self.signals.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.signals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    /// Zdroje, které v posledních `ALIVE_S` neposlaly nic (ani heartbeat).
    pub fn silent_sources(&self, now: i64) -> Vec<OpsSource> {
        OpsSource::ALL
            .iter()
            .copied()
            .filter(|s| {
                self.last_seen
                    .get(s)
                    .is_none_or(|t| now - *t > Self::ALIVE_S)
            })
            .collect()
    }

    /// CIDR rozsahy signálů daného klíče, které se týkají `ips` v okně.
    fn subnet_roots(&self, ips: &[String], keys: &[&str], from: i64, to: i64) -> Vec<String> {
        let mut out: Vec<String> = self
            .matching(ips, from, to)
            .filter(|s| keys.contains(&s.key.as_str()))
            .flat_map(|s| s.scope.iter().filter(|t| t.contains('/')).cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn matching<'a>(
        &'a self,
        ips: &'a [String],
        from: i64,
        to: i64,
    ) -> impl Iterator<Item = &'a OpsSignal> + 'a {
        let parsed: Vec<std::net::IpAddr> = ips.iter().filter_map(|i| i.parse().ok()).collect();
        self.signals.iter().filter(move |s| {
            s.at >= from && s.at <= to && s.scope.iter().any(|t| scope_hits(t, ips, &parsed))
        })
    }
}

fn scope_hits(token: &str, raw: &[String], parsed: &[std::net::IpAddr]) -> bool {
    if token == "*" {
        return true;
    }
    if raw.iter().any(|r| r == token) {
        return true;
    }
    if token.contains('/')
        && let Ok(net) = token.parse::<IpNet>()
    {
        return parsed.iter().any(|ip| net.contains(ip));
    }
    false
}

/// IPv4 adresy zmíněné v textu (nález nese hosty v `host_key`, titulku a důkazech).
pub fn ips_in(text: &str, out: &mut Vec<String>) {
    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if tok.len() >= 7 && tok.len() <= 15 && tok.parse::<std::net::Ipv4Addr>().is_ok() {
            out.push(tok.to_string());
        }
    }
}

/// Typy nálezů, které smí být vysvětleny poruchou (dostupnost, objem, nečekaný provoz).
/// Útokové typy (signatury, skeny, hádání hesel, C2) se nikdy nepřeřazují.
const COMPATIBLE: &[&str] = &[
    "connection_timeout_burst",
    "service_unreachable",
    "service_overload_risk",
    "unexpected_traffic",
    "unmapped_passive_event",
    "packet_rate_spike",
    "inductive_volume_anomaly",
    "broadcast_storm",
    "dns_anomaly",
    "device_disappeared",
    "new_device",
    "egress_volume_anomaly",
    "ingest_volume_anomaly",
    "novel_peer_burst",
    "novel_burst_peer",
    "peer_burst",
    "tls_novel_burst",
    "retry_storm",
    "vpn_reconnect_storm",
];

pub fn compatible_type(finding_type: &str) -> bool {
    COMPATIBLE.contains(&finding_type)
}

/// Behaviorální typy (nový partner, rozptyl cílů, pravidelný maják, pokusy o sken): útok i porucha
/// nebo změna je dělají; přeřadí se jen při silné shodě (viz `diagnose`). Signaturní a neznámé
/// typy se nepřeřazují nikdy (fail closed).
const BEHAVIORAL: &[&str] = &[
    "novel_persistent_peer",
    "novel_fanout",
    "beacon_periodic",
    "scan_attempts",
    "multi_target_pattern",
    "pivot_chain",
    "novel_burst",
];

pub fn behavioral_type(finding_type: &str) -> bool {
    BEHAVIORAL.contains(&finding_type)
}

/// Typy, jejichž podstatou je nedostupnost nebo přetížení: bez telemetrie je třeba říct, že
/// poruchu nelze vyloučit (i bez tokového vzoru E1 až E3).
const AVAILABILITY: &[&str] = &[
    "service_unreachable",
    "connection_timeout_burst",
    "service_overload_risk",
    "broadcast_storm",
    "retry_storm",
    "vpn_reconnect_storm",
    "packet_loss_signal",
];

/// Zdroje, bez nichž se porucha dostupnosti nedá vyloučit.
const PRIMARY: [OpsSource; 2] = [OpsSource::Snmp, OpsSource::Syslog];

/// Výsledek diagnózy jednoho nálezu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpsDiagnosis {
    /// `utok` (žádný provozní důkaz), `porucha`, `zmena`, `nejednoznacne`, `neurceno`.
    pub class: String,
    pub catalog_id: Option<String>,
    pub score: f64,
    pub margin: f64,
    /// Klíče signálů, které shodu nesou.
    pub evidence: Vec<String>,
    /// Další kandidáti (id, skóre).
    pub alternatives: Vec<(String, f64)>,
    /// Zdroje, jejichž telemetrie chybí (jen u `neurceno`).
    pub missing: Vec<String>,
    pub reason: String,
    /// Útokový typ nálezu, ale v okně jsou signály poruchy: jen poznámka, zařazení zůstává `utok`.
    pub explains_partly: bool,
    /// Společná příčina: podsíť (CIDR), které se týká nejsilnější signál shody; nálezy téže podsítě
    /// ve stejném okně mají společný kořen (seskupení incidentů).
    #[serde(default)]
    pub root: Option<String>,
}

impl OpsDiagnosis {
    fn plain(class: &str, reason: &str) -> Self {
        Self {
            class: class.to_string(),
            catalog_id: None,
            score: 0.0,
            margin: 0.0,
            evidence: Vec::new(),
            alternatives: Vec::new(),
            missing: Vec::new(),
            reason: reason.to_string(),
            explains_partly: false,
            root: None,
        }
    }
}

impl OpsDiagnosis {
    /// Záznam pro UI a report: třída, typ z katalogu, příčina a doporučená kontrola.
    pub fn note(&self, catalog: &Catalog) -> crate::incident_catalog::CatalogNote {
        let e = self.catalog_id.as_deref().and_then(|id| catalog.get(id));
        crate::incident_catalog::CatalogNote {
            class: self.class.clone(),
            id: self.catalog_id.clone(),
            name: e.map(|e| e.name.clone()),
            cause: e.map(|e| e.cause.clone()),
            check: e
                .map(|e| e.recommended_check.clone())
                .or_else(|| (self.class == "neurceno").then(|| self.reason.clone())),
        }
    }
}

/// Prahy diagnózy (volba autora před prvním měřením; zapsané v impl-krok14.md).
#[derive(Debug, Clone)]
pub struct DiagPolicy {
    pub window_s: i64,
    pub min_score: f64,
    pub min_margin: f64,
    /// Prahy pro behaviorální typy nálezů (přísnější).
    pub strict_score: f64,
    pub strict_margin: f64,
}

impl Default for DiagPolicy {
    fn default() -> Self {
        Self {
            window_s: 3 * 3600,
            min_score: 0.45,
            min_margin: 0.10,
            strict_score: 0.65,
            strict_margin: 0.15,
        }
    }
}

/// Předpočítaný index katalogu: klíč -> (typ, váha) a idf klíče.
pub struct Index {
    by_entry: Vec<(String, String, Vec<(String, f64)>, f64)>, // id, kategorie, (klíč, w*idf), součet
    idf: HashMap<String, f64>,
}

impl Index {
    pub fn build(catalog: &Catalog) -> Self {
        let n = catalog.incidents.len().max(1) as f64;
        let mut df: HashMap<&str, usize> = HashMap::new();
        for e in &catalog.incidents {
            let keys: HashSet<&str> = e.ops_signals.iter().map(|(k, _)| k.as_str()).collect();
            for k in keys {
                *df.entry(k).or_default() += 1;
            }
        }
        let idf: HashMap<String, f64> = df
            .iter()
            .map(|(k, d)| ((*k).to_string(), (1.0 + n / *d as f64).ln()))
            .collect();
        let by_entry = catalog
            .incidents
            .iter()
            .filter(|e| !e.ops_signals.is_empty())
            .map(|e| {
                let v: Vec<(String, f64)> = e
                    .ops_signals
                    .iter()
                    .map(|(k, w)| (k.clone(), *w as f64 * idf.get(k).copied().unwrap_or(1.0)))
                    .collect();
                let total = v.iter().map(|(_, x)| x).sum();
                (e.id.clone(), e.category.clone(), v, total)
            })
            .collect();
        Self { by_entry, idf }
    }

    pub fn shared() -> &'static Index {
        static INDEX: std::sync::OnceLock<Index> = std::sync::OnceLock::new();
        INDEX.get_or_init(|| Index::build(Catalog::shared()))
    }

    pub fn known(&self, key: &str) -> bool {
        self.idf.contains_key(key)
    }
}

/// Diagnóza nálezu typu `finding_type`, který se týká adres `ips`, k času `now`.
/// `flow_fault_like` = vzor v tocích (E1 až E3) už poruchu naznačuje.
pub fn diagnose(
    index: &Index,
    store: &OpsStore,
    finding_type: &str,
    ips: &[String],
    flow_fault_like: bool,
    now: i64,
    policy: &DiagPolicy,
) -> OpsDiagnosis {
    let present: HashSet<&str> = store
        .matching(ips, now - policy.window_s, now)
        .map(|s| s.key.as_str())
        .collect();
    let compatible = compatible_type(finding_type);
    let behavioral = behavioral_type(finding_type);
    if present.is_empty() {
        let silent: Vec<String> = store
            .silent_sources(now)
            .into_iter()
            .filter(|s| flow_fault_like || PRIMARY.contains(s))
            .map(|s| s.label().to_string())
            .collect();
        // bez signálu: ticho zdrojů je slepé místo jen tehdy, když tok sám naznačuje poruchu
        // nebo když jde o typ nedostupnosti a chybí primární zdroj (SNMP, syslog)
        let fault_like = flow_fault_like || AVAILABILITY.contains(&finding_type);
        if compatible && fault_like && !silent.is_empty() {
            let mut d = OpsDiagnosis::plain("neurceno", "nelze určit, chybí telemetrie");
            d.reason = format!("nelze určit, chybí telemetrie: {}", silent.join(", "));
            d.missing = silent;
            return d;
        }
        return OpsDiagnosis::plain("utok", "bez provozního důkazu");
    }
    // skóre: podíl důkazu, který je přítomen, proti důkazu, který u ŽIVÉHO zdroje chybí
    // (signál ze zdroje bez telemetrie typ nevyvrací; slabé signály (váha 1) chybět smí)
    let silent: HashSet<OpsSource> = store.silent_sources(now).into_iter().collect();
    let mut ranked: Vec<(f64, &str, &str, Vec<&str>)> = Vec::new();
    for (id, cat, sig, _total) in &index.by_entry {
        let top = sig
            .iter()
            .map(|(k, x)| x / index.idf.get(k).copied().unwrap_or(1.0))
            .fold(0.0, f64::max);
        let mut hit = 0.0;
        let mut miss = 0.0;
        let mut keys = Vec::new();
        let mut strong = false;
        for (k, x) in sig {
            let idf = index.idf.get(k).copied().unwrap_or(1.0);
            let w = x / idf;
            if present.contains(k.as_str()) {
                hit += x;
                keys.push(k.as_str());
                strong |= w >= top - 1e-9;
            } else if w >= 2.0 - 1e-9 && !silent.contains(&source_of(k)) {
                miss += 0.5 * x;
            }
        }
        if hit > 0.0 && strong {
            ranked.push((hit / (hit + miss), id.as_str(), cat.as_str(), keys));
        }
    }
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(b.1)));
    let any_known = present.iter().any(|k| index.known(k));
    let Some(best) = ranked.first() else {
        return if compatible {
            OpsDiagnosis::plain(
                "neurceno",
                "signály bez shody v katalogu (typ mimo katalog)",
            )
        } else {
            let mut d = OpsDiagnosis::plain("utok", "bez provozního důkazu");
            d.explains_partly = any_known;
            d
        };
    };
    let second = ranked.get(1).map_or(0.0, |r| r.0);
    let mut d = OpsDiagnosis::plain("utok", "");
    d.score = best.0;
    d.margin = best.0 - second;
    d.evidence = best.3.iter().map(|s| s.to_string()).collect();
    d.alternatives = ranked
        .iter()
        .skip(1)
        .take(3)
        .map(|r| (r.1.to_string(), r.0))
        .collect();
    // behaviorální typ se přeřadí jen při silné shodě (víc signálů nebo typ s ≤ 2 signály)
    let strict_ok = behavioral && {
        let total_signals = index
            .by_entry
            .iter()
            .find(|e| e.0 == best.1)
            .map_or(usize::MAX, |e| e.2.len());
        best.0 >= policy.strict_score
            && d.margin >= policy.strict_margin
            && (best.3.len() >= 2 || total_signals <= 2)
    };
    if !compatible && !strict_ok {
        d.explains_partly = best.0 >= policy.min_score;
        d.reason = "útokový typ nálezu, signály poruchy jen jako poznámka".into();
        d.evidence.clear();
        return d;
    }
    if best.0 < policy.min_score {
        d.class = "neurceno".into();
        d.reason = "slabá shoda s katalogem".into();
        return d;
    }
    d.catalog_id = Some(best.1.to_string());
    d.class = match best.2 {
        "porucha" => "porucha",
        "neskodna_zmena" => "zmena",
        _ => "nejednoznacne",
    }
    .into();
    if d.margin < policy.min_margin {
        // dva typy se signály téměř neliší: třída zůstává, přesný typ ne
        d.reason = "více typů s podobnou shodou".into();
        let same = ranked.iter().take(2).all(|r| r.2 == best.2);
        if !same {
            d.class = "nejednoznacne".into();
        }
        d.catalog_id = if same { d.catalog_id } else { None };
        return d;
    }
    d.reason = "shoda signálů s typem katalogu".into();
    d.root = store
        .subnet_roots(ips, &best.3, now - policy.window_s, now)
        .into_iter()
        .next();
    d
}

#[cfg(test)]
mod tests;
