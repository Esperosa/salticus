//! Žebřík okamžitého ověřování (krok 2B; 00-zaver Dodatek A.3, §5.b R10, RQ3, RQ6).
//!
//! Hypotéza = otevřený behaviorální nález (jeden případ na stabilní klíč nálezu,
//! idempotentně: nový plán jen pro nový, znovuotevřený nebo eskalovaný stav, ne pro
//! každý nález v každém cyklu; dřív 90,6 % plánů mimo rozpočet, D5/A24).
//!
//! Sekvenční ověřování (RQ3 Z1, nízká až střední jistota): stav hypotézy je
//! log-šance, každá kontrola přičte ln věrohodnostního poměru (LR) a po KAŽDÉ kontrole
//! se testují pravidla zastavení:
//! - potvrzeno: p ≥ `p_confirm`,
//! - vyvráceno: p ≤ `p_refute` A aspoň jeden doložený neškodný důkaz (LR < 1);
//!   prázdný výsledek dotazu NENÍ důkaz neškodnosti, je to stav „nezjištěno“
//!   (RQ6 Z3: prázdné vyhledávání souvisí se zamítnutím útoku v 98,6 % případů),
//! - eskalace člověku: strop počtu kontrol (`max_checks`, RQ3 Z3: bez stropu zůstává
//!   přes 80 % nerozhodnuto, strop sám nerozhodnutost neřeší), vyčerpaný plán nebo
//!   opakovaně chybějící rozpočet.
//!
//! Úrovně od nejlevnější a nejbezpečnější (Dodatek A.3, pořadí v A.4):
//! - L0 uložená historie toků („stalo se to už dřív?“, `flow_history`),
//! - L1 kontext a reputace (kalendář, reputace zdroje, KEV/EPSS cílové služby, typ
//!   zařízení), v simulaci s neúplným pokrytím,
//! - L2 cílené pasivní přezkoumání (další cykly a srovnání s peer skupinou),
//! - L3 aktivní kontrola (`verification_exec`: rozsah, schválení, rozpočet; křehká
//!   zařízení jen se schválením, RQ3 Z10),
//! - L4 pivot po souvisejících zařízeních (komunikační hrany, hloubka ≤ 3, jen v rozsahu).
//!
//! Pořadí: globálně podle EVOI proxy = dopad × entropie víry / cena kontroly (RQ3 Z12,
//! jen simulace, nízká jistota), část výběru (`explore`) se losuje a pořadí kontrol
//! uvnitř úrovně je náhodné s tajným klíčem (RQ3 Z11: předvídatelné pořadí je
//! zneužitelné). Dřív rozhodovala abeceda `finding_id` (audit A23).
//!
//! LR v `LrTable` jsou volba autora (kvalitativní síla důkazu), ne odhad z dat; jejich
//! správnost se měří (přesnost rozhodnutí, zavřeno omylem) a učí se v kroku 2C.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    device_class::{DeviceClass, DeviceKind},
    finding_memory::FindingKey,
    flow_history::Recurrence,
};

/// Výchozí apriorní pravděpodobnost útoku u behaviorálního nálezu bez naučeného
/// odhadu (volba autora; v kroku 2C ji nahrazuje kalibrovaný odhad Case Memory).
pub const DEFAULT_PRIOR: f64 = 0.15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::L0 => "L0",
            Level::L1 => "L1",
            Level::L2 => "L2",
            Level::L3 => "L3",
            Level::L4 => "L4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    /// L0: stalo se to už dřív (stejná hodina, předchozí dny)?
    History,
    /// L1: schválený kontext (kalendář, CMDB, registr skenerů).
    Context,
    /// L1: reputace dominantního zdroje.
    Reputation,
    /// L1: zranitelnost cílové služby (CISA KEV, EPSS z intel modulu).
    Intel,
    /// L1: služba nebo chování neobvyklé pro typ zařízení.
    DeviceProfile,
    /// L2: srovnání s peer skupinou (stejný typ zařízení a podsíť) v tomtéž okně.
    Peers,
    /// L2: přetrvá jev v dalších cyklech (čeká se)?
    Persistence,
    /// L3: aktivní kontrola dostupnosti služby.
    Liveness,
    /// L4: podezřelé nálezy na souvisejících zařízeních.
    Pivot,
    /// L0: naučený profil hostu (obvyklý cíl a port, flotila; krok 3E).
    Profile,
    /// L1: koncová telemetrie hostu (krok 8): podezřelý proces zvyšuje jistotu, známý
    /// podepsaný proces s pravidelným vzorem je slabý neškodný důkaz (nikdy sám nezavře).
    Endpoint,
    /// Krok 12: TLS a DNS metadata hosta (novy cil, otisk klienta, certifikat).
    L7,
    /// Krok 14: provozní telemetrie (SNMP, syslog, DHCP, DNS, NTP, probes): shoda s typem poruchy
    /// nebo změny z katalogu je důkaz hypotézy „porucha“, nikdy sama nezavře nález.
    Ops,
}

impl CheckId {
    pub fn level(self) -> Level {
        match self {
            CheckId::History | CheckId::Profile => Level::L0,
            CheckId::Context
            | CheckId::Reputation
            | CheckId::Intel
            | CheckId::DeviceProfile
            | CheckId::Endpoint
            | CheckId::L7
            | CheckId::Ops => Level::L1,
            CheckId::Peers | CheckId::Persistence => Level::L2,
            CheckId::Liveness => Level::L3,
            CheckId::Pivot => Level::L4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CheckId::History => "history",
            CheckId::Context => "context",
            CheckId::Reputation => "reputation",
            CheckId::Intel => "intel",
            CheckId::DeviceProfile => "device_profile",
            CheckId::Peers => "peers",
            CheckId::Persistence => "persistence",
            CheckId::Liveness => "liveness",
            CheckId::Pivot => "pivot",
            CheckId::Profile => "profile",
            CheckId::Endpoint => "endpoint",
            CheckId::L7 => "l7",
            CheckId::Ops => "ops",
        }
    }
}

/// Výsledek jedné kontroly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    /// Důkaz s věrohodnostním poměrem P(o|útok)/P(o|neškodné).
    Evidence { lr: f64, detail: String },
    /// Kontrola nic nezjistila (prázdný dotaz, chybí pokrytí): bez změny víry.
    Undetermined(String),
    /// Kontrolu nešlo provést (mimo rozsah, čeká na schválení, selhání).
    Unavailable(String),
    /// Kontrola potřebuje čas: znovu v cyklu `until`.
    Wait(u64),
}

/// Reputace adresy z poskytovatele (neúplná: `Unknown` je nejčastější).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    Bad(String),
    Good(String),
    Unknown,
}

/// Zranitelnost cílové služby.
#[derive(Debug, Clone, PartialEq)]
pub enum IntelSignal {
    KnownExploited(String),
    HighEpss(f64),
    NothingKnown,
}

/// Výsledek aktivní kontroly dostupnosti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    Up,
    Down,
    NeedsApproval,
    OutOfScope,
    Failed(String),
}

/// Přetrvání jevu (L2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistence {
    /// Jev se opakoval v `cycles` cyklech; `same_source` = s týmž dominantním zdrojem.
    Recurring {
        cycles: u32,
        same_source: bool,
    },
    Gone,
}

/// Vstup případu (z nálezu a paměti nálezů).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseInput {
    pub key: FindingKey,
    pub finding_id: String,
    pub finding_type: String,
    /// IP entity nálezu (cíl; u zdrojových typů zdroj).
    pub host_ip: String,
    pub port: Option<u16>,
    /// Dominantní zdroje nálezu.
    pub sources: Vec<String>,
    /// Objem pozorování (pro L0 srovnání s historií).
    pub volume: f64,
    /// Klíč metriky v `flow_history` (None = L0 neplatí).
    pub history_key: Option<String>,
    pub high_impact: bool,
    /// Apriorní pravděpodobnost útoku (Case Memory nebo výchozí).
    pub prior: f64,
    /// Krok 7 (A1): chráněný případ (P4 degradace, P5 nejednoznačnost; typy P1 až P3
    /// se poznají podle typu). S `LadderPolicy::protect` se nikdy nevyvrátí.
    #[serde(default)]
    pub protected: bool,
}

impl CaseInput {
    /// Chráněný případ (typ nebo signál cyklu).
    pub fn is_protected(&self) -> bool {
        self.protected || crate::protection::is_protected_type(&self.finding_type)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Confirmed,
    Refuted,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub check: CheckId,
    pub cycle: u64,
    pub outcome: Outcome,
    pub posterior: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub input: CaseInput,
    pub opened: u64,
    log_odds: f64,
    plan: VecDeque<CheckId>,
    pub steps: Vec<Step>,
    wait_until: Option<u64>,
    deferred: u32,
    pub status: Status,
    benign_evidence: bool,
    /// Krok 12: nezávislé skupiny neškodného důkazu (`benign_group`), pro přísné vyvrácení.
    #[serde(default)]
    benign_groups: std::collections::BTreeSet<u8>,
    /// Krok 12: pozorování pro režim konkurenčních hypotéz (`policy.competing`).
    #[serde(default)]
    obs: Vec<crate::competing::Obs>,
    #[serde(default)]
    use_competing: bool,
    #[serde(default)]
    susp_groups: std::collections::BTreeSet<u8>,
    /// Cykly po otevření, ve kterých se nález znovu objevil (L2 přetrvání).
    #[serde(default)]
    seen_after_open: u32,
    #[serde(default)]
    same_source_seen: bool,
    #[serde(default)]
    last_seen_cycle: u64,
}

impl Case {
    pub fn posterior(&self) -> f64 {
        if self.use_competing {
            return crate::competing::posterior_attack(
                self.input.prior,
                &self.obs,
                crate::competing::measured_static(),
            );
        }
        1.0 / (1.0 + (-self.log_odds).exp())
    }
}

/// Rozhodnutí případu (zapisuje se do paměti nálezů a auditu).
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub key: FindingKey,
    pub finding_id: String,
    pub finding_type: String,
    pub status: Status,
    pub host_ip: String,
    /// Pravděpodobnost útoku při rozhodnutí (po kalibraci, pokud je zapnutá).
    pub posterior: f64,
    /// Surová posteriora (bez kalibrace), pro kalibrační křivku.
    pub raw_posterior: f64,
    pub opened: u64,
    pub decided: u64,
    /// Proč (kontroly s výsledkem), pro audit a UI.
    pub reason: String,
    pub checks: usize,
    pub budget_escalation: bool,
    /// Vysoký dopad: zobrazeno už při otevření.
    pub high_impact: bool,
    /// Krok 7: chráněný případ (s protect), zobrazen už při otevření.
    pub protected: bool,
    /// Provedené kontroly a značka výsledku (pro měření a učení LR, krok 2C).
    pub steps: Vec<(CheckId, &'static str)>,
    /// Krok 16: kroky s cyklem, poměrem věrohodnosti a textem (podklad případové složky).
    pub notes: Vec<StepNote>,
    /// Krok 18: případ by se potvrdil, ale chybí pozitivní důkaz z nezávislého zdroje
    /// (`LadderPolicy::confirm_evidence`); předán člověku jako „nepotvrzeno, čeká na kontrolu“.
    pub prior_hold: bool,
    /// Krok 18: kontrola, na kterou nepotvrzený případ čeká (`None` = jen ruční ověření).
    pub pending_check: Option<CheckId>,
}

/// Krok 16: jeden provedený krok žebříku pro případovou složku (nic nerozhoduje).
#[derive(Debug, Clone, PartialEq)]
pub struct StepNote {
    pub check: CheckId,
    pub cycle: u64,
    pub tag: &'static str,
    /// Poměr věrohodnosti u výsledku `Evidence`, jinak `None`.
    pub lr: Option<f64>,
    pub detail: String,
}

/// Rozhodnutí v reportu (UI, API, audit).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub finding_id: String,
    pub finding_type: String,
    pub status: Status,
    pub posterior: f64,
    pub checks: usize,
    pub reason: String,
}

impl From<&Decision> for DecisionRecord {
    fn from(d: &Decision) -> Self {
        Self {
            finding_id: d.finding_id.clone(),
            finding_type: d.finding_type.clone(),
            status: d.status,
            posterior: d.posterior,
            checks: d.checks,
            reason: d.reason.clone(),
        }
    }
}

/// Záznam reputačního zdroje (`reputation.json` ve workspace): síť, verdikt, zdroj,
/// expirace. Plní člověk nebo import feedu (Pásmo B); chybějící soubor = vše neznámé.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationEntry {
    pub net: ipnet::IpNet,
    /// `bad` | `good`
    pub verdict: String,
    pub source: String,
    pub expires: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct StaticReputation {
    entries: Vec<ReputationEntry>,
}

impl StaticReputation {
    pub fn new(entries: Vec<ReputationEntry>) -> Self {
        Self { entries }
    }

    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let entries: Vec<ReputationEntry> =
            serde_json::from_str(&text).map_err(crate::error::SalticusError::Json)?;
        Ok(Self::new(entries))
    }

    /// Nejužší platná shoda; vypršelé záznamy se ignorují.
    pub fn lookup(&self, ip: &str, at: chrono::DateTime<chrono::Utc>) -> Reputation {
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return Reputation::Unknown;
        };
        self.entries
            .iter()
            .filter(|e| e.expires > at && e.net.contains(&addr))
            .max_by_key(|e| e.net.prefix_len())
            .map(|e| match e.verdict.as_str() {
                "bad" => Reputation::Bad(e.source.clone()),
                "good" => Reputation::Good(e.source.clone()),
                _ => Reputation::Unknown,
            })
            .unwrap_or(Reputation::Unknown)
    }
}

/// Věrohodnostní poměry (volba autora, kvalitativní síla důkazu; měří se v A/B).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LrTable {
    pub history_seen: f64,
    pub history_new: f64,
    pub context: f64,
    pub reputation_bad: f64,
    pub reputation_good: f64,
    pub intel_kev: f64,
    pub intel_epss: f64,
    pub device_unusual: f64,
    pub peers_widespread: f64,
    pub peers_isolated: f64,
    pub persistence_same_source: f64,
    pub persistence_recurring: f64,
    pub liveness_down_outage: f64,
    pub liveness_up_unreachable: f64,
    pub pivot_per_hit: f64,
    /// Krok 3E: zvyk zavedený u hostu, u flotily, nový cíl zralého profilu.
    pub profile_host: f64,
    pub profile_fleet: f64,
    pub profile_new: f64,
    /// Krok 8: podezřelý proces na hostu případu, pravidelný známý podepsaný proces.
    pub endpoint_suspicious: f64,
    pub endpoint_benign: f64,
    /// Krok 14: proces ze seznamu povolených (hash, podpis, výrobce, protistrana, vlastník, expirace).
    pub endpoint_allow: f64,
    /// Krok 12: TLS a DNS metadata: novy cil s druhym rysem, znamy cil a otisk.
    pub l7_suspicious: f64,
    pub l7_benign: f64,
    /// Krok 14: shoda signálů s typem poruchy nebo změny z katalogu (slabý důkaz, sám nevyvrací).
    pub ops_fault: f64,
}

impl Default for LrTable {
    fn default() -> Self {
        Self {
            history_seen: 0.25,
            history_new: 2.0,
            context: 0.3,
            reputation_bad: 8.0,
            reputation_good: 0.4,
            intel_kev: 3.0,
            intel_epss: 1.8,
            device_unusual: 2.5,
            peers_widespread: 0.25,
            peers_isolated: 1.3,
            persistence_same_source: 2.0,
            persistence_recurring: 1.4,
            liveness_down_outage: 0.15,
            liveness_up_unreachable: 1.5,
            pivot_per_hit: 2.0,
            profile_host: 0.2,
            profile_fleet: 0.35,
            profile_new: 1.5,
            endpoint_suspicious: 12.0,
            endpoint_benign: 0.3,
            endpoint_allow: 0.05,
            l7_suspicious: 3.0,
            l7_benign: 0.6,
            ops_fault: 0.5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LadderPolicy {
    pub p_confirm: f64,
    pub p_refute: f64,
    /// Přísnější mez vyvrácení pro vysoký dopad (Dodatek A.2 c).
    pub p_refute_high_impact: f64,
    /// Strop počtu provedených kontrol na případ (RQ3 Překlad bod 2: 3 až 10; plán
    /// má nejvýš 9 kontrol, většina jsou levné pasivní dotazy).
    pub max_checks: usize,
    /// Rozpočet ceny kontrol za cyklus a strop aktivních kontrol.
    pub budget_per_cycle: f64,
    pub active_per_cycle: usize,
    /// Podíl výběru losem (RQ3 Překlad bod 8: 10 až 20 %, extrapolace).
    pub explore: f64,
    /// Kolik cyklů se čeká na L2 přetrvání.
    pub persistence_wait: u64,
    /// Kolikrát smí případ nedostat rozpočet, než se eskaluje.
    pub max_deferred: u32,
    pub pivot_depth: usize,
    pub pivot_max_nodes: usize,
    pub max_open_cases: usize,
    pub lr: LrTable,
    /// Kontrola profilu hostu (krok 3E); vypnuto = plán jako v kroku 2.
    pub profile: bool,
    /// „Nový cíl zralého profilu“ jako podezřelý důkaz (krok 3E). Krok 4: vypnuto,
    /// empirické LR v kroku 3 vyšlo 1,03 (bez informace) a nový cíl sám potvrzoval
    /// neškodné případy (přesnost potvrzení 96,5 → 91,9 %); RQ4 Z10: nová hrana je rys.
    pub profile_new_evidence: bool,
    /// Krok 7 (A1): chráněný případ se nevyvrací (rozhodnutí jde člověku).
    pub protect: bool,
    /// Krok 8: kontrola koncové telemetrie v plánu.
    pub endpoint: bool,
    /// Krok 12: vyvrácení jen s pozitivním důkazem z ≥ 2 nezávislých skupin.
    pub strict_refute: bool,
    /// Krok 12: režim konkurenčních hypotéz (změřené věrohodnosti, rozhodnutí podle ceny omylu).
    pub competing: bool,
    /// Krok 12: kontrola TLS a DNS metadat v planu.
    pub l7: bool,
    /// Krok 14: kontrola provozní telemetrie v plánu.
    pub ops: bool,
    /// Krok 15 (P1): „nic podezřelého“ od agenta není silná skupina důkazu neškodnosti
    /// (agent může lhát); při `strict_refute` vyvrací jen s kontextem nebo živostí.
    pub endpoint_weak: bool,
    /// Krok 18: stav `Confirmed` jen s aspoň jedním pozitivním výsledkem kontroly z nezávislého
    /// zdroje (`confirm_source`); bez něj se případ předá člověku (`Decision::prior_hold`).
    pub confirm_evidence: bool,
    pub costs: crate::competing::Costs,
}

impl Default for LadderPolicy {
    fn default() -> Self {
        Self {
            p_confirm: 0.9,
            p_refute: 0.03,
            p_refute_high_impact: 0.01,
            max_checks: 8,
            budget_per_cycle: 500.0,
            active_per_cycle: 10,
            explore: 0.15,
            persistence_wait: 2,
            max_deferred: 4,
            pivot_depth: 3,
            pivot_max_nodes: 5,
            max_open_cases: 5_000,
            lr: LrTable::default(),
            profile: false,
            profile_new_evidence: false,
            strict_refute: false,
            competing: false,
            l7: false,
            ops: false,
            endpoint_weak: false,
            confirm_evidence: false,
            costs: crate::competing::Costs::default(),
            protect: false,
            endpoint: false,
        }
    }
}

fn cost(check: CheckId) -> f64 {
    match check.level() {
        Level::L0 => 0.05,
        Level::L1 => 0.1,
        Level::L2 => 0.05,
        Level::L3 => 1.0,
        Level::L4 => 0.3,
    }
}

/// Datové zdroje žebříku (produkce: SQLite, kalendář, intel, exekutor; soak: simulace).
pub trait LadderEvidence {
    fn recurrence(&self, history_key: &str, value: f64) -> Recurrence;
    fn context(&self, case: &CaseInput) -> Option<String>;
    fn reputation(&self, ip: &str) -> Reputation;
    fn intel(&self, case: &CaseInput) -> IntelSignal;
    fn device(&self, ip: &str) -> Option<DeviceClass>;
    /// (zasažení peer členové se stejným typem nálezu, velikost peer skupiny).
    fn peers(&self, case: &CaseInput) -> Option<(usize, usize)>;
    fn liveness(&mut self, case: &CaseInput) -> Liveness;
    fn neighbors(&self, ip: &str) -> Vec<String>;
    fn in_scope(&self, ip: &str) -> bool;
    /// Typy podezřelých otevřených nálezů na zařízení (pro pivot).
    fn suspicious_on(&self, ip: &str) -> usize;
    /// Naučený profil hostu pro případ (krok 3E); výchozí = nic neplyne.
    fn profile(&self, _case: &CaseInput) -> crate::behavior::profile::ProfileVerdict {
        crate::behavior::profile::ProfileVerdict::Unknown("profil neni k dispozici".into())
    }
    /// Koncová telemetrie hosta případu (krok 8); výchozí = bez pokrytí.
    fn endpoint(&self, _case: &CaseInput) -> crate::endpoint::correlate::EndpointSignal {
        crate::endpoint::correlate::EndpointSignal::NoCoverage("koncova telemetrie neni".into())
    }
    /// Krok 12: signal z TLS a DNS metadat; vychozi = bez pokryti.
    /// Krok 14: diagnóza případu podle provozní telemetrie (`None` = telemetrie není připojena).
    fn ops(&self, _case: &CaseInput) -> Option<crate::ops_telemetry::OpsDiagnosis> {
        None
    }

    fn l7(&self, _case: &CaseInput) -> crate::behavior::l7::L7Signal {
        crate::behavior::l7::L7Signal::NoCoverage("metadata TLS a DNS nejsou".into())
    }
}

/// Statistiky žebříku (pro měření a report).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LadderStats {
    pub cases_opened: u64,
    pub cases_merged: u64,
    pub checks_by_level: BTreeMap<String, u64>,
    pub outcomes: BTreeMap<String, u64>,
    pub checks_deferred: u64,
    pub cases_deferred: u64,
    pub explored: u64,
    pub confirmed: u64,
    pub refuted: u64,
    /// Krok 12: vyvrácení odmítnuto pro nedostatek pozitivního důkazu (předáno člověku).
    #[serde(default)]
    pub strict_escalated: u64,
    pub escalated: u64,
    pub escalated_budget: u64,
    pub needs_approval: u64,
    pub cases_capped: u64,
    /// Krok 7: chráněné případy, které by se vyvrátily, a šly člověku.
    pub protect_escalated: u64,
    /// Krok 18: případy, které by se potvrdily bez pozitivního důkazu z nezávislého zdroje
    /// a šly člověku jako nepotvrzené.
    #[serde(default)]
    pub prior_held: u64,
    /// Krok 18: vyvrácení odmítnutá kvůli nedávnému nepotvrzenému podezření (`HOLD_CYCLES`).
    #[serde(default)]
    pub hold_refused: u64,
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn hash_text(text: &str) -> u64 {
    mix(text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |a, b| {
        (a ^ b as u64).wrapping_mul(0x100_0000_01b3)
    }))
}

fn logit(p: f64) -> f64 {
    let p = p.clamp(1e-6, 1.0 - 1e-6);
    (p / (1.0 - p)).ln()
}

fn entropy(p: f64) -> f64 {
    let p = p.clamp(1e-9, 1.0 - 1e-9);
    -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
}

/// Kontroly, které pro typ nálezu dávají smysl (bez kontroly bez exekutoru, R10-lite).
fn checks_for(input: &CaseInput, policy: &LadderPolicy) -> Vec<CheckId> {
    let kind = input.finding_type.as_str();
    let mut checks = Vec::new();
    if input.history_key.is_some() {
        checks.push(CheckId::History);
    }
    if policy.profile {
        checks.push(CheckId::Profile);
    }
    checks.push(CheckId::Context);
    if policy.endpoint {
        checks.push(CheckId::Endpoint);
    }
    if policy.l7 {
        checks.push(CheckId::L7);
    }
    if policy.ops {
        checks.push(CheckId::Ops);
    }
    if !input.sources.is_empty() {
        checks.push(CheckId::Reputation);
    }
    if matches!(
        kind,
        "suricata_alert"
            | "source_volume_outlier"
            | "packet_rate_spike"
            | "inductive_volume_anomaly"
    ) && input.port.is_some()
    {
        checks.push(CheckId::Intel);
    }
    if matches!(
        kind,
        "unexpected_traffic" | "multi_target_pattern" | "source_volume_outlier" | "scan_attempts"
    ) {
        checks.push(CheckId::DeviceProfile);
    }
    if matches!(
        kind,
        "inductive_volume_anomaly"
            | "packet_rate_spike"
            | "unexpected_traffic"
            | "service_unreachable"
            | "connection_timeout_burst"
            | "service_overload_risk"
            | "beacon_periodic"
            | "interactive_session"
            | "long_lived_tunnel"
            | "egress_volume_anomaly"
            | "novel_persistent_peer"
            | "novel_fanout"
            | "ingest_volume_anomaly"
            | "slow_egress"
            | "link_saturation"
            | "novel_bulk_transfer"
            | "novel_peer_burst"
            | "tls_rare_transfer"
            | "tls_novel_burst"
            | "dns_zone_enumeration"
            | "dns_tunnel_names"
            | "doh_suspected"
            | "icmp_payload_anomaly"
    ) {
        checks.push(CheckId::Peers);
    }
    checks.push(CheckId::Persistence);
    if matches!(kind, "service_unreachable" | "connection_timeout_burst") && input.port.is_some() {
        checks.push(CheckId::Liveness);
    }
    if matches!(
        kind,
        "scan_attempts"
            | "multi_target_pattern"
            | "suricata_alert"
            | "source_volume_outlier"
            | "unexpected_traffic"
            | "beacon_periodic"
            | "interactive_session"
            | "long_lived_tunnel"
            | "egress_ids_alert"
            | "pivot_chain"
            | "novel_persistent_peer"
            | "novel_fanout"
    ) {
        checks.push(CheckId::Pivot);
    }
    checks
}

/// Plán kontrol: po úrovních (nejlevnější první), uvnitř úrovně náhodně podle tajného
/// klíče a klíče případu (RQ3 Z11). Přetrvání (L2) je úplně poslední: stojí čas, ne
/// zdroje, a okamžité kontroly (L3 dostupnost služby při výpadku) by po čekání
/// viděly už jiný stav.
fn plan_for(input: &CaseInput, secret: u64, policy: &LadderPolicy) -> VecDeque<CheckId> {
    let mut checks = checks_for(input, policy);
    let salt = mix(secret ^ hash_text(&input.finding_id));
    checks.sort_by_key(|check| {
        let wait_last = (*check == CheckId::Persistence) as u8;
        if policy.competing {
            // krok 12: nejdriv kontrola s nejvyssi informaci na cenu (zmerene tabulky)
            let score = competing_kind(*check)
                .map(|k| {
                    crate::competing::information_per_cost(
                        DEFAULT_PRIOR,
                        k,
                        crate::competing::measured_static(),
                    )
                })
                .unwrap_or(0.0);
            return (
                wait_last,
                0u8,
                std::cmp::Reverse((score * 1e9) as u64),
                mix(salt ^ hash_text(check.label())),
            );
        }
        (
            wait_last,
            check.level() as u8,
            std::cmp::Reverse(0u64),
            mix(salt ^ hash_text(check.label())),
        )
    });
    checks.into_iter().collect()
}

/// Značka výsledku kontroly pro měření a učení (`benign`, `malicious`, `undetermined`,
/// `unavailable`).
/// Nezávislá skupina neškodného důkazu (krok 12): 1 kontext (schválený kalendář),
/// 2 provozní příčina (dostupnost), 3 vlastní zvyk hosta (historie a profil, závislé),
/// 4 koncová telemetrie, 5 dobrá reputace. Srovnání s peery, přetrvání, intel, profil
/// zařízení a pivot se do vyvrácení nezapočítávají (v měření kroku 11 byl podíl útoků
/// mezi případy s neškodným výsledkem „peers“ 32 %).
pub fn benign_group(check: CheckId) -> Option<u8> {
    match check {
        CheckId::Context => Some(1),
        CheckId::Liveness => Some(2),
        CheckId::History | CheckId::Profile => Some(3),
        CheckId::Endpoint => Some(4),
        CheckId::Reputation => Some(5),
        _ => None,
    }
}

/// Krok 18: kontrola, jejíž podezřelý výsledek je pozitivní důkaz z nezávislého zdroje, a smí
/// tedy nést potvrzení. Nezávislý = data nepocházejí z toku, který nález vytvořil, ani z paměti
/// případů. Nepočítá se historie toků a naučený profil hostu (L0, týž tok dat jako detektor),
/// přetrvání (týž detektor znovu) a provozní telemetrie (je jen důkazem poruchy). Množina je
/// předregistrovaná v `docs/diplomka/eval/impl-krok18.md`.
pub fn confirm_source(check: CheckId) -> bool {
    match check {
        CheckId::Reputation
        | CheckId::Intel
        | CheckId::DeviceProfile
        | CheckId::Peers
        | CheckId::Liveness
        | CheckId::Pivot
        | CheckId::Endpoint
        | CheckId::L7 => true,
        CheckId::History
        | CheckId::Profile
        | CheckId::Persistence
        | CheckId::Context
        | CheckId::Ops => false,
    }
}

/// Krok 18: existuje mezi kroky podezřelý výsledek (LR > 1) z nezávislého zdroje?
pub fn has_independent_evidence(notes: &[StepNote]) -> bool {
    notes
        .iter()
        .any(|n| confirm_source(n.check) && n.lr.is_some_and(|lr| lr > 1.0))
}

/// Krok 18: existuje mezi kroky jakýkoli podezřelý výsledek (LR > 1), i ze závislého zdroje?
pub fn has_suspicious_evidence(notes: &[StepNote]) -> bool {
    notes.iter().any(|n| n.lr.is_some_and(|lr| lr > 1.0))
}

fn steps_have_independent_evidence(steps: &[Step]) -> bool {
    steps.iter().any(|s| {
        confirm_source(s.check) && matches!(s.outcome, Outcome::Evidence { lr, .. } if lr > 1.0)
    })
}

/// Kontrola žebříku → druh kontroly řetězu a tabulky věrohodnosti (`competing`).
pub fn competing_kind(check: CheckId) -> Option<crate::verification_chain::CheckKind> {
    use crate::verification_chain::CheckKind as K;
    match check {
        CheckId::History => Some(K::CaseHistory),
        CheckId::Profile => Some(K::HostBaseline),
        CheckId::Peers => Some(K::PeerCompare),
        CheckId::Context => Some(K::ConfigContext),
        CheckId::Reputation => Some(K::Reputation),
        CheckId::Endpoint => Some(K::EndpointTelemetry),
        CheckId::L7 => Some(K::TlsFingerprint),
        CheckId::Ops => Some(K::OpsTelemetry),
        CheckId::Persistence => Some(K::RepeatMeasure),
        CheckId::Liveness => Some(K::ActiveReadOnly),
        _ => None,
    }
}

pub fn outcome_tag(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Evidence { lr, .. } if *lr < 1.0 => "benign",
        Outcome::Evidence { .. } => "malicious",
        Outcome::Undetermined(_) => "undetermined",
        Outcome::Unavailable(_) => "unavailable",
        Outcome::Wait(_) => "wait",
    }
}

fn is_fragile(class: &Option<DeviceClass>) -> bool {
    class.as_ref().is_some_and(|c| {
        c.kind.is_fragile() && c.confidence >= crate::device_class::ClassConfidence::Medium
    })
}

/// Učení věrohodnostních poměrů z ověřených případů (krok 2C). Štítky přicházejí jen
/// přes Case Memory (verdikt člověka nebo audit, s ochranou proti otrávení), počty se
/// drží po (kontrola, značka výsledku). Naučený LR je smrštěný k autorskému
/// (váha `n / (n + 20)`) a má bezpečnostní meze: neškodný důkaz smí jen snižovat
/// (0,02 až 1), podezřelý jen zvyšovat (1 až 50); „nezjištěno“ a „neprovedeno“ se
/// neučí vůbec a zůstávají bez vlivu (RQ6 Z3: prázdný výsledek není důkaz).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LadderLearner {
    /// zdroj štítku -> (kontrola:značka -> (útok, neškodné)); po zdrojích, aby šlo
    /// vyřadit zdroj, který Case Memory označí za otrávený (i zpětně).
    counts: BTreeMap<String, BTreeMap<String, (f64, f64)>>,
    totals: BTreeMap<String, (f64, f64)>,
    #[serde(default)]
    excluded: std::collections::BTreeSet<String>,
}

impl LadderLearner {
    const SHRINK: f64 = 20.0;
    const MIN_PER_CLASS: f64 = 10.0;

    /// Zapíše výsledek ověřeného případu (`attack` = verdikt útok) od zdroje `source`.
    pub fn record(
        &mut self,
        source: &str,
        steps: &[(CheckId, &'static str)],
        attack: bool,
        weight: f64,
    ) {
        let weight = weight.clamp(0.0, 1.0);
        let totals = self.totals.entry(source.to_string()).or_default();
        if attack {
            totals.0 += weight;
        } else {
            totals.1 += weight;
        }
        let counts = self.counts.entry(source.to_string()).or_default();
        let mut seen = HashSet::new();
        for (check, tag) in steps {
            if !seen.insert((*check, *tag)) {
                continue;
            }
            let entry = counts
                .entry(format!("{}:{tag}", check.label()))
                .or_default();
            if attack {
                entry.0 += weight;
            } else {
                entry.1 += weight;
            }
        }
    }

    /// Vyřadí zdroj (Case Memory ho označila za otrávený); jeho štítky přestanou platit.
    pub fn exclude(&mut self, source: &str) {
        self.excluded.insert(source.to_string());
    }

    fn sum<'a>(
        &'a self,
        pick: impl Fn(&'a BTreeMap<String, (f64, f64)>) -> Option<&'a (f64, f64)>,
    ) -> Option<(f64, f64)> {
        let mut out: Option<(f64, f64)> = None;
        for (source, counts) in &self.counts {
            if self.excluded.contains(source) {
                continue;
            }
            if let Some((a, b)) = pick(counts) {
                let entry = out.get_or_insert((0.0, 0.0));
                entry.0 += a;
                entry.1 += b;
            }
        }
        out
    }

    pub fn cases(&self) -> (f64, f64) {
        self.totals
            .iter()
            .filter(|(source, _)| !self.excluded.contains(*source))
            .fold((0.0, 0.0), |acc, (_, t)| (acc.0 + t.0, acc.1 + t.1))
    }

    /// Naučený LR pro výsledek kontroly; `author` = výchozí LR z `LrTable`.
    pub fn lr(&self, check: CheckId, tag: &str, author: f64) -> f64 {
        let (bounds_lo, bounds_hi) = match tag {
            "benign" => (0.02, 1.0),
            "malicious" => (1.0, 50.0),
            _ => return author,
        };
        let (attack_total, benign_total) = self.cases();
        let name = format!("{}:{tag}", check.label());
        let Some((a, b)) = self.sum(|counts| counts.get(&name)) else {
            return author;
        };
        if attack_total < Self::MIN_PER_CLASS || benign_total < Self::MIN_PER_CLASS {
            return author;
        }
        let empirical = ((a + 0.5) / (attack_total + 1.0)) / ((b + 0.5) / (benign_total + 1.0));
        let n = a + b;
        let w = n / (n + Self::SHRINK);
        let blended = (w * empirical.ln() + (1.0 - w) * author.max(1e-6).ln()).exp();
        blended.clamp(bounds_lo, bounds_hi)
    }
}

/// Žebřík: otevřené případy, pořadí a rozpočet napříč případy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ladder {
    pub policy: LadderPolicy,
    secret: u64,
    #[serde(with = "cases_as_list")]
    cases: HashMap<FindingKey, Case>,
    #[serde(default)]
    pub stats: LadderStats,
    /// Naučené LR (krok 2C); `None` = autorské LR.
    #[serde(default)]
    pub learner: Option<LadderLearner>,
    /// Kalibrace posteriory před pravidly zastavení (krok 2C); fit offline.
    #[serde(skip)]
    pub calibrator: Option<crate::calibration::IsotonicCalibrator>,
    /// Krok 18: klíče nepotvrzených případů (`prior_hold`) a cyklus předání. Po dobu
    /// `HOLD_CYCLES` se klíč automaticky nevyvrací (stejná ochrana, jakou dřív dávalo
    /// potvrzení v paměti nálezů), jen se předá člověku.
    #[serde(default)]
    held: Vec<(FindingKey, u64)>,
}

/// Krok 18: jak dlouho (cykly po 30 min) drží nepotvrzené podezření zákaz automatického
/// vyvrácení klíče: 24 h, stejně jako `quiet_close_s` paměti nálezů pro potvrzený klíč.
pub const HOLD_CYCLES: u64 = 48;

/// JSON neumi strukturovane klice map: pripady se ukladaji jako seznam.
mod cases_as_list {
    use super::{Case, FindingKey};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S: Serializer>(
        cases: &HashMap<FindingKey, Case>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut list: Vec<&Case> = cases.values().collect();
        list.sort_by(|a, b| a.input.key.cmp(&b.input.key));
        list.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<FindingKey, Case>, D::Error> {
        let list: Vec<Case> = Vec::deserialize(deserializer)?;
        Ok(list
            .into_iter()
            .map(|case| (case.input.key.clone(), case))
            .collect())
    }
}

impl Ladder {
    /// `secret` = tajný klíč instalace (náhodný při prvním startu, perzistentní).
    pub fn new(policy: LadderPolicy, secret: u64) -> Self {
        Self {
            policy,
            secret,
            cases: HashMap::new(),
            stats: LadderStats::default(),
            learner: None,
            calibrator: None,
            held: Vec::new(),
        }
    }

    pub fn open_cases(&self) -> usize {
        self.cases.len()
    }

    pub fn is_open(&self, key: &FindingKey) -> bool {
        self.cases.contains_key(key)
    }

    /// Otevře případ pro nový stav nálezu. Idempotentní: stejný klíč s otevřeným
    /// případem = jen sloučení zdrojů (žádný nový plán). Vrací `true` při otevření.
    pub fn open(&mut self, input: CaseInput, cycle: u64) -> bool {
        if let Some(case) = self.cases.get_mut(&input.key) {
            for source in input.sources {
                if !case.input.sources.contains(&source) && case.input.sources.len() < 16 {
                    case.input.sources.push(source);
                }
            }
            case.input.volume = case.input.volume.max(input.volume);
            self.stats.cases_merged += 1;
            return false;
        }
        if self.cases.len() >= self.policy.max_open_cases {
            self.stats.cases_capped += 1;
            return false;
        }
        let plan = plan_for(&input, self.secret, &self.policy);
        self.cases.insert(
            input.key.clone(),
            Case {
                log_odds: logit(input.prior),
                input,
                opened: cycle,
                plan,
                steps: Vec::new(),
                wait_until: None,
                deferred: 0,
                status: Status::Open,
                benign_evidence: false,
                benign_groups: Default::default(),
                obs: Vec::new(),
                use_competing: self.policy.competing,
                susp_groups: Default::default(),
                seen_after_open: 0,
                same_source_seen: false,
                last_seen_cycle: cycle,
            },
        );
        self.stats.cases_opened += 1;
        true
    }

    /// Nález s otevřeným případem se v cyklu znovu objevil (vstup pro L2 přetrvání).
    pub fn observe(&mut self, key: &FindingKey, sources: &[String], cycle: u64) {
        let Some(case) = self.cases.get_mut(key) else {
            return;
        };
        if cycle <= case.last_seen_cycle {
            return;
        }
        case.last_seen_cycle = cycle;
        case.seen_after_open += 1;
        if sources.iter().any(|s| case.input.sources.contains(s)) {
            case.same_source_seen = true;
        }
    }

    /// Zruší případ (nález uzavřel člověk nebo kontext).
    pub fn drop_case(&mut self, key: &FindingKey) {
        self.cases.remove(key);
    }

    /// Review kola 2 (S2, S3): případ novosti s dříve přijatým zakázaným neškodným
    /// důkazem (kontext, zvyk profilu; uložený stav před opravou) se resetuje na
    /// začátek: prior, nový plán, bez kroků. Volá se při načtení stavu i v každém
    /// cyklu (`step`). Vrací počet resetovaných případů.
    pub fn reset_forbidden_novelty_evidence(&mut self) -> usize {
        let protect = self.policy.protect;
        let mut keys: Vec<FindingKey> = self
            .cases
            .iter()
            .filter(|(_, case)| {
                // krok 7 (A1): totez pro chranene pripady
                (crate::behavior::novelty::is_novelty_type(&case.input.finding_type)
                    || (protect && case.input.is_protected()))
                    && case.steps.iter().any(|step| {
                        matches!(step.check, CheckId::Context | CheckId::Profile)
                            && matches!(step.outcome, Outcome::Evidence { lr, .. } if lr < 1.0)
                    })
            })
            .map(|(key, _)| key.clone())
            .collect();
        keys.sort();
        for key in &keys {
            if let Some(case) = self.cases.get_mut(key) {
                case.log_odds = logit(case.input.prior);
                case.plan = plan_for(&case.input, self.secret, &self.policy);
                case.steps.clear();
                case.wait_until = None;
                case.deferred = 0;
                case.benign_evidence = false;
                case.benign_groups.clear();
            }
        }
        keys.len()
    }

    /// Jeden cyklus: provede kontroly v pořadí EVOI proxy pod rozpočtem a vrátí
    /// rozhodnuté případy (ty se z žebříku odeberou).
    pub fn step(&mut self, cycle: u64, env: &mut dyn LadderEvidence) -> Vec<Decision> {
        self.reset_forbidden_novelty_evidence();
        self.held
            .retain(|(_, at)| cycle.saturating_sub(*at) <= HOLD_CYCLES);
        let mut decisions = Vec::new();
        let mut budget = self.policy.budget_per_cycle;
        let mut active_left = self.policy.active_per_cycle;
        let mut keys: Vec<FindingKey> = self.cases.keys().cloned().collect();
        keys.sort();
        let mut touched: HashSet<FindingKey> = HashSet::new();
        // po kolech: v kazdem kole jedna kontrola kazdeho pripraveneho pripadu, poradi
        // podle EVOI proxy s castecnym losovanim (O(n log n) na kolo, kol <= delka planu)
        let mut exhausted = false;
        let mut round = 0u64;
        while !exhausted {
            let mut ready: Vec<(f64, u64, FindingKey)> = keys
                .iter()
                .filter_map(|key| {
                    let case = self.cases.get(key)?;
                    if case.status != Status::Open
                        || case.wait_until.is_some_and(|until| until > cycle)
                    {
                        return None;
                    }
                    let check = *case.plan.front()?;
                    let impact = if case.input.high_impact { 1.0 } else { 0.5 };
                    let score = impact * entropy(case.posterior()) / cost(check);
                    Some((
                        score,
                        hash_text(&key.entity) ^ hash_text(&key.finding_type),
                        key.clone(),
                    ))
                })
                .collect();
            if ready.is_empty() {
                break;
            }
            ready.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
            // losovani (RQ3 Z11): podil `explore` pozic se prohodi s nahodnou pozdejsi
            let n = ready.len();
            for i in 0..n {
                let roll = mix(self.secret
                    ^ cycle.wrapping_mul(0x51ED)
                    ^ round.wrapping_mul(0x9E37)
                    ^ i as u64);
                if (roll % 10_000) as f64 / 10_000.0 < self.policy.explore && i + 1 < n {
                    let j = i + 1 + (mix(roll) % (n - i - 1) as u64) as usize;
                    ready.swap(i, j);
                    self.stats.explored += 1;
                }
            }
            round += 1;
            let mut progressed = false;
            for (_, _, key) in ready {
                let Some(check) = self.cases.get(&key).and_then(|c| c.plan.front().copied()) else {
                    continue;
                };
                if check.level() == Level::L3 && active_left == 0 {
                    continue;
                }
                let price = cost(check);
                if price > budget {
                    exhausted = true;
                    break;
                }
                budget -= price;
                if check.level() == Level::L3 {
                    active_left -= 1;
                }
                touched.insert(key.clone());
                progressed = true;
                if let Some(decision) = self.run_check(&key, check, cycle, env) {
                    decisions.push(decision);
                }
            }
            if !progressed {
                break;
            }
        }
        // pripady, na ktere nezbyl rozpocet: odlozit, po `max_deferred` eskalovat
        let mut budget_escalations = Vec::new();
        for key in &keys {
            let Some(case) = self.cases.get_mut(key) else {
                continue;
            };
            if case.status != Status::Open || touched.contains(key) {
                continue;
            }
            let ready = case.wait_until.is_none_or(|until| until <= cycle) && !case.plan.is_empty();
            if !ready {
                continue;
            }
            case.deferred += 1;
            self.stats.checks_deferred += 1;
            if case.deferred == 1 {
                self.stats.cases_deferred += 1;
            }
            if case.deferred > self.policy.max_deferred {
                budget_escalations.push(key.clone());
            }
        }
        for key in budget_escalations {
            if let Some(decision) = self.finish(&key, Status::Escalated, cycle, true) {
                decisions.push(decision);
            }
        }
        decisions
    }

    fn run_check(
        &mut self,
        key: &FindingKey,
        check: CheckId,
        cycle: u64,
        env: &mut dyn LadderEvidence,
    ) -> Option<Decision> {
        let lr = self.policy.lr;
        let case = self.cases.get(key)?;
        let input = case.input.clone();
        let opened = case.opened;
        let persistence = if case.seen_after_open == 0 {
            Persistence::Gone
        } else {
            Persistence::Recurring {
                cycles: case.seen_after_open,
                same_source: case.same_source_seen,
            }
        };
        let outcome = evaluate(
            check,
            &input,
            (opened, persistence),
            cycle,
            env,
            &lr,
            &self.policy,
            self.secret,
        );
        *self
            .stats
            .checks_by_level
            .entry(check.level().label().to_string())
            .or_default() += 1;
        let tag = outcome_tag(&outcome);
        *self
            .stats
            .outcomes
            .entry(format!("{}:{tag}", check.label()))
            .or_default() += 1;
        if matches!(&outcome, Outcome::Unavailable(d) if d.contains("schvaleni")) {
            self.stats.needs_approval += 1;
        }
        let case = self.cases.get_mut(key)?;
        case.deferred = 0;
        match &outcome {
            Outcome::Wait(until) => {
                case.wait_until = Some(*until);
                return None; // kontrola zustava v planu, vrati se po cekani
            }
            Outcome::Evidence { lr, detail } => {
                let lr = match &self.learner {
                    Some(learner) => learner.lr(check, tag, *lr),
                    None => *lr,
                };
                case.log_odds += lr.max(1e-6).ln();
                if let Some(kind) = competing_kind(check) {
                    case.obs.push(crate::competing::Obs {
                        kind,
                        result: if lr < 1.0 {
                            crate::competing::Result3::Benign
                        } else if lr > 1.0 {
                            crate::competing::Result3::Suspicious
                        } else {
                            crate::competing::Result3::Nothing
                        },
                    });
                    if lr > 1.0
                        && let Some(group) = benign_group(check)
                    {
                        case.susp_groups.insert(group);
                    }
                }
                if lr < 1.0 {
                    case.benign_evidence = true;
                    if let Some(group) = benign_group(check) {
                        // krok 15 (P1): „nic podezreleho“ od agenta je slaba skupina (6):
                        // sama ani s historii nestaci, agent muze lhat (rameno `lying`)
                        let weak = check == CheckId::Endpoint
                            && self.policy.endpoint_weak
                            && !detail.starts_with("seznam povolenych");
                        case.benign_groups.insert(if weak { 6 } else { group });
                    }
                    // krok 14: seznam povolenych je schvaleni vlastnikem (kontext, skupina 1)
                    // potvrzene pozorovanym procesem (koncova telemetrie, skupina 4): dve skupiny
                    if check == CheckId::Endpoint && detail.starts_with("seznam povolenych") {
                        case.benign_groups.insert(1);
                    }
                }
            }
            Outcome::Undetermined(_) | Outcome::Unavailable(_) => {
                if let Some(kind) = competing_kind(check) {
                    case.obs.push(crate::competing::Obs {
                        kind,
                        result: crate::competing::Result3::Nothing,
                    });
                }
            }
        }
        case.plan.pop_front();
        case.wait_until = None;
        let raw = case.posterior();
        let posterior = self
            .calibrator
            .as_ref()
            .map_or(raw, |calibrator| calibrator.predict(raw));
        case.steps.push(Step {
            check,
            cycle,
            outcome,
            posterior,
        });
        let executed = case
            .steps
            .iter()
            // krok 8: koncova kontrola bez nalezu nespotrebuje strop kontrol (jinak by
            // vytlacila posledni kontrolu planu a zmenila rozhodnuti i bez dukazu)
            .filter(|s| {
                !matches!(s.outcome, Outcome::Unavailable(_))
                    && !(matches!(s.check, CheckId::Endpoint | CheckId::Ops)
                        && matches!(s.outcome, Outcome::Undetermined(_)))
            })
            .count();
        let refute_at = if case.input.high_impact {
            self.policy.p_refute_high_impact
        } else {
            self.policy.p_refute
        };
        let shielded = self.policy.protect && case.input.is_protected();
        // krok 12: vyvraceni jen na pozitivni dukaz z aspon dvou nezavislych skupin,
        // z nichz aspon jedna je silna (kontext, provozni pricina, koncova telemetrie)
        let proven = !self.policy.strict_refute
            || (case.benign_groups.len() >= 2
                && case.benign_groups.iter().any(|g| matches!(g, 1 | 2 | 4)));
        let competing_action = case
            .use_competing
            .then(|| crate::competing::best_action(raw, &self.policy.costs).0);
        let status = if let Some(action) = competing_action {
            use crate::competing::Action;
            match action {
                Action::ConfirmAttack if case.susp_groups.len() >= 2 => Some(Status::Confirmed),
                Action::CloseBenign if !shielded && proven => Some(Status::Refuted),
                _ if executed >= self.policy.max_checks || case.plan.is_empty() => {
                    Some(Status::Escalated)
                }
                _ => None,
            }
        } else if posterior >= self.policy.p_confirm {
            Some(Status::Confirmed)
        } else if posterior <= refute_at && case.benign_evidence && !shielded && !proven {
            // nizka pravdepodobnost utoku bez dostatecneho pozitivniho dukazu: nezavirat,
            // predat cloveku (zustava viditelne)
            self.stats.strict_escalated += 1;
            let groups: Vec<u8> = case.benign_groups.iter().copied().collect();
            let decision = self.finish(key, Status::Escalated, cycle, false);
            return decision.map(|mut d| {
                d.reason = format!(
                    "pozitivni dukaz neskodnosti nestaci (mene nez dve nezavisle skupiny nebo zadna silna; skupiny {groups:?}): {}",
                    d.reason
                );
                d
            });
        } else if posterior <= refute_at && case.benign_evidence && !shielded {
            Some(Status::Refuted)
        } else if posterior <= refute_at && case.benign_evidence {
            // krok 7 (A1): chraneny pripad se nevyvraci, rozhodnuti jde cloveku
            self.stats.protect_escalated += 1;
            let decision = self.finish(key, Status::Escalated, cycle, false);
            return decision.map(|mut d| {
                d.reason = format!("chraneny nalez: vyvraceni zakazano; {}", d.reason);
                d
            });
        } else if executed >= self.policy.max_checks || case.plan.is_empty() {
            Some(Status::Escalated)
        } else {
            None
        };
        // krok 18: vysoka P bez nezavisleho dukazu jeste neni potvrzeni; dokud dalsi kontrola
        // planu bezi hned (ne cekani na pretrvani, ne aktivni L3 s limitem za cyklus), pokracuje
        // se ve stejnem cyklu, jinak `finish` pripad preda cloveku jako nepotvrzeny
        let status = match status {
            Some(Status::Confirmed)
                if self.policy.confirm_evidence
                    && !steps_have_independent_evidence(&case.steps)
                    && executed < self.policy.max_checks
                    && case
                        .plan
                        .front()
                        .is_some_and(|c| *c != CheckId::Persistence && c.level() != Level::L3) =>
            {
                None
            }
            other => other,
        };
        status.and_then(|status| self.finish(key, status, cycle, false))
    }

    fn finish(
        &mut self,
        key: &FindingKey,
        status: Status,
        cycle: u64,
        budget: bool,
    ) -> Option<Decision> {
        let case = self.cases.remove(key)?;
        // krok 18: potvrzeni jen s pozitivnim dukazem z nezavisleho zdroje (jedine misto,
        // plati pro prah posteriory i rezim konkurencnich hypotez); jinak predat cloveku
        let prior_hold = status == Status::Confirmed
            && self.policy.confirm_evidence
            && !steps_have_independent_evidence(&case.steps);
        let held_refute = status == Status::Refuted
            && self.policy.confirm_evidence
            && self
                .held
                .iter()
                .any(|(k, at)| k == key && cycle.saturating_sub(*at) <= HOLD_CYCLES);
        let status = if prior_hold {
            self.stats.prior_held += 1;
            self.held.retain(|(k, _)| k != key);
            self.held.push((key.clone(), cycle));
            Status::Escalated
        } else if held_refute {
            self.stats.hold_refused += 1;
            Status::Escalated
        } else {
            status
        };
        let pending_check = prior_hold
            .then(|| {
                case.plan
                    .iter()
                    .copied()
                    .find(|c| confirm_source(*c))
                    .or_else(|| case.plan.front().copied())
            })
            .flatten();
        match status {
            Status::Confirmed => self.stats.confirmed += 1,
            Status::Refuted => self.stats.refuted += 1,
            Status::Escalated => {
                self.stats.escalated += 1;
                self.stats.escalated_budget += budget as u64;
            }
            Status::Open => {}
        }
        let reason = case
            .steps
            .iter()
            .map(|step| {
                let what = match &step.outcome {
                    Outcome::Evidence { lr, detail } => format!("LR {lr:.2}: {detail}"),
                    Outcome::Undetermined(d) => format!("nezjisteno: {d}"),
                    Outcome::Unavailable(d) => format!("neprovedeno: {d}"),
                    Outcome::Wait(_) => "ceka".to_string(),
                };
                format!(
                    "{} {} [{what}]",
                    step.check.level().label(),
                    step.check.label()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let raw = case.posterior();
        let calibrated = self
            .calibrator
            .as_ref()
            .map_or(raw, |calibrator| calibrator.predict(raw));
        Some(Decision {
            raw_posterior: raw,
            host_ip: case.input.host_ip.clone(),
            finding_id: case.input.finding_id.clone(),
            finding_type: case.input.finding_type.clone(),
            key: case.input.key.clone(),
            status,
            posterior: calibrated,
            opened: case.opened,
            decided: cycle,
            reason: if prior_hold {
                let waiting = match pending_check {
                    Some(check) => format!(
                        "ceka na kontrolu {} {} (cena {:.2})",
                        check.level().label(),
                        check.label(),
                        cost(check)
                    ),
                    None => "automaticka kontrola nezbyva, nutne rucni overeni".to_string(),
                };
                format!(
                    "nepotvrzeno: P(utok) {calibrated:.2} jen z apriorni pravdepodobnosti, bez pozitivniho dukazu z nezavisleho zdroje; {waiting}; {reason}"
                )
            } else if held_refute {
                format!(
                    "drzeno: klic ma nedavne nepotvrzene podezreni, automaticke vyvraceni zakazano; {reason}"
                )
            } else if budget {
                format!("rozpocet vycerpan opakovane; {reason}")
            } else {
                reason
            },
            checks: case.steps.len(),
            budget_escalation: budget,
            high_impact: case.input.high_impact,
            protected: self.policy.protect && case.input.is_protected(),
            steps: case
                .steps
                .iter()
                .map(|step| (step.check, outcome_tag(&step.outcome)))
                .collect(),
            notes: case
                .steps
                .iter()
                .map(|step| {
                    let (lr, detail) = match &step.outcome {
                        Outcome::Evidence { lr, detail } => (Some(*lr), detail.clone()),
                        Outcome::Undetermined(d) | Outcome::Unavailable(d) => (None, d.clone()),
                        Outcome::Wait(_) => (None, "ceka na dalsi cyklus".to_string()),
                    };
                    StepNote {
                        check: step.check,
                        cycle: step.cycle,
                        tag: outcome_tag(&step.outcome),
                        lr,
                        detail,
                    }
                })
                .collect(),
            prior_hold,
            pending_check,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    check: CheckId,
    input: &CaseInput,
    (opened, persistence): (u64, Persistence),
    cycle: u64,
    env: &mut dyn LadderEvidence,
    lr: &LrTable,
    policy: &LadderPolicy,
    secret: u64,
) -> Outcome {
    match check {
        CheckId::History => {
            let Some(key) = &input.history_key else {
                return Outcome::Undetermined("bez metriky historie".into());
            };
            match env.recurrence(key, input.volume) {
                Recurrence::Seen { days } => Outcome::Evidence {
                    lr: lr.history_seen,
                    detail: format!("stejny jev uz {days} dny ve stejne hodine"),
                },
                Recurrence::New { history_days } => Outcome::Evidence {
                    lr: lr.history_new,
                    detail: format!("za {history_days} dni historie nikdy"),
                },
                Recurrence::Insufficient { history_days } => {
                    Outcome::Undetermined(format!("historie jen {history_days} dny"))
                }
            }
        }
        // krok 7 (A1): chraneny pripad kontext nepodpori ani pri chybe prostredi
        CheckId::Context if policy.protect && input.is_protected() => {
            Outcome::Undetermined("chraneny nalez: kontext neni dukaz".into())
        }
        CheckId::Context => match env.context(input) {
            Some(reason) => Outcome::Evidence {
                lr: lr.context,
                detail: format!("schvaleny kontext: {reason}"),
            },
            None => Outcome::Undetermined("zadny zaznam kontextu".into()),
        },
        CheckId::Endpoint => {
            use crate::endpoint::correlate::EndpointSignal;
            match env.endpoint(input) {
                EndpointSignal::Suspicious(detail) => Outcome::Evidence {
                    lr: lr.endpoint_suspicious,
                    detail: format!("koncova telemetrie: {detail}"),
                },
                // krok 8 (A2, 1): u chraneneho pripadu neni koncovy signal neskodny dukaz
                EndpointSignal::Allowed(_) if policy.protect && input.is_protected() => {
                    Outcome::Undetermined(
                        "chraneny nalez: seznam povolenych neni dukaz neskodnosti".into(),
                    )
                }
                EndpointSignal::Allowed(detail) => Outcome::Evidence {
                    lr: lr.endpoint_allow,
                    detail: format!("seznam povolenych: {detail}"),
                },
                EndpointSignal::Benign(_) if policy.protect && input.is_protected() => {
                    Outcome::Undetermined(
                        "chraneny nalez: koncova telemetrie neni dukaz neskodnosti".into(),
                    )
                }
                EndpointSignal::Benign(detail) => Outcome::Evidence {
                    lr: lr.endpoint_benign,
                    detail: format!("koncova telemetrie: {detail}"),
                },
                EndpointSignal::NoSignal(why) => Outcome::Undetermined(why),
                // host bez agenta: nedostupne (nepocita se do stropu kontrol, neni neskodne)
                EndpointSignal::NoCoverage(why) => Outcome::Unavailable(why),
            }
        }
        CheckId::Ops => match env.ops(input) {
            // chráněný nález: provozní vysvětlení není důkaz neškodnosti
            Some(d) if policy.protect && input.is_protected() => {
                let _ = d;
                Outcome::Undetermined(
                    "chraneny nalez: provozni telemetrie neni dukaz neskodnosti".into(),
                )
            }
            Some(d)
                if matches!(d.class.as_str(), "porucha" | "zmena") && d.catalog_id.is_some() =>
            {
                Outcome::Evidence {
                    lr: lr.ops_fault,
                    detail: format!(
                        "provozni telemetrie: {} ({}), signaly {}",
                        d.catalog_id.as_deref().unwrap_or("-"),
                        d.class,
                        d.evidence.join(", ")
                    ),
                }
            }
            // chybí telemetrie, o které by šlo rozhodnout: nedostupné, ne neškodné
            Some(d) if d.class == "neurceno" => Outcome::Unavailable(d.reason),
            Some(_) => Outcome::Undetermined("bez provozniho dukazu".into()),
            None => Outcome::Unavailable("provozni telemetrie neni".into()),
        },
        CheckId::L7 => {
            use crate::behavior::l7::L7Signal;
            match env.l7(input) {
                L7Signal::Suspicious(detail) => Outcome::Evidence {
                    lr: lr.l7_suspicious,
                    detail: format!("TLS a DNS: {detail}"),
                },
                L7Signal::Benign(_) if policy.protect && input.is_protected() => {
                    Outcome::Undetermined(
                        "chraneny nalez: metadata nejsou dukaz neskodnosti".into(),
                    )
                }
                L7Signal::Benign(detail) => Outcome::Evidence {
                    lr: lr.l7_benign,
                    detail: format!("TLS a DNS: {detail}"),
                },
                L7Signal::NoSignal(why) => Outcome::Undetermined(why),
                L7Signal::NoCoverage(why) => Outcome::Unavailable(why),
            }
        }
        CheckId::Reputation => {
            let mut good = None;
            for source in &input.sources {
                match env.reputation(source) {
                    Reputation::Bad(from) => {
                        return Outcome::Evidence {
                            lr: lr.reputation_bad,
                            detail: format!("{source} ma spatnou reputaci ({from})"),
                        };
                    }
                    Reputation::Good(from) => good = Some(format!("{source} ({from})")),
                    Reputation::Unknown => {}
                }
            }
            match good {
                // vsechny zname zdroje dobre a zadny spatny
                Some(detail) if input.sources.len() == 1 => Outcome::Evidence {
                    lr: lr.reputation_good,
                    detail: format!("duveryhodny zdroj {detail}"),
                },
                _ => Outcome::Undetermined("zdroj bez reputace".into()),
            }
        }
        CheckId::Intel => match env.intel(input) {
            IntelSignal::KnownExploited(cve) => Outcome::Evidence {
                lr: lr.intel_kev,
                detail: format!("cilova sluzba ma aktivne zneuzivanou zranitelnost {cve} (KEV)"),
            },
            IntelSignal::HighEpss(score) => Outcome::Evidence {
                lr: lr.intel_epss,
                detail: format!("cilova sluzba ma zranitelnost s EPSS {score:.2}"),
            },
            IntelSignal::NothingKnown => Outcome::Undetermined("o zranitelnosti nic nevime".into()),
        },
        CheckId::DeviceProfile => {
            let Some(class) = env.device(&input.host_ip) else {
                return Outcome::Undetermined("typ zarizeni neznamy".into());
            };
            let unusual = match input.finding_type.as_str() {
                "multi_target_pattern" | "scan_attempts" => {
                    // spravcovsky rozptyl z tiskarny, kamery, IoT, PLC je neobvykly
                    class.kind.is_fragile() || class.kind == DeviceKind::Voip
                }
                _ => input.port.is_some_and(|port| class.unusual_service(port)),
            };
            if unusual {
                Outcome::Evidence {
                    lr: lr.device_unusual,
                    detail: format!(
                        "neobvykle pro {} ({})",
                        class.kind.label(),
                        class.reasons.first().cloned().unwrap_or_default()
                    ),
                }
            } else {
                Outcome::Undetermined(format!("bezne pro {}", class.kind.label()))
            }
        }
        CheckId::Peers => match env.peers(input) {
            Some((affected, size)) if size >= 3 && affected * 2 >= size => Outcome::Evidence {
                lr: lr.peers_widespread,
                detail: format!("totez u {affected} z {size} zarizeni stejneho typu"),
            },
            Some((affected, size)) if size >= 5 && affected * 10 <= size => Outcome::Evidence {
                lr: lr.peers_isolated,
                detail: format!("jen {affected} z {size} zarizeni stejneho typu"),
            },
            Some((affected, size)) => {
                Outcome::Undetermined(format!("{affected} z {size} v peer skupine"))
            }
            None => Outcome::Undetermined("bez peer skupiny".into()),
        },
        CheckId::Persistence => {
            if cycle < opened + policy.persistence_wait {
                return Outcome::Wait(opened + policy.persistence_wait);
            }
            match persistence {
                Persistence::Recurring {
                    cycles,
                    same_source: true,
                } if !input.sources.is_empty() => Outcome::Evidence {
                    lr: lr.persistence_same_source,
                    detail: format!("pretrvava {cycles} cyklu se stejnym zdrojem"),
                },
                Persistence::Recurring { cycles, .. } if cycles >= 2 => Outcome::Evidence {
                    lr: lr.persistence_recurring,
                    detail: format!("pretrvava {cycles} cyklu"),
                },
                Persistence::Recurring { cycles, .. } => {
                    Outcome::Undetermined(format!("opakovani jen {cycles}x"))
                }
                // prechodny jev NENI dukaz neskodnosti (kratke utoky jsou prechodne)
                Persistence::Gone => Outcome::Undetermined("jev se neopakoval".into()),
            }
        }
        CheckId::Liveness => {
            if !env.in_scope(&input.host_ip) {
                return Outcome::Unavailable("mimo rozsah".into());
            }
            if is_fragile(&env.device(&input.host_ip)) {
                // kontrola krehkeho zarizeni jen se schvalenim (RQ3 Z10)
                return Outcome::Unavailable("krehke zarizeni, ceka na schvaleni".into());
            }
            let dominant = !input.sources.is_empty();
            match env.liveness(input) {
                Liveness::Down if !dominant => Outcome::Evidence {
                    lr: lr.liveness_down_outage,
                    detail: "sluzba neodpovida ani kontrole: vypadek vysvetluje selhani".into(),
                },
                Liveness::Down => {
                    Outcome::Undetermined("sluzba dole, ale s dominantnim zdrojem".into())
                }
                Liveness::Up if input.finding_type == "service_unreachable" => Outcome::Evidence {
                    lr: lr.liveness_up_unreachable,
                    detail: "sluzba odpovida kontrole, klientum ne".into(),
                },
                Liveness::Up => Outcome::Undetermined("sluzba odpovida".into()),
                Liveness::NeedsApproval => {
                    Outcome::Unavailable("aktivni kontrola ceka na schvaleni".into())
                }
                Liveness::OutOfScope => Outcome::Unavailable("mimo rozsah".into()),
                Liveness::Failed(reason) => Outcome::Unavailable(reason),
            }
        }
        CheckId::Profile => {
            use crate::behavior::profile::ProfileVerdict;
            let verdict = env.profile(input);
            // novost: zvyk hostu ani flotily neni neskodny dukaz (profil drzi zvyky 14 dni,
            // novost 7; review kola 1 S3, pojistka A7)
            // krok 7 (A1): totez pro chranene pripady (graf, signatura, degradace)
            if (crate::behavior::novelty::is_novelty_type(&input.finding_type)
                || (policy.protect && input.is_protected()))
                && matches!(
                    verdict,
                    ProfileVerdict::Established { .. } | ProfileVerdict::Fleet { .. }
                )
            {
                return Outcome::Undetermined(
                    "novost vztahu: zvyk profilu neni dukaz neskodnosti".into(),
                );
            }
            match verdict {
                ProfileVerdict::Established { since, days } => Outcome::Evidence {
                    lr: lr.profile_host,
                    detail: format!(
                        "zavedeny zvyk hostu od {} ({days} dni)",
                        chrono::DateTime::from_timestamp(since, 0)
                            .map(|d| d.format("%Y-%m-%d").to_string())
                            .unwrap_or_default()
                    ),
                },
                ProfileVerdict::Fleet { hosts } => Outcome::Evidence {
                    lr: lr.profile_fleet,
                    detail: format!("zavedeny zvyk u {hosts} hostu stejne skupiny"),
                },
                ProfileVerdict::NewForMature { profile_days } if policy.profile_new_evidence => {
                    Outcome::Evidence {
                        lr: lr.profile_new,
                        detail: format!("novy cil pro profil hostu ({profile_days:.0} dni dat)"),
                    }
                }
                ProfileVerdict::NewForMature { profile_days } => Outcome::Undetermined(format!(
                    "novy cil pro profil hostu ({profile_days:.0} dni dat): rys, ne dukaz"
                )),
                ProfileVerdict::Unknown(why) => Outcome::Undetermined(why),
            }
        }
        CheckId::Pivot => {
            // BFS po komunikacnich hranach z entity a zdroju, jen v rozsahu
            let mut frontier: Vec<String> = std::iter::once(input.host_ip.clone())
                .chain(input.sources.iter().cloned())
                .filter(|ip| env.in_scope(ip))
                .collect();
            let mut seen: HashSet<String> = frontier.iter().cloned().collect();
            let mut visited = 0usize;
            let mut hits = 0usize;
            let salt = mix(secret ^ hash_text(&input.finding_id) ^ 0x9137);
            for _ in 0..policy.pivot_depth {
                let mut next = Vec::new();
                for node in &frontier {
                    let mut peers = env.neighbors(node);
                    peers.retain(|p| !seen.contains(p) && env.in_scope(p));
                    peers.sort_by_key(|p| mix(salt ^ hash_text(p)));
                    for peer in peers {
                        if visited >= policy.pivot_max_nodes {
                            break;
                        }
                        visited += 1;
                        seen.insert(peer.clone());
                        if env.suspicious_on(&peer) > 0 {
                            hits += 1;
                        }
                        next.push(peer);
                    }
                }
                if visited >= policy.pivot_max_nodes || next.is_empty() {
                    break;
                }
                frontier = next;
            }
            if hits == 0 {
                Outcome::Undetermined(format!("{visited} souvisejicich zarizeni bez podezreni"))
            } else {
                Outcome::Evidence {
                    lr: lr.pivot_per_hit.powi(hits.min(2) as i32),
                    detail: format!("podezreni na {hits} z {visited} souvisejicich zarizeni"),
                }
            }
        }
    }
}

/// Klíč metriky v historii toků pro typ nálezu (L0). `service` = `ip/proto/port`.
pub fn history_key_for(
    finding_type: &str,
    service: Option<&str>,
    entity_ip: &str,
    sources: &[String],
) -> Option<String> {
    use crate::flow_history::{Metric, key};
    match finding_type {
        "inductive_volume_anomaly"
        | "packet_rate_spike"
        | "service_overload_risk"
        | "unexpected_traffic" => service.map(|s| key(s, Metric::ServiceFlows)),
        "connection_timeout_burst" | "service_unreachable" => {
            service.map(|s| key(s, Metric::ServiceFailures))
        }
        "scan_attempts" => sources.first().map(|s| key(s, Metric::SourceAttempts)),
        "multi_target_pattern" => Some(key(entity_ip, Metric::SourceFanout)),
        "source_volume_outlier" => sources.first().map(|s| key(s, Metric::SourceFlows)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_class::ClassConfidence;

    #[derive(Default)]
    struct Env {
        recurrence: Option<Recurrence>,
        context: Option<String>,
        bad: HashSet<String>,
        peers: Option<(usize, usize)>,
        liveness: Option<Liveness>,
        device: Option<DeviceClass>,
        edges: HashMap<String, Vec<String>>,
        suspicious: HashSet<String>,
        liveness_calls: usize,
        kev: bool,
        profile: Option<crate::behavior::profile::ProfileVerdict>,
        endpoint: Option<crate::endpoint::correlate::EndpointSignal>,
        ops: Option<crate::ops_telemetry::OpsDiagnosis>,
    }

    impl LadderEvidence for Env {
        fn recurrence(&self, _: &str, _: f64) -> Recurrence {
            self.recurrence
                .unwrap_or(Recurrence::Insufficient { history_days: 0 })
        }
        fn context(&self, _: &CaseInput) -> Option<String> {
            self.context.clone()
        }
        fn reputation(&self, ip: &str) -> Reputation {
            if self.bad.contains(ip) {
                Reputation::Bad("feed".into())
            } else {
                Reputation::Unknown
            }
        }
        fn intel(&self, _: &CaseInput) -> IntelSignal {
            if self.kev {
                IntelSignal::KnownExploited("CVE-2021-41773".into())
            } else {
                IntelSignal::NothingKnown
            }
        }
        fn device(&self, _: &str) -> Option<DeviceClass> {
            self.device.clone()
        }
        fn peers(&self, _: &CaseInput) -> Option<(usize, usize)> {
            self.peers
        }
        fn liveness(&mut self, _: &CaseInput) -> Liveness {
            self.liveness_calls += 1;
            self.liveness.clone().unwrap_or(Liveness::Up)
        }
        fn neighbors(&self, ip: &str) -> Vec<String> {
            self.edges.get(ip).cloned().unwrap_or_default()
        }
        fn in_scope(&self, ip: &str) -> bool {
            ip.starts_with("10.")
        }
        fn suspicious_on(&self, ip: &str) -> usize {
            self.suspicious.contains(ip) as usize
        }
        fn profile(&self, _: &CaseInput) -> crate::behavior::profile::ProfileVerdict {
            self.profile
                .clone()
                .unwrap_or(crate::behavior::profile::ProfileVerdict::Unknown(
                    "test".into(),
                ))
        }
        fn ops(&self, _: &CaseInput) -> Option<crate::ops_telemetry::OpsDiagnosis> {
            self.ops.clone()
        }
        fn endpoint(&self, _: &CaseInput) -> crate::endpoint::correlate::EndpointSignal {
            self.endpoint
                .clone()
                .unwrap_or(crate::endpoint::correlate::EndpointSignal::NoCoverage(
                    "test".into(),
                ))
        }
    }

    fn ep_policy(endpoint: bool) -> LadderPolicy {
        LadderPolicy {
            endpoint,
            protect: true,
            ..Default::default()
        }
    }

    fn decide(policy: LadderPolicy, kind: &str, env: &mut Env) -> Decision {
        let mut ladder = Ladder::new(policy, 7);
        ladder.open(input(kind, "10.0.0.5", &["203.0.113.9"]), 0);
        run_until_decided(&mut ladder, env)
    }

    /// Krok 8 (A2, 1): neskodny koncovy signal nikdy nevyvrati chraneny pripad, ani kdyz
    /// k nemu pristoupi dalsi neskodny dukaz.
    #[test]
    fn endpoint_benign_never_refutes_protected_case() {
        use crate::endpoint::correlate::EndpointSignal;
        for kind in ["suricata_alert", "novel_persistent_peer", "endpoint_alert"] {
            let mut env = Env {
                recurrence: Some(Recurrence::Seen { days: 9 }),
                peers: Some((5, 6)),
                endpoint: Some(EndpointSignal::Benign("podepsany updater".into())),
                ..Env::default()
            };
            let d = decide(ep_policy(true), kind, &mut env);
            assert_ne!(d.status, Status::Refuted, "{kind}: {}", d.reason);
            assert!(
                !d.steps
                    .iter()
                    .any(|(c, t)| *c == CheckId::Endpoint && *t == "benign"),
                "{kind}: koncovy signal u chraneneho nesmi byt neskodny dukaz"
            );
        }
    }

    /// Neskodny koncovy signal sam (bez dalsiho neskodneho dukazu) nezavira ani nechraneny nalez.
    #[test]
    fn endpoint_benign_alone_does_not_refute_unprotected_case() {
        use crate::endpoint::correlate::EndpointSignal;
        let mut env = Env {
            endpoint: Some(EndpointSignal::Benign("podepsany updater".into())),
            ..Env::default()
        };
        let d = decide(ep_policy(true), "inductive_volume_anomaly", &mut env);
        assert_ne!(d.status, Status::Refuted, "{}", d.reason);
        assert!(d.reason.contains("koncova telemetrie"));
    }

    /// Spolu s dalsim doslozenym neskodnym dukazem muze koncovy signal snizit prioritu
    /// (vyvraceni s auditni stopou v duvodu); bez kontroly ve planu totez nevyvrati.
    #[test]
    fn endpoint_benign_with_other_benign_evidence_can_refute_with_audit_reason() {
        use crate::endpoint::correlate::EndpointSignal;
        let mk = || Env {
            recurrence: Some(Recurrence::Seen { days: 4 }),
            endpoint: Some(EndpointSignal::Benign("podepsany updater".into())),
            ..Env::default()
        };
        let with = decide(ep_policy(true), "inductive_volume_anomaly", &mut mk());
        assert_eq!(with.status, Status::Refuted, "{}", with.reason);
        assert!(
            with.reason
                .contains("endpoint [LR 0.30: koncova telemetrie")
        );
        let without = decide(ep_policy(false), "inductive_volume_anomaly", &mut mk());
        assert_ne!(without.status, Status::Refuted, "{}", without.reason);
    }

    /// Krok 15 (P1): pri `strict_refute` + `endpoint_weak` neni „nic podezreleho“ od agenta
    /// silna skupina: historie + koncovy signal nevyvrati (rozhodnuti jde cloveku); bez
    /// `endpoint_weak` tataz dvojice vyvrati (drzene seedy 20267401, sit 7, lhouci agent).
    #[test]
    fn lying_capable_agent_benign_signal_is_not_a_strong_group_under_strict_refute() {
        use crate::endpoint::correlate::EndpointSignal;
        let mk = || Env {
            recurrence: Some(Recurrence::Seen { days: 3 }),
            endpoint: Some(EndpointSignal::Benign("vse v poradku".into())),
            ..Env::default()
        };
        let policy = |weak: bool| LadderPolicy {
            endpoint: true,
            protect: true,
            strict_refute: true,
            endpoint_weak: weak,
            ..Default::default()
        };
        let before = decide(policy(false), "scan_attempts", &mut mk());
        assert_eq!(before.status, Status::Refuted, "{}", before.reason);
        let after = decide(policy(true), "scan_attempts", &mut mk());
        assert_eq!(after.status, Status::Escalated, "{}", after.reason);
        assert!(after.reason.contains("skupiny [3, 6]"), "{}", after.reason);
    }

    /// Koncova kontrola bez nalezu (NoSignal) nespotrebuje strop kontrol: rozhodnuti i
    /// vira jsou stejne jako bez kontroly.
    #[test]
    fn endpoint_without_finding_does_not_consume_check_cap() {
        use crate::endpoint::correlate::EndpointSignal;
        for kind in [
            "unexpected_traffic",
            "beacon_periodic",
            "inductive_volume_anomaly",
        ] {
            let mut on = Env {
                endpoint: Some(EndpointSignal::NoSignal("nic".into())),
                recurrence: Some(Recurrence::New { history_days: 5 }),
                ..Env::default()
            };
            let mut off = Env {
                recurrence: Some(Recurrence::New { history_days: 5 }),
                ..Env::default()
            };
            let a = decide(ep_policy(true), kind, &mut on);
            let b = decide(ep_policy(false), kind, &mut off);
            assert_eq!(a.status, b.status, "{kind}");
            assert!((a.posterior - b.posterior).abs() < 1e-9, "{kind}");
            assert_eq!(
                a.checks,
                b.checks + 1,
                "{kind}: jedna kontrola navic, bez vlivu"
            );
        }
    }

    #[test]
    fn endpoint_suspicious_raises_belief_and_missing_coverage_changes_nothing() {
        use crate::endpoint::correlate::EndpointSignal;
        let base = decide(ep_policy(true), "beacon_periodic", &mut Env::default());
        let mut sus = Env {
            endpoint: Some(EndpointSignal::Suspicious("w3wp spousti cmd".into())),
            ..Env::default()
        };
        let up = decide(ep_policy(true), "beacon_periodic", &mut sus);
        assert!(
            up.posterior > base.posterior + 0.3,
            "{} {}",
            up.posterior,
            base.posterior
        );
        let off = decide(ep_policy(false), "beacon_periodic", &mut Env::default());
        assert!(
            (off.posterior - base.posterior).abs() < 1e-9,
            "bez pokryti se viera nemeni"
        );
        assert!(base.reason.contains("neprovedeno"));
    }

    /// Krok 4: nový cíl zralého profilu je rys bez vlivu na víru (empirické LR 1,03),
    /// jako důkaz jen při výslovném zapnutí.
    #[test]
    fn new_target_of_mature_profile_is_not_evidence_by_default() {
        use crate::behavior::profile::ProfileVerdict;
        for (on, tag) in [(false, "profile:undetermined"), (true, "profile:malicious")] {
            let policy = LadderPolicy {
                profile: true,
                profile_new_evidence: on,
                ..Default::default()
            };
            let mut ladder = Ladder::new(policy, 7);
            let mut env = Env {
                profile: Some(ProfileVerdict::NewForMature { profile_days: 9.0 }),
                ..Env::default()
            };
            ladder.open(input("beacon_periodic", "10.0.0.5", &["203.0.113.9"]), 0);
            run_until_decided(&mut ladder, &mut env);
            assert_eq!(ladder.stats.outcomes.get(tag), Some(&1), "{on}");
        }
    }

    /// Review kola 1 (S3): zvyk flotily (profil drzi 14 dni, novost 7) ani zvyk hostu
    /// novost nevyvrati; u jinych typu zustava neskodnym dukazem.
    #[test]
    fn profile_habit_is_not_benign_evidence_for_novelty() {
        use crate::behavior::profile::ProfileVerdict;
        let policy = LadderPolicy {
            profile: true,
            ..Default::default()
        };
        for verdict in [
            ProfileVerdict::Fleet { hosts: 4 },
            ProfileVerdict::Established {
                since: 1_700_000_000,
                days: 8,
            },
        ] {
            for kind in ["novel_persistent_peer", "novel_fanout"] {
                let mut ladder = Ladder::new(policy, 7);
                let mut env = Env {
                    profile: Some(verdict.clone()),
                    peers: Some((5, 6)),
                    ..Env::default()
                };
                let mut case = input(kind, "10.0.0.5", &["203.0.113.9"]);
                case.history_key = None;
                ladder.open(case, 0);
                let decision = run_until_decided(&mut ladder, &mut env);
                assert_ne!(
                    decision.status,
                    Status::Refuted,
                    "{kind}: {}",
                    decision.reason
                );
                assert_eq!(ladder.stats.outcomes.get("profile:benign"), None, "{kind}");
                assert_eq!(
                    ladder.stats.outcomes.get("profile:undetermined"),
                    Some(&1),
                    "{kind}"
                );
            }
        }
        // kontrola: jiny typ dostane zvyk flotily jako neskodny dukaz
        let mut ladder = Ladder::new(policy, 7);
        let mut env = Env {
            profile: Some(ProfileVerdict::Fleet { hosts: 4 }),
            ..Env::default()
        };
        ladder.open(input("beacon_periodic", "10.0.0.5", &["203.0.113.9"]), 0);
        run_until_decided(&mut ladder, &mut env);
        assert_eq!(ladder.stats.outcomes.get("profile:benign"), Some(&1));
    }

    /// Review kola 2 (S2, S3): ulozeny pripad novosti s drive prijatym neskodnym
    /// dukazem Profile (zvyk flotily, LR 0,35) nebo Context se po nacteni ani za behu
    /// nesmi vyvratit cekajici kontrolou Peers (LR 0,25): 0,15 → 0,0152 by vyvratilo.
    #[test]
    fn persisted_forbidden_novelty_evidence_is_reset() {
        let policy = LadderPolicy {
            profile: true,
            ..Default::default()
        };
        for forbidden in [CheckId::Profile, CheckId::Context] {
            // stav pred opravou: prvni kontrola uz prinesla zakazany neskodny dukaz
            let mut ladder = Ladder::new(policy, 7);
            let mut case = input("novel_persistent_peer", "10.0.0.5", &["203.0.113.9"]);
            case.history_key = None;
            let key = case.key.clone();
            ladder.open(case, 0);
            let lr = if forbidden == CheckId::Profile {
                policy.lr.profile_fleet
            } else {
                policy.lr.context
            };
            {
                let case = ladder.cases.get_mut(&key).unwrap();
                case.plan.retain(|c| *c != forbidden);
                case.log_odds += lr.ln();
                case.benign_evidence = true;
                case.steps.push(Step {
                    check: forbidden,
                    cycle: 0,
                    outcome: Outcome::Evidence {
                        lr,
                        detail: "pred opravou".into(),
                    },
                    posterior: case.posterior(),
                });
            }
            // migrace: ulozeny a znovu nacteny stav
            let text = serde_json::to_string(&ladder).unwrap();
            let mut ladder: Ladder = serde_json::from_str(&text).unwrap();
            let mut env = Env {
                profile: Some(crate::behavior::profile::ProfileVerdict::Fleet { hosts: 4 }),
                peers: Some((5, 6)),
                ..Env::default()
            };
            let decision = run_until_decided(&mut ladder, &mut env);
            assert_ne!(
                decision.status,
                Status::Refuted,
                "{forbidden:?}: {}",
                decision.reason
            );
            assert!(
                !decision.reason.contains("pred opravou"),
                "{forbidden:?}: {}",
                decision.reason
            );
            // nacteni stavu: reset je idempotentni, druhy pruchod nic nenajde
            assert_eq!(ladder.reset_forbidden_novelty_evidence(), 0);
        }
    }

    fn input(kind: &str, entity: &str, sources: &[&str]) -> CaseInput {
        CaseInput {
            key: FindingKey::new(entity, kind, "tcp/80"),
            finding_id: format!("finding:{kind}:{entity}"),
            finding_type: kind.to_string(),
            host_ip: entity.to_string(),
            port: Some(80),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            volume: 100.0,
            history_key: Some(format!("{entity}/tcp/80#flows")),
            high_impact: false,
            prior: 0.15,
            protected: false,
        }
    }

    fn run_until_decided(ladder: &mut Ladder, env: &mut Env) -> Decision {
        run_observed(ladder, env, &[])
    }

    /// Jako `run_until_decided`, ale nález se každý cyklus znovu objeví se `sources`.
    fn run_observed(ladder: &mut Ladder, env: &mut Env, sources: &[&str]) -> Decision {
        let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        let keys: Vec<FindingKey> = ladder.cases.keys().cloned().collect();
        for cycle in 0..20 {
            if !sources.is_empty() {
                for key in &keys {
                    ladder.observe(key, &sources, cycle);
                }
            }
            if let Some(d) = ladder.step(cycle, env).into_iter().next() {
                return d;
            }
        }
        panic!("nerozhodnuto");
    }

    #[test]
    fn empty_results_never_refute_and_case_escalates_after_cap() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env::default();
        assert!(ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0));
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(decision.status, Status::Escalated, "{}", decision.reason);
        assert!(decision.reason.contains("nezjisteno"));
        assert!(
            (decision.posterior - 0.15).abs() < 1e-9,
            "prazdne dotazy viru nemeni"
        );
    }

    /// Krok 12: `strict_refute` nevyvrati pripad na historii a peerech (jedna skupina, zadna
    /// silna); pridani schvaleneho kontextu (druha nezavisla skupina, silna) ano.
    #[test]
    fn strict_refute_needs_two_independent_groups_one_strong() {
        let strict = LadderPolicy {
            strict_refute: true,
            ..LadderPolicy::default()
        };
        let mut ladder = Ladder::new(strict, 7);
        let mut env = Env {
            recurrence: Some(Recurrence::Seen { days: 4 }),
            peers: Some((5, 6)),
            ..Env::default()
        };
        ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_ne!(decision.status, Status::Refuted, "{}", decision.reason);
        assert_eq!(decision.status, Status::Escalated);
        assert!(
            decision.reason.contains("pozitivni dukaz"),
            "{}",
            decision.reason
        );
        assert_eq!(ladder.stats.strict_escalated, 1);
        // s kontextem (kalendar) je dukaz ze dvou nezavislych skupin, jedna silna
        let mut ladder = Ladder::new(
            LadderPolicy {
                strict_refute: true,
                ..LadderPolicy::default()
            },
            7,
        );
        let mut env = Env {
            recurrence: Some(Recurrence::Seen { days: 4 }),
            peers: Some((5, 6)),
            context: Some("backup (schvalil spravce)".into()),
            ..Env::default()
        };
        ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(decision.status, Status::Refuted, "{}", decision.reason);
    }

    /// Krok 12: rezim konkurencnich hypotez rozhoduje podle ceny omylu (zmerene LR),
    /// ne podle pevneho prahu; slaby neskodny dukaz pripad nezavre, jde cloveku.
    #[test]
    fn competing_mode_escalates_weak_benign_evidence_and_tracks_observations() {
        let mut ladder = Ladder::new(
            LadderPolicy {
                competing: true,
                strict_refute: true,
                ..LadderPolicy::default()
            },
            7,
        );
        let mut env = Env {
            recurrence: Some(Recurrence::Seen { days: 4 }),
            peers: Some((5, 6)),
            ..Env::default()
        };
        ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(decision.status, Status::Escalated, "{}", decision.reason);
        assert!(decision.raw_posterior > 0.0 && decision.raw_posterior < 1.0);
    }

    /// Krok 12: kontrola L7 je v planu jen s `l7`, bez pokryti je nedostupna (nic neznamena),
    /// a plan v rezimu `competing` zacina kontrolou s nejvyssi informaci na cenu.
    #[test]
    fn l7_check_is_planned_only_when_enabled_and_competing_orders_by_information() {
        let off = checks_for(
            &input("tls_rare_transfer", "10.0.0.5", &[]),
            &LadderPolicy::default(),
        );
        assert!(!off.contains(&CheckId::L7));
        let policy = LadderPolicy {
            l7: true,
            competing: true,
            ..LadderPolicy::default()
        };
        let on = checks_for(&input("tls_rare_transfer", "10.0.0.5", &[]), &policy);
        assert!(on.contains(&CheckId::L7));
        let plan = plan_for(&input("tls_rare_transfer", "10.0.0.5", &[]), 7, &policy);
        let first = plan.front().copied().unwrap();
        assert_ne!(first, CheckId::Persistence, "cekani je vzdy posledni");
        // bez dat je kontrola nedostupna a nema vahu
        let mut ladder = Ladder::new(policy, 7);
        let mut env = Env::default();
        ladder.open(input("tls_rare_transfer", "10.0.0.5", &[]), 0);
        let d = run_until_decided(&mut ladder, &mut env);
        assert!(
            d.steps
                .iter()
                .any(|(c, tag)| *c == CheckId::L7 && *tag == "unavailable")
        );
    }

    #[test]
    fn recurring_and_widespread_pattern_is_refuted_with_reason() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            recurrence: Some(Recurrence::Seen { days: 4 }),
            peers: Some((5, 6)),
            ..Env::default()
        };
        ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(decision.status, Status::Refuted, "{}", decision.reason);
        assert!(decision.reason.contains("history") && decision.reason.contains("peers"));
        assert_eq!(decision.decided, 0, "rozhodnuto okamzite, bez cekani");
    }

    #[test]
    fn bad_reputation_new_behaviour_and_persistence_confirm() {
        // bez KEV: silne podezreni, ale pod mezi potvrzeni -> eskalace cloveku
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            recurrence: Some(Recurrence::New { history_days: 5 }),
            bad: ["203.0.113.9".to_string()].into_iter().collect(),
            ..Env::default()
        };
        ladder.open(
            input("source_volume_outlier", "10.0.0.5", &["203.0.113.9"]),
            0,
        );
        let decision = run_observed(&mut ladder, &mut env, &["203.0.113.9"]);
        assert_eq!(decision.status, Status::Escalated, "{}", decision.reason);
        assert!(decision.posterior > 0.8);

        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            kev: true,
            recurrence: Some(Recurrence::New { history_days: 5 }),
            bad: ["203.0.113.9".to_string()].into_iter().collect(),
            ..Env::default()
        };
        ladder.open(
            input("source_volume_outlier", "10.0.0.5", &["203.0.113.9"]),
            0,
        );
        let decision = run_observed(&mut ladder, &mut env, &["203.0.113.9"]);
        assert_eq!(decision.status, Status::Confirmed, "{}", decision.reason);
        assert!(decision.posterior >= 0.9);
    }

    #[test]
    fn open_is_idempotent_and_merges_sources() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        assert!(ladder.open(input("scan_attempts", "10.0.0.5", &["198.51.100.1"]), 0));
        assert!(!ladder.open(input("scan_attempts", "10.0.0.5", &["198.51.100.2"]), 1));
        assert_eq!(ladder.open_cases(), 1);
        assert_eq!(ladder.stats.cases_merged, 1);
    }

    #[test]
    fn fragile_device_gets_no_active_probe_and_outage_refutes_otherwise() {
        let printer = DeviceClass {
            kind: DeviceKind::Printer,
            confidence: ClassConfidence::High,
            reasons: vec!["tiskovy protokol".into()],
        };
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            device: Some(printer),
            liveness: Some(Liveness::Down),
            ..Env::default()
        };
        ladder.open(input("service_unreachable", "10.0.0.20", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(
            env.liveness_calls, 0,
            "krehke zarizeni bez schvaleni neproklepnout"
        );
        assert_eq!(decision.status, Status::Escalated);
        assert_eq!(ladder.stats.needs_approval, 1);

        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            liveness: Some(Liveness::Down),
            ..Env::default()
        };
        ladder.open(input("service_unreachable", "10.0.0.21", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(env.liveness_calls, 1);
        assert_eq!(decision.status, Status::Refuted, "{}", decision.reason);
    }

    #[test]
    fn pivot_stays_in_scope_and_respects_depth_and_node_cap() {
        let mut env = Env::default();
        env.edges
            .insert("10.0.0.5".into(), vec!["10.0.0.6".into(), "8.8.8.8".into()]);
        env.edges.insert("10.0.0.6".into(), vec!["10.0.0.7".into()]);
        env.edges.insert("10.0.0.7".into(), vec!["10.0.0.8".into()]);
        env.edges.insert("10.0.0.8".into(), vec!["10.0.0.9".into()]);
        env.suspicious.insert("10.0.0.9".into());
        env.suspicious.insert("10.0.0.8".into());
        let policy = LadderPolicy::default();
        let case = input("scan_attempts", "10.0.0.5", &[]);
        let out = evaluate(
            CheckId::Pivot,
            &case,
            (0, Persistence::Gone),
            0,
            &mut env,
            &policy.lr,
            &policy,
            1,
        );
        // hloubka 3: 10.0.0.6, .7, .8 (ne .9, ne 8.8.8.8 mimo rozsah)
        match out {
            Outcome::Evidence { lr, detail } => {
                assert!((lr - 2.0).abs() < 1e-9, "{detail}");
                assert!(detail.contains("z 3"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn budget_defers_and_escalates_and_order_is_not_alphabetical() {
        let policy = LadderPolicy {
            budget_per_cycle: 0.12,
            max_deferred: 2,
            explore: 0.0,
            ..LadderPolicy::default()
        };
        let mut ladder = Ladder::new(policy, 99);
        for i in 0..6 {
            ladder.open(
                input("inductive_volume_anomaly", &format!("10.0.0.{i}"), &[]),
                0,
            );
        }
        let mut env = Env::default();
        let mut decided = Vec::new();
        for cycle in 0..6 {
            decided.extend(ladder.step(cycle, &mut env));
        }
        assert!(ladder.stats.checks_deferred > 0);
        assert!(decided.iter().any(|d| d.budget_escalation));
        // stejny tajny klic = stejne poradi (reprodukovatelnost), jiny klic = jine poradi
        let order = |secret: u64| {
            let mut l = Ladder::new(LadderPolicy::default(), secret);
            let case = input("unexpected_traffic", "10.0.0.5", &["10.0.1.1"]);
            l.open(case.clone(), 0);
            plan_for(&case, secret, &LadderPolicy::default())
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(order(1), order(1));
        let plan = order(1);
        assert_eq!(
            plan.last(),
            Some(&CheckId::Persistence),
            "cekani az nakonec"
        );
        let levels: Vec<Level> = plan[..plan.len() - 1].iter().map(|c| c.level()).collect();
        let mut sorted = levels.clone();
        sorted.sort();
        assert_eq!(levels, sorted, "urovne od nejlevnejsi");
        assert!(
            (0..40).any(|s| order(s) != order(1)),
            "pořadí uvnitř úrovně je náhodné"
        );
    }

    #[test]
    fn ladder_state_roundtrips_through_json() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 3);
        ladder.open(input("scan_attempts", "10.0.0.5", &["198.51.100.1"]), 0);
        let mut env = Env::default();
        ladder.step(0, &mut env);
        let json = serde_json::to_string(&ladder).unwrap();
        let back: Ladder = serde_json::from_str(&json).unwrap();
        assert_eq!(back.open_cases(), ladder.open_cases());
    }

    #[test]
    fn learner_shrinks_toward_author_respects_bounds_and_drops_poisoned_source() {
        let mut learner = LadderLearner::default();
        let steps = [
            (CheckId::History, "benign"),
            (CheckId::Context, "undetermined"),
        ];
        assert_eq!(
            learner.lr(CheckId::History, "benign", 0.25),
            0.25,
            "bez dat autorsky"
        );
        for _ in 0..200 {
            learner.record("operator:op", &steps, false, 1.0);
        }
        for _ in 0..50 {
            learner.record(
                "operator:op",
                &[(CheckId::Context, "undetermined")],
                true,
                1.0,
            );
        }
        let lr = learner.lr(CheckId::History, "benign", 0.25);
        assert!((0.02..0.25).contains(&lr), "{lr}");
        assert_eq!(
            learner.lr(CheckId::Context, "undetermined", 1.0),
            1.0,
            "prazdny vysledek se neuci"
        );
        // benigni znacka nikdy nad 1, i kdyby data rikala opak
        for _ in 0..500 {
            learner.record("operator:mallory", &steps, true, 1.0);
        }
        assert!(learner.lr(CheckId::History, "benign", 0.25) <= 1.0);
        learner.exclude("operator:mallory");
        assert!((learner.lr(CheckId::History, "benign", 0.25) - lr).abs() < 1e-12);
    }

    fn ops_diag(class: &str, id: Option<&str>) -> crate::ops_telemetry::OpsDiagnosis {
        crate::ops_telemetry::OpsDiagnosis {
            class: class.into(),
            catalog_id: id.map(str::to_string),
            score: 0.9,
            margin: 0.5,
            evidence: vec!["if_oper_down".into()],
            alternatives: vec![],
            missing: vec!["snmp".into()],
            reason: "nelze urcit, chybi telemetrie: snmp".into(),
            explains_partly: false,
            root: None,
            candidates: vec![],
        }
    }

    fn ops_policy() -> LadderPolicy {
        LadderPolicy {
            ops: true,
            protect: true,
            ..Default::default()
        }
    }

    /// Krok 14 (C2): shoda s poruchou je dukaz, ale sama nikdy nezavre nalez
    /// (porucha se nezavira jen proto, ze neni utok; dokaz vyvraceni potrebuje dalsi skupiny).
    #[test]
    fn ops_fault_evidence_is_recorded_but_never_refutes_alone() {
        let mut env = Env {
            ops: Some(ops_diag("porucha", Some("OPS-001"))),
            ..Env::default()
        };
        let d = decide(ops_policy(), "service_unreachable", &mut env);
        assert_ne!(d.status, Status::Refuted, "{}", d.reason);
        assert!(
            d.steps
                .iter()
                .any(|(c, t)| *c == CheckId::Ops && *t == "benign"),
            "{:?}",
            d.steps
        );
    }

    /// Chybejici telemetrie je nedostupna (nic neznamena), neurceny nebo bez dukazu se neuzna.
    #[test]
    fn ops_missing_telemetry_is_unavailable_not_benign() {
        for diag in [Some(ops_diag("neurceno", None)), None] {
            let mut env = Env {
                ops: diag,
                ..Env::default()
            };
            let d = decide(ops_policy(), "service_unreachable", &mut env);
            assert_ne!(d.status, Status::Refuted, "{}", d.reason);
            assert!(
                d.steps
                    .iter()
                    .any(|(c, t)| *c == CheckId::Ops && *t == "unavailable"),
                "{:?}",
                d.steps
            );
        }
        // vypnuta kontrola v planu neni
        let mut env = Env::default();
        let d = decide(LadderPolicy::default(), "service_unreachable", &mut env);
        assert!(!d.steps.iter().any(|(c, _)| *c == CheckId::Ops));
    }

    /// Chraneny nalez: provozni vysvetleni neni dukaz neskodnosti.
    #[test]
    fn ops_evidence_never_helps_protected_case() {
        let mut env = Env {
            ops: Some(ops_diag("porucha", Some("OPS-001"))),
            recurrence: Some(Recurrence::Seen { days: 9 }),
            peers: Some((5, 6)),
            ..Env::default()
        };
        let d = decide(ops_policy(), "suricata_alert", &mut env);
        assert_ne!(d.status, Status::Refuted, "{}", d.reason);
        assert!(
            !d.steps
                .iter()
                .any(|(c, t)| *c == CheckId::Ops && *t == "benign")
        );
    }

    /// Krok 14: proces ze seznamu povolenych (schvaleni vlastnikem + potvrzeni procesem) jsou dve
    /// nezavisle skupiny, stoji za vyvracenim i pri `strict_refute`; u chraneneho nalezu nikdy.
    #[test]
    fn allowlisted_process_refutes_under_strict_close_but_never_protected() {
        use crate::endpoint::correlate::EndpointSignal;
        let strict = LadderPolicy {
            endpoint: true,
            protect: true,
            strict_refute: true,
            ..Default::default()
        };
        let mk = || Env {
            endpoint: Some(EndpointSignal::Allowed(
                "a: veeamagent.exe (vlastnik sprava-it, do 1)".into(),
            )),
            ..Env::default()
        };
        let d = decide(strict, "inductive_volume_anomaly", &mut mk());
        assert_eq!(d.status, Status::Refuted, "{}", d.reason);
        // totez s bezny neskodnym vzorem (bez seznamu) jedna skupina nestaci
        let benign = Env {
            endpoint: Some(EndpointSignal::Benign("podepsany updater".into())),
            ..Env::default()
        };
        let mut benign = benign;
        let d2 = decide(strict, "inductive_volume_anomaly", &mut benign);
        assert_ne!(d2.status, Status::Refuted, "{}", d2.reason);
        for kind in ["suricata_alert", "novel_persistent_peer", "endpoint_alert"] {
            let d3 = decide(strict, kind, &mut mk());
            assert_ne!(d3.status, Status::Refuted, "{kind}: {}", d3.reason);
        }
    }

    fn high_prior(kind: &str) -> CaseInput {
        CaseInput {
            prior: 0.95,
            ..input(kind, "10.0.0.5", &["203.0.113.9"])
        }
    }

    fn decide_input(policy: LadderPolicy, case: CaseInput, env: &mut Env) -> Decision {
        let mut ladder = Ladder::new(policy, 7);
        ladder.open(case, 0);
        run_until_decided(&mut ladder, env)
    }

    /// Krok 18: bez prepinace potvrdi vysoka apriorni P sama po prvni kontrole bez vysledku
    /// (stav kroku 17, koren nalezu K16-4); s prepinacem jde pripad cloveku jako nepotvrzeny
    /// s kontrolou, na kterou ceka, a apriorni P zustava v rozhodnuti (poradi).
    #[test]
    fn prior_alone_does_not_confirm_with_confirm_evidence() {
        let off = decide_input(
            LadderPolicy::default(),
            high_prior("unexpected_traffic"),
            &mut Env::default(),
        );
        assert_eq!(off.status, Status::Confirmed, "{}", off.reason);
        assert!(!has_suspicious_evidence(&off.notes));
        let policy = LadderPolicy {
            confirm_evidence: true,
            ..LadderPolicy::default()
        };
        let mut ladder = Ladder::new(policy, 7);
        ladder.open(high_prior("unexpected_traffic"), 0);
        let on = run_until_decided(&mut ladder, &mut Env::default());
        assert_eq!(on.status, Status::Escalated, "{}", on.reason);
        assert!(on.prior_hold && on.posterior >= 0.9);
        assert!(
            on.reason.starts_with("nepotvrzeno: P(utok)"),
            "{}",
            on.reason
        );
        assert!(on.pending_check.is_some(), "{}", on.reason);
        assert!(on.reason.contains("ceka na kontrolu"), "{}", on.reason);
        assert_eq!(ladder.stats.prior_held, 1);
        assert_eq!(ladder.stats.confirmed, 0);
        // rozhodnuto ve stejnem cyklu jako bez prepinace (zobrazeni se neposouva)
        assert_eq!(on.decided, off.decided);
    }

    /// Krok 18: podezrely vysledek z nezavisleho zdroje (reputace zdroje) potvrzeni nese.
    #[test]
    fn independent_suspicious_result_confirms_with_confirm_evidence() {
        let policy = LadderPolicy {
            confirm_evidence: true,
            ..LadderPolicy::default()
        };
        let mut env = Env {
            bad: ["203.0.113.9".to_string()].into_iter().collect(),
            ..Env::default()
        };
        let d = decide_input(policy, high_prior("unexpected_traffic"), &mut env);
        assert_eq!(d.status, Status::Confirmed, "{}", d.reason);
        assert!(has_independent_evidence(&d.notes) && !d.prior_hold);
    }

    /// Krok 18: historie toku („novy jev“) a pretrvani jsou tyz tok dat jako detektor, ne
    /// nezavisly zdroj; samy potvrzeni nenesou.
    #[test]
    fn dependent_evidence_alone_does_not_confirm() {
        assert!(!confirm_source(CheckId::History) && !confirm_source(CheckId::Persistence));
        assert!(!confirm_source(CheckId::Profile) && !confirm_source(CheckId::Ops));
        let policy = LadderPolicy {
            confirm_evidence: true,
            ..LadderPolicy::default()
        };
        let mut env = Env {
            recurrence: Some(Recurrence::New { history_days: 14 }),
            ..Env::default()
        };
        let mut case = high_prior("unexpected_traffic");
        case.prior = 0.85;
        let d = decide_input(policy, case, &mut env);
        assert_ne!(d.status, Status::Confirmed, "{}", d.reason);
        assert!(has_suspicious_evidence(&d.notes) && !has_independent_evidence(&d.notes));
    }

    /// Krok 18: klic s nedavnym nepotvrzenym podezrenim se automaticky nevyvraci (drive to
    /// branilo potvrzeni v pameti nalezu); po `HOLD_CYCLES` ochrana konci.
    #[test]
    fn held_key_is_not_refuted_within_hold_window() {
        let policy = LadderPolicy {
            confirm_evidence: true,
            ..LadderPolicy::default()
        };
        let benign = || Env {
            recurrence: Some(Recurrence::Seen { days: 9 }),
            context: Some("planovana zaloha".into()),
            liveness: Some(Liveness::Down),
            peers: Some((5, 6)),
            ..Env::default()
        };
        let low = || input("connection_timeout_burst", "10.0.0.5", &[]);
        // bez drzeni se pripad s neskodnymi dukazy vyvrati
        let free = decide_input(policy, low(), &mut benign());
        assert_eq!(free.status, Status::Refuted, "{}", free.reason);
        let mut ladder = Ladder::new(policy, 7);
        let mut first = low();
        first.prior = 0.95;
        ladder.open(first, 0);
        let held = run_until_decided(&mut ladder, &mut Env::default());
        assert!(held.prior_hold, "{}", held.reason);
        ladder.open(low(), held.decided + 1);
        let mut env = benign();
        let mut again = None;
        for cycle in held.decided + 1..held.decided + 20 {
            if let Some(d) = ladder.step(cycle, &mut env).into_iter().next() {
                again = Some(d);
                break;
            }
        }
        let again = again.expect("rozhodnuto");
        assert_eq!(again.status, Status::Escalated, "{}", again.reason);
        assert!(again.reason.starts_with("drzeno:"), "{}", again.reason);
        assert_eq!(ladder.stats.hold_refused, 1);
        // po okne drzeni se klic opet vyvraci
        let late = held.decided + HOLD_CYCLES + 5;
        ladder.open(low(), late);
        let mut env = benign();
        let mut after = None;
        for cycle in late..late + 20 {
            if let Some(d) = ladder.step(cycle, &mut env).into_iter().next() {
                after = Some(d);
                break;
            }
        }
        assert_eq!(after.expect("rozhodnuto").status, Status::Refuted);
    }

    /// Krok 18 (K18-7): property/fuzz test invariantu „confirmed ⇒ existuje pozitivni dukaz
    /// z nezavisleho zdroje“ na 20 000 nahodnych pripadech (apriorni P, politika, typ nalezu,
    /// vysledky vsech zdroju, opakovani nalezu). Zaroven: nepotvrzeny pripad je vzdy
    /// eskalovany a nikdy vyvraceny, P konecna v [0, 1].
    #[test]
    fn confirmed_always_has_independent_evidence_fuzz() {
        use crate::endpoint::correlate::EndpointSignal;
        let kinds = [
            "unexpected_traffic",
            "pivot_chain",
            "suricata_alert",
            "packet_rate_spike",
            "connection_timeout_burst",
            "service_unreachable",
            "scan_attempts",
            "beacon_periodic",
            "egress_volume_anomaly",
            "unmapped_passive_event",
        ];
        let mut state = 0x1818_2026u64;
        let mut next = |n: u64| {
            state = mix(state);
            state % n.max(1)
        };
        let (mut confirmed, mut held) = (0u64, 0u64);
        for i in 0..20_000u64 {
            let policy = LadderPolicy {
                confirm_evidence: true,
                strict_refute: next(2) == 0,
                competing: next(4) == 0,
                protect: next(2) == 0,
                endpoint: next(2) == 0,
                endpoint_weak: next(2) == 0,
                max_checks: 1 + next(9) as usize,
                ..LadderPolicy::default()
            };
            let kind = kinds[next(kinds.len() as u64) as usize];
            let mut case = input(
                kind,
                &format!("10.0.{}.{}", next(4), 1 + next(200)),
                &["203.0.113.9"],
            );
            case.prior = match next(4) {
                0 => 0.5 + next(500) as f64 / 1000.0,
                1 => 0.9 + next(100) as f64 / 1000.0,
                2 => next(1000) as f64 / 1000.0,
                _ => 0.15,
            };
            case.high_impact = next(5) == 0;
            let mut env = Env {
                recurrence: match next(4) {
                    0 => Some(Recurrence::Seen {
                        days: 1 + next(9) as u32,
                    }),
                    1 => Some(Recurrence::New { history_days: 14 }),
                    _ => None,
                },
                context: (next(6) == 0).then(|| "kalendar".to_string()),
                bad: if next(5) == 0 {
                    ["203.0.113.9".to_string()].into_iter().collect()
                } else {
                    HashSet::new()
                },
                peers: match next(3) {
                    0 => Some((0, 6)),
                    1 => Some((5, 6)),
                    _ => None,
                },
                liveness: match next(5) {
                    0 => Some(Liveness::Down),
                    1 => Some(Liveness::NeedsApproval),
                    2 => Some(Liveness::OutOfScope),
                    _ => None,
                },
                kev: next(6) == 0,
                suspicious: if next(4) == 0 {
                    ["10.0.0.9".to_string()].into_iter().collect()
                } else {
                    HashSet::new()
                },
                edges: [(case.host_ip.clone(), vec!["10.0.0.9".to_string()])]
                    .into_iter()
                    .collect(),
                endpoint: match next(5) {
                    0 => Some(EndpointSignal::Suspicious("proces".into())),
                    1 => Some(EndpointSignal::Benign("updater".into())),
                    2 => Some(EndpointSignal::Allowed("seznam povolenych".into())),
                    _ => None,
                },
                ..Env::default()
            };
            let mut ladder = Ladder::new(policy, i);
            ladder.open(case, 0);
            let sources: &[&str] = if next(2) == 0 { &["203.0.113.9"] } else { &[] };
            let d = run_observed(&mut ladder, &mut env, sources);
            assert!(d.posterior.is_finite() && (0.0..=1.0).contains(&d.posterior));
            if d.status == Status::Confirmed {
                confirmed += 1;
                assert!(has_independent_evidence(&d.notes), "{i}: {}", d.reason);
            }
            if d.prior_hold {
                held += 1;
                assert_eq!(d.status, Status::Escalated, "{i}: {}", d.reason);
                assert!(!has_independent_evidence(&d.notes), "{i}: {}", d.reason);
            }
        }
        // generator musi pokryt obe vetve, jinak test nic nedokazuje
        assert!(
            confirmed > 500 && held > 500,
            "potvrzeno {confirmed}, drzeno {held}"
        );
    }
}
