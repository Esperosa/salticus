//! Přepínač jádra (`engine.mode = legacy | v3`) a volby jednotlivých změn v3.
//!
//! Stará cesta (`legacy`) zůstává výchozí, dokud párové A/B na stejných seedech
//! neprojde laťkou (00-zaver Dodatek A, §5A.2). Každou změnu v3 jde vypnout zvlášť,
//! aby šlo změřit její samostatný přínos (ablace, krok 1, docs/diplomka/eval/impl-krok1.md).

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    #[default]
    Legacy,
    V3,
}

impl EngineMode {
    pub fn label(self) -> &'static str {
        match self {
            EngineMode::Legacy => "legacy",
            EngineMode::V3 => "v3",
        }
    }
}

impl fmt::Display for EngineMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for EngineMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "legacy" => Ok(EngineMode::Legacy),
            "v3" => Ok(EngineMode::V3),
            other => Err(format!("neznamy rezim jadra '{other}' (legacy | v3)")),
        }
    }
}

/// Jednotlivé změny jádra v3. Výchozí: vše zapnuto. V režimu `legacy` se ignorují.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct V3Features {
    /// Paměť nálezů: stabilní identita, stav, TTL, strop, deduplikace (krok B).
    pub memory: bool,
    /// Robustní `packet_rate_spike` (p95 kvalifikovaných toků + historie, krok C).
    pub rate: bool,
    /// `inductive_volume_anomaly` proti vlastní historii a skupině (krok C).
    pub volume: bool,
    /// `unexpected_traffic`: úspěch vs. pokusy, perzistentní inventář, agregace unmapped (krok C).
    pub unexpected: bool,
    /// Kontextové vyloučení s auditem (krok D).
    pub context: bool,
    /// Vícesignálová identita (krok E).
    pub identity: bool,
    /// Obnova recallu (krok 2A): eskalace při prvním dominantním zdroji, pokusy i na
    /// známé služby, IDS nálezy podle signatury, zdrojová odlehlost, timeouty podle
    /// rozložení zdrojů.
    pub recall: bool,
    /// Žebřík okamžitého ověřování (krok 2B).
    pub ladder: bool,
    /// Učení z výsledků ověření a kalibrace (krok 2C).
    pub learning: bool,
    /// Typ zařízení v jádru: kontext ověřování a ochrana křehkých zařízení (krok 2D).
    pub devices: bool,
    /// Peer baseline detektoru podle typu zařízení a podsítě (krok 2D, zvlášť měřeno).
    #[serde(default)]
    pub peers: bool,
    /// Viditelnost odchozího provozu: toky a alerty se zdrojem NEBO cílem v rozsahu,
    /// se směrem a vzorkováním (krok 3A, audit 01 A10/R2).
    pub egress: bool,
    /// Beaconing na dvojici zdroj-cíl (krok 3B, RQ4 Z1/Z2, hypotéza).
    pub beacon: bool,
    /// Interaktivní relace a dlouhé tunely ven (krok 3C, RQ4 Z13, hypotéza).
    pub interactive: bool,
    /// Graf spojení: nové hrany a řetěz A→B→C (krok 3D, RQ4 Z10/Z11).
    pub graph: bool,
    /// Profil hostu a známé neškodné vzory jako pozitivní důkaz žebříku (krok 3E).
    pub profile: bool,
    /// Krok 6 (kandidát 1): výpadek senzoru nic nezavře a není neškodný důkaz žebříku
    /// (Dodatek A.2 d, RQ6 Z3: chybějící data nejsou důkaz neškodnosti).
    #[serde(default)]
    pub sensor_strict: bool,
    /// Krok 6 (kandidát 2): třída „provozní problém“ s pozitivním důkazem provozní
    /// příčiny; nezavírá se, jen jde do fronty provoz místo podezření na útok.
    #[serde(default)]
    pub ops_class: bool,
    /// Krok 6 (kandidáti 4 a 5): obecná novost vztahů hostu (nová trvalá vazba ven,
    /// nové vnitřní vazby), nezávislá na rodině útoku.
    #[serde(default)]
    pub novelty: bool,
    /// Krok 6 (kandidát 6): zdrojově citlivý kontext nezavře nález bez
    /// identifikovaného zdroje (kromě objemu v okně zálohy a dávky).
    #[serde(default)]
    pub context_guard: bool,
    /// Krok 7 (A1): chráněné nálezy (novost, graf, signatura, degradace, nejednoznačný
    /// kontext) se nikdy automaticky nezavřou, nevyvrátí ani neodkloní a zobrazí se hned.
    #[serde(default)]
    pub protect: bool,
    /// Krok 7 (B1): třída provoz jen jako anotace, nález zůstává ve frontě podezření.
    #[serde(default)]
    pub ops_annotate: bool,
    /// Krok 7 (B2): hopy jednoho pivotu a kořene řetězu jsou jeden incident paměti.
    #[serde(default)]
    pub graph_incident: bool,
    /// Krok 7 (B3a): rychlá nová vazba ven (`novel_burst_peer`).
    #[serde(default)]
    pub novel_burst: bool,
    /// Krok 7 (B3b): `novel_fanout` jen s druhým signálem.
    #[serde(default)]
    pub fanout2: bool,
    /// Krok 7 (B4): agregace selhání a nových vazeb přes zdroje (`distributed_sources`).
    #[serde(default)]
    pub cross_source: bool,
    /// Krok 7 (B5): opakovaná upozornění na novou vazbu ven jako jeden incident.
    #[serde(default)]
    pub saas_group: bool,
    /// Krok 8: koncová telemetrie (Sysmon, Wazuh, osquery) jako nezávislý druh důkazu.
    /// Platí jen s `protect` a `memory`; výchozí vypnuto (impl-krok8.md).
    #[serde(default)]
    pub endpoint: bool,
    /// Krok 9: obecné detektory rysů provozu (bouře na broadcast, stažený objem,
    /// pomalý únik, zaplnění linky). Výchozí vypnuto (impl-krok9.md).
    #[serde(default)]
    pub breadth: bool,
    /// Krok 9: objemove detektory `breadth` (`ingest_volume_anomaly`, `link_saturation`).
    /// Vypnuto: na ladicim seedu pridaly 3,4 zobrazenych FP na sit-den (impl-krok9.md, D).
    #[serde(default)]
    pub breadth_volume: bool,
    /// Krok 11: velky prenos s prvne videnym vnejsim protejskem (`novel_bulk_transfer`).
    /// Vychozi vypnuto (impl-krok11.md).
    #[serde(default)]
    pub bulk_novel: bool,
    /// Krok 11: rychly shluk toku na prvne videne vnejsi protejsky (`novel_peer_burst`).
    #[serde(default)]
    pub peer_burst: bool,
    /// Krok 11: jako `bulk_novel`, ale jen pro prenos po nesifrovanych portech.
    #[serde(default)]
    pub bulk_clear: bool,
    /// Krok 12: zavreni kontextem jen s identifikovanymi zdroji, z nichz VSECHNY patri zaznamu
    /// (zadny souhrn `any`), bez vyjimky pro objem. Vychozi vypnuto (impl-krok12.md).
    #[serde(default)]
    pub strict_close: bool,
    /// Krok 12: detektory nad TLS metadaty (SNI, JA3/JA4, certifikat).
    #[serde(default)]
    pub l7_tls: bool,
    /// Krok 12: detektory nad DNS metadaty (vycet zony).
    #[serde(default)]
    pub l7_dns: bool,
    /// Krok 12: konkurencni hypotezy a rozhodnuti podle ceny omylu v zebricku.
    #[serde(default)]
    pub hypotheses: bool,
    /// Krok 12: citlivejsi znovuzobrazeni opakovaneho nalezu pri zmene objemu (faktor 2, min. 8).
    #[serde(default)]
    pub redisplay: bool,
    /// Krok 12: ICMP s neobvykle velkou uzitecnou casti (`icmp_payload_anomaly`).
    #[serde(default)]
    pub icmp_payload: bool,
    /// Krok 13: `slow_egress` mlci o cilech, na ktere odesila mnoho zdroju (sluzba site).
    #[serde(default)]
    pub slow_fanin: bool,
    /// Krok 12: spisy pripadu, incidenty, prehodnoceni s auditem (report `correlation`).
    #[serde(default)]
    pub case_files: bool,
    /// Krok 12: kontrola TLS a DNS metadat v planu zebricku.
    #[serde(default)]
    pub l7_ladder: bool,
    /// Krok 12: znovuzobrazeni otevreneho opakujiciho se nalezu po 6 h od posledniho zobrazeni.
    #[serde(default)]
    pub redisplay_age: bool,
    /// Krok 14 (C2): provozní telemetrie (SNMP, syslog, DHCP, DNS, ARP, NTP, probes) a
    /// diagnóza nálezu podle katalogu. Jen anotace a fronta, nikdy zavření.
    #[serde(default)]
    pub ops_telemetry: bool,
    /// Krok 14 (A): rozšířené koncové indikátory (cloud, DNS, kancelářské procesy, stažení a spuštění)
    /// a seznam povolených s vlastníkem a expirací jako pozitivní důkaz neškodnosti. Vyžaduje `endpoint`.
    #[serde(default)]
    pub endpoint_ext: bool,
    /// Krok 14 (A): seznam povolených (hash, podpis, výrobce, protistrana, vlastník, expirace) jako
    /// pozitivní důkaz neškodnosti v žebříčku. Vyžaduje `endpoint_ext`. Měření: bez prokázaného
    /// přínosu a s rizikem při lhoucím agentu, proto jen volitelně.
    #[serde(default)]
    pub endpoint_allow: bool,
    /// Krok 11: sken vnejsiho zdroje s mene cili, ale bez jedineho uspechu (`scan_attempts`).
    #[serde(default)]
    pub scan_fresh: bool,
    /// Krok 15 (P1): „nic podezřelého“ od koncového agenta není silná skupina důkazu
    /// neškodnosti; při `strict_close` vyvrací jen spolu s kontextem nebo živostí.
    #[serde(default)]
    pub endpoint_weak: bool,
    /// Krok 15 (P1): vyvrácený klíč paměti pohltí jen souvislé pokračování téže epizody;
    /// po odmlce (> 1 h) se nález znovu ověřuje žebříkem místo tichého potlačení.
    #[serde(default)]
    pub refute_episode: bool,
    /// Krok 15 (P3): typ katalogu vysvětlí jen příznaky, které jeho mechanismus vyvolává
    /// (`explains`), a mezi rovnocennými kandidáty vyhrává ten, který pokrývá víc signálů.
    #[serde(default)]
    pub ops_symptoms: bool,
    /// Krok 15 (P3): signál o infrastrukturním zařízení (router, DNS, VPN, AP) platí pro
    /// hosty, které na něm závisí (celá síť), ne jen pro jeho vlastní adresu.
    #[serde(default)]
    pub ops_blast: bool,
    /// Krok 15 (P2): nahraný objem hostu se hodnotí i přes klouzavé okno 6 oken (3 h)
    /// se stejnými prahy; zaplňuje mezeru mezi jedním oknem a pomalým únikem.
    #[serde(default)]
    pub upload_horizon: bool,
    /// Krok 27: opakovaná krátká spojení na přihlašovací službu (hádání hesel), nezávisle
    /// na vrstevnících. Výchozí vypnuto; `recommended()` se nemění.
    #[serde(default)]
    pub attempts: bool,
    /// Krok 31: odchozí skenování vnitřního hosta (mnoho vnějších cílů bez odpovědi),
    /// nezávisle na zralosti profilu. Výchozí vypnuto; `recommended()` se nemění.
    #[serde(default)]
    pub outscan: bool,
    /// Krok 32: opakované neúspěšné pokusy vnitřního hosta na stejný vnější cíl a port.
    /// Výchozí vypnuto; `recommended()` se nemění.
    #[serde(default)]
    pub retry: bool,
    /// Krok 33: opravená korelace (skutečný čas nálezu, bez duplicitních událostí, seskupení v2,
    /// stabilní id incidentu, čítače zahozených). Jen anotace, nic nezavírá. Výchozí vypnuto.
    #[serde(default)]
    pub corr_v2: bool,
    /// Krok 34: kauzální seskupení incidentů (protějšek se stane aktérem), nálezy bez hosta jako
    /// oběť, ochrana proti hubům. Vyžaduje `corr_v2`. Výchozí vypnuto.
    #[serde(default)]
    pub corr_v3: bool,
    /// Krok 36: stejný vnější protějšek spojuje nálezy do incidentu (s mezí hubu). Vyžaduje `corr_v3`.
    #[serde(default)]
    pub corr_ext: bool,
    /// Krok 37: seskupení incidentů podle sdílené adresy s oknem a mezí hubu. Vyžaduje `corr_v2`.
    #[serde(default)]
    pub corr_union: bool,
    /// Krok 37: související incidenty podle sdílené adresy s důvodem (bez slučování). Vyžaduje `corr_v3`.
    #[serde(default)]
    pub corr_related: bool,
    /// Krok 16: případová složka pro seniora (shrnutí, aktéři, hypotézy, důkazy pro a
    /// proti, co zbývá ověřit, slepá místa, důvod předání, uzávěr L1). Nic nerozhoduje.
    #[serde(default)]
    pub case_folder: bool,
    /// Krok 18: stav `confirmed` jen s aspoň jedním pozitivním výsledkem kontroly z nezávislého
    /// zdroje; samotná apriorní P zvedá pořadí, nepotvrzuje (případ jde člověku s kontrolou, na
    /// kterou čeká). Vyžaduje žebřík.
    #[serde(default)]
    pub confirm_evidence: bool,
    /// Krok 20: jediná brána zavření (`closure_gate`): zavřít jen s pozitivním důkazem a
    /// vlastníkem, nikdy chráněné ani vysoký dopad, zámek podezření, rozsah epizody. Vyžaduje paměť.
    #[serde(default)]
    pub close_gate: bool,
    /// Krok 22 (kontext v2, K21-N14 a K21-N13): záznam kontextu ovlivní nález (včetně
    /// nejednoznačnosti P5) jen při shodě hostu; rozsah autorizovaného skeneru se porovnává
    /// s cíli nálezu. Výchozí vypnuto.
    #[serde(default)]
    pub ctx_host_first: bool,
    /// Krok 23 (O1 až O3): závažnost objemových nálezů podle události, zdroj objemové anomálie
    /// podle rysu, který ji vyhlásil (bajty, pakety), a zdroj nespárovaných událostí.
    /// Výchozí vypnuto.
    #[serde(default)]
    pub sev_calib: bool,
    /// Krok 24: jen atribuce zdroje z kroku 23 (O2 a O3) bez kalibrace závažnosti. Výchozí vypnuto.
    #[serde(default)]
    pub attr_calib: bool,
    /// Krok 24: jen kalibrace závažnosti objemových nálezů z kroku 23 (O1). Výchozí vypnuto.
    #[serde(default)]
    pub sev_calib_o1: bool,
    /// Krok 24: kontext (jakýkoli druh) nezavře ani nepodpoří nález hostu, který se v okně
    /// záznamu účastní aktivity mimo pokrytí záznamu. Výchozí vypnuto.
    #[serde(default)]
    pub ctx_activity_guard: bool,
}

impl Default for V3Features {
    fn default() -> Self {
        Self::recommended()
    }
}

impl V3Features {
    pub const NAMES: [&'static str; 68] = [
        "memory",
        "rate",
        "volume",
        "unexpected",
        "context",
        "identity",
        "recall",
        "ladder",
        "learning",
        "devices",
        "peers",
        "egress",
        "beacon",
        "interactive",
        "graph",
        "profile",
        "sensor_strict",
        "ops_class",
        "novelty",
        "context_guard",
        "protect",
        "ops_annotate",
        "graph_incident",
        "novel_burst",
        "fanout2",
        "cross_source",
        "saas_group",
        "endpoint",
        "breadth",
        "breadth_volume",
        "bulk_novel",
        "peer_burst",
        "scan_fresh",
        "bulk_clear",
        "strict_close",
        "l7_tls",
        "l7_dns",
        "hypotheses",
        "redisplay",
        "icmp_payload",
        "slow_fanin",
        "case_files",
        "l7_ladder",
        "redisplay_age",
        "ops_telemetry",
        "endpoint_ext",
        "endpoint_allow",
        "endpoint_weak",
        "refute_episode",
        "ops_symptoms",
        "ops_blast",
        "upload_horizon",
        "attempts",
        "outscan",
        "retry",
        "corr_v2",
        "corr_v3",
        "corr_ext",
        "corr_union",
        "corr_related",
        "case_folder",
        "confirm_evidence",
        "close_gate",
        "ctx_host_first",
        "sev_calib",
        "attr_calib",
        "sev_calib_o1",
        "ctx_activity_guard",
    ];

    pub fn all() -> Self {
        Self {
            memory: true,
            rate: true,
            volume: true,
            unexpected: true,
            context: true,
            identity: true,
            recall: true,
            ladder: true,
            learning: true,
            devices: true,
            peers: true,
            egress: true,
            beacon: true,
            interactive: true,
            graph: true,
            profile: true,
            sensor_strict: true,
            ops_class: true,
            novelty: true,
            context_guard: true,
            protect: true,
            ops_annotate: true,
            graph_incident: true,
            novel_burst: true,
            fanout2: true,
            cross_source: true,
            saas_group: true,
            endpoint: true,
            breadth: true,
            breadth_volume: true,
            bulk_novel: true,
            peer_burst: true,
            scan_fresh: true,
            bulk_clear: true,
            strict_close: true,
            l7_tls: true,
            l7_dns: true,
            hypotheses: true,
            redisplay: true,
            icmp_payload: true,
            slow_fanin: true,
            case_files: true,
            l7_ladder: true,
            redisplay_age: true,
            ops_telemetry: true,
            endpoint_ext: true,
            endpoint_allow: true,
            endpoint_weak: true,
            refute_episode: true,
            ops_symptoms: true,
            ops_blast: true,
            upload_horizon: true,
            attempts: false,
            outscan: false,
            retry: false,
            corr_v2: false,
            corr_v3: false,
            corr_ext: false,
            corr_union: false,
            corr_related: false,
            case_folder: true,
            confirm_evidence: true,
            close_gate: true,
            ctx_host_first: true,
            sev_calib: true,
            attr_calib: true,
            sev_calib_o1: true,
            ctx_activity_guard: true,
        }
    }

    /// Doporučené (výchozí) nastavení v3: vše kromě peer baseline detektoru, která
    /// v párovém A/B kroku 2 neměla měřitelný přínos (impl-krok2.md, D), a kromě
    /// grafu nových hran (`pivot_chain`), který v A/B kroku 4 na ladicích seedech
    /// přidal +3,7 % zobrazených FP při zisku detekce jen u malých rodin
    /// (impl-krok4.md, A). Graf zůstává volitelný.
    /// Krok 6 (impl-krok6.md, C a D): do presetu patří vybraná sestava předregistrovaného
    /// A/B, přísný výpadek senzoru a novost vztahů (bez `novel_fanout`). Na držených
    /// seedech zavřeno omylem 6,7 → 2,5 %, detekce +0,5 p. b., FP × 1,06. Třída provoz,
    /// kontext jen se zdrojem a graf zůstávají volitelné (neprošly B5).
    /// Preset po kroku 7 (impl-krok7.md, sekce D3 a E): preset kroku 6 + chráněné
    /// nálezy (`protect`), graf s incidentem (`graph`, `graph_incident`) a `novel_fanout`
    /// s druhým signálem (`fanout2`).
    pub fn recommended() -> Self {
        Self {
            graph: true,
            protect: true,
            graph_incident: true,
            fanout2: true,
            ..Self::step6()
        }
    }

    /// Preset po kroku 6 (bez změn kroku 7), pro párové srovnání.
    pub fn step6() -> Self {
        Self {
            peers: false,
            graph: false,
            ops_class: false,
            context_guard: false,
            protect: false,
            ops_annotate: false,
            graph_incident: false,
            novel_burst: false,
            fanout2: false,
            cross_source: false,
            saas_group: false,
            endpoint: false,
            breadth: false,
            breadth_volume: false,
            bulk_novel: false,
            peer_burst: false,
            scan_fresh: false,
            bulk_clear: false,
            strict_close: false,
            l7_tls: false,
            l7_dns: false,
            hypotheses: false,
            redisplay: false,
            icmp_payload: false,
            slow_fanin: false,
            case_files: false,
            l7_ladder: false,
            redisplay_age: false,
            ops_telemetry: false,
            endpoint_ext: false,
            endpoint_allow: false,
            endpoint_weak: false,
            refute_episode: false,
            ops_symptoms: false,
            ops_blast: false,
            upload_horizon: false,
            attempts: false,
            outscan: false,
            retry: false,
            corr_v2: false,
            corr_v3: false,
            corr_ext: false,
            corr_union: false,
            corr_related: false,
            case_folder: false,
            confirm_evidence: false,
            close_gate: false,
            ctx_host_first: false,
            sev_calib: false,
            attr_calib: false,
            sev_calib_o1: false,
            ctx_activity_guard: false,
            ..Self::all()
        }
    }

    /// Preset po kroku 5 (bez změn kroku 6 a 7), pro párové srovnání.
    pub fn step5() -> Self {
        Self {
            sensor_strict: false,
            novelty: false,
            ..Self::step6()
        }
    }

    pub fn none() -> Self {
        Self {
            memory: false,
            rate: false,
            volume: false,
            unexpected: false,
            context: false,
            identity: false,
            recall: false,
            ladder: false,
            learning: false,
            devices: false,
            peers: false,
            egress: false,
            beacon: false,
            interactive: false,
            graph: false,
            profile: false,
            sensor_strict: false,
            ops_class: false,
            novelty: false,
            context_guard: false,
            protect: false,
            ops_annotate: false,
            graph_incident: false,
            novel_burst: false,
            fanout2: false,
            cross_source: false,
            saas_group: false,
            endpoint: false,
            breadth: false,
            breadth_volume: false,
            bulk_novel: false,
            peer_burst: false,
            scan_fresh: false,
            bulk_clear: false,
            strict_close: false,
            l7_tls: false,
            l7_dns: false,
            hypotheses: false,
            redisplay: false,
            icmp_payload: false,
            slow_fanin: false,
            case_files: false,
            l7_ladder: false,
            redisplay_age: false,
            ops_telemetry: false,
            endpoint_ext: false,
            endpoint_allow: false,
            endpoint_weak: false,
            refute_episode: false,
            ops_symptoms: false,
            ops_blast: false,
            upload_horizon: false,
            attempts: false,
            outscan: false,
            retry: false,
            corr_v2: false,
            corr_v3: false,
            corr_ext: false,
            corr_union: false,
            corr_related: false,
            case_folder: false,
            confirm_evidence: false,
            close_gate: false,
            ctx_host_first: false,
            sev_calib: false,
            attr_calib: false,
            sev_calib_o1: false,
            ctx_activity_guard: false,
        }
    }

    /// Stav po kroku 2 (bez změn kroku 3), pro párové srovnání kroku 3.
    pub fn step2() -> Self {
        Self {
            egress: false,
            beacon: false,
            interactive: false,
            graph: false,
            profile: false,
            ..Self::step5()
        }
    }

    /// Stav po kroku 1 (bez změn kroku 2), pro párové srovnání kroku 2.
    pub fn step1() -> Self {
        Self {
            recall: false,
            ladder: false,
            learning: false,
            devices: false,
            peers: false,
            ..Self::step2()
        }
    }

    fn slot(&mut self, name: &str) -> Option<&mut bool> {
        Some(match name {
            "memory" => &mut self.memory,
            "rate" => &mut self.rate,
            "volume" => &mut self.volume,
            "unexpected" => &mut self.unexpected,
            "context" => &mut self.context,
            "identity" => &mut self.identity,
            "recall" => &mut self.recall,
            "ladder" => &mut self.ladder,
            "learning" => &mut self.learning,
            "devices" => &mut self.devices,
            "peers" => &mut self.peers,
            "egress" => &mut self.egress,
            "beacon" => &mut self.beacon,
            "interactive" => &mut self.interactive,
            "graph" => &mut self.graph,
            "profile" => &mut self.profile,
            "sensor_strict" => &mut self.sensor_strict,
            "ops_class" => &mut self.ops_class,
            "novelty" => &mut self.novelty,
            "context_guard" => &mut self.context_guard,
            "protect" => &mut self.protect,
            "ops_annotate" => &mut self.ops_annotate,
            "graph_incident" => &mut self.graph_incident,
            "novel_burst" => &mut self.novel_burst,
            "fanout2" => &mut self.fanout2,
            "cross_source" => &mut self.cross_source,
            "saas_group" => &mut self.saas_group,
            "endpoint" => &mut self.endpoint,
            "breadth" => &mut self.breadth,
            "breadth_volume" => &mut self.breadth_volume,
            "bulk_novel" => &mut self.bulk_novel,
            "peer_burst" => &mut self.peer_burst,
            "scan_fresh" => &mut self.scan_fresh,
            "bulk_clear" => &mut self.bulk_clear,
            "strict_close" => &mut self.strict_close,
            "l7_tls" => &mut self.l7_tls,
            "l7_dns" => &mut self.l7_dns,
            "hypotheses" => &mut self.hypotheses,
            "redisplay" => &mut self.redisplay,
            "icmp_payload" => &mut self.icmp_payload,
            "slow_fanin" => &mut self.slow_fanin,
            "case_files" => &mut self.case_files,
            "l7_ladder" => &mut self.l7_ladder,
            "redisplay_age" => &mut self.redisplay_age,
            "ops_telemetry" => &mut self.ops_telemetry,
            "endpoint_ext" => &mut self.endpoint_ext,
            "endpoint_allow" => &mut self.endpoint_allow,
            "endpoint_weak" => &mut self.endpoint_weak,
            "refute_episode" => &mut self.refute_episode,
            "ops_symptoms" => &mut self.ops_symptoms,
            "ops_blast" => &mut self.ops_blast,
            "upload_horizon" => &mut self.upload_horizon,
            "attempts" => &mut self.attempts,
            "outscan" => &mut self.outscan,
            "retry" => &mut self.retry,
            "corr_v2" => &mut self.corr_v2,
            "corr_v3" => &mut self.corr_v3,
            "corr_ext" => &mut self.corr_ext,
            "corr_union" => &mut self.corr_union,
            "corr_related" => &mut self.corr_related,
            "case_folder" => &mut self.case_folder,
            "confirm_evidence" => &mut self.confirm_evidence,
            "close_gate" => &mut self.close_gate,
            "ctx_host_first" => &mut self.ctx_host_first,
            "sev_calib" => &mut self.sev_calib,
            "attr_calib" => &mut self.attr_calib,
            "sev_calib_o1" => &mut self.sev_calib_o1,
            "ctx_activity_guard" => &mut self.ctx_activity_guard,
            _ => return None,
        })
    }

    /// Vypne vyjmenované změny (seznam oddělený čárkami, např. `rate,volume`).
    pub fn disable_list(self, list: &str) -> Result<Self, String> {
        self.set_list(list, false)
    }

    /// Zapne vyjmenované změny mimo preset (ablace kroku 5, např. `graph`).
    pub fn enable_list(self, list: &str) -> Result<Self, String> {
        self.set_list(list, true)
    }

    fn set_list(mut self, list: &str, on: bool) -> Result<Self, String> {
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            *self.slot(name).ok_or_else(|| {
                format!(
                    "neznama zmena v3 '{name}' (povolene: {})",
                    Self::NAMES.join(", ")
                )
            })? = on;
        }
        Ok(self)
    }

    /// Krátký popis zapnutých změn (do reportu a statusu).
    pub fn label(&self) -> String {
        let mut copy = *self;
        let on: Vec<&str> = Self::NAMES
            .iter()
            .copied()
            .filter(|name| copy.slot(name).is_some_and(|value| *value))
            .collect();
        if on.is_empty() {
            "zadne".to_string()
        } else {
            on.join("+")
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub mode: EngineMode,
    pub v3: V3Features,
}

impl EngineConfig {
    pub fn legacy() -> Self {
        Self::default()
    }

    pub fn v3() -> Self {
        Self {
            mode: EngineMode::V3,
            v3: V3Features::recommended(),
        }
    }

    fn on(&self, pick: impl Fn(&V3Features) -> bool) -> bool {
        self.mode == EngineMode::V3 && pick(&self.v3)
    }

    pub fn memory(&self) -> bool {
        self.on(|f| f.memory)
    }
    pub fn robust_rate(&self) -> bool {
        self.on(|f| f.rate)
    }
    pub fn volume_baseline(&self) -> bool {
        self.on(|f| f.volume)
    }
    pub fn unexpected_v3(&self) -> bool {
        self.on(|f| f.unexpected)
    }
    pub fn context_gate(&self) -> bool {
        self.on(|f| f.context)
    }
    pub fn identity_v3(&self) -> bool {
        self.on(|f| f.identity)
    }
    pub fn recall(&self) -> bool {
        self.on(|f| f.recall)
    }
    /// Žebřík potřebuje paměť nálezů (ověřuje se jen otevřený stav).
    pub fn ladder(&self) -> bool {
        self.on(|f| f.ladder && f.memory)
    }
    pub fn learning(&self) -> bool {
        self.on(|f| f.learning)
    }
    pub fn devices(&self) -> bool {
        self.on(|f| f.devices)
    }
    /// Peer baseline detektoru podle typu zařízení (vyžaduje rozpoznání zařízení).
    pub fn peer_baseline(&self) -> bool {
        self.on(|f| f.devices && f.peers)
    }
    /// Odchozí toky a alerty (zdroj nebo cíl v rozsahu, krok 3A).
    pub fn egress(&self) -> bool {
        self.on(|f| f.egress)
    }
    /// Detektory nad odchozím provozem potřebují viditelnost ven (krok 3A).
    pub fn beacon(&self) -> bool {
        self.on(|f| f.egress && f.beacon)
    }
    pub fn interactive(&self) -> bool {
        self.on(|f| f.egress && f.interactive)
    }
    pub fn graph(&self) -> bool {
        self.on(|f| f.graph)
    }
    /// Profil hostu je důkaz žebříku, bez žebříku nemá smysl.
    pub fn profile(&self) -> bool {
        self.on(|f| f.profile && f.ladder && f.memory)
    }
    /// Krok 6: výpadek senzoru není vysvětlení (jen s kontextovou bránou).
    pub fn sensor_strict(&self) -> bool {
        self.on(|f| f.context && f.sensor_strict)
    }
    /// Krok 6: třída provozní problém (jen s pamětí nálezů, rozhoduje o zobrazení).
    pub fn ops_class(&self) -> bool {
        self.on(|f| f.ops_class && f.memory)
    }
    /// Krok 6: novost vztahů stojí na profilu hostu a viditelnosti ven.
    pub fn novelty(&self) -> bool {
        self.profile() && self.egress() && self.v3.novelty
    }
    /// Krok 6: kontext bez identifikovaného zdroje nezavírá.
    pub fn context_guard(&self) -> bool {
        self.on(|f| f.context && f.context_guard)
    }
    /// Krok 7 (A1): chráněné nálezy.
    pub fn protect(&self) -> bool {
        self.on(|f| f.protect)
    }
    /// Krok 7 (B1): třída provoz jen jako anotace (s pamětí nálezů).
    pub fn ops_annotate(&self) -> bool {
        self.on(|f| f.ops_annotate && f.memory)
    }
    /// Třída provoz běží (jako fronta nebo jako anotace).
    pub fn ops_evidence(&self) -> bool {
        self.ops_class() || self.ops_annotate() || self.cross_source()
    }
    /// Krok 7 (B2): incident grafu (jen s grafem).
    pub fn graph_incident(&self) -> bool {
        self.graph() && self.v3.graph_incident
    }
    /// Krok 7 (B3): varianty novosti stojí na novosti.
    pub fn novel_burst(&self) -> bool {
        self.novelty() && self.v3.novel_burst
    }
    pub fn fanout2(&self) -> bool {
        self.novelty() && self.v3.fanout2
    }
    /// Krok 7 (B4): agregace přes zdroje (klientela služeb, s pamětí nálezů).
    pub fn cross_source(&self) -> bool {
        self.on(|f| f.cross_source && f.memory)
    }
    /// Krok 8: koncová telemetrie (potřebuje ochranu a paměť nálezů).
    pub fn endpoint(&self) -> bool {
        self.on(|f| f.endpoint && f.protect && f.memory)
    }
    /// Krok 9: obecné detektory rysů provozu (potřebují odchozí toky).
    pub fn breadth(&self) -> bool {
        self.on(|f| f.egress && f.breadth)
    }
    /// Krok 9: objemové detektory `breadth` (jen s `breadth`).
    pub fn breadth_volume(&self) -> bool {
        self.breadth() && self.v3.breadth_volume
    }
    /// Krok 11: detektory prvniho videni protejsku (potrebuji odchozi toky a profil).
    pub fn bulk_novel(&self) -> bool {
        self.on(|f| f.egress && f.profile && f.bulk_novel)
    }
    /// Krok 12: prisne zavirani kontextem (potrebuje ochranu a pamet nalezu).
    pub fn strict_close(&self) -> bool {
        self.on(|f| f.strict_close)
    }
    pub fn endpoint_allow(&self) -> bool {
        self.endpoint_ext() && self.on(|f| f.endpoint_allow)
    }
    pub fn endpoint_ext(&self) -> bool {
        self.on(|f| f.endpoint_ext && f.endpoint && f.protect && f.memory)
    }
    pub fn ops_telemetry(&self) -> bool {
        self.on(|f| f.ops_telemetry && f.memory)
    }
    pub fn redisplay_age(&self) -> bool {
        self.on(|f| f.redisplay_age && f.memory)
    }
    /// Krok 15 (P1): koncový „nic podezřelého“ není silná skupina (jen s žebříkem a endpointem).
    pub fn endpoint_weak(&self) -> bool {
        self.on(|f| f.endpoint_weak && f.endpoint && f.ladder)
    }
    /// Krok 15 (P1): vyvrácený klíč pohltí jen souvislou epizodu (jen s pamětí a žebříkem).
    pub fn refute_episode(&self) -> bool {
        self.on(|f| f.refute_episode && f.memory && f.ladder)
    }
    /// Krok 15 (P3): příznakové skupiny katalogu a pokrytí signálů v diagnóze.
    pub fn ops_symptoms(&self) -> bool {
        self.ops_telemetry() && self.v3.ops_symptoms
    }
    /// Krok 15 (P3): dosah signálu infrastrukturního zařízení na závislé hosty.
    pub fn ops_blast(&self) -> bool {
        self.ops_telemetry() && self.v3.ops_blast
    }
    /// Krok 15 (P2): nahraný objem přes klouzavý horizont oken (jen s odchozími toky).
    pub fn upload_horizon(&self) -> bool {
        self.on(|f| f.egress && f.upload_horizon)
    }
    /// Krok 27: opakovaná krátká spojení na přihlašovací službu.
    pub fn attempts(&self) -> bool {
        self.on(|f| f.egress && f.attempts)
    }
    /// Krok 31: odchozí skenování vnitřního hosta.
    pub fn outscan(&self) -> bool {
        self.on(|f| f.egress && f.outscan)
    }
    /// Krok 32: opakované neúspěšné pokusy na stejný vnější cíl.
    pub fn retry(&self) -> bool {
        self.on(|f| f.egress && f.retry)
    }
    /// Krok 33: opravená korelace (jen s `case_files`).
    pub fn corr_v2(&self) -> bool {
        self.case_files() && self.v3.corr_v2
    }
    pub fn corr_v3(&self) -> bool {
        self.corr_v2() && self.v3.corr_v3
    }
    pub fn corr_ext(&self) -> bool {
        self.corr_v3() && self.v3.corr_ext
    }
    pub fn corr_union(&self) -> bool {
        self.corr_v2() && self.v3.corr_union
    }
    pub fn corr_related(&self) -> bool {
        self.corr_v3() && self.v3.corr_related
    }
    pub fn l7_ladder(&self) -> bool {
        self.on(|f| f.l7_ladder && f.ladder && (f.l7_tls || f.l7_dns))
    }
    /// Krok 16: případová složka (jen s `case_files`).
    pub fn case_folder(&self) -> bool {
        self.case_files() && self.v3.case_folder
    }
    /// Krok 18: potvrzení jen s pozitivním důkazem z nezávislého zdroje (jen se žebříkem).
    pub fn confirm_evidence(&self) -> bool {
        self.on(|f| f.confirm_evidence && f.ladder)
    }
    /// Krok 20: jediná brána zavření (jen s pamětí nálezů, která drží stav a lístek).
    pub fn close_gate(&self) -> bool {
        self.on(|f| f.close_gate && f.memory)
    }
    /// Krok 22: kontext v2 (shoda hostu před přísnou kontrolou, rozsah skeneru na cíle).
    pub fn ctx_host_first(&self) -> bool {
        self.on(|f| f.ctx_host_first)
    }
    /// Krok 23: kalibrace závažnosti a atribuce zdroje objemových a nespárovaných nálezů.
    pub fn sev_calib(&self) -> bool {
        self.on(|f| f.sev_calib)
    }
    /// Krok 24: atribuce zdroje kroku 23 (O2, O3); `sev_calib` ji zapíná také.
    pub fn attr_calib(&self) -> bool {
        self.on(|f| f.attr_calib || f.sev_calib)
    }
    /// Krok 24: kalibrace závažnosti objemu kroku 23 (O1); `sev_calib` ji zapíná také.
    pub fn sev_calib_o1(&self) -> bool {
        self.on(|f| f.sev_calib_o1 || f.sev_calib)
    }
    /// Krok 24: pojistka souběžné aktivity hostu pro všechny druhy kontextu.
    pub fn ctx_activity_guard(&self) -> bool {
        self.on(|f| f.ctx_activity_guard)
    }
    /// Přísné vyvrácení žebříku: `strict_close`, nebo brána zavření (krok 20).
    pub fn strict_refute(&self) -> bool {
        self.strict_close() || self.close_gate()
    }
    /// „Vše v pořádku“ od agenta jako slabá skupina: `endpoint_weak`, nebo brána (krok 20).
    pub fn endpoint_weak_effective(&self) -> bool {
        self.endpoint_weak() || (self.close_gate() && self.endpoint())
    }
    pub fn case_files(&self) -> bool {
        self.on(|f| f.case_files && f.ladder && f.memory)
    }
    pub fn icmp_payload(&self) -> bool {
        self.on(|f| f.egress && f.icmp_payload)
    }
    pub fn slow_fanin(&self) -> bool {
        self.breadth() && self.v3.slow_fanin
    }
    pub fn redisplay(&self) -> bool {
        self.on(|f| f.redisplay && f.memory)
    }
    pub fn hypotheses(&self) -> bool {
        self.on(|f| f.hypotheses && f.ladder && f.memory)
    }
    pub fn l7_tls(&self) -> bool {
        self.on(|f| f.egress && f.profile && f.l7_tls)
    }
    pub fn l7_dns(&self) -> bool {
        self.on(|f| f.egress && f.l7_dns)
    }
    pub fn bulk_clear(&self) -> bool {
        self.on(|f| f.egress && f.profile && f.bulk_clear)
    }
    pub fn peer_burst(&self) -> bool {
        self.on(|f| f.egress && f.profile && f.peer_burst)
    }
    /// Krok 11: nizsi prah skenu pro vnejsi zdroj bez uspesneho spojeni.
    pub fn scan_fresh(&self) -> bool {
        self.on(|f| f.unexpected && f.recall && f.scan_fresh)
    }
    /// Krok 7 (B5): seskupení nové vazby ven (jen s novostí).
    pub fn saas_group(&self) -> bool {
        self.novelty() && self.v3.saas_group
    }
    /// Běží behaviorální vrstva kroku 3 (aspoň jedna její část)?
    pub fn behavior(&self) -> bool {
        self.egress() || self.graph() || self.profile() || self.breadth()
    }
    /// Běží v3 detektor (aspoň jedna detekční změna)?
    pub fn v3_detector(&self) -> bool {
        self.robust_rate() || self.volume_baseline() || self.unexpected_v3()
    }

    /// Konfigurace paměti nálezů podle zapnutých změn.
    pub fn memory_config(&self) -> crate::finding_memory::MemoryConfig {
        crate::finding_memory::MemoryConfig {
            escalate_first_source: self.recall() || self.strict_close() || self.close_gate(),
            reopen_stale: self.strict_close(),
            redisplay_age_s: if self.redisplay_age() { 6 * 3600 } else { 0 },
            // krok 15: odmlka delsi nez hodina = nova epizoda (dva cykly po 30 min);
            // krok 20: brana zavreni ma rozsah epizody vzdy
            refute_episode_s: if self.refute_episode() || self.close_gate() {
                3600
            } else {
                0
            },
            gate: self.close_gate(),
            protect: self.protect(),
            volume_factor: if self.redisplay() { 2.0 } else { 4.0 },
            min_escalation_count: if self.redisplay() { 8 } else { 20 },
            ..Default::default()
        }
    }

    pub fn label(&self) -> String {
        match self.mode {
            EngineMode::Legacy => "legacy".to_string(),
            EngineMode::V3 => format!("v3[{}]", self.v3.label()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_legacy_and_v3_flags_are_inert_in_legacy() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.mode, EngineMode::Legacy);
        assert!(!cfg.memory() && !cfg.v3_detector() && !cfg.context_gate());
        assert_eq!(cfg.label(), "legacy");
    }

    /// Krok 20: brána zavření je mimo preset, potřebuje paměť a zapíná pravidla, která dřív
    /// visela na kombinacích přepínačů (přísné vyvrácení, slabý agent, rozsah epizody).
    #[test]
    fn close_gate_is_opt_in_needs_memory_and_subsumes_combinations() {
        assert!(!V3Features::recommended().close_gate);
        let base = EngineConfig::v3();
        assert!(!base.close_gate() && !base.memory_config().gate);
        assert_eq!(base.strict_refute(), base.strict_close());
        let gate = EngineConfig {
            v3: V3Features::recommended()
                .enable_list("close_gate,endpoint")
                .unwrap(),
            ..EngineConfig::v3()
        };
        assert!(gate.close_gate() && gate.strict_refute() && gate.endpoint_weak_effective());
        let cfg = gate.memory_config();
        assert!(cfg.gate && cfg.escalate_first_source && cfg.refute_episode_s == 3600);
        assert!(crate::context_gate::GatePolicy::for_engine(&gate).strict_close);
        let no_memory = EngineConfig {
            v3: V3Features::recommended()
                .enable_list("close_gate")
                .unwrap()
                .disable_list("memory")
                .unwrap(),
            ..EngineConfig::v3()
        };
        assert!(!no_memory.close_gate());
    }

    /// Krok 18: politika potvrzování je mimo preset a bez žebříku nic nedělá.
    #[test]
    fn confirm_evidence_is_opt_in_and_needs_ladder() {
        assert!(!V3Features::recommended().confirm_evidence);
        let on = |v3: V3Features| EngineConfig {
            mode: EngineMode::V3,
            v3,
        };
        let with = V3Features::recommended()
            .enable_list("confirm_evidence")
            .unwrap();
        assert!(on(with).confirm_evidence());
        assert!(!on(with.disable_list("ladder").unwrap()).confirm_evidence());
        assert!(!on(V3Features::recommended()).confirm_evidence());
    }

    #[test]
    fn parse_mode_and_disable_list() {
        assert_eq!("V3".parse::<EngineMode>().unwrap(), EngineMode::V3);
        assert!("v4".parse::<EngineMode>().is_err());
        let features = V3Features::all().disable_list("rate, volume").unwrap();
        assert!(!features.rate && !features.volume && features.memory);
        assert!(V3Features::all().disable_list("nic").is_err());
        // krok 5: zapnuti mimo preset (graf neni v presetu kroku 6)
        let with_graph = V3Features::step6().enable_list("graph").unwrap();
        assert!(with_graph.graph && !V3Features::step6().graph);
        assert!(V3Features::recommended().enable_list("nic").is_err());
        let cfg = EngineConfig {
            mode: EngineMode::V3,
            v3: features,
        };
        assert_eq!(
            cfg.label(),
            "v3[memory+unexpected+context+identity+recall+ladder+learning+devices+peers+egress+beacon+interactive+graph+profile+sensor_strict+ops_class+novelty+context_guard+protect+ops_annotate+graph_incident+novel_burst+fanout2+cross_source+saas_group+endpoint+breadth+breadth_volume+bulk_novel+peer_burst+scan_fresh+bulk_clear+strict_close+l7_tls+l7_dns+hypotheses+redisplay+icmp_payload+slow_fanin+case_files+l7_ladder+redisplay_age+ops_telemetry+endpoint_ext+endpoint_allow+endpoint_weak+refute_episode+ops_symptoms+ops_blast+upload_horizon+case_folder+confirm_evidence+close_gate+ctx_host_first+sev_calib+attr_calib+sev_calib_o1+ctx_activity_guard]"
        );
        let step2 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::step2(),
        };
        assert_eq!(
            step2.label(),
            "v3[memory+rate+volume+unexpected+context+identity+recall+ladder+learning+devices]"
        );
        assert!(!step2.behavior() && !step2.egress());
        // krok 4 A: graf nových hran není v presetu kroku 6; krok 7 ho přidává
        let step6 = V3Features::step6();
        assert!(!step6.graph && !step6.peers && step6.beacon);
        let recommended = V3Features::recommended();
        assert!(recommended.graph && recommended.graph_incident && !recommended.peers);
        assert!(recommended.protect && recommended.fanout2);
        assert!(!recommended.ops_annotate && !recommended.novel_burst);
        assert!(!recommended.cross_source && !recommended.saas_group);
        let no_egress = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::all().disable_list("egress").unwrap(),
        };
        // beacon a interaktivni relace bez viditelnosti ven nebezi
        assert!(!no_egress.beacon() && !no_egress.interactive() && no_egress.graph());
        let step1 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::step1(),
        };
        assert_eq!(
            step1.label(),
            "v3[memory+rate+volume+unexpected+context+identity]"
        );
        assert!(!step1.ladder() && !step1.recall());
        // krok 6: nove zmeny mimo preset, zapinaji se jmenem
        let k6 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::recommended()
                .enable_list("sensor_strict,ops_class,novelty,context_guard")
                .unwrap(),
        };
        assert!(k6.sensor_strict() && k6.ops_class() && k6.novelty() && k6.context_guard());
        let preset = EngineConfig::v3();
        assert!(preset.sensor_strict() && preset.novelty());
        assert!(!preset.ops_class() && !preset.context_guard());
        let step5 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::step5(),
        };
        assert!(!step5.sensor_strict() && !step5.novelty());
        let no_profile = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::recommended()
                .enable_list("novelty")
                .unwrap()
                .disable_list("profile")
                .unwrap(),
        };
        assert!(!no_profile.novelty(), "novost potrebuje profil hostu");
    }

    #[test]
    fn config_toml_roundtrip_with_missing_section_defaults_to_legacy() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            engine: EngineConfig,
        }
        let parsed: Wrapper = toml::from_str("").unwrap();
        assert_eq!(parsed.engine.mode, EngineMode::Legacy);
        let parsed: Wrapper =
            toml::from_str("[engine]\nmode = \"v3\"\n[engine.v3]\ncontext = false\n").unwrap();
        assert!(parsed.engine.memory());
        assert!(!parsed.engine.context_gate());
    }

    /// Krok 24: `sev_calib` = `attr_calib` + `sev_calib_o1`; každá polovina zvlášť zapne jen
    /// svou část; doporučené nastavení nemá zapnuté nic z kroku 23 a 24.
    #[test]
    fn k24_split_switches() {
        let with = |names: &[&str]| {
            let mut v3 = V3Features::recommended();
            for name in names {
                *v3.slot(name).expect("prepinac") = true;
            }
            EngineConfig {
                mode: EngineMode::V3,
                v3,
            }
        };
        let rec = with(&[]);
        assert!(!rec.attr_calib() && !rec.sev_calib_o1() && !rec.ctx_activity_guard());
        let both = with(&["sev_calib"]);
        assert!(both.attr_calib() && both.sev_calib_o1());
        let attr = with(&["attr_calib"]);
        assert!(attr.attr_calib() && !attr.sev_calib_o1() && !attr.sev_calib());
        let o1 = with(&["sev_calib_o1"]);
        assert!(!o1.attr_calib() && o1.sev_calib_o1());
        let guard = with(&["ctx_activity_guard"]);
        assert!(guard.ctx_activity_guard() && !guard.attr_calib());
        let legacy = EngineConfig {
            mode: EngineMode::Legacy,
            v3: V3Features::all(),
        };
        assert!(!legacy.attr_calib() && !legacy.sev_calib_o1() && !legacy.ctx_activity_guard());
    }
}
