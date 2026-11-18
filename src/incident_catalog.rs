//! Krok 13 (dodatek B): katalog běžných síťových a provozních incidentů.
//!
//! Data jsou v `data/incident-catalog.json` (verzovaná, se zdroji) a vkládají se do binárky.
//! Engine a UI z nich berou vysvětlení nálezu, pravděpodobnou příčinu a doporučenou kontrolu.
//! Katalog není klasifikátor: říká, co typ znamená a co ověřit; rozhodnutí o zařazení nálezu
//! dělá detekce a ladder.

use std::collections::BTreeMap;

use serde::Deserialize;

const EMBEDDED: &str = include_str!("../data/incident-catalog.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Signals {
    pub flows: String,
    pub dns: String,
    pub tls: String,
    pub dhcp: String,
    pub arp: String,
    pub snmp: String,
    pub syslog: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub id: String,
    pub name: String,
    /// `porucha`, `neskodna_zmena` nebo `nejednoznacne`.
    pub category: String,
    pub cause: String,
    pub signals: Signals,
    pub confusable_with_attack: String,
    pub recommended_check: String,
    pub severity: String,
    pub owner: String,
    pub sources: Vec<String>,
    /// Štítek varianty generátoru v simulátoru (`soak::variants`), pokud existuje.
    pub sim_variant: Option<String>,
    pub basis: String,
    /// Krok 14 (C2): provozní signály typu (klíč, váha 1 až 3), viz `ops_telemetry`.
    #[serde(default)]
    pub ops_signals: Vec<(String, u8)>,
    /// Krok 15 (P3): příznakové skupiny nálezů, které mechanismus typu vyvolává
    /// (`availability`, `volume`, `broadcast`, `novelty`, `periodic`, `scan`); prázdné =
    /// bez omezení. Generuje `tools/k15_catalog_explains.py` z povahy původce a tvaru provozu.
    #[serde(default)]
    pub explains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Source {
    pub title: String,
    pub url: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    pub catalog_version: String,
    pub sources: BTreeMap<String, Source>,
    pub incidents: Vec<Entry>,
}

impl Catalog {
    pub fn embedded() -> Self {
        serde_json::from_str(EMBEDDED).expect("data/incident-catalog.json je platné")
    }

    /// Jednou načtený katalog (engine ho čte při každém cyklu).
    pub fn shared() -> &'static Catalog {
        static CATALOG: std::sync::OnceLock<Catalog> = std::sync::OnceLock::new();
        CATALOG.get_or_init(Catalog::embedded)
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.incidents.iter().find(|e| e.id == id)
    }

    /// Záznam podle štítku varianty simulátoru (pro doporučení u nálezu z poruchy).
    pub fn by_variant(&self, label: &str) -> Option<&Entry> {
        self.incidents
            .iter()
            .find(|e| e.sim_variant.as_deref() == Some(label))
    }
}

/// Zařazení zobrazeného nálezu podle katalogu (krok 13, B2, B3, B6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// `utok` (bez provozní příčiny), `porucha` nebo `zmena`.
    pub class: &'static str,
    /// Nejpravděpodobnější typ z katalogu; u třídy `utok` žádný.
    pub catalog_id: Option<&'static str>,
}

/// Pravidlová shoda nálezu s typem katalogu. Vstupem je typ nálezu a důvod fronty provoz
/// (`ops_evidence`, E1 až E3), jiný signál tu zatím není: bez provozního důkazu je nález
/// podezřením na útok a katalog mu nic nepřiřazuje (prázdný důkaz není důkaz poruchy).
/// Mapování je hrubé a míra jeho správnosti se měří (`incident_catalog` v soaku), ne předpokládá.
pub fn suggest(finding_type: &str, ops_reason: Option<&str>) -> Suggestion {
    let Some(reason) = ops_reason else {
        return Suggestion {
            class: "utok",
            catalog_id: None,
        };
    };
    if reason.contains("E2") {
        return Suggestion {
            class: "porucha",
            catalog_id: Some("OPS-013"),
        };
    }
    if reason.contains("E3") {
        // nárůst od dosavadních klientů bez dominantního zdroje: sezónní špička nebo záloha
        return Suggestion {
            class: "zmena",
            catalog_id: Some("CHG-001"),
        };
    }
    let id = match finding_type {
        "connection_timeout_burst" | "service_unreachable" | "service_overload_risk" => "OPS-016",
        _ => "OPS-016",
    };
    Suggestion {
        class: "porucha",
        catalog_id: Some(id),
    }
}

/// Krátký záznam katalogu pro nález (UI: příčina a doporučená kontrola).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogNote {
    pub class: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub cause: Option<String>,
    pub check: Option<String>,
}

impl Catalog {
    pub fn note(&self, finding_type: &str, ops_reason: Option<&str>) -> CatalogNote {
        let s = suggest(finding_type, ops_reason);
        let e = s.catalog_id.and_then(|id| self.get(id));
        CatalogNote {
            class: s.class.to_string(),
            id: s.catalog_id.map(str::to_string),
            name: e.map(|e| e.name.clone()),
            cause: e.map(|e| e.cause.clone()),
            check: e.map(|e| e.recommended_check.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_point_to_existing_entries_and_attacks_get_none() {
        let c = Catalog::embedded();
        assert!(suggest("web_exploit", None).catalog_id.is_none());
        for (ty, reason) in [
            ("broadcast_storm", "provoz E2: x"),
            ("packet_rate_spike", "provoz E3: x"),
            ("service_unreachable", "provoz E1: x"),
        ] {
            let s = suggest(ty, Some(reason));
            assert!(c.get(s.catalog_id.unwrap()).is_some(), "{ty}");
            assert_ne!(s.class, "utok");
        }
        let n = c.note("broadcast_storm", Some("provoz E2"));
        assert!(n.cause.is_some() && n.check.is_some());
    }

    #[test]
    fn catalog_is_complete_and_consistent_with_the_simulator() {
        let c = Catalog::embedded();
        assert!(c.incidents.len() >= 60, "{}", c.incidents.len());
        let mut ids = std::collections::HashSet::new();
        let labels: std::collections::HashSet<&str> = (0..crate::soak::variants::count() as u8)
            .map(|i| crate::soak::variants::spec(i).label)
            .collect();
        let mut with_gen = 0;
        for e in &c.incidents {
            assert!(ids.insert(e.id.clone()), "duplicitní id {}", e.id);
            assert!(
                ["porucha", "neskodna_zmena", "nejednoznacne"].contains(&e.category.as_str()),
                "{}",
                e.id
            );
            assert!(!e.recommended_check.is_empty() && !e.cause.is_empty());
            assert!(!e.sources.is_empty());
            for s in &e.sources {
                assert!(c.sources.contains_key(s), "{}: zdroj {s}", e.id);
            }
            if let Some(v) = &e.sim_variant {
                assert!(labels.contains(v.as_str()), "{}: varianta {v}", e.id);
                with_gen += 1;
            }
        }
        // B1: generátor má aspoň 60 % katalogu
        assert!(with_gen * 100 >= c.incidents.len() * 60, "{with_gen}");
    }
}
