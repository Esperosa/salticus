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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_complete_and_consistent_with_the_simulator() {
        let c = Catalog::embedded();
        assert!(c.incidents.len() >= 60, "{}", c.incidents.len());
        let mut ids = std::collections::HashSet::new();
        let labels: std::collections::HashSet<&str> =
            (0..crate::soak::variants::count() as u8)
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
