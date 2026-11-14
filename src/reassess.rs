//! Znovuotevření a audit rozhodnutí (krok 12, studie 12b, oddíl 2 bod 5).
//!
//! Žádné rozhodnutí není definitivní. Každé autonomní rozhodnutí se zapíše s důkazy
//! (`record`); když později přijdou nové důkazy, `reassess` přepočítá posterior nad
//! všemi důkazy a při změně akce vrátí záznam auditu (starý a nový výsledek, spouštěč,
//! přidané důkazy). Zavřený případ se smí znovu otevřít vždy; opačný směr (z předání
//! člověku na zavření) nastává jen běžnou cestou žebříku, ne přehodnocením.
//! Audit je omezený (nejnovějších `max_audit`), ale počítadlo se nikdy neresetuje.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    competing::{Action, Costs, Likelihoods, Obs, best_action, posterior_attack},
    verification_chain::CheckKind,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recorded {
    pub finding_id: String,
    pub prior: f64,
    pub action: Action,
    pub posterior: f64,
    pub evidence: Vec<Obs>,
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: i64,
    pub finding_id: String,
    pub old_action: Action,
    pub new_action: Action,
    pub old_posterior: f64,
    pub new_posterior: f64,
    pub trigger: String,
    pub added: Vec<Obs>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Ledger {
    decisions: BTreeMap<String, Recorded>,
    pub audit: Vec<AuditEntry>,
    pub reopened_total: u64,
    pub max_audit: usize,
    pub max_decisions: usize,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            max_audit: 10_000,
            max_decisions: 100_000,
            ..Self::default()
        }
    }

    /// Zapíše rozhodnutí s důkazy.
    pub fn record(&mut self, finding_id: &str, prior: f64, evidence: Vec<Obs>, lik: &Likelihoods, costs: &Costs, at: i64) -> Action {
        let posterior = posterior_attack(prior, &evidence, lik);
        let action = best_action(posterior, costs).0;
        if self.decisions.len() >= self.max_decisions.max(1) {
            // nejstarší pryč; audit zůstává
            if let Some(oldest) = self.decisions.iter().min_by_key(|(_, r)| r.at).map(|(k, _)| k.clone()) {
                self.decisions.remove(&oldest);
            }
        }
        self.decisions.insert(
            finding_id.to_string(),
            Recorded {
                finding_id: finding_id.to_string(),
                prior,
                action,
                posterior,
                evidence,
                at,
            },
        );
        action
    }

    pub fn get(&self, finding_id: &str) -> Option<&Recorded> {
        self.decisions.get(finding_id)
    }

    /// Nové důkazy k dřívějšímu rozhodnutí. Vrací audit, pokud se akce změnila směrem k
    /// větší opatrnosti (zavřeno → člověk či útok, člověk → útok). Posterior a důkazy
    /// se aktualizují vždy.
    pub fn reassess(
        &mut self,
        finding_id: &str,
        added: &[Obs],
        trigger: &str,
        lik: &Likelihoods,
        costs: &Costs,
        at: i64,
    ) -> Option<AuditEntry> {
        let rec = self.decisions.get_mut(finding_id)?;
        let old_action = rec.action;
        let old_posterior = rec.posterior;
        rec.evidence.extend(added.iter().copied());
        let posterior = posterior_attack(rec.prior, &rec.evidence, lik);
        let proposed = best_action(posterior, costs).0;
        rec.posterior = posterior;
        let rank = |a: Action| match a {
            Action::CloseBenign => 0,
            Action::Human => 1,
            Action::ConfirmAttack => 2,
        };
        // nic se neuzavira definitivne, ale ani se nic nezavira zpetne na zaklade novych dukazu
        if rank(proposed) <= rank(old_action) {
            return None;
        }
        rec.action = proposed;
        rec.at = at;
        if old_action == Action::CloseBenign {
            self.reopened_total += 1;
        }
        let entry = AuditEntry {
            at,
            finding_id: finding_id.to_string(),
            old_action,
            new_action: proposed,
            old_posterior,
            new_posterior: posterior,
            trigger: trigger.to_string(),
            added: added.to_vec(),
        };
        self.audit.push(entry.clone());
        let cap = self.max_audit.max(1);
        if self.audit.len() > cap {
            self.audit.drain(..self.audit.len() - cap);
        }
        Some(entry)
    }
}

/// Pomocník pro testy a volající: nový podezřelý důkaz.
pub fn suspicious(kind: CheckKind) -> Obs {
    Obs {
        kind,
        result: crate::competing::Result3::Suspicious,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::competing::Result3;

    #[test]
    fn closed_case_is_reopened_by_new_evidence_with_audit_and_never_silently() {
        let lik = Likelihoods::measured();
        let costs = Costs {
            miss: 20.0,
            ..Costs::default()
        };
        let mut ledger = Ledger::new();
        let benign = vec![Obs {
            kind: CheckKind::CaseHistory,
            result: Result3::Benign,
        }];
        let action = ledger.record("f1", 0.01, benign, &lik, &costs, 100);
        assert_eq!(action, Action::CloseBenign);
        // nezavisle podezrele dukazy (reputace, koncova telemetrie): znovuotevreni
        let entry = ledger
            .reassess(
                "f1",
                &[
                    suspicious(CheckKind::Reputation),
                    suspicious(CheckKind::EndpointTelemetry),
                    suspicious(CheckKind::ActiveReadOnly),
                ],
                "novy indikator: reputace a proces",
                &lik,
                &costs,
                200,
            )
            .expect("musi se prehodnotit");
        assert_eq!(entry.old_action, Action::CloseBenign);
        assert_ne!(entry.new_action, Action::CloseBenign);
        assert!(entry.new_posterior > entry.old_posterior);
        assert_eq!(ledger.audit.len(), 1);
        assert_eq!(ledger.reopened_total, 1);
        assert_eq!(ledger.get("f1").unwrap().evidence.len(), 4);
    }

    #[test]
    fn reassessment_never_closes_a_case_retroactively_and_unknown_ids_are_ignored() {
        let lik = Likelihoods::measured();
        let costs = Costs::default();
        let mut ledger = Ledger::new();
        ledger.record("f2", 0.3, vec![], &lik, &costs, 1);
        let before = ledger.get("f2").unwrap().action;
        let benign = Obs {
            kind: CheckKind::CaseHistory,
            result: Result3::Benign,
        };
        assert!(ledger.reassess("f2", &[benign], "neskodny dukaz", &lik, &costs, 2).is_none());
        assert_eq!(ledger.get("f2").unwrap().action, before);
        assert!(ledger.reassess("neexistuje", &[benign], "x", &lik, &costs, 3).is_none());
        assert!(ledger.audit.is_empty());
    }
}
