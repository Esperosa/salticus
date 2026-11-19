//! Jediná brána zavření nálezu (krok 20, `docs/diplomka/eval/impl-krok20.md`).
//!
//! Audit jádra (`docs/diplomka/eval/audit-jadra.md`) ukázal, že o zavření téhož klíče
//! rozhodovaly tři moduly (kontextová brána, žebřík, paměť) a pravidla rozsahu autonomie
//! (`docs/diplomka/rozsah-autonomie.md`) platila jen v některých kombinacích přepínačů.
//! Tady je jediné místo, kde vzniká oprávnění k zavření: [`CloseTicket`]. Paměť nálezů v
//! režimu brány (`MemoryConfig::gate`) vstoupí do `AutoResolved` nebo `Refuted` jen s
//! lístkem a uloží ho k položce, takže invariant „zavřeno ⇒ pozitivní důkaz a vlastník“
//! je kontrolovatelný na stavu ([`crate::finding_memory::FindingMemory::gate_violations`]).
//!
//! Podmínky lístku:
//! - R2: nález není chráněný a nemá vysoký dopad (bez výjimky);
//! - vlastník: neprázdný schvalovatel pozitivního důkazu;
//! - kontext: ne výpadek senzoru (R5), záznam s expirací, zdroje nálezu neprázdné a celé
//!   v záznamu;
//! - žebřík: P pod prahem vyvrácení a neškodné výsledky aspoň ze dvou nezávislých skupin,
//!   z nichž jedna je pozitivní důkaz s vlastníkem (schválený kontext nebo seznam
//!   povolených, ten jen jednou); „vše v pořádku“ od agenta, výpadek služby (R4),
//!   historie, profil, peeři a přetrvání jsou jen podpůrné.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::verify_ladder::{CheckId, Decision, Status, StepNote};

/// Mez vyvrácení, kterou brána kontroluje sama (shodná s `LadderPolicy::default().p_refute`).
pub const P_REFUTE: f64 = 0.03;

/// Oprávnění k zavření. Vzniká jen v této bráně ([`admit_context`], [`admit_ladder`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloseTicket {
    kind: String,
    owner: String,
    groups: Vec<u8>,
    evidence: Vec<String>,
    sources: Vec<String>,
    reason: String,
}

impl CloseTicket {
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn groups(&self) -> &[u8] {
        &self.groups
    }
    pub fn evidence(&self) -> &[String] {
        &self.evidence
    }
    pub fn sources(&self) -> &[String] {
        &self.sources
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    /// Lístek nese pozitivní důkaz s vlastníkem (pro kontrolu invariantu na stavu).
    pub fn is_positive(&self) -> bool {
        !self.owner.trim().is_empty() && !self.evidence.is_empty()
    }
}

/// Proč brána zavření odmítla (jde do důvodu eskalace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Protected,
    HighImpact,
    NoOwner,
    SensorOutage,
    Expired,
    SourceNotProven,
    NotLowEnough,
    NoPositiveEvidence,
    TooFewGroups,
}

impl Refusal {
    pub fn label(self) -> &'static str {
        match self {
            Refusal::Protected => "chraneny nalez",
            Refusal::HighImpact => "vysoky dopad",
            Refusal::NoOwner => "dukaz bez vlastnika",
            Refusal::SensorOutage => "vypadek senzoru neni dukaz",
            Refusal::Expired => "zaznam kontextu bez platne expirace",
            Refusal::SourceNotProven => "zdroje nalezu nejsou cele v zaznamu",
            Refusal::NotLowEnough => "P(utok) nad mezi vyvraceni",
            Refusal::NoPositiveEvidence => {
                "chybi pozitivni dukaz s vlastnikem (schvaleny kontext nebo seznam povolenych)"
            }
            Refusal::TooFewGroups => "mene nez dve nezavisle skupiny neskodneho dukazu",
        }
    }
}

/// Co se zavírá: vlastnosti nálezu, které rozhodují o R2.
#[derive(Debug, Clone, Copy)]
pub struct Subject {
    pub protected: bool,
    pub high_impact: bool,
}

fn guard(subject: Subject) -> Result<(), Refusal> {
    if subject.protected {
        return Err(Refusal::Protected);
    }
    if subject.high_impact {
        return Err(Refusal::HighImpact);
    }
    Ok(())
}

/// Nárok kontextové brány na zavření (C1).
#[derive(Debug, Clone)]
pub struct ContextClaim<'a> {
    pub finding_type: &'a str,
    pub kind: crate::context_gate::ContextKind,
    pub approved_by: &'a str,
    pub expires: DateTime<Utc>,
    pub at: DateTime<Utc>,
    /// Zdroje nálezu jsou neprázdné a všechny patří záznamu (skener má rozsah cílů).
    pub sources_proven: bool,
    pub sources: &'a [String],
    pub reason: &'a str,
}

/// Brána pro kontextové zavření.
pub fn admit_context(claim: &ContextClaim<'_>, subject: Subject) -> Result<CloseTicket, Refusal> {
    guard(subject)?;
    if crate::protection::is_protected_type(claim.finding_type) {
        return Err(Refusal::Protected);
    }
    if claim.kind == crate::context_gate::ContextKind::SensorOutage {
        return Err(Refusal::SensorOutage);
    }
    if claim.approved_by.trim().is_empty() {
        return Err(Refusal::NoOwner);
    }
    if claim.expires <= claim.at {
        return Err(Refusal::Expired);
    }
    if !claim.sources_proven || claim.sources.is_empty() {
        return Err(Refusal::SourceNotProven);
    }
    Ok(CloseTicket {
        kind: format!("context:{}", claim.kind.label()),
        owner: claim.approved_by.to_string(),
        groups: vec![1],
        evidence: vec![format!("kontext {}", claim.kind.label())],
        sources: claim.sources.to_vec(),
        reason: claim.reason.to_string(),
    })
}

/// Brána pro vysvětlení kontextové brány (soak i produkce volají totéž).
pub fn admit_explanation(
    explanation: &crate::context_gate::Explanation,
    finding_type: &str,
    sources: &[String],
    at: DateTime<Utc>,
    subject: Subject,
) -> Result<CloseTicket, Refusal> {
    admit_context(
        &ContextClaim {
            finding_type,
            kind: explanation.kind,
            approved_by: &explanation.approved_by,
            expires: explanation.expires,
            at,
            sources_proven: explanation.sources_proven,
            sources,
            reason: &explanation.reason,
        },
        subject,
    )
}

fn after<'a>(detail: &'a str, marker: &str) -> Option<&'a str> {
    let rest = &detail[detail.find(marker)? + marker.len()..];
    let end = rest.find([',', ')', ';']).unwrap_or(rest.len());
    let owner = rest[..end].trim();
    (!owner.is_empty()).then_some(owner)
}

/// Pozitivní důkaz s vlastníkem z kroku žebříku: (skupina, vlastník, popis).
fn positive(note: &StepNote) -> Option<(u8, String, String)> {
    match note.check {
        CheckId::Context if !note.detail.contains("sensor_outage") => {
            after(&note.detail, "schvalil ").map(|o| (1, o.to_string(), "schvaleny kontext".into()))
        }
        CheckId::Endpoint if note.detail.starts_with("seznam povolenych") => {
            after(&note.detail, "vlastnik ").map(|o| (4, o.to_string(), "seznam povolenych".into()))
        }
        _ => None,
    }
}

/// Podpůrná skupina neškodného výsledku (počítá se do dvou nezávislých skupin).
fn supporting(note: &StepNote) -> Option<u8> {
    match note.check {
        // vypadek senzoru neni dukaz (R5), agent „vse v poradku“ neni pozitivni dukaz
        CheckId::Context if note.detail.contains("sensor_outage") => None,
        CheckId::Endpoint if !note.detail.starts_with("seznam povolenych") => None,
        check => crate::verify_ladder::benign_group(check),
    }
}

/// Brána pro vyvrácení žebříkem (C2, C3).
pub fn admit_ladder(decision: &Decision) -> Result<CloseTicket, Refusal> {
    guard(Subject {
        // R2 plati i bez prepinace `protect`: chraneny typ se nezavira nikdy
        protected: decision.protected
            || crate::protection::is_protected_type(&decision.finding_type),
        high_impact: decision.high_impact,
    })?;
    if decision.posterior.is_nan() || decision.posterior > P_REFUTE {
        return Err(Refusal::NotLowEnough);
    }
    let benign: Vec<&StepNote> = decision
        .notes
        .iter()
        .filter(|n| n.lr.is_some_and(|lr| lr < 1.0))
        .collect();
    let positive: Vec<(u8, String, String)> = benign.iter().filter_map(|n| positive(n)).collect();
    let Some((_, owner, _)) = positive.first().cloned() else {
        return Err(Refusal::NoPositiveEvidence);
    };
    let mut groups: Vec<u8> = benign.iter().filter_map(|n| supporting(n)).collect();
    groups.extend(positive.iter().map(|(g, _, _)| *g));
    groups.sort_unstable();
    groups.dedup();
    if groups.len() < 2 {
        return Err(Refusal::TooFewGroups);
    }
    Ok(CloseTicket {
        kind: "ladder".into(),
        owner,
        groups,
        evidence: benign
            .iter()
            .map(|n| format!("{} {}", n.check.label(), n.tag))
            .collect(),
        sources: Vec::new(),
        reason: decision.reason.clone(),
    })
}

/// Krok 22 (B4): výsledek stínové brány. Stín volá tytéž funkce brány nad týmiž vstupy,
/// ale nic nezavírá a nemění stav ani zobrazení; slouží jen k měření hranice automatizace.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Shadow {
    /// Brána by vydala lístek.
    pub admitted: bool,
    /// Důvod odmítnutí (`Refusal::label`), když lístek nevznikl.
    pub refusal: Option<&'static str>,
    /// Druh pozitivního důkazu (`context:<druh>`, `allowlist`); prázdné = žádný.
    pub positive: Vec<String>,
    /// Nezávislé skupiny neškodného důkazu (podpůrné i pozitivní).
    pub groups: Vec<u8>,
    pub owner: Option<String>,
}

fn positive_kind(note: &StepNote) -> Option<String> {
    let (group, _, _) = positive(note)?;
    if group == 4 {
        return Some("allowlist".into());
    }
    let label = note
        .detail
        .split("kontext: ")
        .nth(1)
        .and_then(|rest| rest.split([' ', '(', ',', ';']).next())
        .filter(|l| !l.is_empty())
        .unwrap_or("?");
    Some(format!("context:{label}"))
}

/// Stínové posouzení rozhodnutí žebříku (stejná logika jako [`admit_ladder`]).
pub fn shadow_ladder(decision: &Decision) -> Shadow {
    let benign: Vec<&StepNote> = decision
        .notes
        .iter()
        .filter(|n| n.lr.is_some_and(|lr| lr < 1.0))
        .collect();
    let mut positive_kinds: Vec<String> = benign.iter().filter_map(|n| positive_kind(n)).collect();
    positive_kinds.sort();
    positive_kinds.dedup();
    let mut groups: Vec<u8> = benign
        .iter()
        .filter_map(|n| supporting(n).or_else(|| positive(n).map(|(g, _, _)| g)))
        .collect();
    groups.sort_unstable();
    groups.dedup();
    match admit_ladder(decision) {
        Ok(ticket) => Shadow {
            admitted: true,
            refusal: None,
            positive: positive_kinds,
            groups: ticket.groups,
            owner: Some(ticket.owner),
        },
        Err(refusal) => Shadow {
            admitted: false,
            refusal: Some(refusal.label()),
            positive: positive_kinds,
            groups,
            owner: None,
        },
    }
}

/// Stínové posouzení kontextového vysvětlení (stejná logika jako [`admit_explanation`]).
pub fn shadow_context(
    explanation: &crate::context_gate::Explanation,
    finding_type: &str,
    sources: &[String],
    at: DateTime<Utc>,
    subject: Subject,
) -> Shadow {
    let positive = vec![format!("context:{}", explanation.kind.label())];
    match admit_explanation(explanation, finding_type, sources, at, subject) {
        Ok(ticket) => Shadow {
            admitted: true,
            refusal: None,
            positive,
            groups: ticket.groups,
            owner: Some(ticket.owner),
        },
        Err(refusal) => Shadow {
            admitted: false,
            refusal: Some(refusal.label()),
            positive,
            groups: vec![1],
            owner: None,
        },
    }
}

/// Zapíše rozhodnutí žebříku do paměti jedinou cestou a vrátí skutečný výsledek: vyvrácení
/// odmítnuté bránou nebo pamětí (potvrzený nebo podezřelý klíč) se stává eskalací s důvodem.
/// Zobrazení a čítače se mají řídit vráceným rozhodnutím.
pub fn settle(
    memory: &mut crate::finding_memory::FindingMemory,
    mut decision: Decision,
    sources: &[String],
    at: DateTime<Utc>,
) -> Decision {
    match decision.status {
        Status::Refuted => match admit_ladder(&decision) {
            Ok(mut ticket) => {
                ticket.sources = sources.to_vec();
                if !memory.refute_gated(&decision.key, ticket, at) {
                    decision.status = Status::Escalated;
                    decision.reason = format!(
                        "brana zavreni: klic je potvrzeny nebo podezrely, nezavira se; {}",
                        decision.reason
                    );
                    memory.note(&decision.key, "verify_escalate", &decision.reason, at);
                }
            }
            Err(refusal) => {
                decision.status = Status::Escalated;
                decision.reason =
                    format!("brana zavreni: {}; {}", refusal.label(), decision.reason);
                memory.note(&decision.key, "gate_refuse", &decision.reason, at);
            }
        },
        Status::Confirmed => {
            memory.confirm(&decision.key, "verify_ladder", at);
            memory.note(&decision.key, "verify_confirm", &decision.reason, at);
        }
        Status::Escalated | Status::Open => {
            if decision.prior_hold {
                memory.mark_suspected(&decision.key, at);
            }
            memory.note(&decision.key, "verify_escalate", &decision.reason, at);
        }
    }
    decision
}

#[cfg(test)]
mod probes_k21;
#[cfg(test)]
mod tests;
