//! Konkurenční hypotézy, sekvenční vážení důkazů a volba další kontroly podle očekávané
//! informace na cenu (krok 12, studie 12b, oddíl 2 body 1 až 3).
//!
//! Postup vychází z Analysis of Competing Hypotheses (Heuer, *Psychology of Intelligence
//! Analysis*, kap. 8): vedle hypotézy „útok“ stojí explicitní neškodná vysvětlení; důkaz
//! bez rozlišovací schopnosti (poměr věrohodnosti blízko 1) nemá váhu; rozhoduje se
//! vyvracením; reportují se všechny hypotézy a **co by případ rozhodlo**.
//!
//! Matematika (čistá, bez I/O a náhody):
//! - Každá kontrola má tabulku `P(výsledek | třída)` pro třídy útok a neškodné a výsledky
//!   {podezřelý, neškodný, nic}. Výsledek „nic“ (chybějící data, nerozhodnuto) má poměr
//!   věrohodnosti 1 a váhu 0 (prázdná data nejsou důkaz, RQ6 Z3).
//! - Log poměru věrohodnosti se sčítá po nezávislých skupinách (`verification_chain`);
//!   další důkaz téže skupiny má váhu 1/2, 1/4, ... (závislost se nesčítá naplno).
//! - Rozhodnutí podle ceny omylu: zavřít jako neškodné stojí `cost_miss · P(útok)`,
//!   potvrdit jako útok stojí `cost_false_alarm · (1 − P(útok))`, předat člověku stojí
//!   `cost_human`. Zvolí se nejlevnější akce. Prahy tedy nejsou pevné, plynou z cen.
//! - Další kontrola se vybírá podle EVOI: očekávané snížení ztráty rozhodnutí mínus cena
//!   kontroly. Když žádná kontrola nemá kladné EVOI, hledání končí (zastavení podle ceny
//!   omylu proti ceně zjišťování).
//! Tabulky věrohodnosti: `Likelihoods::measured()` jsou četnosti výsledků kontrol z
//! rozhodnutých případů simulace (ladicí seedy 20261102 a 20261103, svět k10, 55 609
//! případů, štítek = kontrafaktuální pravda); v produkci se nahrazují měřením z vlastních
//! verdiktů přes Case Memory.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::verification_chain::{CheckKind, Group};

/// Hypotézy: útok a neškodná vysvětlení (provozní příčiny včetně).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hypothesis {
    Attack,
    Backup,
    Update,
    ScheduledScan,
    Fault,
    Misconfig,
}

impl Hypothesis {
    pub const BENIGN: [Hypothesis; 5] = [
        Hypothesis::Backup,
        Hypothesis::Update,
        Hypothesis::ScheduledScan,
        Hypothesis::Fault,
        Hypothesis::Misconfig,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Hypothesis::Attack => "utok",
            Hypothesis::Backup => "zaloha",
            Hypothesis::Update => "aktualizace",
            Hypothesis::ScheduledScan => "planovany_skener",
            Hypothesis::Fault => "porucha",
            Hypothesis::Misconfig => "chybna_konfigurace",
        }
    }

    /// Testovatelná předpověď: co musí platit v telemetrii, když hypotéza platí.
    pub fn prediction(self) -> &'static str {
        match self {
            Hypothesis::Attack => "cil nebo klient je pro hosta novy; novy otisk klienta; chybi zaznam v kalendari",
            Hypothesis::Backup => "stabilni cil s historii hosta; nahrani v okne zalohy; zaznam v kalendari",
            Hypothesis::Update => "cil zna vice hostu (flotila); stazeni; podepsany proces na hostu",
            Hypothesis::ScheduledScan => "zdroj je v registru skeneru; okno schvaleno; vsechny zdroje nalezu patri skeneru",
            Hypothesis::Fault => "vice klientu selhava naraz; sluzba nebo linka nedostupna; zadny novy protejsek",
            Hypothesis::Misconfig => "jeden host opakuje stejny nezdareny vzor; bez noveho protejsku",
        }
    }
}

/// Výsledek kontroly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Result3 {
    Suspicious,
    Benign,
    /// Nic (chybějící data, nerozhodnuto): žádná váha.
    Nothing,
}

/// `P(výsledek | třída)` jedné kontroly pro třídy útok a neškodné.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Table {
    pub atk_susp: f64,
    pub atk_ben: f64,
    pub ben_susp: f64,
    pub ben_ben: f64,
}

impl Table {
    /// Logaritmus poměru věrohodnosti `ln P(r | útok) / P(r | neškodné)` s vyhlazením.
    pub fn log_lr(&self, r: Result3) -> f64 {
        const EPS: f64 = 0.002;
        match r {
            Result3::Suspicious => ((self.atk_susp + EPS) / (self.ben_susp + EPS)).ln(),
            Result3::Benign => ((self.atk_ben + EPS) / (self.ben_ben + EPS)).ln(),
            Result3::Nothing => 0.0,
        }
    }

    /// Pravděpodobnost výsledku ve třídě.
    pub fn p(&self, attack: bool, r: Result3) -> f64 {
        let (s, b) = if attack {
            (self.atk_susp, self.atk_ben)
        } else {
            (self.ben_susp, self.ben_ben)
        };
        match r {
            Result3::Suspicious => s,
            Result3::Benign => b,
            Result3::Nothing => (1.0 - s - b).max(0.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Likelihoods {
    pub tables: BTreeMap<CheckKind, Table>,
}

impl Likelihoods {
    /// Četnosti z rozhodnutých případů simulace (viz hlavička modulu).
    pub fn measured() -> Self {
        let t = |atk_susp, atk_ben, ben_susp, ben_ben| Table {
            atk_susp,
            atk_ben,
            ben_susp,
            ben_ben,
        };
        let mut tables = BTreeMap::new();
        tables.insert(CheckKind::CaseHistory, t(0.058, 0.017, 0.153, 0.194));
        tables.insert(CheckKind::HostBaseline, t(0.000, 0.003, 0.000, 0.018));
        tables.insert(CheckKind::PeerCompare, t(0.131, 0.096, 0.066, 0.147));
        tables.insert(CheckKind::ConfigContext, t(0.000, 0.000, 0.000, 0.005));
        tables.insert(CheckKind::Reputation, t(0.116, 0.001, 0.002, 0.016));
        tables.insert(CheckKind::EndpointTelemetry, t(0.117, 0.000, 0.072, 0.006));
        tables.insert(CheckKind::RepeatMeasure, t(0.259, 0.000, 0.247, 0.000));
        tables.insert(CheckKind::ActiveReadOnly, t(0.499, 0.008, 0.051, 0.128));
        // krok 14: provozní telemetrie dává výsledek „neškodný“ jen jako shodu s typem poruchy nebo
        // změny v katalogu (nikdy „podezřelý"); četnosti z ladicího běhu k14 (impl-krok14.md)
        tables.insert(CheckKind::OpsTelemetry, t(0.0, 0.065, 0.0, 0.70));
        // kontroly bez měření v kroku 12: neutrální tabulka (poměr 1), váha 0
        for kind in CheckKind::ALL {
            tables.entry(kind).or_insert_with(|| t(0.1, 0.1, 0.1, 0.1));
        }
        Self { tables }
    }
}

/// Změřené tabulky jako sdílená konstanta (bez opakovaného stavění mapy).
pub fn measured_static() -> &'static Likelihoods {
    static LIK: std::sync::OnceLock<Likelihoods> = std::sync::OnceLock::new();
    LIK.get_or_init(Likelihoods::measured)
}

/// Jedno pozorování.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Obs {
    pub kind: CheckKind,
    pub result: Result3,
}

/// Ceny rozhodnutí (relativní; přirozená jednotka = práce analytika na jeden případ).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Costs {
    /// Zavřít jako neškodné, a byl to útok.
    pub miss: f64,
    /// Potvrdit jako útok, a bylo to neškodné.
    pub false_alarm: f64,
    /// Předat člověku.
    pub human: f64,
}

impl Default for Costs {
    fn default() -> Self {
        Self {
            miss: 200.0,
            false_alarm: 3.0,
            human: 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    CloseBenign,
    ConfirmAttack,
    Human,
}

/// Posterior útoku z pozorování: nezávislé skupiny plnou vahou, další členy skupiny
/// polovinou, čtvrtinou, ...
pub fn posterior_attack(prior: f64, obs: &[Obs], lik: &Likelihoods) -> f64 {
    let mut per_group: BTreeMap<Group, u32> = BTreeMap::new();
    let mut log_odds = (prior.clamp(1e-6, 1.0 - 1e-6) / (1.0 - prior.clamp(1e-6, 1.0 - 1e-6))).ln();
    for o in obs {
        if o.result == Result3::Nothing {
            continue;
        }
        let Some(table) = lik.tables.get(&o.kind) else {
            continue;
        };
        let seen = per_group.entry(o.kind.group()).or_default();
        log_odds += 0.5f64.powi((*seen).min(8) as i32) * table.log_lr(o.result);
        *seen += 1;
    }
    1.0 / (1.0 + (-log_odds).exp())
}

/// Nejlevnější akce a její očekávaná ztráta pro posterior `p`.
pub fn best_action(p: f64, costs: &Costs) -> (Action, f64) {
    let close = costs.miss * p;
    let confirm = costs.false_alarm * (1.0 - p);
    let human = costs.human;
    if close <= confirm && close <= human {
        (Action::CloseBenign, close)
    } else if confirm <= human {
        (Action::ConfirmAttack, confirm)
    } else {
        (Action::Human, human)
    }
}

/// EVOI kontroly při aktuálním posterioru: očekávané snížení ztráty rozhodnutí po
/// pozorování výsledku mínus cena kontroly. Výsledky se váží pravděpodobností
/// `p·P(r|útok) + (1−p)·P(r|neškodné)`; posterior po výsledku používá váhu skupiny
/// podle již provedených pozorování.
pub fn evoi(
    prior: f64,
    done: &[Obs],
    kind: CheckKind,
    lik: &Likelihoods,
    costs: &Costs,
    price: f64,
) -> f64 {
    let Some(table) = lik.tables.get(&kind) else {
        return f64::NEG_INFINITY;
    };
    let p = posterior_attack(prior, done, lik);
    let now = best_action(p, costs).1;
    let mut after = 0.0;
    for r in [Result3::Suspicious, Result3::Benign, Result3::Nothing] {
        let w = p * table.p(true, r) + (1.0 - p) * table.p(false, r);
        if w <= 0.0 {
            continue;
        }
        let mut next: Vec<Obs> = done.to_vec();
        next.push(Obs { kind, result: r });
        let q = posterior_attack(prior, &next, lik);
        after += w * best_action(q, costs).1;
    }
    now - after - price * costs.human
}

/// Vzajemna informace mezi tridou (utok, neskodne) a vysledkem kontroly, deleno cenou
/// (bity na jednotku ceny). Slouzi k poradi planu: prvni kontrola, ktera nejvic rozlisuje.
pub fn information_per_cost(prior: f64, kind: CheckKind, lik: &Likelihoods) -> f64 {
    let Some(t) = lik.tables.get(&kind) else {
        return 0.0;
    };
    let mut mi = 0.0;
    for r in [Result3::Suspicious, Result3::Benign, Result3::Nothing] {
        let (a, b) = (t.p(true, r), t.p(false, r));
        let marginal = prior * a + (1.0 - prior) * b;
        for (pc, p) in [(prior, a), (1.0 - prior, b)] {
            if p > 0.0 && marginal > 0.0 {
                mi += pc * p * (p / marginal).log2();
            }
        }
    }
    mi / (kind.cost().0 + 0.02)
}

/// Další kontrola s nejvyšším kladným EVOI, nebo `None` (zastavit a rozhodnout).
pub fn next_by_evoi(
    prior: f64,
    done: &[Obs],
    available: &dyn Fn(CheckKind) -> bool,
    lik: &Likelihoods,
    costs: &Costs,
) -> Option<(CheckKind, f64)> {
    let tried: std::collections::BTreeSet<CheckKind> = done.iter().map(|o| o.kind).collect();
    CheckKind::ALL
        .iter()
        .copied()
        .filter(|k| !tried.contains(k) && available(*k))
        .map(|k| (k, evoi(prior, done, k, lik, costs, k.cost().0)))
        .filter(|(_, v)| *v > 1e-9)
        .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0)))
}

/// Zpráva pro člověka nebo audit: hypotézy a co případ rozhodne.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub posterior_attack: f64,
    pub action: Action,
    pub expected_loss: f64,
    pub next_check: Option<CheckKind>,
    /// Pořadí hypotéz (útok vždy uveden); neškodné rozděleno rovnoměrně, dokud
    /// vysvětlující důkaz nezvolí konkrétní druh (`explained_by`).
    pub hypotheses: Vec<(Hypothesis, f64)>,
}

pub fn assess(
    prior: f64,
    done: &[Obs],
    available: &dyn Fn(CheckKind) -> bool,
    lik: &Likelihoods,
    costs: &Costs,
    explained_by: Option<Hypothesis>,
) -> Assessment {
    let p = posterior_attack(prior, done, lik);
    let (action, expected_loss) = best_action(p, costs);
    let next = next_by_evoi(prior, done, available, lik, costs).map(|(k, _)| k);
    let mut hypotheses = vec![(Hypothesis::Attack, p)];
    let rest = 1.0 - p;
    match explained_by {
        Some(h) if h != Hypothesis::Attack => {
            hypotheses.push((h, rest * 0.8));
            let others = Hypothesis::BENIGN.iter().filter(|x| **x != h).count() as f64;
            for x in Hypothesis::BENIGN.iter().filter(|x| **x != h) {
                hypotheses.push((*x, rest * 0.2 / others));
            }
        }
        _ => {
            for x in Hypothesis::BENIGN {
                hypotheses.push((x, rest / Hypothesis::BENIGN.len() as f64));
            }
        }
    }
    Assessment {
        posterior_attack: p,
        action,
        expected_loss,
        next_check: next,
        hypotheses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(kind: CheckKind, result: Result3) -> Obs {
        Obs { kind, result }
    }

    #[test]
    fn empty_results_carry_no_weight_and_dependent_evidence_is_discounted() {
        let lik = Likelihoods::measured();
        let base = posterior_attack(0.3, &[], &lik);
        let nothing = posterior_attack(
            0.3,
            &[obs(CheckKind::Reputation, Result3::Nothing), obs(CheckKind::CaseHistory, Result3::Nothing)],
            &lik,
        );
        assert!((base - nothing).abs() < 1e-12);
        // dva podezrele dukazy ze stejne skupiny (Behaviour) mene nez ze dvou ruznych
        let same = posterior_attack(
            0.3,
            &[obs(CheckKind::PeerCompare, Result3::Suspicious), obs(CheckKind::CaseHistory, Result3::Suspicious)],
            &lik,
        );
        let diff = posterior_attack(
            0.3,
            &[obs(CheckKind::PeerCompare, Result3::Suspicious), obs(CheckKind::Reputation, Result3::Suspicious)],
            &lik,
        );
        assert!(diff > same, "{diff} > {same}");
    }

    #[test]
    fn decision_follows_error_costs_not_a_fixed_threshold() {
        let costs = Costs::default();
        // nizky posterior, ale cena prehlednuteho utoku je vysoka: neni to zavreni
        assert_eq!(best_action(0.02, &costs).0, Action::Human);
        assert_eq!(best_action(0.001, &costs).0, Action::CloseBenign);
        assert_eq!(best_action(0.95, &costs).0, Action::ConfirmAttack);
        // levnejsi omyl zmeni hranici
        let lenient = Costs { miss: 20.0, ..costs };
        assert_eq!(best_action(0.02, &lenient).0, Action::CloseBenign);
    }

    /// Tabulka s jednou levnou, ostrou kontrolou: neskodny vysledek jen u neskodnych.
    fn sharp() -> Likelihoods {
        let mut lik = Likelihoods::measured();
        lik.tables.insert(
            CheckKind::ConfigContext,
            Table {
                atk_susp: 0.0,
                atk_ben: 0.0,
                ben_susp: 0.0,
                ben_ben: 0.5,
            },
        );
        lik
    }

    #[test]
    fn evoi_picks_the_informative_check_and_stops_when_nothing_pays() {
        let costs = Costs::default();
        let avail = |_k: CheckKind| true;
        let lik = sharp();
        // nejisty pripad (posterior 0,01): jedine ostra kontrola ma kladne EVOI
        let (kind, gain) = next_by_evoi(0.01, &[], &avail, &lik, &costs).expect("kontrola se vyplati");
        assert_eq!(kind, CheckKind::ConfigContext);
        assert!(gain > 0.3, "{gain}");
        // kontrola bez rozlisovaci schopnosti (neutralni tabulka) EVOI nema
        let neutral = evoi(0.01, &[], CheckKind::Timing, &lik, &costs, CheckKind::Timing.cost().0);
        assert!(neutral < 1e-9, "{neutral}");
        // zmerene tabulky: pri cene omylu 200 : 1 se zadna z beznych kontrol nevyplati,
        // program se zastavi a predava cloveku (poctivy vysledek, ne chyba)
        let measured = Likelihoods::measured();
        assert!(next_by_evoi(0.2, &[], &avail, &measured, &costs).is_none());
        assert_eq!(best_action(0.2, &costs).0, Action::Human);
    }

    #[test]
    fn assessment_reports_all_hypotheses_and_the_deciding_check() {
        let lik = sharp();
        let a = assess(0.01, &[], &|_| true, &lik, &Costs::default(), Some(Hypothesis::Backup));
        assert_eq!(a.hypotheses.len(), 1 + Hypothesis::BENIGN.len());
        let total: f64 = a.hypotheses.iter().map(|(_, p)| p).sum();
        assert!((total - 1.0).abs() < 1e-9);
        assert_eq!(a.hypotheses[1].0, Hypothesis::Backup);
        assert!(a.next_check.is_some());
        assert!(!Hypothesis::Backup.prediction().is_empty());
    }
}
