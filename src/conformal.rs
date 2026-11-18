//! Konformální abstence nad posteriory žebříku (krok 12, studie 12b, oddíl 2 bod 6).
//!
//! Třídně podmíněná (Mondrian) varianta dělené konformální predikce pro dvě třídy:
//! útok a neškodné. Nekonformitní skóre je 1 − p(třída). Z kalibračních případů se pro
//! každou třídu vezme kvantil na pořadí ⌈(n + 1)(1 − α)⌉ z n; třída vstoupí do množiny
//! predikce, když skóre případu pro ni nepřevyšuje kvantil. Při výměnnosti případů
//! kalibrace a testu platí **třídně podmíněné pokrytí aspoň 1 − α** (Angelopoulos a
//! Bates, arXiv:2107.07511; záruka je konečně-vzorková a bez předpokladu o rozdělení).
//! Výstup:
//! - množina {neškodné}: autonomní rozhodnutí „neškodné“; šance, že byl skutečný útok
//!   takto vyřazen, je nejvýš `alpha_attack` (kalibrace útoků);
//! - množina {útok}: autonomní „útok“; šance omylu u neškodného nejvýš `alpha_benign`;
//! - prázdná nebo obě třídy: **abstence**, rozhoduje člověk.
//!
//! Záruka je marginální přes případy téhož rozdělení: na jiné síti nebo u nové rodiny
//! útoků neplatí automaticky, proto se kalibruje po síti a při malém počtu případů
//! (`min_per_class`) modul vždy abstinuje (nikdy neodhaduje z mála dat).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Class {
    Attack,
    Benign,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Call {
    /// Autonomní rozhodnutí s třídou.
    Decide(Class),
    /// Předat člověku, s důvodem.
    Abstain(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Abstainer {
    /// Přípustná míra přehlédnutého útoku (útok mimo množinu).
    pub alpha_attack: f64,
    /// Přípustná míra neškodného případu mimo množinu.
    pub alpha_benign: f64,
    pub min_per_class: usize,
    /// Seřazená nekonformitní skóre kalibračních útoků (1 − p).
    attack: Vec<f64>,
    /// Seřazená skóre kalibračních neškodných případů (p).
    benign: Vec<f64>,
}

impl Abstainer {
    pub fn new(alpha_attack: f64, alpha_benign: f64, min_per_class: usize) -> Self {
        Self {
            alpha_attack,
            alpha_benign,
            min_per_class,
            attack: Vec::new(),
            benign: Vec::new(),
        }
    }

    /// Kalibrace z dvojic (posterior útoku, byl to útok).
    pub fn fit(&mut self, pairs: &[(f64, bool)]) {
        self.attack = pairs
            .iter()
            .filter(|(_, a)| *a)
            .map(|(p, _)| 1.0 - p)
            .collect();
        self.benign = pairs.iter().filter(|(_, a)| !*a).map(|(p, _)| *p).collect();
        self.attack.sort_by(f64::total_cmp);
        self.benign.sort_by(f64::total_cmp);
    }

    pub fn samples(&self) -> (usize, usize) {
        (self.attack.len(), self.benign.len())
    }

    /// Kvantil na pořadí ⌈(n + 1)(1 − α)⌉; `None`, když pořadí přesáhne n (málo dat
    /// pro zadané α: množina musí obsahovat třídu vždy, tj. nekonečný kvantil).
    fn quantile(sorted: &[f64], alpha: f64) -> Option<f64> {
        let n = sorted.len();
        let rank = (((n + 1) as f64) * (1.0 - alpha)).ceil() as usize;
        if rank == 0 || rank > n {
            None
        } else {
            Some(sorted[rank - 1])
        }
    }

    /// Množina predikce pro posterior útoku `p`.
    pub fn set(&self, p: f64) -> Vec<Class> {
        let mut set = Vec::new();
        // None = kvantil nekonecny: tridu nelze vyloucit
        let qa = Self::quantile(&self.attack, self.alpha_attack);
        let qb = Self::quantile(&self.benign, self.alpha_benign);
        if qa.is_none_or(|q| 1.0 - p <= q) {
            set.push(Class::Attack);
        }
        if qb.is_none_or(|q| p <= q) {
            set.push(Class::Benign);
        }
        set
    }

    pub fn call(&self, p: f64) -> Call {
        let (na, nb) = self.samples();
        if na < self.min_per_class || nb < self.min_per_class {
            return Call::Abstain(format!(
                "malo kalibracnich pripadu (utoky {na}, neskodne {nb}, potreba {})",
                self.min_per_class
            ));
        }
        match self.set(p).as_slice() {
            [Class::Benign] => Call::Decide(Class::Benign),
            [Class::Attack] => Call::Decide(Class::Attack),
            [] => Call::Abstain("prazdna mnozina predikce (pripad netypicky pro kalibraci)".into()),
            _ => Call::Abstain("mnozina obsahuje obe tridy (nerozlisitelne)".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministicky generator jednotkovych cisel.
    fn lcg(state: &mut u64) -> f64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*state >> 11) as f64) / ((1u64 << 53) as f64)
    }

    /// Synteticka data: utoky maji posterior z Beta-podobneho rozdeleni vyssiho,
    /// neskodne nizsiho (prekryv zamerny).
    fn sample(n: usize, seed: u64) -> Vec<(f64, bool)> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                let attack = lcg(&mut s) < 0.3;
                let u = (lcg(&mut s) + lcg(&mut s)) / 2.0;
                let p = if attack { 0.35 + 0.65 * u } else { 0.65 * u };
                (p, attack)
            })
            .collect()
    }

    #[test]
    fn class_conditional_coverage_holds_on_exchangeable_data() {
        let mut abstainer = Abstainer::new(0.05, 0.05, 50);
        abstainer.fit(&sample(4000, 1));
        let test = sample(20_000, 2);
        let (mut a_cov, mut a_n, mut b_cov, mut b_n) = (0, 0, 0, 0);
        let mut decided = 0;
        for (p, attack) in &test {
            let set = abstainer.set(*p);
            if *attack {
                a_n += 1;
                a_cov += set.contains(&Class::Attack) as u32;
            } else {
                b_n += 1;
                b_cov += set.contains(&Class::Benign) as u32;
            }
            decided += matches!(abstainer.call(*p), Call::Decide(_)) as u32;
        }
        let attack_cov = f64::from(a_cov) / f64::from(a_n);
        let benign_cov = f64::from(b_cov) / f64::from(b_n);
        assert!(attack_cov >= 0.95 - 0.01, "pokryti utoku {attack_cov}");
        assert!(benign_cov >= 0.95 - 0.01, "pokryti neskodnych {benign_cov}");
        assert!(decided > 0, "nektere pripady se rozhodnou autonomne");
        assert!(decided < 20_000, "prekryv zpusobi abstenci");
    }

    #[test]
    fn too_little_calibration_always_abstains() {
        let mut abstainer = Abstainer::new(0.05, 0.05, 50);
        abstainer.fit(&sample(40, 3));
        for p in [0.0, 0.5, 1.0] {
            assert!(matches!(abstainer.call(p), Call::Abstain(_)));
        }
        // bez kalibrace: prazdny kvantil, mnozina obsahuje obe tridy
        let empty = Abstainer::new(0.05, 0.05, 0);
        assert_eq!(empty.set(0.5).len(), 2);
    }

    #[test]
    fn extreme_posteriors_are_decided_only_when_calibration_supports_it() {
        let mut abstainer = Abstainer::new(0.05, 0.05, 50);
        abstainer.fit(&sample(4000, 5));
        assert_eq!(abstainer.call(0.0), Call::Decide(Class::Benign));
        assert_eq!(abstainer.call(1.0), Call::Decide(Class::Attack));
        assert!(matches!(abstainer.call(0.5), Call::Abstain(_)));
    }
}
