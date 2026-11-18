//! Retrospektivní vyhledávání a incidenty (krok 12, studie 12b, oddíl 2 bod 4).
//!
//! Nový indikátor (jméno, otisk klienta, adresa) se dohledá napříč uloženou historií
//! nálezů a metadat: první výskyt (pacient nula), časová osa hostu, řetězec fází podle
//! taktik ATT&CK a propojení nálezů do jednoho incidentu. Nálezy se spojují, když sdílejí
//! hosta nebo indikátor v časovém odstupu `max_gap_s`. Incident dostane příčinu:
//! útok, porucha, smíšený (útok i porucha, např. útok během výpadku), neznámý.
//! Historie je omezená (nejnovějších `cap` záznamů).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Pořadí taktik v kill-chainu (ATT&CK Enterprise, taktiky podle matice).
pub const TACTIC_ORDER: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cause {
    Attack,
    Fault,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: i64,
    pub host: String,
    pub finding_id: String,
    /// Indikátory: jména, otisky, protější adresy.
    pub indicators: Vec<String>,
    pub tactic: Option<String>,
    pub cause: Cause,
    /// Typ nálezu (krok 13: seskupení v2 ho používá, `cause` je jen pro měření).
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: usize,
    pub findings: Vec<String>,
    pub hosts: Vec<String>,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Fáze v pořadí kill-chainu, bez opakování.
    pub phases: Vec<String>,
    pub cause: Cause,
    /// Nález s nejstarším časem (pacient nula incidentu).
    pub first_finding: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct History {
    events: Vec<Event>,
    pub cap: usize,
}

impl History {
    pub fn new(cap: usize) -> Self {
        Self {
            events: Vec::new(),
            cap: cap.max(1),
        }
    }

    pub fn add(&mut self, event: Event) {
        self.events.push(event);
        if self.events.len() > self.cap.max(1) {
            self.events.drain(..self.events.len() - self.cap.max(1));
        }
    }

    /// Všechny výskyty indikátoru, nejstarší první.
    pub fn hits(&self, indicator: &str) -> Vec<&Event> {
        let mut v: Vec<&Event> = self
            .events
            .iter()
            .filter(|e| e.indicators.iter().any(|i| i == indicator))
            .collect();
        v.sort_by_key(|e| e.ts);
        v
    }

    /// První výskyt (pacient nula): nejstarší host s indikátorem.
    pub fn patient_zero(&self, indicator: &str) -> Option<(&str, i64)> {
        self.hits(indicator)
            .first()
            .map(|e| (e.host.as_str(), e.ts))
    }

    /// Surové události (jen pro export měření v soaku).
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn host_timeline(&self, host: &str) -> Vec<&Event> {
        let mut v: Vec<&Event> = self.events.iter().filter(|e| e.host == host).collect();
        v.sort_by_key(|e| e.ts);
        v
    }

    /// Propojení do incidentů (sdílený host nebo indikátor, odstup nejvýš `max_gap_s`).
    pub fn incidents(&self, max_gap_s: i64) -> Vec<Incident> {
        self.incidents_by(max_gap_s, |e| {
            std::iter::once(format!("h:{}", e.host))
                .chain(e.indicators.iter().map(|x| format!("i:{x}")))
                .collect()
        })
    }

    /// Krok 13, `incident_v2`: spojuje jen nálezy téhož cíle a téhož protějšku (dvojice)
    /// nebo téhož cíle a téhož typu nálezu. Sdílený host sám (server, resolver) nespojuje,
    /// protože slévá nesouvisející nálezy; cena je nižší úplnost (viz `k13/incidenty.md`).
    pub fn incidents_v2(&self, max_gap_s: i64) -> Vec<Incident> {
        self.incidents_by(max_gap_s, |e| {
            let mut keys = vec![format!("hk:{}|{}", e.host, e.kind)];
            keys.extend(e.indicators.iter().filter(|x| **x != e.host).map(|x| {
                // krok 14: společná příčina z provozní telemetrie (`ops:<podsíť>`) spojuje i různé hosty
                if x.starts_with("ops:") {
                    x.clone()
                } else {
                    format!("hp:{}|{x}", e.host)
                }
            }));
            keys
        })
    }

    fn incidents_by(
        &self,
        max_gap_s: i64,
        keys_of: impl Fn(&Event) -> Vec<String>,
    ) -> Vec<Incident> {
        let n = self.events.len();
        let mut parent: Vec<usize> = (0..n).collect();
        fn find(p: &mut Vec<usize>, x: usize) -> usize {
            let mut r = x;
            while p[r] != r {
                r = p[r];
            }
            let mut c = x;
            while p[c] != r {
                let next = p[c];
                p[c] = r;
                c = next;
            }
            r
        }
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|i| self.events[*i].ts);
        let mut last_by_key: BTreeMap<String, usize> = BTreeMap::new();
        for &i in &order {
            let e = &self.events[i];
            for key in keys_of(e) {
                if let Some(&j) = last_by_key.get(&key)
                    && e.ts - self.events[j].ts <= max_gap_s
                {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        parent[a] = b;
                    }
                }
                last_by_key.insert(key, i);
            }
        }
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for i in 0..n {
            let r = find(&mut parent, i);
            groups.entry(r).or_default().push(i);
        }
        let mut out: Vec<Incident> = groups
            .into_values()
            .map(|members| {
                let evs: Vec<&Event> = members.iter().map(|i| &self.events[*i]).collect();
                let first = evs.iter().min_by_key(|e| e.ts).expect("neprazdna skupina");
                let mut phases: Vec<String> = Vec::new();
                for t in TACTIC_ORDER {
                    if evs.iter().any(|e| e.tactic.as_deref() == Some(*t)) {
                        phases.push((*t).to_string());
                    }
                }
                let attack = evs.iter().any(|e| e.cause == Cause::Attack);
                let fault = evs.iter().any(|e| e.cause == Cause::Fault);
                let cause = match (attack, fault) {
                    (true, true) => Cause::Mixed,
                    (true, false) => Cause::Attack,
                    (false, true) => Cause::Fault,
                    _ => Cause::Unknown,
                };
                let hosts: BTreeSet<String> = evs.iter().map(|e| e.host.clone()).collect();
                Incident {
                    id: 0,
                    findings: evs.iter().map(|e| e.finding_id.clone()).collect(),
                    hosts: hosts.into_iter().collect(),
                    first_ts: first.ts,
                    last_ts: evs.iter().map(|e| e.ts).max().unwrap_or(first.ts),
                    phases,
                    cause,
                    first_finding: first.finding_id.clone(),
                }
            })
            .collect();
        out.sort_by_key(|i| (i.first_ts, i.first_finding.clone()));
        for (id, inc) in out.iter_mut().enumerate() {
            inc.id = id;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        ts: i64,
        host: &str,
        id: &str,
        ind: &[&str],
        tactic: Option<&str>,
        cause: Cause,
    ) -> Event {
        Event {
            ts,
            host: host.into(),
            finding_id: id.into(),
            indicators: ind.iter().map(|s| s.to_string()).collect(),
            tactic: tactic.map(str::to_string),
            cause,
            kind: String::new(),
        }
    }

    #[test]
    fn v2_does_not_link_through_a_shared_host_alone() {
        let mut h = History::new(100);
        for (ts, id, peer, kind) in [
            (0, "a", "9.9.9.9", "scan"),
            (60, "b", "8.8.8.8", "dos"),
            (120, "c", "9.9.9.9", "dos"),
        ] {
            let mut e = ev(ts, "srv", id, &["srv", peer], None, Cause::Unknown);
            e.kind = kind.into();
            h.add(e);
        }
        assert_eq!(h.incidents(3600).len(), 1);
        let v2 = h.incidents_v2(3600);
        // a-c sdílejí dvojici (srv, 9.9.9.9), b-c sdílejí typ nálezu na srv
        assert_eq!(v2.len(), 1);
        let mut h = History::new(100);
        let mut a = ev(0, "srv", "a", &["srv", "1.1.1.1"], None, Cause::Unknown);
        a.kind = "scan".into();
        let mut b = ev(60, "srv", "b", &["srv", "2.2.2.2"], None, Cause::Unknown);
        b.kind = "dos".into();
        h.add(a);
        h.add(b);
        assert_eq!(h.incidents(3600).len(), 1);
        assert_eq!(h.incidents_v2(3600).len(), 2);
    }

    #[test]
    fn indicator_search_finds_patient_zero_timeline_chain_and_incident_cause() {
        let mut h = History::new(1000);
        h.add(ev(
            300,
            "10.0.0.7",
            "f-c2",
            &["ja4:tool", "x1.rare.example"],
            Some("command-and-control"),
            Cause::Attack,
        ));
        h.add(ev(
            100,
            "10.0.0.5",
            "f-scan",
            &["198.51.100.4"],
            Some("discovery"),
            Cause::Attack,
        ));
        h.add(ev(
            200,
            "10.0.0.5",
            "f-lat",
            &["ja4:tool"],
            Some("lateral-movement"),
            Cause::Attack,
        ));
        h.add(ev(250, "10.0.9.9", "f-dns", &[], None, Cause::Fault));
        h.add(ev(
            900_000,
            "10.0.3.3",
            "f-far",
            &["other"],
            None,
            Cause::Unknown,
        ));
        let (host, ts) = h.patient_zero("ja4:tool").unwrap();
        assert_eq!((host, ts), ("10.0.0.5", 200));
        assert_eq!(h.hits("ja4:tool").len(), 2);
        assert_eq!(h.host_timeline("10.0.0.5").len(), 2);
        let incidents = h.incidents(3600);
        let main = incidents
            .iter()
            .find(|i| i.findings.contains(&"f-c2".to_string()))
            .unwrap();
        assert!(
            main.findings.contains(&"f-scan".to_string())
                && main.findings.contains(&"f-lat".to_string())
        );
        assert_eq!(
            main.phases,
            vec!["discovery", "lateral-movement", "command-and-control"]
        );
        assert_eq!(main.cause, Cause::Attack);
        assert_eq!(main.first_finding, "f-scan");
        // porucha na jinem hostu bez sdileni nepatri k incidentu a vzdaleny nalez take ne
        assert_eq!(incidents.len(), 3);
    }

    #[test]
    fn attack_during_fault_is_a_mixed_incident() {
        let mut h = History::new(10);
        h.add(ev(10, "10.0.0.5", "a", &[], Some("impact"), Cause::Attack));
        h.add(ev(20, "10.0.0.5", "b", &[], None, Cause::Fault));
        let i = h.incidents(100);
        assert_eq!(i.len(), 1);
        assert_eq!(i[0].cause, Cause::Mixed);
    }

    #[test]
    fn history_is_bounded() {
        let mut h = History::new(3);
        for t in 0..10 {
            h.add(ev(t, "h", &format!("f{t}"), &[], None, Cause::Unknown));
        }
        assert_eq!(h.host_timeline("h").len(), 3);
    }
}
