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
    /// Krok 34: nález bez hosta (nespárovaná pasivní událost); `host` je tu cíl (oběť).
    #[serde(default)]
    pub hostless: bool,
}

/// Veřejná jednosměrová IPv4 adresa (vnější protějšek); privátní, loopback, link-local,
/// broadcast a multicast ne.
fn is_public_unicast(ip: &str) -> bool {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(a) => {
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_unspecified())
        }
        Err(_) => false,
    }
}

fn find_root(p: &mut [usize], x: usize) -> usize {
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
    /// Krok 33: stabilní klíč incidentu (hash nejstaršího nálezu); `id` je jen pořadí v běhu.
    #[serde(default)]
    pub key: String,
}

/// FNV-1a 64 bit jako hex; stabilní mezi běhy a platformami (na rozdíl od `DefaultHasher`).
pub fn stable_key(text: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct History {
    events: Vec<Event>,
    pub cap: usize,
    /// Počet událostí, které už vypadly ze začátku (pořadové číslo události = `base` + pozice).
    base: u64,
    /// `finding_id` -> pořadové číslo události; neukládá se, po načtení `reindex`.
    #[serde(skip)]
    index: std::collections::HashMap<String, u64>,
}

impl History {
    pub fn new(cap: usize) -> Self {
        Self {
            events: Vec::new(),
            cap: cap.max(1),
            base: 0,
            index: std::collections::HashMap::new(),
        }
    }

    /// Po načtení ze stavu: znovu postaví index (neukládá se).
    pub fn reindex(&mut self) {
        self.index = self
            .events
            .iter()
            .enumerate()
            .map(|(i, e)| (e.finding_id.clone(), self.base + i as u64))
            .collect();
    }

    /// Je nález už v historii (krok 33: jedna událost na nález, ne na každé zobrazení)?
    pub fn has_finding(&self, finding_id: &str) -> bool {
        self.index.contains_key(finding_id)
    }

    /// Krok 35: nové důkazy k už zapsanému nálezu (další protějšky); událost se nepřidává.
    pub fn merge_indicators(&mut self, finding_id: &str, extra: &[String]) {
        let Some(&seq) = self.index.get(finding_id) else {
            return;
        };
        let Some(pos) = seq.checked_sub(self.base) else {
            return;
        };
        if let Some(e) = self.events.get_mut(pos as usize) {
            for x in extra {
                if e.indicators.len() < 8 && !e.indicators.contains(x) {
                    e.indicators.push(x.clone());
                }
            }
        }
    }

    pub fn add(&mut self, event: Event) {
        let seq = self.base + self.events.len() as u64;
        self.index.insert(event.finding_id.clone(), seq);
        self.events.push(event);
        let cap = self.cap.max(1);
        if self.events.len() > cap {
            let drop = self.events.len() - cap;
            for e in self.events.drain(..drop) {
                // index smaže jen pokud ukazuje na vyřazenou událost (nález mohl být zapsán znovu)
                if self
                    .index
                    .get(&e.finding_id)
                    .is_some_and(|s| *s < self.base + drop as u64)
                {
                    self.index.remove(&e.finding_id);
                }
            }
            self.base += drop as u64;
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
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|i| self.events[*i].ts);
        let mut last_by_key: BTreeMap<String, usize> = BTreeMap::new();
        for &i in &order {
            let e = &self.events[i];
            for key in keys_of(e) {
                if let Some(&j) = last_by_key.get(&key)
                    && e.ts - self.events[j].ts <= max_gap_s
                {
                    let (a, b) = (find_root(&mut parent, i), find_root(&mut parent, j));
                    if a != b {
                        parent[a] = b;
                    }
                }
                last_by_key.insert(key, i);
            }
        }
        self.assemble(parent)
    }

    /// Krok 34: kauzální seskupení. Spojuje (1) stejného aktéra a stejný protějšek, (2) protějšek
    /// dřívějšího nálezu, který se pak sám stane aktérem (A skenuje V, V posílá data na X),
    /// (3) oběť (nález bez hosta) s nálezy, kde je ta adresa aktérem nebo protějškem, (4) téhož
    /// aktéra u dvou útočných nálezů. Dva nálezy se nespojují jen proto, že míří na stejný
    /// protějšek (sdílený server, vnější cíl): to není kauzální vazba, ale slévá souběžné útoky.
    /// Klíč, který by spojil víc než `max_degree` nálezů, je uzel typu hub a dál nespojuje.
    pub fn incidents_v3(
        &self,
        max_gap_s: i64,
        max_degree: usize,
        max_actor_degree: usize,
        ext_links: bool,
    ) -> Vec<Incident> {
        let n = self.events.len();
        let mut parent: Vec<usize> = (0..n).collect();
        let mut order: Vec<usize> = (0..n).collect();
        // stejný čas (nálezy jednoho okna): pořadí podle fáze kill-chainu, pak podle id, aby
        // výsledek nezávisel na pořadí vložení
        let rank = |e: &Event| {
            e.tactic
                .as_deref()
                .and_then(|t| TACTIC_ORDER.iter().position(|x| *x == t))
                .map_or(0, |p| p + 1)
        };
        order.sort_by(|a, b| {
            let (x, y) = (&self.events[*a], &self.events[*b]);
            (x.ts, rank(x), &x.finding_id).cmp(&(y.ts, rank(y), &y.finding_id))
        });
        // klíč -> (poslední nález, počet použití)
        let mut peer_seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut actor_seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut pair_seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut victim_seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut ext_seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let union = |parent: &mut Vec<usize>, a: usize, b: usize| {
            let (ra, rb) = (find_root(parent, a), find_root(parent, b));
            if ra != rb {
                parent[ra] = rb;
            }
        };
        for &i in &order {
            let e = &self.events[i];
            // `cap`: nejvýš tolik použití klíče v jednom časovém okně (hub se v čase uvolní)
            let mut link = |map: &mut BTreeMap<String, (usize, usize)>,
                            key: &str,
                            parent: &mut Vec<usize>,
                            register: bool,
                            cap: usize| {
                let mut used_now = 0;
                if let Some(&(j, used)) = map.get(key) {
                    if e.ts - self.events[j].ts <= max_gap_s {
                        used_now = used;
                        if used < cap {
                            union(parent, i, j);
                        }
                    }
                }
                if register {
                    map.insert(key.to_string(), (i, used_now + 1));
                }
            };
            let peers: Vec<&String> = e.indicators.iter().filter(|x| **x != e.host).collect();
            // jen zápis klíče (bez spojení), počet použití v okně
            let register = |map: &mut BTreeMap<String, (usize, usize)>, key: &str| {
                let used = match map.get(key) {
                    Some(&(j, used)) if e.ts - self.events[j].ts <= max_gap_s => used,
                    _ => 0,
                };
                map.insert(key.to_string(), (i, used + 1));
            };
            if e.hostless {
                // oběť: spojí se s nálezy, kde je adresa protějškem nebo aktérem; s jinými nálezy
                // bez hosta na téže oběti se nespojuje (sdílená oběť není kauzální vazba)
                link(&mut peer_seen, &e.host, &mut parent, false, max_degree);
                link(
                    &mut actor_seen,
                    &e.host,
                    &mut parent,
                    false,
                    max_actor_degree,
                );
                if ext_links {
                    // stejná oběť v dalších nálezech téže kampaně (sken, sonda, průnik na tentýž cíl)
                    link(&mut victim_seen, &e.host, &mut parent, true, max_degree);
                } else {
                    register(&mut victim_seen, &e.host);
                }
                if ext_links {
                    for p in &peers {
                        if is_public_unicast(p) {
                            link(&mut ext_seen, p, &mut parent, true, max_degree);
                        }
                    }
                }
                continue;
            }
            // protějšek dřívějšího nálezu, který teď jedná
            link(&mut peer_seen, &e.host, &mut parent, false, max_degree);
            // dřívější nález, kde byl tento host obětí
            link(&mut victim_seen, &e.host, &mut parent, false, max_degree);
            for p in &peers {
                link(
                    &mut pair_seen,
                    &format!("{}|{p}", e.host),
                    &mut parent,
                    true,
                    usize::MAX,
                );
                // nález bez hosta, který míří na tento protějšek
                link(&mut victim_seen, p, &mut parent, false, max_degree);
            }
            if e.cause == Cause::Attack {
                link(
                    &mut actor_seen,
                    &e.host,
                    &mut parent,
                    true,
                    max_actor_degree,
                );
            }
            if ext_links {
                // stejný vnější protějšek u dvou nálezů (útočník zasáhl víc obětí, společný cíl C2)
                for p in &peers {
                    if is_public_unicast(p) {
                        link(&mut ext_seen, p, &mut parent, true, max_degree);
                    }
                }
            }
            for p in &peers {
                register(&mut peer_seen, p);
            }
        }
        self.assemble(parent)
    }

    /// Krok 37: seskupení podle sdílené adresy (host a všechny indikátory). Spojuje nálezy, které
    /// sdílejí adresu v odstupu nejvýš `max_gap_s`, dokud adresa nespojila `max_degree` nálezů
    /// v okně (hub). Bez rolí aktér a protějšek: sdílený útočník, oběť i cíl jsou stejně vazba.
    pub fn incidents_union(&self, max_gap_s: i64, max_degree: usize) -> Vec<Incident> {
        let n = self.events.len();
        let mut parent: Vec<usize> = (0..n).collect();
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|a, b| {
            let (x, y) = (&self.events[*a], &self.events[*b]);
            (x.ts, &x.finding_id).cmp(&(y.ts, &y.finding_id))
        });
        let mut last: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for &i in &order {
            let e = &self.events[i];
            let keys =
                std::iter::once(e.host.as_str()).chain(e.indicators.iter().map(String::as_str));
            for key in keys {
                let mut used = 0;
                if let Some(&(j, u)) = last.get(key)
                    && e.ts - self.events[j].ts <= max_gap_s
                {
                    used = u;
                    if u < max_degree {
                        let (ra, rb) = (find_root(&mut parent, i), find_root(&mut parent, j));
                        if ra != rb {
                            parent[ra] = rb;
                        }
                    }
                }
                last.insert(key, (i, used + 1));
            }
        }
        self.assemble(parent)
    }

    fn assemble(&self, mut parent: Vec<usize>) -> Vec<Incident> {
        let n = self.events.len();
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for i in 0..n {
            let r = find_root(&mut parent, i);
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
                    key: stable_key(&first.finding_id),
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
            hostless: false,
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
