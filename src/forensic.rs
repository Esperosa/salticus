//! Bezpečný forenzní sběr (krok 12, studie 12b, oddíl 5): jen čtecí akce a jen po
//! schválení člověka.
//!
//! Žádost je uzavřený výčet druhů (`Kind`), ne volný příkaz: obsah logů ani nálezů se
//! nikdy nepoužije jako příkaz (ochrana proti injekci). Každá žádost nese žadatele,
//! rozsah (hosté, časové okno, artefakty), expiraci a stav. Provedení vyžaduje stav
//! `Approved` od jiné osoby než žadatele (dvojí klíč), neprošlou expiraci a shodu rozsahu
//! s politikou. Vše se loguje do auditu. Samotné provedení deleguje na `Executor`
//! (adaptér k PCAP bufferu, EDR nebo vyhledávání v logu); engine sám nic nespouští.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// Vyžádání úseku PCAP z ring bufferu.
    PcapSlice,
    /// Triage balíček z EDR (jen čtení: procesy, spojení, autorun).
    EdrTriage,
    /// Vyhledání v logu podle Sigma pravidla (jen čtení).
    SigmaSearch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Pending,
    Approved,
    Rejected,
    Executed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub kind: Kind,
    pub hosts: Vec<String>,
    pub from: i64,
    pub to: i64,
    /// Název artefaktu nebo pravidla z povoleného katalogu (ne volný text).
    pub artifact: String,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub expires: i64,
    pub status: Status,
}

/// Politika: povolené artefakty a největší rozsah.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub allowed_artifacts: Vec<String>,
    pub max_hosts: usize,
    pub max_window_s: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allowed_artifacts: vec![
                "pcap_ring_slice".into(),
                "edr_triage_basic".into(),
                "sigma_log_search".into(),
            ],
            max_hosts: 20,
            max_window_s: 24 * 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLine {
    pub at: i64,
    pub id: u64,
    pub action: String,
    pub actor: String,
    pub detail: String,
}

pub trait Executor {
    fn run(&self, request: &Request) -> Result<String, String>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Broker {
    pub policy: Policy,
    requests: Vec<Request>,
    pub audit: Vec<AuditLine>,
    next_id: u64,
}

impl Broker {
    fn log(&mut self, at: i64, id: u64, action: &str, actor: &str, detail: &str) {
        self.audit.push(AuditLine {
            at,
            id,
            action: action.into(),
            actor: actor.into(),
            detail: detail.chars().take(200).collect(),
        });
    }

    /// Založí žádost; odmítne artefakt mimo katalog a rozsah mimo politiku.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        kind: Kind,
        hosts: Vec<String>,
        from: i64,
        to: i64,
        artifact: &str,
        requested_by: &str,
        ttl_s: i64,
        now: i64,
    ) -> Result<u64, String> {
        if !self.policy.allowed_artifacts.iter().any(|a| a == artifact) {
            return Err(format!("artefakt '{artifact}' neni v katalogu"));
        }
        if hosts.is_empty() || hosts.len() > self.policy.max_hosts {
            return Err("rozsah hostu mimo politiku".into());
        }
        if to < from || to - from > self.policy.max_window_s {
            return Err("casove okno mimo politiku".into());
        }
        if requested_by.trim().is_empty() {
            return Err("chybi zadatel".into());
        }
        self.next_id += 1;
        let id = self.next_id;
        self.requests.push(Request {
            id,
            kind,
            hosts,
            from,
            to,
            artifact: artifact.into(),
            requested_by: requested_by.into(),
            approved_by: None,
            expires: now + ttl_s.clamp(60, 7 * 86_400),
            status: Status::Pending,
        });
        self.log(now, id, "request", requested_by, artifact);
        Ok(id)
    }

    fn find(&mut self, id: u64) -> Option<&mut Request> {
        self.requests.iter_mut().find(|r| r.id == id)
    }

    /// Schválení člověkem; schvalovatel musí být jiná osoba než žadatel.
    pub fn approve(&mut self, id: u64, approver: &str, now: i64) -> Result<(), String> {
        let req = self.find(id).ok_or("neznama zadost")?;
        if approver.trim().is_empty() || approver == req.requested_by {
            return Err("schvalovat musi jina osoba nez zadatel".into());
        }
        if req.status != Status::Pending || now > req.expires {
            return Err("zadost neni cekajici nebo vyprsela".into());
        }
        req.status = Status::Approved;
        req.approved_by = Some(approver.into());
        self.log(now, id, "approve", approver, "");
        Ok(())
    }

    pub fn reject(&mut self, id: u64, approver: &str, now: i64) -> Result<(), String> {
        let req = self.find(id).ok_or("neznama zadost")?;
        req.status = Status::Rejected;
        self.log(now, id, "reject", approver, "");
        Ok(())
    }

    /// Provede schválenou žádost; jinak se nic nespustí.
    pub fn execute(&mut self, id: u64, exec: &dyn Executor, now: i64) -> Result<String, String> {
        let (request, ok) = {
            let req = self.find(id).ok_or("neznama zadost")?;
            (
                req.clone(),
                req.status == Status::Approved && now <= req.expires,
            )
        };
        if !ok {
            self.log(
                now,
                id,
                "execute_refused",
                "engine",
                "bez schvaleni nebo po expiraci",
            );
            return Err("provedeni odmitnuto: neni schvaleno nebo vyprselo".into());
        }
        if !self
            .policy
            .allowed_artifacts
            .iter()
            .any(|a| *a == request.artifact)
        {
            self.log(
                now,
                id,
                "execute_refused",
                "engine",
                "artefakt mimo katalog",
            );
            return Err("artefakt mimo katalog".into());
        }
        let result = exec.run(&request);
        if let Some(req) = self.find(id) {
            req.status = Status::Executed;
        }
        match &result {
            Ok(summary) => self.log(now, id, "executed", "engine", summary),
            Err(e) => self.log(now, id, "execute_failed", "engine", e),
        }
        result
    }

    pub fn list(&self) -> &[Request] {
        &self.requests
    }

    pub fn status(&self, id: u64) -> Option<Status> {
        self.requests.iter().find(|r| r.id == id).map(|r| r.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Counting(Cell<u32>);
    impl Executor for Counting {
        fn run(&self, _: &Request) -> Result<String, String> {
            self.0.set(self.0.get() + 1);
            Ok("ok".into())
        }
    }

    fn open(b: &mut Broker) -> u64 {
        b.request(
            Kind::PcapSlice,
            vec!["10.0.0.5".into()],
            0,
            600,
            "pcap_ring_slice",
            "analytik-a",
            3600,
            10,
        )
        .unwrap()
    }

    #[test]
    fn nothing_runs_without_approval_by_a_second_person_and_before_expiry() {
        let mut b = Broker::default();
        let exec = Counting(Cell::new(0));
        let id = open(&mut b);
        assert!(b.execute(id, &exec, 20).is_err());
        assert_eq!(exec.0.get(), 0, "bez schvaleni se nic nespusti");
        assert!(
            b.approve(id, "analytik-a", 20).is_err(),
            "zadatel neschvaluje sam sebe"
        );
        b.approve(id, "vedouci-b", 20).unwrap();
        assert!(
            b.execute(id, &exec, 10 + 3601).is_err(),
            "po expiraci se nespusti"
        );
        assert_eq!(exec.0.get(), 0);
        let id2 = open(&mut b);
        b.approve(id2, "vedouci-b", 30).unwrap();
        assert!(b.execute(id2, &exec, 40).is_ok());
        assert_eq!(exec.0.get(), 1);
        assert_eq!(b.status(id2), Some(Status::Executed));
        assert!(b.audit.iter().any(|l| l.action == "execute_refused"));
        assert!(b.audit.iter().any(|l| l.action == "executed"));
    }

    #[test]
    fn free_text_commands_and_out_of_policy_scopes_are_rejected() {
        let mut b = Broker::default();
        // obsah logu nelze pouzit jako prikaz: artefakt musi byt z katalogu
        assert!(
            b.request(
                Kind::EdrTriage,
                vec!["h".into()],
                0,
                10,
                "rm -rf /; curl evil",
                "a",
                60,
                0
            )
            .is_err()
        );
        assert!(
            b.request(
                Kind::PcapSlice,
                vec![],
                0,
                10,
                "pcap_ring_slice",
                "a",
                60,
                0
            )
            .is_err()
        );
        assert!(
            b.request(
                Kind::PcapSlice,
                vec!["h".into()],
                0,
                10 * 86_400,
                "pcap_ring_slice",
                "a",
                60,
                0
            )
            .is_err()
        );
        assert!(
            b.request(
                Kind::PcapSlice,
                vec!["h".into()],
                0,
                10,
                "pcap_ring_slice",
                " ",
                60,
                0
            )
            .is_err()
        );
        assert!(b.audit.is_empty());
    }
}
