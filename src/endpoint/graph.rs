//! Krok 14 (A): graf aktiv a incidentů, kontext procesu u nálezu, soukromí a nesoulad síť x agent.
//!
//! Všechno je čtení nad `EndpointStore`; nic se nezavírá. Pravidla:
//! - příkazová řádka se před uložením do nálezu redaktuje (tajemství, zakódované příkazy),
//! - uživatel se pseudonymizuje solenou funkcí (sůl z nastavení nasazení, ne z kódu),
//! - kauzální řetěz je rodič -> potomek -> spojení s časem, bez domýšlených hran,
//! - host, který v síti komunikuje a jeho agent mlčí, je slepé místo nebo tampering (nevíme které).
//!
//! Zdroje metod (jen ověřené): provenance graf jako kauzální strom procesů (DARPA TC, Holmes,
//! SIGL; viz studie 14), svázání spojení s procesem přes pětici a čas (Sysmon 3, osquery
//! `process_open_sockets`; studie 14, bod 3).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::{
    correlate::EndpointStore,
    model::{EndpointEvent, EventKind},
};

/// Nastavení soukromí nasazení (minimalizace dat, retence, pseudonymizace).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Privacy {
    /// Sůl pseudonymizace uživatelů (v nasazení tajná; prázdná = pseudonymy nejsou stabilní mezi instalacemi).
    pub salt: String,
    pub pseudonymize_users: bool,
    pub redact_cmdline: bool,
    /// Retence událostí v sekundách (uložení jinde ořezává `EndpointStore::prune`).
    pub retention_s: i64,
}

impl Default for Privacy {
    fn default() -> Self {
        Self {
            salt: String::new(),
            pseudonymize_users: true,
            redact_cmdline: true,
            retention_s: 24 * 3600,
        }
    }
}

fn fnv64(salt: &str, text: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in salt.bytes().chain([0u8]).chain(text.bytes()) {
        h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
    }
    h
}

impl Privacy {
    /// `DOMENA\jmeno` a `jmeno` mají stejný pseudonym; systémové účty zůstávají čitelné.
    pub fn user(&self, user: &str) -> String {
        let name = user.rsplit(['\\', '/']).next().unwrap_or(user).trim();
        let low = name.to_ascii_lowercase();
        if !self.pseudonymize_users
            || matches!(
                low.as_str(),
                "system"
                    | "local service"
                    | "network service"
                    | "root"
                    | "nt authority\\system"
                    | ""
            )
            || low.ends_with('$')
        {
            return name.to_string();
        }
        format!("u-{:08x}", fnv64(&self.salt, &low) as u32)
    }

    pub fn cmdline(&self, cmd: &str) -> String {
        if self.redact_cmdline {
            redact_cmdline(cmd)
        } else {
            cmd.to_string()
        }
    }
}

const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "key",
    "auth",
    "authorization",
    "bearer",
    "credential",
    "sas",
];
const SECRET_FLAGS: &[&str] = &[
    "-p",
    "-pw",
    "--password",
    "--passwd",
    "--token",
    "--secret",
    "-key",
    "--key",
    "-encodedcommand",
    "-enc",
    "-e",
    "-ec",
    "--access-key",
    "--secret-key",
];

fn is_base64ish(tok: &str) -> bool {
    tok.len() >= 40
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

/// Tajemství v příkazové řádce -> `[redacted]` (klíč=hodnota, příznaky s hodnotou, dlouhé base64,
/// `Authorization: Bearer ...`). Redakce je záměrně hrubá: raději smazat víc.
pub fn redact_cmdline(cmd: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut hide_next = false;
    for tok in cmd.split_whitespace().take(256) {
        let low = tok.to_ascii_lowercase();
        if hide_next {
            out.push("[redacted]".into());
            hide_next = false;
            continue;
        }
        if let Some((k, _)) = tok.split_once('=') {
            let kl = k.trim_start_matches('-').to_ascii_lowercase();
            if SECRET_KEYS.iter().any(|s| kl.contains(s)) {
                out.push(format!("{k}=[redacted]"));
                continue;
            }
        }
        if let Some((k, _)) = tok.split_once(':')
            && SECRET_KEYS
                .iter()
                .any(|s| k.to_ascii_lowercase().contains(s))
            && tok.len() > k.len() + 1
        {
            out.push(format!("{k}:[redacted]"));
            continue;
        }
        if SECRET_FLAGS.contains(&low.as_str()) || low == "bearer" || low == "authorization:" {
            out.push(tok.to_string());
            hide_next = true;
            continue;
        }
        if is_base64ish(tok) {
            out.push("[redacted]".into());
            continue;
        }
        out.push(tok.to_string());
    }
    out.join(" ")
}

/// Kontext procesu, který nese spojení nálezu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessContext {
    pub host: String,
    pub image: String,
    pub parent_image: Option<String>,
    pub cmdline: String,
    pub user: Option<String>,
    pub signed: Option<bool>,
    pub vendor: Option<String>,
    pub hash: Option<String>,
    /// Čas spojení podle hodin agenta (epocha).
    pub connected_at: i64,
}

/// Tolerance času při párování spojení a procesu (hodiny agenta se liší, viz `estimate_skew`).
pub const BIND_WINDOW_S: i64 = 300;

/// Proces, který v okně kolem `at` navázal spojení na `peer_ip` (a případně port).
/// Spojení a proces se párují přes obraz (`image`) na témže hostu; nejnovější proces téhož obrazu
/// před spojením vyhrává. Bez shody `None` (nic se nedomýšlí).
pub fn bind_process(
    store: &EndpointStore,
    host: &str,
    peer_ip: &str,
    port: Option<u16>,
    at: i64,
    privacy: &Privacy,
) -> Option<ProcessContext> {
    let events: Vec<&EndpointEvent> = store.events_of(host).collect();
    let conn = events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::NetConnect(c)
                if c.dst_ip == peer_ip
                    && port.is_none_or(|p| p == c.dst_port)
                    && (e.ts - at).abs() <= BIND_WINDOW_S =>
            {
                Some((e.ts, c))
            }
            _ => None,
        })
        .min_by_key(|(ts, _)| (ts - at).abs())?;
    let (ts, c) = conn;
    let image = c.image.clone()?;
    let proc = events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::ProcessCreate(p) if p.image == image && e.ts <= ts + BIND_WINDOW_S => {
                Some((e.ts, p))
            }
            _ => None,
        })
        .max_by_key(|(t, _)| *t);
    Some(match proc {
        Some((_, p)) => ProcessContext {
            host: host.to_string(),
            image,
            parent_image: p.parent_image.clone(),
            cmdline: privacy.cmdline(&p.cmdline),
            user: p.user.as_deref().map(|u| privacy.user(u)),
            signed: p.signed.or(c.signed),
            vendor: p.vendor.clone().or_else(|| c.vendor.clone()),
            hash: p.hash.clone(),
            connected_at: ts,
        },
        None => ProcessContext {
            host: host.to_string(),
            image,
            parent_image: None,
            cmdline: String::new(),
            user: None,
            signed: c.signed,
            vendor: c.vendor.clone(),
            hash: None,
            connected_at: ts,
        },
    })
}

/// Položka seznamu povolených (pozitivní důkaz neškodnosti): hash binárky, výrobce, protistrana,
/// vlastník a expirace. Bez vlastníka nebo s prošlou expirací neplatí.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowEntry {
    pub hash: String,
    pub vendor: Option<String>,
    /// Povolená protistrana: IP, CIDR nebo `*` (jen s vlastníkem; `*` se nedoporučuje).
    pub peer: String,
    pub owner: String,
    /// Expirace (epocha); `0` = bez expirace se NEPŘIJÍMÁ.
    pub expires_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Allowlist {
    pub entries: Vec<AllowEntry>,
}

impl Allowlist {
    pub fn valid(e: &AllowEntry, now: i64) -> bool {
        !e.hash.is_empty() && e.hash.len() == 64 && !e.owner.trim().is_empty() && e.expires_at > now
    }

    /// Proces smí být pozitivním důkazem neškodnosti jen s podpisem, shodou hashe, výrobce
    /// a protistrany a platným vlastníkem a expirací.
    pub fn permits(&self, ctx: &ProcessContext, peer_ip: &str, now: i64) -> Option<&AllowEntry> {
        let hash = ctx.hash.as_deref()?;
        if ctx.signed != Some(true) {
            return None;
        }
        let parsed: Option<std::net::IpAddr> = peer_ip.parse().ok();
        self.entries.iter().find(|e| {
            Self::valid(e, now)
                && e.hash.eq_ignore_ascii_case(hash)
                && e.vendor
                    .as_ref()
                    .is_none_or(|v| ctx.vendor.as_ref() == Some(v))
                && (e.peer == peer_ip
                    || e.peer
                        .parse::<ipnet::IpNet>()
                        .ok()
                        .is_some_and(|n| parsed.is_some_and(|ip| n.contains(&ip))))
        })
    }
}

/// Druh uzlu grafu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Host,
    User,
    Process,
    Peer,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// rodič -> potomek
    Spawned,
    /// proces -> protistrana
    Connected,
    /// uživatel -> host
    LoggedOn,
    /// proces -> soubor
    Wrote,
    /// host -> host (laterální pohyb: přihlášení ze síťového zdroje)
    MovedTo,
    /// host -> proces
    Ran,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Počet výskytů (první výskyt `first_seen` je kill-chain návaznost).
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Graph {
    pub nodes: BTreeMap<String, Node>,
    pub edges: BTreeSet<Edge>,
    /// Meze exportu (graf se ořezává, ne roste bez hranic).
    pub truncated: bool,
}

pub const MAX_NODES: usize = 5_000;
pub const MAX_EDGES: usize = 20_000;

impl Graph {
    fn touch(&mut self, id: String, kind: NodeKind, label: &str, at: i64) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.first_seen = n.first_seen.min(at);
            n.last_seen = n.last_seen.max(at);
            n.count = n.count.saturating_add(1);
        } else if self.nodes.len() < MAX_NODES {
            self.nodes.insert(
                id.clone(),
                Node {
                    id,
                    kind,
                    label: label.chars().take(160).collect(),
                    first_seen: at,
                    last_seen: at,
                    count: 1,
                },
            );
        } else {
            self.truncated = true;
        }
    }

    fn link(&mut self, from: &str, to: &str, kind: EdgeKind, at: i64) {
        if !self.nodes.contains_key(from) || !self.nodes.contains_key(to) {
            return;
        }
        if self.edges.len() >= MAX_EDGES {
            self.truncated = true;
            return;
        }
        self.edges.insert(Edge {
            from: from.to_string(),
            to: to.to_string(),
            kind,
            at,
        });
    }

    /// Graf ze skladu událostí jednoho nebo více hostů v časovém okně.
    pub fn build(
        store: &EndpointStore,
        hosts: &[String],
        from: i64,
        to: i64,
        privacy: &Privacy,
    ) -> Self {
        let mut g = Graph::default();
        let mut seen: HashSet<(String, String, i64)> = HashSet::new();
        for host in hosts {
            let hid = format!("host:{host}");
            for e in store.events_of(host) {
                if e.ts < from || e.ts > to {
                    continue;
                }
                match &e.kind {
                    EventKind::ProcessCreate(p) => {
                        g.touch(hid.clone(), NodeKind::Host, host, e.ts);
                        let pid = format!("proc:{host}:{}", p.image);
                        g.touch(pid.clone(), NodeKind::Process, &p.image, e.ts);
                        g.link(&hid, &pid, EdgeKind::Ran, e.ts);
                        if let Some(parent) = &p.parent_image {
                            let ppid = format!("proc:{host}:{parent}");
                            g.touch(ppid.clone(), NodeKind::Process, parent, e.ts);
                            g.link(&ppid, &pid, EdgeKind::Spawned, e.ts);
                        }
                        if let Some(u) = &p.user {
                            let name = privacy.user(u);
                            let uid = format!("user:{name}");
                            g.touch(uid.clone(), NodeKind::User, &name, e.ts);
                            g.link(&uid, &pid, EdgeKind::Ran, e.ts);
                        }
                    }
                    EventKind::NetConnect(c) => {
                        g.touch(hid.clone(), NodeKind::Host, host, e.ts);
                        let image = c.image.clone().unwrap_or_else(|| "?".into());
                        let pid = format!("proc:{host}:{image}");
                        g.touch(pid.clone(), NodeKind::Process, &image, e.ts);
                        g.link(&hid, &pid, EdgeKind::Ran, e.ts);
                        let peer = format!("peer:{}:{}", c.dst_ip, c.dst_port);
                        if seen.insert((pid.clone(), peer.clone(), e.ts / 60)) {
                            g.touch(
                                peer.clone(),
                                NodeKind::Peer,
                                &format!("{}:{}", c.dst_ip, c.dst_port),
                                e.ts,
                            );
                            g.link(&pid, &peer, EdgeKind::Connected, e.ts);
                        }
                    }
                    EventKind::Logon(l) if l.success => {
                        g.touch(hid.clone(), NodeKind::Host, host, e.ts);
                        let name = privacy.user(&l.user);
                        let uid = format!("user:{name}");
                        g.touch(uid.clone(), NodeKind::User, &name, e.ts);
                        g.link(&uid, &hid, EdgeKind::LoggedOn, e.ts);
                        if let Some(src) = &l.src_ip {
                            let sid = format!("peer:{src}:0");
                            g.touch(sid.clone(), NodeKind::Peer, src, e.ts);
                            g.link(&sid, &hid, EdgeKind::MovedTo, e.ts);
                        }
                    }
                    EventKind::FileCreate { image, path } => {
                        g.touch(hid.clone(), NodeKind::Host, host, e.ts);
                        let fid = format!("file:{host}:{path}");
                        g.touch(fid.clone(), NodeKind::File, path, e.ts);
                        if let Some(i) = image {
                            let pid = format!("proc:{host}:{i}");
                            g.touch(pid.clone(), NodeKind::Process, i, e.ts);
                            g.link(&pid, &fid, EdgeKind::Wrote, e.ts);
                        }
                    }
                    _ => {}
                }
            }
        }
        g
    }

    /// Kauzální řetěz od uzlu `from` po hranách `Spawned` a `Connected` v pořadí času.
    pub fn chain(&self, from: &str) -> Vec<&Edge> {
        let mut out: Vec<&Edge> = Vec::new();
        let mut frontier = vec![from.to_string()];
        let mut visited: HashSet<String> = HashSet::new();
        while let Some(n) = frontier.pop() {
            if !visited.insert(n.clone()) || out.len() > 1000 {
                continue;
            }
            for e in &self.edges {
                if e.from == n && matches!(e.kind, EdgeKind::Spawned | EdgeKind::Connected) {
                    out.push(e);
                    frontier.push(e.to.clone());
                }
            }
        }
        out.sort_by_key(|e| e.at);
        out
    }

    /// Uzly poprvé viděné v okně `[from, to]` (první výskyt = kandidát na novost v kill chainu).
    pub fn first_seen_in(&self, from: i64, to: i64) -> Vec<&Node> {
        self.nodes
            .values()
            .filter(|n| n.first_seen >= from && n.first_seen <= to)
            .collect()
    }

    /// Export do DOT (pro `dot -Tsvg`; bez vlastního stylu).
    pub fn to_dot(&self) -> String {
        let mut s = String::from("digraph G {\n");
        for n in self.nodes.values() {
            s.push_str(&format!(
                "  \"{}\" [label=\"{}\"];\n",
                n.id.replace('"', "'"),
                n.label.replace('"', "'")
            ));
        }
        for e in &self.edges {
            s.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{:?}\"];\n",
                e.from.replace('"', "'"),
                e.to.replace('"', "'"),
                e.kind
            ));
        }
        s.push_str("}\n");
        s
    }
}

/// Nesoulad síť x agent: host s provozem v síti a mlčící agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMismatch {
    pub host: String,
    /// `blind` (agent nikdy nehlásil) nebo `silent` (hlásil a umlkl).
    pub kind: &'static str,
    pub silent_for_s: Option<i64>,
    /// Ostatní agenti ve stejnou dobu hlásí (nejde o výpadek sběru jako celku).
    pub peers_alive: bool,
}

/// Hosty, které v síti komunikují (`net_active`), ale jejich agent mlčí déle než `silent_after_s`.
/// Rozlišení „blind“ a „silent“ a příznak, že ostatní agenti žijí (tampering je pak pravděpodobnější
/// než výpadek sběru); závěr o příčině se z toho neodvozuje.
pub fn agent_mismatch(
    store: &EndpointStore,
    net_active: &[String],
    now: i64,
    silent_after_s: i64,
) -> Vec<AgentMismatch> {
    let last: HashMap<&String, i64> = store
        .hosts()
        .map(|h| (h, store.events_of(h).map(|e| e.ts).max().unwrap_or(0)))
        .collect();
    let alive = last.values().any(|t| now - *t <= silent_after_s);
    let mut out = Vec::new();
    for host in net_active {
        match last.get(host) {
            None => out.push(AgentMismatch {
                host: host.clone(),
                kind: "blind",
                silent_for_s: None,
                peers_alive: alive,
            }),
            Some(t) if now - *t > silent_after_s => out.push(AgentMismatch {
                host: host.clone(),
                kind: "silent",
                silent_for_s: Some(now - *t),
                peers_alive: alive,
            }),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests;
