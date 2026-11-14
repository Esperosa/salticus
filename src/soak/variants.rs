//! Krok 9: svet `--coverage k9`, parametricke varianty bezpecnostnich utoku a provoznich
//! poruch na urovni pozorovatelne telemetrie (impl-krok9.md, sekce C1).
//!
//! Neni tu zadny exploit, payload ani nastroj. Varianta je radek tabulky `SPECS`
//! (protokol, port, tempo, jitter, objem, topologie, rozprostreni zdroju a casu,
//! maskovani do beznych objemu) a jeden obecny emitor vyrobi syntetické zaznamy toku
//! a IDS radky. Ground truth nese kategorii (bezpecnostni / provozni porucha /
//! neskodna zmena) a odkaz na techniku ATT&CK, aby sel sestavit krytovy prehled.
//! Vlastni proud nahody a vlastni vetev planu: ostatni svety zustavaji bajtove stejne.

use std::collections::BTreeSet;

use crate::soak::{
    netmodel::{NetworkModel, Role},
    rng::{Rng, derive},
    traffic::{
        CYCLE_SECS, CycleContext, CycleOutput, Family, Kind, Pools, Telemetry, Truth, eve_line,
        obs, public_ip, push,
    },
};

/// Kategorie pravdy (doplnek zadani kroku 9: provozni incidenty jsou rovnocenne).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Security,
    OpsFault,
    BenignChange,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Security => "security",
            Category::OpsFault => "ops_fault",
            Category::BenignChange => "benign_change",
        }
    }
}

/// Obecny tvar chovani na urovni toku.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// Pravidelny maják na pevne casove mrizce s jitterem.
    Periodic,
    /// Kratky shluk toku v nahodnem okne cyklu.
    Burst,
    /// Jeden port, mnoho cilu.
    Sweep,
    /// Jeden cil, mnoho portu.
    PortSweep,
    /// Velky pocet kratkych toku z jednoho nebo vice zdroju na jeden cil.
    Flood,
    /// Jedno dlouhe spojeni na zdroj a cyklus.
    Sustained,
    /// Male toky ze zdroje na vice vnitrnich cilu.
    FanOut,
    /// Serie kratkych (casto neuspesnych) prihlaseni.
    FailedAuth,
    /// Velky objem odchozich bajtu.
    BulkOut,
    /// Velky objem prichozich bajtu (stahovani).
    BulkIn,
    /// Velmi male toky v pravidelnem nizkem tempu.
    Trickle,
    /// Mnoho dlouhych spojeni s malym objemem.
    SlowConn,
    // --- provozni vzory ---
    /// Klienti marne opakuji spojeni na vypadly cil (S0).
    Outage,
    /// Vypadek stridave zapnuty a vypnuty (perioda v cyklech).
    Flap,
    /// Postupna degradace: podil selhani a delka toku rostou v case.
    Degrade,
    /// Broadcast bourka (mnoho toku na broadcast).
    Storm,
    /// Zaplnena linka: mnoho dlouhych velkych toku.
    Saturate,
    /// Kaskada: dalsi zavisle cile vypadavaji s odstupem (perioda = odstup v cyklech).
    Cascade,
    /// Sezonni spicka (mnoho legitimnich klientu na web).
    Peak,
    /// Drift hodin: toky hosta s posunutym casem.
    Drift,
}

/// Odkud a kam provoz jde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    /// Vnejsi zdroj na jeden vnitrni cil.
    ExtToVictim,
    /// Vnejsi zdroj na mnoho vnitrnich cilu.
    ExtToMany,
    /// Vnitrni klient na vnejsi cil.
    IntToExt,
    /// Vnitrni klient na DNS server site.
    IntToDns,
    /// Vnitrni klient na vnitrni cile.
    IntToInt,
    /// Skupina vnitrnich klientu na jeden vnejsi cil.
    FleetToExt,
    /// Provozni porucha: klienti (nahodni v kazdem cyklu) a cile poruchy.
    Fault,
}

/// Jaka zarizeni jsou potreba pro cil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    Any,
    Web,
    Plc,
    Files,
    Server,
    Dns,
    Iot,
    Vpn,
    Gateway,
}

#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub label: &'static str,
    /// ID techniky ATT&CK (Enterprise `Txxxx(.xxx)`, ICS `T08xx`), `-` u poruch.
    pub attack: &'static str,
    pub cat: Category,
    pub pattern: Pattern,
    pub actor: Actor,
    pub needs: Needs,
    pub proto: &'static str,
    pub port: u16,
    /// Zakladni pocet toku za cyklus pri intenzite 1 (u Periodic nepouzito).
    pub rate: f64,
    /// Perioda majaku v sekundach (Cascade/Flap: v cyklech).
    pub period: f64,
    pub jitter: f64,
    /// Median bajtu odchozich a prichozich na tok.
    pub ob: u64,
    pub rb: u64,
    pub dur: f64,
    pub len: (u64, u64),
    /// Pocet zdroju (pro Flood/Fleet/ExtToVictim rozprostreni).
    pub srcs: u8,
    /// Zacatek v nocnich hodinach mistniho casu.
    pub night: bool,
    /// IDS signatura (id, text), jen pri pokryti IDS.
    pub ids: Option<(u32, &'static str)>,
    /// Tvrdy zaporny scenar (krok 10): neskodny, ale tvarem podobny utoku; planuje se
    /// jen ve svete `k10` vlastnim proudem.
    pub hard: bool,
}

#[allow(clippy::too_many_arguments)]
const fn sp(
    label: &'static str,
    attack: &'static str,
    cat: Category,
    pattern: Pattern,
    actor: Actor,
    needs: Needs,
    proto: &'static str,
    port: u16,
) -> Spec {
    Spec {
        label,
        attack,
        cat,
        pattern,
        actor,
        needs,
        proto,
        port,
        rate: 20.0,
        period: 300.0,
        jitter: 0.1,
        ob: 600,
        rb: 900,
        dur: 0.5,
        len: (2, 12),
        srcs: 1,
        night: false,
        ids: None,
        hard: false,
    }
}

impl Spec {
    const fn rate(mut self, v: f64) -> Self {
        self.rate = v;
        self
    }
    const fn period(mut self, v: f64) -> Self {
        self.period = v;
        self
    }
    const fn jitter(mut self, v: f64) -> Self {
        self.jitter = v;
        self
    }
    const fn bytes(mut self, ob: u64, rb: u64) -> Self {
        self.ob = ob;
        self.rb = rb;
        self
    }
    const fn dur(mut self, v: f64) -> Self {
        self.dur = v;
        self
    }
    const fn len(mut self, a: u64, b: u64) -> Self {
        self.len = (a, b);
        self
    }
    const fn srcs(mut self, v: u8) -> Self {
        self.srcs = v;
        self
    }
    const fn night(mut self) -> Self {
        self.night = true;
        self
    }
    const fn hard(mut self) -> Self {
        self.hard = true;
        self
    }
    const fn ids(mut self, id: u32, text: &'static str) -> Self {
        self.ids = Some((id, text));
        self
    }
}

use Actor as A;
use Category::{BenignChange as BC, OpsFault as OF, Security as SE};
use Needs as N;
use Pattern as P;

/// Tabulka variant. Poradi je stabilni (index = `Family::Var`), nove radky jen na konec.
pub static SPECS: &[Spec] = &[
    // --- Reconnaissance a Discovery ---
    sp(
        "dns_zone_enum_burst",
        "T1590.002",
        SE,
        P::Burst,
        A::ExtToVictim,
        N::Dns,
        "udp",
        53,
    )
    .rate(60.0)
    .bytes(70, 500)
    .len(1, 3),
    sp(
        "snmp_sweep_ext",
        "T1046",
        SE,
        P::Sweep,
        A::ExtToMany,
        N::Any,
        "udp",
        161,
    )
    .bytes(80, 0)
    .len(1, 4)
    .ids(2011500, "ET SCAN Potential SNMP Sweep"),
    sp(
        "rdp_sweep_ext",
        "T1046",
        SE,
        P::Sweep,
        A::ExtToMany,
        N::Any,
        "tcp",
        3389,
    )
    .len(1, 4)
    .ids(2023753, "ET SCAN Potential RDP Sweep"),
    sp(
        "smb_sweep_ext",
        "T1046",
        SE,
        P::Sweep,
        A::ExtToMany,
        N::Any,
        "tcp",
        445,
    )
    .len(1, 4),
    sp(
        "distributed_low_port_probe",
        "T1595.001",
        SE,
        P::PortSweep,
        A::ExtToVictim,
        N::Server,
        "tcp",
        0,
    )
    .rate(8.0)
    .srcs(10)
    .len(8, 48),
    sp(
        "mqtt_probe_ext",
        "T1046",
        SE,
        P::Sweep,
        A::ExtToMany,
        N::Iot,
        "tcp",
        1883,
    )
    .len(1, 6),
    sp(
        "vnc_probe_ext",
        "T1021.005",
        SE,
        P::Sweep,
        A::ExtToMany,
        N::Any,
        "tcp",
        5900,
    )
    .len(1, 4),
    sp(
        "web_scanner_404_storm",
        "T1595.003",
        SE,
        P::Burst,
        A::ExtToVictim,
        N::Web,
        "tcp",
        80,
    )
    .rate(250.0)
    .bytes(300, 500)
    .len(1, 3)
    .ids(2009582, "ET SCAN Web Scanner Probe"),
    sp(
        "api_enum_distributed",
        "T1595.002",
        SE,
        P::Flood,
        A::ExtToVictim,
        N::Web,
        "tcp",
        443,
    )
    .rate(120.0)
    .srcs(20)
    .bytes(400, 1200)
    .len(2, 10),
    sp(
        "smb_share_enum_internal",
        "T1135",
        SE,
        P::Sweep,
        A::IntToInt,
        N::Server,
        "tcp",
        445,
    )
    .len(1, 4),
    sp(
        "snmp_walk_internal",
        "T1602.001",
        SE,
        P::Burst,
        A::IntToInt,
        N::Server,
        "udp",
        161,
    )
    .rate(120.0)
    .bytes(90, 1400)
    .len(1, 3),
    sp(
        "ldap_directory_enum_bulk",
        "T1087.002",
        SE,
        P::Burst,
        A::IntToInt,
        N::Server,
        "tcp",
        389,
    )
    .rate(40.0)
    .bytes(900, 60000)
    .len(1, 3),
    // --- Initial Access a Credential Access ---
    sp(
        "vpn_password_spray_slow",
        "T1110.003",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Vpn,
        "tcp",
        443,
    )
    .rate(10.0)
    .srcs(12)
    .len(12, 72),
    sp(
        "ssh_spray_slow_distributed",
        "T1110.003",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        22,
    )
    .rate(6.0)
    .srcs(10)
    .len(12, 72),
    sp(
        "rdp_bruteforce",
        "T1110.001",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        3389,
    )
    .rate(120.0)
    .len(2, 12)
    .ids(2001972, "ET POLICY RDP Brute Force Attempt"),
    sp(
        "smb_login_failures",
        "T1110",
        SE,
        P::FailedAuth,
        A::IntToInt,
        N::Server,
        "tcp",
        445,
    )
    .rate(60.0)
    .len(2, 10),
    sp(
        "ldap_bind_spray",
        "T1110.003",
        SE,
        P::FailedAuth,
        A::IntToInt,
        N::Server,
        "tcp",
        389,
    )
    .rate(40.0)
    .len(2, 12),
    sp(
        "kerberos_ticket_request_burst",
        "T1558.003",
        SE,
        P::Burst,
        A::IntToInt,
        N::Server,
        "tcp",
        88,
    )
    .rate(80.0)
    .bytes(1200, 2500)
    .len(1, 4),
    sp(
        "imap_spray",
        "T1110.003",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        993,
    )
    .rate(20.0)
    .srcs(8)
    .len(6, 48),
    sp(
        "smtp_auth_spray",
        "T1110.003",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        587,
    )
    .rate(20.0)
    .srcs(8)
    .len(6, 48),
    sp(
        "ftp_bruteforce",
        "T1110.001",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        21,
    )
    .rate(80.0)
    .len(2, 10),
    sp(
        "telnet_iot_login",
        "T1110.001",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Iot,
        "tcp",
        23,
    )
    .rate(90.0)
    .len(2, 12),
    sp(
        "mysql_login_failures",
        "T1110.001",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        3306,
    )
    .rate(70.0)
    .len(2, 10),
    sp(
        "mssql_login_failures",
        "T1110.001",
        SE,
        P::FailedAuth,
        A::ExtToVictim,
        N::Server,
        "tcp",
        1433,
    )
    .rate(70.0)
    .len(2, 10),
    sp(
        "public_app_probe_trickle",
        "T1190",
        SE,
        P::Trickle,
        A::ExtToVictim,
        N::Web,
        "tcp",
        443,
    )
    .rate(6.0)
    .bytes(900, 700)
    .len(8, 40)
    .ids(2024897, "ET WEB_SERVER Suspicious Request Pattern"),
    sp(
        "clicks_to_rare_destination",
        "T1566.002",
        SE,
        P::Burst,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(6.0)
    .bytes(900, 20000)
    .len(1, 2),
    sp(
        "drive_by_bulk_download",
        "T1189",
        SE,
        P::BulkIn,
        A::IntToExt,
        N::Any,
        "tcp",
        80,
    )
    .rate(2.0)
    .bytes(800, 4000000)
    .dur(8.0)
    .len(1, 2),
    sp(
        "vendor_remote_access_odd_hours",
        "T1199",
        SE,
        P::Sustained,
        A::ExtToVictim,
        N::Vpn,
        "tcp",
        443,
    )
    .bytes(500000, 900000)
    .night()
    .len(2, 8),
    sp(
        "update_channel_compromise_fleet",
        "T1195.002",
        SE,
        P::Periodic,
        A::FleetToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(3600.0)
    .jitter(0.2)
    .bytes(1500, 8000)
    .len(24, 200)
    .srcs(12),
    // --- Command and Control (ruzne tvary a casovani) ---
    sp(
        "c2_https_legit_service",
        "T1102",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(300.0)
    .jitter(0.3)
    .bytes(500, 900)
    .len(6, 60),
    sp(
        "c2_dns_txt_beacon",
        "T1071.004",
        SE,
        P::Periodic,
        A::IntToDns,
        N::Dns,
        "udp",
        53,
    )
    .period(90.0)
    .jitter(0.2)
    .bytes(120, 700)
    .len(6, 60),
    sp(
        "c2_doh_resolver",
        "T1572",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(30.0)
    .jitter(0.4)
    .bytes(300, 600)
    .len(6, 40),
    sp(
        "c2_icmp_tunnel",
        "T1095",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "icmp",
        0,
    )
    .period(60.0)
    .jitter(0.1)
    .bytes(300, 300)
    .len(4, 40),
    sp(
        "c2_slow_long_interval",
        "T1071.001",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(3600.0)
    .jitter(0.5)
    .bytes(400, 700)
    .len(48, 400),
    sp(
        "c2_high_jitter",
        "T1071.001",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(120.0)
    .jitter(0.8)
    .bytes(450, 800)
    .len(12, 100),
    sp(
        "c2_alt_port_8443",
        "T1571",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        8443,
    )
    .period(180.0)
    .jitter(0.15)
    .bytes(500, 900)
    .len(6, 60),
    sp(
        "c2_udp_custom_port",
        "T1095",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "udp",
        4444,
    )
    .period(120.0)
    .jitter(0.1)
    .bytes(200, 200)
    .len(6, 60),
    sp(
        "c2_cdn_fronted",
        "T1090.004",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(240.0)
    .jitter(0.25)
    .bytes(700, 1500)
    .len(6, 60),
    sp(
        "c2_websocket_long",
        "T1071.001",
        SE,
        P::Sustained,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .bytes(40000, 60000)
    .len(6, 60),
    sp(
        "c2_internal_proxy_chain",
        "T1090.001",
        SE,
        P::Periodic,
        A::IntToInt,
        N::Server,
        "tcp",
        8080,
    )
    .period(120.0)
    .jitter(0.2)
    .bytes(600, 900)
    .len(6, 40),
    sp(
        "c2_cloud_storage_dead_drop",
        "T1102.002",
        SE,
        P::Burst,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(4.0)
    .bytes(8000, 30000)
    .len(6, 48),
    sp(
        "c2_iot_mqtt_cloud",
        "T1071",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        8883,
    )
    .period(60.0)
    .jitter(0.05)
    .bytes(180, 120)
    .len(12, 120),
    sp(
        "c2_ntp_port_misuse",
        "T1095",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "udp",
        123,
    )
    .period(300.0)
    .jitter(0.2)
    .bytes(400, 400)
    .len(6, 60),
    sp(
        "onion_style_circuit_egress",
        "T1090.003",
        SE,
        P::Sustained,
        A::IntToExt,
        N::Any,
        "tcp",
        9001,
    )
    .bytes(300000, 800000)
    .len(4, 40),
    sp(
        "c2_irc_style_channel",
        "T1071",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        6667,
    )
    .period(45.0)
    .jitter(0.3)
    .bytes(120, 200)
    .len(6, 60),
    // --- Lateral Movement ---
    sp(
        "lateral_smb_admin_shares",
        "T1021.002",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        445,
    )
    .bytes(4000, 20000)
    .len(2, 8)
    .ids(2027781, "ET POLICY SMB Admin Share Access"),
    sp(
        "lateral_rdp_hop",
        "T1021.001",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        3389,
    )
    .rate(4.0)
    .bytes(30000, 90000)
    .dur(300.0)
    .len(2, 10),
    sp(
        "lateral_winrm",
        "T1021.006",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        5985,
    )
    .bytes(3000, 8000)
    .len(2, 8),
    sp(
        "lateral_ssh_hop",
        "T1021.004",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        22,
    )
    .rate(5.0)
    .bytes(6000, 12000)
    .dur(60.0)
    .len(2, 10),
    sp(
        "lateral_wmi_dcom",
        "T1047",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        135,
    )
    .bytes(1500, 3000)
    .len(2, 8),
    sp(
        "lateral_cautious_one_target",
        "T1021.002",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        445,
    )
    .rate(1.0)
    .bytes(3000, 9000)
    .len(24, 120),
    sp(
        "ntlm_relay_style_fanout",
        "T1550.002",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        445,
    )
    .rate(6.0)
    .bytes(2500, 6000)
    .len(2, 10),
    sp(
        "dc_replication_from_workstation",
        "T1003.006",
        SE,
        P::Burst,
        A::IntToInt,
        N::Server,
        "tcp",
        135,
    )
    .rate(30.0)
    .bytes(2000, 40000)
    .len(1, 3),
    // --- Collection a Exfiltration ---
    sp(
        "exfil_https_burst",
        "T1041",
        SE,
        P::BulkOut,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(3.0)
    .bytes(40000000, 20000)
    .dur(60.0)
    .len(1, 3),
    sp(
        "exfil_cloud_storage_upload",
        "T1567.002",
        SE,
        P::BulkOut,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(4.0)
    .bytes(8000000, 10000)
    .dur(120.0)
    .len(2, 8),
    sp(
        "exfil_dns_slow",
        "T1048.003",
        SE,
        P::Trickle,
        A::IntToDns,
        N::Dns,
        "udp",
        53,
    )
    .rate(30.0)
    .bytes(220, 120)
    .len(12, 120),
    sp(
        "exfil_icmp_payload",
        "T1048",
        SE,
        P::Trickle,
        A::IntToExt,
        N::Any,
        "icmp",
        0,
    )
    .rate(20.0)
    .bytes(900, 900)
    .len(6, 60),
    sp(
        "exfil_alt_protocol_ftp",
        "T1048.003",
        SE,
        P::BulkOut,
        A::IntToExt,
        N::Any,
        "tcp",
        21,
    )
    .rate(2.0)
    .bytes(15000000, 3000)
    .dur(90.0)
    .len(1, 3),
    sp(
        "exfil_scheduled_chunks",
        "T1029",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(1800.0)
    .jitter(0.05)
    .bytes(500000, 5000)
    .len(12, 100),
    sp(
        "data_staging_smb_internal",
        "T1039",
        SE,
        P::BulkIn,
        A::IntToInt,
        N::Files,
        "tcp",
        445,
    )
    .rate(3.0)
    .bytes(2000, 30000000)
    .dur(120.0)
    .len(2, 8),
    sp(
        "mail_forward_smtp_exfil",
        "T1114",
        SE,
        P::Trickle,
        A::IntToExt,
        N::Any,
        "tcp",
        25,
    )
    .rate(10.0)
    .bytes(900000, 2000)
    .len(6, 40),
    sp(
        "exfil_over_c2_trickle",
        "T1041",
        SE,
        P::Trickle,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(12.0)
    .bytes(40000, 900)
    .len(12, 100),
    sp(
        "insider_after_hours_cloud_sync",
        "T1567.002",
        SE,
        P::BulkOut,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(3.0)
    .bytes(25000000, 8000)
    .dur(180.0)
    .night()
    .len(2, 6),
    sp(
        "bucket_mass_download",
        "T1530",
        SE,
        P::BulkIn,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(6.0)
    .bytes(2000, 20000000)
    .dur(60.0)
    .len(1, 4),
    sp(
        "cloud_api_discovery_burst",
        "T1580",
        SE,
        P::Burst,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(60.0)
    .bytes(900, 3000)
    .len(1, 3),
    sp(
        "oauth_token_abuse_periodic",
        "T1528",
        SE,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(900.0)
    .jitter(0.3)
    .bytes(1200, 4000)
    .len(8, 80),
    // --- Impact ---
    sp(
        "ddos_ntp_amplification",
        "T1498.002",
        SE,
        P::Flood,
        A::ExtToVictim,
        N::Server,
        "udp",
        123,
    )
    .rate(900.0)
    .srcs(30)
    .bytes(90, 4000)
    .len(1, 4)
    .ids(2019012, "ET DOS Possible NTP DDoS Inbound"),
    sp(
        "ddos_dns_amplification",
        "T1498.002",
        SE,
        P::Flood,
        A::ExtToVictim,
        N::Dns,
        "udp",
        53,
    )
    .rate(800.0)
    .srcs(30)
    .bytes(70, 3000)
    .len(1, 4),
    sp(
        "ddos_syn_flood_distributed",
        "T1498.001",
        SE,
        P::Flood,
        A::ExtToVictim,
        N::Web,
        "tcp",
        80,
    )
    .rate(1200.0)
    .srcs(40)
    .bytes(0, 0)
    .len(1, 4),
    sp(
        "http_slow_connections_dos",
        "T1499.002",
        SE,
        P::SlowConn,
        A::ExtToVictim,
        N::Web,
        "tcp",
        80,
    )
    .rate(150.0)
    .srcs(4)
    .bytes(300, 100)
    .dur(1700.0)
    .len(2, 8),
    sp(
        "app_layer_flood_api",
        "T1499.003",
        SE,
        P::Flood,
        A::ExtToVictim,
        N::Web,
        "tcp",
        443,
    )
    .rate(700.0)
    .srcs(6)
    .bytes(900, 4000)
    .len(1, 6),
    sp(
        "share_encryption_wave_slow",
        "T1486",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Files,
        "tcp",
        445,
    )
    .rate(8.0)
    .bytes(900000, 900000)
    .dur(30.0)
    .len(4, 24),
    sp(
        "data_destruction_smb_wave",
        "T1485",
        SE,
        P::FanOut,
        A::IntToInt,
        N::Files,
        "tcp",
        445,
    )
    .rate(10.0)
    .bytes(40000, 1000)
    .len(2, 8),
    sp(
        "resource_hijack_pool_tls",
        "T1496",
        SE,
        P::Sustained,
        A::IntToExt,
        N::Any,
        "tcp",
        4433,
    )
    .bytes(200000, 700000)
    .len(24, 300),
    sp(
        "backup_service_probing",
        "T1490",
        SE,
        P::Burst,
        A::IntToInt,
        N::Server,
        "tcp",
        10000,
    )
    .rate(12.0)
    .bytes(600, 900)
    .len(1, 3),
    // --- ICS ---
    sp(
        "ics_modbus_write_burst",
        "T0836",
        SE,
        P::Burst,
        A::IntToInt,
        N::Plc,
        "tcp",
        502,
    )
    .rate(25.0)
    .bytes(40, 40)
    .len(1, 4)
    .ids(2014500, "ET SCADA Modbus Write From Unauthorized Source"),
    sp(
        "ics_s7_operating_mode_change",
        "T0858",
        SE,
        P::Burst,
        A::IntToInt,
        N::Plc,
        "tcp",
        102,
    )
    .rate(5.0)
    .bytes(80, 60)
    .len(1, 3),
    sp(
        "ics_dnp3_unsolicited_flood",
        "T0814",
        SE,
        P::Flood,
        A::IntToInt,
        N::Plc,
        "tcp",
        20000,
    )
    .rate(300.0)
    .bytes(60, 60)
    .len(1, 4),
    sp(
        "ics_opcua_enumeration",
        "T0846",
        SE,
        P::Sweep,
        A::IntToInt,
        N::Plc,
        "tcp",
        4840,
    )
    .len(1, 4),
    sp(
        "ics_bacnet_enumeration",
        "T0846",
        SE,
        P::Sweep,
        A::IntToInt,
        N::Plc,
        "udp",
        47808,
    )
    .bytes(60, 0)
    .len(1, 4),
    sp(
        "ics_ethernetip_scan",
        "T0846",
        SE,
        P::Sweep,
        A::IntToInt,
        N::Plc,
        "tcp",
        44818,
    )
    .len(1, 4),
    sp(
        "ics_slow_poll_new_source",
        "T0801",
        SE,
        P::Periodic,
        A::IntToInt,
        N::Plc,
        "tcp",
        502,
    )
    .period(60.0)
    .jitter(0.05)
    .bytes(12, 24)
    .len(12, 120),
    sp(
        "ics_program_download_slow",
        "T0843",
        SE,
        P::BulkOut,
        A::IntToInt,
        N::Plc,
        "tcp",
        102,
    )
    .rate(2.0)
    .bytes(400000, 3000)
    .dur(90.0)
    .len(1, 3),
    // --- provozni poruchy a incidenty (rovnocenna kategorie, ground truth: ops_fault) ---
    sp(
        "switch_outage_subnet",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Gateway,
        "tcp",
        443,
    )
    .rate(30.0)
    .len(2, 10),
    sp(
        "core_router_flapping",
        "-",
        OF,
        P::Flap,
        A::Fault,
        N::Gateway,
        "tcp",
        443,
    )
    .rate(30.0)
    .period(2.0)
    .len(8, 30),
    sp(
        "dhcp_pool_exhaustion",
        "-",
        OF,
        P::Storm,
        A::Fault,
        N::Any,
        "udp",
        67,
    )
    .rate(150.0)
    .len(2, 12),
    sp(
        "dhcp_server_down",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Server,
        "udp",
        67,
    )
    .rate(20.0)
    .len(2, 10),
    sp(
        "dns_partial_failure",
        "-",
        OF,
        P::Degrade,
        A::Fault,
        N::Dns,
        "udp",
        53,
    )
    .rate(80.0)
    .len(4, 24),
    sp(
        "dns_slow_resolution",
        "-",
        OF,
        P::Degrade,
        A::Fault,
        N::Dns,
        "udp",
        53,
    )
    .rate(60.0)
    .dur(4.0)
    .len(4, 24),
    sp(
        "ntp_unreachable",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Gateway,
        "udp",
        123,
    )
    .rate(6.0)
    .len(4, 24),
    sp(
        "ntp_clock_drift_host",
        "-",
        OF,
        P::Drift,
        A::Fault,
        N::Server,
        "tcp",
        443,
    )
    .rate(30.0)
    .len(6, 48),
    sp(
        "cert_expired_internal_service",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Web,
        "tcp",
        8443,
    )
    .rate(25.0)
    .len(4, 30),
    sp(
        "cert_chain_misconfig_external",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Gateway,
        "tcp",
        443,
    )
    .rate(20.0)
    .len(2, 12),
    sp(
        "uplink_saturation",
        "-",
        OF,
        P::Saturate,
        A::Fault,
        N::Gateway,
        "tcp",
        443,
    )
    .rate(25.0)
    .bytes(12000000, 60000)
    .dur(900.0)
    .len(2, 10),
    sp(
        "backup_window_overrun",
        "-",
        OF,
        P::Saturate,
        A::Fault,
        N::Files,
        "tcp",
        445,
    )
    .rate(10.0)
    .bytes(80000000, 5000)
    .dur(1500.0)
    .len(2, 8),
    sp(
        "broadcast_storm_loop",
        "-",
        OF,
        P::Storm,
        A::Fault,
        N::Any,
        "udp",
        137,
    )
    .rate(900.0)
    .len(1, 6),
    sp(
        "mdns_ssdp_storm",
        "-",
        OF,
        P::Storm,
        A::Fault,
        N::Any,
        "udp",
        1900,
    )
    .rate(500.0)
    .len(1, 6),
    sp(
        "duplicate_ip_conflict",
        "-",
        OF,
        P::Flap,
        A::Fault,
        N::Server,
        "tcp",
        445,
    )
    .rate(25.0)
    .period(1.0)
    .len(4, 20),
    sp(
        "app_server_crash_cascade",
        "-",
        OF,
        P::Cascade,
        A::Fault,
        N::Server,
        "tcp",
        8080,
    )
    .rate(25.0)
    .period(2.0)
    .len(8, 24),
    sp(
        "db_overload_degradation",
        "-",
        OF,
        P::Degrade,
        A::Fault,
        N::Files,
        "tcp",
        5432,
    )
    .rate(50.0)
    .dur(3.0)
    .len(8, 40),
    sp(
        "load_balancer_partial_outage",
        "-",
        OF,
        P::Degrade,
        A::Fault,
        N::Web,
        "tcp",
        443,
    )
    .rate(50.0)
    .len(4, 24),
    sp(
        "flapping_service",
        "-",
        OF,
        P::Flap,
        A::Fault,
        N::Server,
        "tcp",
        8080,
    )
    .rate(25.0)
    .period(1.0)
    .len(8, 30),
    sp(
        "slow_link_loss_degradation",
        "-",
        OF,
        P::Degrade,
        A::Fault,
        N::Gateway,
        "tcp",
        443,
    )
    .rate(40.0)
    .dur(5.0)
    .len(24, 120),
    sp(
        "disk_full_backup_failure",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Files,
        "tcp",
        445,
    )
    .rate(12.0)
    .len(2, 12),
    sp(
        "memory_exhaustion_stall",
        "-",
        OF,
        P::Degrade,
        A::Fault,
        N::Server,
        "tcp",
        8080,
    )
    .rate(40.0)
    .dur(8.0)
    .len(6, 36),
    sp(
        "vpn_concentrator_down",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Vpn,
        "tcp",
        443,
    )
    .rate(20.0)
    .len(2, 12),
    sp(
        "access_point_controller_failure",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Server,
        "udp",
        5246,
    )
    .rate(15.0)
    .len(2, 12),
    sp(
        "mail_relay_queue_retry",
        "-",
        OF,
        P::Outage,
        A::Fault,
        N::Gateway,
        "tcp",
        25,
    )
    .rate(15.0)
    .len(4, 24),
    sp(
        "iot_firmware_chatter_loop",
        "-",
        OF,
        P::Periodic,
        A::IntToExt,
        N::Iot,
        "tcp",
        8883,
    )
    .period(10.0)
    .jitter(0.02)
    .bytes(150, 100)
    .len(12, 120),
    sp(
        "monitoring_agent_misconfig_poll",
        "-",
        OF,
        P::Sweep,
        A::IntToInt,
        N::Server,
        "tcp",
        22,
    )
    .len(2, 12),
    // --- neskodne zmeny (kategorie benign_change) ---
    sp(
        "seasonal_peak_web",
        "-",
        BC,
        P::Peak,
        A::Fault,
        N::Web,
        "tcp",
        443,
    )
    .rate(400.0)
    .bytes(600, 15000)
    .len(4, 24),
    sp(
        "planned_maintenance_window",
        "-",
        BC,
        P::Outage,
        A::Fault,
        N::Server,
        "tcp",
        443,
    )
    .rate(20.0)
    .night()
    .len(2, 6),
    sp(
        "planned_patch_reboot_wave",
        "-",
        BC,
        P::Cascade,
        A::Fault,
        N::Server,
        "tcp",
        445,
    )
    .rate(20.0)
    .period(1.0)
    .night()
    .len(4, 10),
    // --- krok 10: tvrde zaporne scenare (neskodne, ale tvarem podobne utoku) ---
    sp(
        "hn_nightly_cloud_backup_upload",
        "-",
        BC,
        P::BulkOut,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(3.0)
    .bytes(30000000, 9000)
    .dur(180.0)
    .night()
    .len(2, 6)
    .hard(),
    sp(
        "hn_cdn_update_download",
        "-",
        BC,
        P::BulkIn,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .rate(4.0)
    .bytes(3000, 25000000)
    .dur(90.0)
    .len(1, 4)
    .hard(),
    sp(
        "hn_monitoring_snmp_sweep",
        "-",
        BC,
        P::Sweep,
        A::IntToInt,
        N::Server,
        "udp",
        161,
    )
    .rate(40.0)
    .bytes(90, 800)
    .len(1, 2)
    .hard(),
    sp(
        "hn_password_sync_periodic",
        "-",
        BC,
        P::Periodic,
        A::IntToExt,
        N::Any,
        "tcp",
        443,
    )
    .period(300.0)
    .jitter(0.1)
    .bytes(800, 1500)
    .len(24, 96)
    .hard(),
    sp(
        "hn_admin_bulk_ssh",
        "-",
        BC,
        P::FanOut,
        A::IntToInt,
        N::Server,
        "tcp",
        22,
    )
    .rate(6.0)
    .bytes(5000, 9000)
    .dur(40.0)
    .len(1, 4)
    .hard(),
    sp(
        "hn_db_replication_bulk",
        "-",
        BC,
        P::BulkIn,
        A::IntToInt,
        N::Server,
        "tcp",
        5432,
    )
    .rate(3.0)
    .bytes(2000, 40000000)
    .dur(150.0)
    .night()
    .len(2, 8)
    .hard(),
    sp(
        "hn_mail_newsletter_burst",
        "-",
        BC,
        P::Burst,
        A::IntToExt,
        N::Any,
        "tcp",
        587,
    )
    .rate(60.0)
    .bytes(30000, 900)
    .len(1, 2)
    .hard(),
    sp(
        "hn_authorized_internal_scan",
        "-",
        BC,
        P::PortSweep,
        A::IntToInt,
        N::Server,
        "tcp",
        0,
    )
    .rate(400.0)
    .len(1, 2)
    .hard(),
];

/// Pocet variant (index do `SPECS`).
pub fn count() -> usize {
    SPECS.len()
}

pub fn spec(index: u8) -> &'static Spec {
    &SPECS[index as usize]
}

/// Vzor -> typy nalezu, ktere engine umi pro dany tvar vyprodukovat.
pub fn expected_types(index: u8) -> &'static [&'static str] {
    let spec = spec(index);
    match spec.pattern {
        Pattern::Periodic => &[
            "external_flow_observed",
            "unexpected_traffic",
            "unmapped_passive_event",
            "beacon_periodic",
            "egress_ids_alert",
            "novel_persistent_peer",
        ],
        Pattern::Burst | Pattern::BulkIn => &[
            "inductive_volume_anomaly",
            "unexpected_traffic",
            "external_flow_observed",
            "packet_rate_spike",
            "suricata_alert",
            "novel_burst_peer",
            "ingest_volume_anomaly",
            "novel_bulk_transfer",
            "novel_peer_burst",
            "tls_rare_transfer",
            "tls_novel_burst",
            "dns_zone_enumeration",
        ],
        Pattern::Sweep | Pattern::PortSweep => &[
            "unexpected_traffic",
            "connection_timeout_burst",
            "external_flow_observed",
            "packet_rate_spike",
            "scan_attempts",
            "suricata_alert",
            "multi_target_pattern",
            "novel_fanout",
        ],
        Pattern::Flood | Pattern::SlowConn => &[
            "packet_rate_spike",
            "service_overload_risk",
            "connection_timeout_burst",
            "inductive_volume_anomaly",
            "suricata_alert",
            "source_volume_outlier",
        ],
        Pattern::Sustained => &[
            "external_flow_observed",
            "unexpected_traffic",
            "inductive_volume_anomaly",
            "long_lived_tunnel",
            "egress_volume_anomaly",
            "novel_persistent_peer",
        ],
        Pattern::FanOut => &[
            "unexpected_traffic",
            "multi_target_pattern",
            "connection_timeout_burst",
            "pivot_chain",
            "novel_fanout",
            "suricata_alert",
        ],
        Pattern::FailedAuth => &[
            "connection_timeout_burst",
            "packet_rate_spike",
            "unexpected_traffic",
            "suricata_alert",
            "source_volume_outlier",
            "inductive_volume_anomaly",
        ],
        Pattern::BulkOut | Pattern::Trickle => &[
            "external_flow_observed",
            "inductive_volume_anomaly",
            "unexpected_traffic",
            "egress_volume_anomaly",
            "long_lived_tunnel",
            "source_volume_outlier",
            "packet_rate_spike",
            "beacon_periodic",
            "slow_egress",
            "link_saturation",
            "novel_bulk_transfer",
            "tls_rare_transfer",
        ],
        // provozni vzory: vsechno, co engine k vypadku a degradaci umi rict
        Pattern::Outage | Pattern::Flap | Pattern::Degrade | Pattern::Cascade | Pattern::Drift => {
            &[
                "connection_timeout_burst",
                "service_unreachable",
                "unmapped_passive_event",
                "unexpected_traffic",
                "packet_rate_spike",
                "service_overload_risk",
                "inductive_volume_anomaly",
            ]
        }
        Pattern::Storm | Pattern::Saturate | Pattern::Peak => &[
            "packet_rate_spike",
            "inductive_volume_anomaly",
            "service_overload_risk",
            "unexpected_traffic",
            "connection_timeout_burst",
            "egress_volume_anomaly",
            "broadcast_storm",
            "link_saturation",
            "ingest_volume_anomaly",
        ],
    }
}

fn pool_for(needs: Needs, model: &NetworkModel, pools: &Pools) -> Vec<u32> {
    let by_role = |roles: &[Role]| -> Vec<u32> {
        model
            .devices
            .iter()
            .filter(|d| d.up && roles.contains(&d.role))
            .map(|d| d.id)
            .collect()
    };
    match needs {
        Needs::Any => pools.internal.clone(),
        Needs::Web => pools.webs.clone(),
        Needs::Plc => by_role(&[Role::Plc]),
        Needs::Files => pools.files.clone(),
        Needs::Server => pools.servers.clone(),
        Needs::Dns => vec![model.dns],
        Needs::Iot => by_role(&[Role::IotSensor, Role::Camera]),
        Needs::Vpn => {
            let v = by_role(&[Role::Vpn]);
            if v.is_empty() { pools.webs.clone() } else { v }
        }
        Needs::Gateway => vec![model.gateway],
    }
}

/// Doplni plan o varianty kroku 9 (vlastni proud). Idempotentni jen vuci jednomu volani.
pub(crate) fn plan_variants(
    model: &NetworkModel,
    pools: &Pools,
    truths: &mut Vec<Truth>,
    hours: u32,
    telemetry: &Telemetry,
    hard_only: bool,
) {
    let mut rng = Rng::new(derive(
        model.seed,
        if hard_only { 0x4B31_0001 } else { 0x4B39_0001 },
    ));
    let cycles = hours * 2;
    let days = hours as f64 / 24.0;
    let size_scale = (model.devices.len() as f64 / 60.0)
        .max(1.0)
        .powf(0.45)
        .min(4.0);
    let sec_n = if hard_only {
        0
    } else {
        (rng.poisson(2.5 * days * size_scale) as usize).min(60)
    };
    let ops_n = if hard_only {
        (rng.poisson(2.0 * days * size_scale.sqrt()) as usize).min(30)
    } else {
        (rng.poisson(1.3 * days * size_scale.sqrt()) as usize).min(30)
    };
    let plan = |security: bool, rng: &mut Rng, truths: &mut Vec<Truth>| {
        let eligible: Vec<usize> = (0..SPECS.len())
            .filter(|&i| (SPECS[i].cat == Category::Security) == security)
            .filter(|&i| SPECS[i].hard == hard_only)
            .filter(|&i| !pool_for(SPECS[i].needs, model, pools).is_empty())
            .filter(|&i| {
                // zdroj z vnitrni site potrebuje klienta
                !matches!(
                    SPECS[i].actor,
                    Actor::IntToExt | Actor::IntToDns | Actor::IntToInt | Actor::FleetToExt
                ) || !pools.clients.is_empty()
            })
            .collect();
        if eligible.is_empty() {
            return;
        }
        let index = eligible[rng.range(0, eligible.len() as u64 - 1) as usize];
        let s = &SPECS[index];
        let intensity = match rng.weighted(&[0.4, 0.4, 0.2]) {
            0 => rng.range_f(0.8, 1.0),
            1 => rng.range_f(0.4, 0.7),
            _ => rng.range_f(0.15, 0.35),
        };
        let len = (rng.range(s.len.0, s.len.1) as u32).min(cycles.max(1));
        let start = if s.night {
            let day = rng.range(0, (hours as u64 / 24).max(1) - 1) as i64;
            let hour = rng.range(0, 4) as i64;
            let secs = (-(model.tz_hours * 3600) + day * 86400 + hour * 3600)
                .rem_euclid(86400 * (hours as i64 / 24).max(1));
            ((secs / CYCLE_SECS) as u32).min(cycles - 1)
        } else {
            rng.range(0, cycles.saturating_sub(1) as u64) as u32
        };
        let end = (start + len - 1).min(cycles - 1);
        let targets = pool_for(s.needs, model, pools);
        let many = ((model.devices.len() as f64 * intensity * 0.4).ceil() as usize).clamp(3, 60);
        let mut truth = Truth {
            id: truths.len() as u32,
            kind: Kind::Attack(Family::Var(index as u8)),
            start_cycle: start,
            end_cycle: end,
            intensity,
            attacker_device: None,
            attacker_external: None,
            victim_devices: Vec::new(),
            target_external: None,
            ids_visible: s.ids.is_some() && rng.chance(telemetry.ids_coverage),
            touched_ips: BTreeSet::new(),
            cycle_targets: Default::default(),
            cycle_sources: Default::default(),
            flows_emitted: 0,
            flows_blocked: 0,
            first_emit_cycle: None,
            blocked_at_cycle: None,
            cov: Default::default(),
        };
        let pick_client = |rng: &mut Rng| *rng.pick(&pools.clients);
        match s.actor {
            Actor::ExtToVictim => {
                truth.attacker_external = Some(public_ip(rng));
                truth.victim_devices = vec![*rng.pick(&targets)];
                for _ in 1..s.srcs {
                    truth.cov.extra_external.push(public_ip(rng));
                }
            }
            Actor::ExtToMany => {
                truth.attacker_external = Some(public_ip(rng));
                let n = many.min(targets.len());
                truth.victim_devices = rng
                    .sample_distinct(targets.len(), n)
                    .into_iter()
                    .map(|p| targets[p])
                    .collect();
            }
            Actor::IntToExt => {
                truth.attacker_device = Some(pick_client(rng));
                truth.target_external = Some(public_ip(rng));
            }
            Actor::IntToDns => {
                truth.attacker_device = Some(pick_client(rng));
                truth.victim_devices = vec![model.dns];
            }
            Actor::IntToInt => {
                // ICS: zdroj vnitrni (klient) i u PLC cilu
                let attacker = pick_client(rng);
                truth.attacker_device = Some(attacker);
                let n = if s.needs == Needs::Plc {
                    many.min(targets.len()).min(3)
                } else {
                    many.min(targets.len())
                };
                truth.victim_devices = rng
                    .sample_distinct(targets.len(), n)
                    .into_iter()
                    .map(|p| targets[p])
                    .filter(|d| *d != attacker)
                    .collect();
                if truth.victim_devices.is_empty() {
                    return;
                }
            }
            Actor::FleetToExt => {
                let n = (s.srcs as usize).clamp(2, pools.clients.len().max(2));
                let picks = rng.sample_distinct(pools.clients.len(), n.min(pools.clients.len()));
                let mut it = picks.into_iter().map(|p| pools.clients[p]);
                truth.attacker_device = it.next();
                truth.cov.extra_devices = it.collect();
                truth.target_external = Some(public_ip(rng));
            }
            Actor::Fault => {
                let mut victims = if s.pattern == Pattern::Cascade {
                    rng.sample_distinct(targets.len(), targets.len().min(3))
                        .into_iter()
                        .map(|p| targets[p])
                        .collect::<Vec<u32>>()
                } else {
                    vec![*rng.pick(&targets)]
                };
                victims.sort_unstable();
                truth.victim_devices = victims;
            }
        }
        if truth.attacker_device.is_none() && s.actor != Actor::Fault {
            // vnejsi zdroj uz je nastaven
        }
        truths.push(truth);
    };
    for _ in 0..sec_n {
        plan(true, &mut rng, truths);
    }
    for _ in 0..ops_n {
        plan(false, &mut rng, truths);
    }
}

/// Emise jedne variantny v jednom cyklu. Vola se z `emit_truth`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit(
    truth: &Truth,
    index: u8,
    ctx: &CycleContext<'_>,
    t0: i64,
    flow_id: &mut u64,
    rng: &mut Rng,
    out: &mut CycleOutput,
    truths: &mut [Truth],
    truth_index: usize,
) {
    let s = spec(index);
    let ips = ctx.ips;
    let intensity = truth.intensity;
    let scale = 0.2 + 0.8 * intensity;
    let n = ((s.rate * scale).round() as u64).max(1);
    let cyc = ctx.cycle.saturating_sub(truth.start_cycle) as f64;
    let len = (truth.end_cycle - truth.start_cycle + 1) as f64;
    let at = |rng: &mut Rng| t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
    let ip_of = |d: u32| ips[d as usize].clone();

    // zdroje: hlavni utocnik + dalsi vnitrni/vnejsi
    let mut sources: Vec<String> = Vec::new();
    if let Some(d) = truth.attacker_device {
        sources.push(ip_of(d));
    }
    if let Some(e) = &truth.attacker_external {
        sources.push(e.clone());
    }
    sources.extend(truth.cov.extra_devices.iter().map(|d| ip_of(*d)));
    sources.extend(truth.cov.extra_external.iter().cloned());
    let victim_ips: Vec<String> = truth.victim_devices.iter().map(|d| ip_of(*d)).collect();
    let dest_one: Option<String> = truth
        .target_external
        .clone()
        .or_else(|| victim_ips.first().cloned());
    let port = s.port;
    let proto = s.proto;
    let jitter_bytes = |rng: &mut Rng, median: u64| -> u64 {
        if median == 0 {
            0
        } else {
            rng.lognormal(median as f64, 0.5) as u64
        }
    };
    let emit_flow = |out: &mut CycleOutput,
                     rng: &mut Rng,
                     when: i64,
                     src: &str,
                     dst: &str,
                     dport: u16,
                     dur: f64,
                     ob: u64,
                     rb: u64,
                     state: &str,
                     truths: &mut [Truth]| {
        let sport = rng.range(32768, 60999) as u16;
        push(
            out,
            ctx,
            obs(when, src, sport, dst, proto, dport, dur, ob, rb, state),
            Some(truth_index),
            truths,
        );
    };

    if s.actor == Actor::Fault {
        emit_fault(
            s,
            truth,
            ctx,
            t0,
            n,
            cyc,
            len,
            rng,
            out,
            truths,
            truth_index,
        );
        return;
    }

    match s.pattern {
        Pattern::Periodic => {
            let (Some(dst),) = (dest_one.clone(),) else {
                return;
            };
            let period = s.period.max(5.0) as i64;
            let phase = (derive(truth.id as u64, 0x9E1) % period as u64) as i64;
            // mrizka v absolutnim case, aby periodicita prezila hranice cyklu
            let mut t = t0 + (phase - t0).rem_euclid(period);
            while t < t0 + CYCLE_SECS {
                let jit = ((rng.f64() * 2.0 - 1.0) * s.jitter * period as f64) as i64;
                let when = (t + jit).clamp(t0, t0 + CYCLE_SECS - 1);
                for src in &sources {
                    let (ob, rb) = (jitter_bytes(rng, s.ob), jitter_bytes(rng, s.rb));
                    emit_flow(out, rng, when, src, &dst, port, s.dur, ob, rb, "SF", truths);
                }
                t += period;
            }
        }
        Pattern::Burst | Pattern::Trickle => {
            let Some(dst) = dest_one.clone() else { return };
            let dsts: Vec<String> = if victim_ips.len() > 1 {
                victim_ips.clone()
            } else {
                vec![dst]
            };
            let width = if s.pattern == Pattern::Burst {
                240
            } else {
                1700
            };
            let begin = t0 + rng.range(0, (CYCLE_SECS - width).max(1) as u64 - 1) as i64;
            for _ in 0..n {
                let when = begin + rng.range(0, width as u64 - 1) as i64;
                let src = &sources[rng.range(0, sources.len() as u64 - 1) as usize];
                let d = &dsts[rng.range(0, dsts.len() as u64 - 1) as usize];
                let (ob, rb) = (jitter_bytes(rng, s.ob), jitter_bytes(rng, s.rb));
                emit_flow(out, rng, when, src, d, port, s.dur, ob, rb, "SF", truths);
            }
        }
        Pattern::Sweep => {
            for d in &victim_ips {
                if rng.chance(0.3 + intensity * 0.7) {
                    let state = if rng.chance(0.7) { "S0" } else { "SF" };
                    let (ob, rb) = if state == "S0" {
                        (0, 0)
                    } else {
                        (s.ob.max(60), s.rb)
                    };
                    let when = at(rng);
                    emit_flow(
                        out,
                        rng,
                        when,
                        &sources[0],
                        d,
                        port,
                        0.0,
                        ob,
                        rb,
                        state,
                        truths,
                    );
                }
            }
        }
        Pattern::PortSweep => {
            let Some(d) = victim_ips.first() else { return };
            for p in rng.sample_distinct(65535, n as usize) {
                let state = if rng.chance(0.9) { "S0" } else { "S1" };
                let when = at(rng);
                let src = &sources[rng.range(0, sources.len() as u64 - 1) as usize];
                emit_flow(
                    out,
                    rng,
                    when,
                    src,
                    d,
                    p as u16 + 1,
                    0.0,
                    0,
                    0,
                    state,
                    truths,
                );
            }
        }
        Pattern::Flood | Pattern::SlowConn => {
            let Some(d) = victim_ips.first() else { return };
            for _ in 0..n {
                let when = at(rng);
                let src = &sources[rng.range(0, sources.len() as u64 - 1) as usize];
                let slow = s.pattern == Pattern::SlowConn;
                let state = if slow {
                    "S1"
                } else {
                    match rng.weighted(&[0.6, 0.3, 0.1]) {
                        0 => "SF",
                        1 => "S0",
                        _ => "RSTO",
                    }
                };
                let dur = if slow {
                    s.dur * rng.range_f(0.5, 1.0)
                } else {
                    s.dur * 0.2
                };
                let (ob, rb) = if state == "S0" {
                    (0, 0)
                } else {
                    (jitter_bytes(rng, s.ob), jitter_bytes(rng, s.rb))
                };
                emit_flow(out, rng, when, src, d, port, dur, ob, rb, state, truths);
            }
        }
        Pattern::Sustained => {
            let Some(dst) = dest_one.clone() else { return };
            for src in &sources {
                let (ob, rb) = (jitter_bytes(rng, s.ob), jitter_bytes(rng, s.rb));
                emit_flow(out, rng, t0, src, &dst, port, 1700.0, ob, rb, "S1", truths);
            }
        }
        Pattern::FanOut => {
            for d in &victim_ips {
                if rng.chance(0.25 + intensity * 0.6) {
                    for _ in 0..rng.range(1, (n / 3).max(2)) {
                        let (ob, rb) = (jitter_bytes(rng, s.ob), jitter_bytes(rng, s.rb));
                        let when = at(rng);
                        emit_flow(
                            out,
                            rng,
                            when,
                            &sources[0],
                            d,
                            port,
                            s.dur,
                            ob,
                            rb,
                            "SF",
                            truths,
                        );
                    }
                }
            }
        }
        Pattern::FailedAuth => {
            let Some(d) = victim_ips.first() else { return };
            for _ in 0..n {
                let when = at(rng);
                let src = &sources[rng.range(0, sources.len() as u64 - 1) as usize];
                let state = match rng.weighted(&[0.5, 0.3, 0.2]) {
                    0 => "RSTO",
                    1 => "S1",
                    _ => "SF",
                };
                let (ob, rb) = (rng.range(100, 500), rng.range(80, 400));
                let dur = rng.range_f(0.2, 2.0);
                emit_flow(out, rng, when, src, d, port, dur, ob, rb, state, truths);
            }
        }
        Pattern::BulkOut | Pattern::BulkIn => {
            let Some(dst) = dest_one.clone() else { return };
            for _ in 0..rng.range(1, n.max(1)) {
                let when = at(rng);
                let (ob, rb) = (
                    jitter_bytes(rng, (s.ob as f64 * scale) as u64),
                    jitter_bytes(rng, (s.rb as f64 * scale) as u64),
                );
                let dur = s.dur * rng.range_f(0.6, 1.4);
                emit_flow(
                    out,
                    rng,
                    when,
                    &sources[0],
                    &dst,
                    port,
                    dur,
                    ob,
                    rb,
                    "SF",
                    truths,
                );
            }
        }
        _ => {}
    }
    if truth.ids_visible
        && let (Some((sid, text)), Some(src), Some(dst)) = (
            s.ids,
            sources.first(),
            dest_one.or_else(|| victim_ips.first().cloned()),
        )
    {
        let when = at(rng);
        *flow_id += 1;
        out.alerts.push(eve_line(
            when, *flow_id, src, 40100, &dst, port, sid, text, 2,
        ));
    }
}

/// Provozni porucha: klienti (nahodni v kazdem cyklu) proti cilum poruchy.
#[allow(clippy::too_many_arguments)]
fn emit_fault(
    s: &Spec,
    truth: &Truth,
    ctx: &CycleContext<'_>,
    t0: i64,
    n: u64,
    cyc: f64,
    len: f64,
    rng: &mut Rng,
    out: &mut CycleOutput,
    truths: &mut [Truth],
    truth_index: usize,
) {
    let ips = ctx.ips;
    let model = ctx.model;
    let clients: Vec<u32> = model
        .devices
        .iter()
        .filter(|d| d.up && !d.role.is_server() && !matches!(d.role, Role::Gateway | Role::Dns))
        .map(|d| d.id)
        .collect();
    if clients.is_empty() && s.actor == Actor::Fault {
        return;
    }
    let at = |rng: &mut Rng| t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
    let flow = |out: &mut CycleOutput,
                rng: &mut Rng,
                when: i64,
                src: &str,
                dst: &str,
                dport: u16,
                proto: &str,
                dur: f64,
                ob: u64,
                rb: u64,
                state: &str,
                truths: &mut [Truth]| {
        let sport = rng.range(32768, 60999) as u16;
        push(
            out,
            ctx,
            obs(when, src, sport, dst, proto, dport, dur, ob, rb, state),
            Some(truth_index),
            truths,
        );
    };
    let victims: Vec<String> = truth
        .victim_devices
        .iter()
        .map(|d| ips[*d as usize].clone())
        .collect();
    if victims.is_empty() {
        return;
    }
    let port = s.port;
    let proto = s.proto;
    let progress = ((cyc + 1.0) / len).clamp(0.0, 1.0);
    let pick = |rng: &mut Rng| {
        ips[clients[rng.range(0, clients.len() as u64 - 1) as usize] as usize].clone()
    };
    match s.pattern {
        Pattern::Outage | Pattern::Flap | Pattern::Cascade => {
            // Flap: stridani okna zap/vyp po `period` cyklech; Cascade: dalsi cil po odstupu
            let phase_on = match s.pattern {
                Pattern::Flap => ((cyc / s.period.max(1.0)) as u64) % 2 == 0,
                _ => true,
            };
            if !phase_on {
                return;
            }
            for (i, v) in victims.iter().enumerate() {
                if s.pattern == Pattern::Cascade && cyc < i as f64 * s.period {
                    continue;
                }
                for _ in 0..n {
                    let when = at(rng);
                    let src = pick(rng);
                    let state = if s.port == 8443 || s.port == 443 && rng.chance(0.3) {
                        "RSTO"
                    } else {
                        "S0"
                    };
                    flow(
                        out, rng, when, &src, v, port, proto, 0.0, 0, 0, state, truths,
                    );
                }
            }
        }
        Pattern::Degrade => {
            for _ in 0..n {
                let when = at(rng);
                let src = pick(rng);
                let v = &victims[0];
                if rng.chance(progress.max(0.25) * 0.6) {
                    flow(
                        out, rng, when, &src, v, port, proto, 0.0, 0, 0, "S0", truths,
                    );
                } else {
                    let dur = s.dur * (0.5 + progress * 3.0) * rng.range_f(0.5, 1.5);
                    let (ob, rb) = (
                        rng.lognormal(700.0, 1.0) as u64,
                        rng.lognormal(9000.0, 1.4) as u64,
                    );
                    flow(
                        out, rng, when, &src, v, port, proto, dur, ob, rb, "SF", truths,
                    );
                }
            }
        }
        Pattern::Storm => {
            let sources: Vec<String> = (0..3).map(|_| pick(rng)).collect();
            for _ in 0..n {
                let when = at(rng);
                let src = &sources[rng.range(0, 2) as usize];
                flow(
                    out,
                    rng,
                    when,
                    src,
                    "255.255.255.255",
                    port,
                    proto,
                    0.0,
                    90,
                    0,
                    "S0",
                    truths,
                );
            }
        }
        Pattern::Saturate => {
            let target = victims[0].clone();
            let external = ctx.model.externals
                [rng.range(0, ctx.model.externals.len() as u64 - 1) as usize]
                .clone();
            let to_ext = s.needs == Needs::Gateway;
            for _ in 0..n {
                let when = at(rng);
                let src = pick(rng);
                let dst = if to_ext { &external } else { &target };
                let ob = rng.lognormal(s.ob as f64, 0.5) as u64;
                let rb = rng.lognormal(s.rb as f64, 0.5) as u64;
                let dur = s.dur * rng.range_f(0.5, 1.0);
                flow(
                    out, rng, when, &src, dst, port, proto, dur, ob, rb, "SF", truths,
                );
            }
        }
        Pattern::Peak => {
            let v = &victims[0];
            for _ in 0..n {
                let when = at(rng);
                let client = public_ip(rng);
                let (ob, rb) = (
                    rng.lognormal(s.ob as f64, 0.8) as u64,
                    rng.lognormal(s.rb as f64, 1.2) as u64,
                );
                let dur = rng.lognormal(0.4, 1.0);
                flow(
                    out, rng, when, &client, v, port, proto, dur, ob, rb, "SF", truths,
                );
            }
        }
        Pattern::Drift => {
            let v = &victims[0];
            let drift = (progress * 1500.0) as i64;
            for _ in 0..n {
                let when = (at(rng) + drift - 750).clamp(t0, t0 + CYCLE_SECS - 1);
                let src = pick(rng);
                let (ob, rb) = (
                    rng.lognormal(700.0, 1.0) as u64,
                    rng.lognormal(9000.0, 1.4) as u64,
                );
                flow(
                    out, rng, when, &src, v, port, proto, 0.5, ob, rb, "SF", truths,
                );
            }
        }
        _ => {}
    }
}

/// Tabulka rodin pro pokryti (TSV): zakladni rodiny a varianty kroku 9.
/// Sloupce: label, kategorie, ATT&CK, vzor, smer, protokol, port, ocekavane typy.
pub fn families_tsv() -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "label	category	attack	pattern	actor	proto	port	expected_types	tactic	tempo	volume	topology	sources	port_class
",
    );
    for family in Family::ALL {
        let f = base_features(family.label());
        let _ = writeln!(
            out,
            "{}	security		base				{}	{}	{}	{}	{}	{}	{}",
            family.label(),
            family.expected_types().join(","),
            f.tactic,
            f.tempo,
            f.volume,
            f.topology,
            f.sources,
            f.port_class
        );
    }
    for (i, s) in SPECS.iter().enumerate() {
        let f = features(s);
        let _ = writeln!(
            out,
            "{}	{}	{}	{:?}	{:?}	{}	{}	{}	{}	{}	{}	{}	{}	{}",
            s.label,
            s.cat.label(),
            s.attack,
            s.pattern,
            s.actor,
            s.proto,
            s.port,
            expected_types(i as u8).join(","),
            f.tactic,
            f.tempo,
            f.volume,
            f.topology,
            f.sources,
            f.port_class
        );
    }
    out
}

/// Abstraktni rysy chování (slovniky `analyst_feedback`): zadna adresa, seed ani sit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Features {
    pub tactic: &'static str,
    pub tempo: &'static str,
    pub volume: &'static str,
    pub topology: &'static str,
    pub sources: &'static str,
    pub port_class: &'static str,
}

/// Taktika ATT&CK podle ID techniky (tabulka studie 09 plus doplnek pro ICS a nadrazene ID).
pub fn tactic_of(attack: &str) -> &'static str {
    static TABLE: &str = include_str!("../../docs/diplomka/studie/09-attack-technik.txt");
    if attack == "-" || attack.is_empty() {
        return "none";
    }
    let lookup = |id: &str| -> Option<&'static str> {
        TABLE.lines().find_map(|line| {
            let mut cols = line.split('\t');
            (cols.next() == Some(id)).then(|| cols.next()).flatten()
        })
    };
    let raw = lookup(attack).or_else(|| lookup(attack.split('.').next().unwrap_or(attack)));
    match raw {
        Some("defense-impairment") | Some("stealth") => "defense-evasion",
        Some(t) => TACTICS_CANON
            .iter()
            .copied()
            .find(|c| *c == t)
            .unwrap_or("none"),
        None => match attack.split('.').next().unwrap_or(attack) {
            "T0801" => "collection",
            "T0814" | "T0836" | "T1485" | "T1490" | "T1499" => "impact",
            "T0843" | "T0858" | "T1047" => "execution",
            "T0846" | "T1580" => "discovery",
            "T1048" => "exfiltration",
            "T1071" | "T1102" => "command-and-control",
            "T1114" => "collection",
            "T1195" => "initial-access",
            "T1590" => "reconnaissance",
            _ => "none",
        },
    }
}

const TACTICS_CANON: &[&str] = &[
    "reconnaissance",
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

pub fn features(s: &Spec) -> Features {
    let tempo = match s.pattern {
        Pattern::Periodic if s.period <= 600.0 => "periodic_fast",
        Pattern::Periodic => "periodic_slow",
        Pattern::Burst | Pattern::Flood | Pattern::Storm | Pattern::Peak | Pattern::BulkOut | Pattern::BulkIn => "burst",
        Pattern::Sustained | Pattern::SlowConn | Pattern::Saturate => "sustained",
        Pattern::Trickle => "trickle",
        _ => "instant",
    };
    let per_cycle = (s.ob + s.rb) as f64 * s.rate.max(1.0);
    let volume = match per_cycle {
        v if v < 1.0e5 => "tiny",
        v if v < 1.0e7 => "small",
        v if v < 1.0e8 => "medium",
        v if v < 1.0e9 => "large",
        _ => "huge",
    };
    let topology = match (s.pattern, s.actor) {
        (Pattern::Sweep | Pattern::FanOut, _) | (_, Actor::ExtToMany) => "one_to_many",
        (_, Actor::FleetToExt) => "many_to_one",
        (Pattern::Flood, _) if s.srcs > 1 => "many_to_one",
        (_, Actor::IntToInt) => "internal_chain",
        _ if s.srcs > 1 => "many_to_one",
        _ => "one_to_one",
    };
    let sources = match s.srcs {
        0 | 1 => "1",
        2..=5 => "few",
        _ => "many",
    };
    let proto = if s.proto == "icmp" { "icmp" } else { s.proto };
    Features {
        tactic: tactic_of(s.attack),
        tempo,
        volume,
        topology,
        sources,
        port_class: crate::analyst_feedback::port_class(proto, s.port),
    }
}

/// Rysy puvodnich osmnacti rodin (ruční tabulka; rodiny nemaji `Spec`).
pub fn base_features(label: &str) -> Features {
    let f = |tactic, tempo, volume, topology, sources, port_class| Features {
        tactic,
        tempo,
        volume,
        topology,
        sources,
        port_class,
    };
    match label {
        "port_scan_vertical" | "slow_scan" => f("discovery", "burst", "small", "one_to_one", "1", "high"),
        "port_scan_horizontal" => f("discovery", "burst", "small", "one_to_many", "1", "other"),
        "ssh_bruteforce" | "credential_stuffing" => f("credential-access", "burst", "small", "one_to_one", "few", "remote_admin"),
        "c2_beacon" | "fleet_beacon" => f("command-and-control", "periodic_fast", "tiny", "one_to_one", "1", "web"),
        "dns_tunnel" => f("command-and-control", "sustained", "small", "one_to_one", "1", "dns"),
        "exfiltration" | "insider_hoarding" => f("exfiltration", "burst", "huge", "one_to_one", "1", "web"),
        "ddos_volume" => f("impact", "burst", "large", "many_to_one", "many", "web"),
        "cryptomining" => f("impact", "sustained", "small", "one_to_one", "1", "high"),
        "lateral_movement" => f("lateral-movement", "burst", "small", "internal_chain", "1", "remote_admin"),
        "ransomware" => f("impact", "burst", "large", "one_to_many", "1", "file_share"),
        "rogue_device" => f("initial-access", "instant", "tiny", "one_to_one", "1", "other"),
        "exploit_attempt" | "web_exploit" => f("initial-access", "instant", "tiny", "one_to_one", "1", "web"),
        "ics_attack" => f("impact", "burst", "tiny", "one_to_one", "1", "ics"),
        "apt_chain" => f("lateral-movement", "sustained", "medium", "internal_chain", "1", "remote_admin"),
        _ => f("none", "instant", "tiny", "one_to_one", "1", "other"),
    }
}

/// Je tvar vzoru "provozni" (porucha nebo zmena), ne utok.
pub fn is_ops(index: u8) -> bool {
    spec(index).cat != Category::Security
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soak::{
        coverage::{CoverageMode, plan_coverage},
        traffic::{NoBlocks, generate_cycle, no_mask, plan_episode, seed_for_cycle},
    };

    fn telemetry() -> Telemetry {
        Telemetry {
            drop_p: 0.0,
            dup_p: 0.0,
            skew_s: 0,
            outage_p: 0.0,
            ids_coverage: 1.0,
            blind_subnets: Vec::new(),
        }
    }

    #[test]
    fn table_is_large_and_labels_unique() {
        assert!(SPECS.len() >= 100, "{}", SPECS.len());
        assert!(SPECS.len() <= 255);
        let mut seen = std::collections::HashSet::new();
        for (i, s) in SPECS.iter().enumerate() {
            assert!(seen.insert(s.label), "duplicitni {}", s.label);
            assert!(s.attack == "-" || s.attack.starts_with('T'), "{}", s.attack);
            assert_eq!(
                (s.cat != Category::Security),
                s.attack == "-",
                "{}",
                s.label
            );
            assert!(!expected_types(i as u8).is_empty());
            assert!(s.len.0 >= 1 && s.len.0 <= s.len.1);
        }
    }

    #[test]
    fn variants_only_in_k9_and_most_emit_flows_deterministically() {
        let mut emitted: BTreeSet<u8> = BTreeSet::new();
        let mut planned: BTreeSet<u8> = BTreeSet::new();
        for id in 0..80u64 {
            let model = NetworkModel::generate(20269901, id);
            let ips: Vec<String> = (0..model.devices.len() as u32)
                .map(|d| model.ip_of(d))
                .collect();
            let mut rng = Rng::new(id);
            let base = plan_episode(&model, &mut rng, 168, &telemetry());
            let mut k7 = base.clone();
            plan_coverage(&model, &mut k7, 168, &telemetry(), CoverageMode::K7);
            assert!(
                !k7.iter()
                    .any(|t| matches!(t.kind, Kind::Attack(Family::Var(_))))
            );
            let mut run = |truths: &mut Vec<Truth>| -> Vec<u64> {
                for cycle in 0..336u32 {
                    let ctx = CycleContext {
                        model: &model,
                        ips: &ips,
                        cycle,
                        start_offset_s: 0,
                        telemetry: &telemetry(),
                        oracle: &NoBlocks,
                        rogue: None,
                        scan_now: false,
                        masked: no_mask(),
                        regular: &[],
                    };
                    let mut rng = Rng::new(seed_for_cycle(model.seed, cycle));
                    generate_cycle(&ctx, truths, &mut rng);
                }
                truths.iter().map(|t| t.flows_emitted).collect()
            };
            let mut a = base.clone();
            plan_coverage(&model, &mut a, 168, &telemetry(), CoverageMode::K9);
            let mut b = a.clone();
            for (i, t) in a.iter().enumerate() {
                assert_eq!(t.id as usize, i);
                assert!(t.start_cycle <= t.end_cycle && t.end_cycle < 336);
            }
            let fa = run(&mut a);
            let fb = run(&mut b);
            assert_eq!(fa, fb, "determinismus");
            for (t, flows) in a.iter().zip(fa) {
                if let Kind::Attack(Family::Var(v)) = t.kind {
                    planned.insert(v);
                    if flows > 0 {
                        emitted.insert(v);
                    }
                }
            }
        }
        let missing: Vec<&str> = (0..SPECS.len() as u8)
            .filter(|v| !emitted.contains(v))
            .map(|v| spec(v).label)
            .collect();
        assert!(
            missing.len() <= SPECS.len() / 10,
            "nevyemitovane varianty: {missing:?} (planovano {})",
            planned.len()
        );
    }

    #[test]
    fn hard_negatives_only_in_k10_and_k9_plan_is_unchanged() {
        let mut hard_seen = 0;
        for id in 0..30u64 {
            let model = NetworkModel::generate(20269902, id);
            let mut rng = Rng::new(id);
            let base = plan_episode(&model, &mut rng, 168, &telemetry());
            let mut k9 = base.clone();
            plan_coverage(&model, &mut k9, 168, &telemetry(), CoverageMode::K9);
            let mut k10 = base.clone();
            plan_coverage(&model, &mut k10, 168, &telemetry(), CoverageMode::K10);
            let is_hard = |t: &Truth| matches!(t.kind, Kind::Attack(Family::Var(v)) if spec(v).hard);
            assert!(!k9.iter().any(is_hard), "k9 nesmi mit tvrde zaporne");
            let non_hard: Vec<_> = k10.iter().filter(|t| !is_hard(t)).collect();
            assert_eq!(non_hard.len(), k9.len(), "k10 = k9 + tvrde zaporne");
            for (a, b) in non_hard.iter().zip(k9.iter()) {
                assert_eq!((a.start_cycle, a.end_cycle), (b.start_cycle, b.end_cycle));
            }
            hard_seen += k10.iter().filter(|t| is_hard(t)).count();
        }
        assert!(hard_seen > 0);
    }
}
