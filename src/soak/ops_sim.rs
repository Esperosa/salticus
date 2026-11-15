//! Simulace provozní telemetrie pro soak (krok 14, C2; impl-krok14.md).
//!
//! Každá porucha, neškodná změna a nejednoznačný případ z katalogu nese své provozní signály
//! (`ops_signals` v `data/incident-catalog.json`), ne jen toky. Imperfekce: zdroj telemetrie
//! v síti buď existuje, nebo ne (pokrytí zdrojů, výpadek `drop_pct`), signál přijde jen s
//! pravděpodobností podle váhy (specifický 0,9, typický 0,6, slabý 0,35 za cyklus), šum
//! (nesouvisející signály), zavádějící signály u útoků (`noise > 1`) a poruchy typu mimo
//! katalog (`unknown_pct`, nesou jen anomálii bez shody).
//!
//! Přiznané omezení (impl-krok14.md, Co se předem přiznává): signály poruch generuje tatáž
//! tabulka, kterou engine porovnává; přesnost je proto horní odhad. Nezávislost zlepšuje
//! šum, výpadky, zavádějící signály a typ mimo katalog.

use std::collections::HashSet;

use crate::{
    incident_catalog::Catalog,
    ops_telemetry::{OpsSignal, OpsSource, source_of},
    soak::{
        netmodel::NetworkModel,
        rng::{Rng, derive},
        traffic::{Family, Kind, Truth},
        variants::{self, Category},
    },
};

/// Volby světa provozní telemetrie (`--ops-telemetry`, `--ops-drop`, `--ops-noise`, `--ops-unknown`).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct OpsWorld {
    pub on: bool,
    /// Další výpadek zdrojů telemetrie v procentech (na pokrytí zdrojů).
    pub drop_pct: u32,
    /// Násobek šumu; nad 1 se přidávají zavádějící signály poruch k útokům.
    pub noise: f64,
    /// Podíl poruch typu mimo katalog v procentech.
    pub unknown_pct: u32,
}

impl Default for OpsWorld {
    fn default() -> Self {
        Self {
            on: false,
            drop_pct: 0,
            noise: 1.0,
            unknown_pct: 0,
        }
    }
}

/// Základní pokrytí zdrojů v síti v procentech (volba autora; typická malá a střední síť:
/// SNMP polling a syslog bývají, DHCP a DNS logy a synthetic probes méně často).
fn base_coverage(source: OpsSource) -> u64 {
    match source {
        OpsSource::Snmp => 90,
        OpsSource::Syslog => 85,
        OpsSource::Dhcp => 80,
        OpsSource::Dns => 70,
        OpsSource::Arp => 60,
        OpsSource::Ntp => 60,
        OpsSource::Probe => 60,
    }
}

const NOISE_P: f64 = 0.002;

pub struct OpsSim {
    pub world: OpsWorld,
    seed: u64,
    covered: [bool; 7],
    all_keys: Vec<String>,
    delivered: std::collections::HashMap<u32, u32>,
}

fn idx(source: OpsSource) -> usize {
    OpsSource::ALL
        .iter()
        .position(|s| *s == source)
        .unwrap_or(0)
}

/// Signály, které nese zařízení nebo služba celé podsítě (přepínač, DHCP, směrování): jejich rozsah
/// je /24 obětí. Ostatní signály (proces, disk, paměť, certifikát) se týkají jen postiženého hosta.
const SUBNET_KEYS: &[&str] = &[
    "if_oper_down",
    "if_flap",
    "if_util_high",
    "if_out_discards",
    "qos_drop",
    "stp_tc",
    "mac_flap",
    "bcast_pps",
    "mcast_pps",
    "snmp_timeout",
    "power_fail",
    "route_adj_change",
    "sys_link_down",
    "dhcp_pool_high",
    "dhcp_no_free",
    "dhcp_service_down",
    "dhcp_no_offer",
    "dhcp_relay_missing",
    "dhcp_rogue_offer",
    "dhcp_discover_absent",
    "arp_absent",
    "dns_queries_absent",
    "sys_dhcp_snoop_viol",
    "sys_native_vlan_mismatch",
    "vlan_double_tag",
    "sys_route_null0",
    "route_default_changed",
    "sys_oos_drop",
    "conntrack_high",
    "sys_conntrack_full",
];

/// Rozsah signálu: IP postižených zařízení a u podsíťových signálů i jejich /24.
fn scope_of(devices: &[u32], ips: &[String], subnet: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in devices.iter().take(12) {
        if let Some(ip) = ips.get(*d as usize) {
            out.push(ip.clone());
        }
    }
    if subnet && let Some(first) = out.first() {
        let mut parts = first.split('.');
        if let (Some(a), Some(b), Some(c)) = (parts.next(), parts.next(), parts.next()) {
            out.push(format!("{a}.{b}.{c}.0/24"));
        }
    }
    out
}

impl OpsSim {
    pub fn new(world: OpsWorld, model: &NetworkModel) -> Self {
        let seed = derive(model.seed, 0x0B5_7E1E);
        let mut rng = Rng::new(derive(seed, 1));
        let mut covered = [false; 7];
        for s in OpsSource::ALL {
            let c = base_coverage(s) * (100 - world.drop_pct.min(100) as u64) / 100;
            covered[idx(s)] = rng.range(0, 99) < c;
        }
        let mut keys: Vec<String> = Catalog::shared()
            .incidents
            .iter()
            .flat_map(|e| e.ops_signals.iter().map(|(k, _)| k.clone()))
            .collect();
        keys.sort();
        keys.dedup();
        Self {
            world,
            seed,
            covered,
            all_keys: keys,
            delivered: Default::default(),
        }
    }

    /// Počet signálů, které událost `truth_id` doručila.
    pub fn delivered(&self, truth_id: u32) -> u32 {
        self.delivered.get(&truth_id).copied().unwrap_or(0)
    }

    pub fn covered(&self, source: OpsSource) -> bool {
        self.covered[idx(source)]
    }

    /// Zdroje, které v síti existují (pro heartbeat).
    pub fn live_sources(&self) -> Vec<OpsSource> {
        OpsSource::ALL
            .iter()
            .copied()
            .filter(|s| self.covered(*s))
            .collect()
    }

    /// Je typ poruchy této pravdy „mimo katalog“ (podle hashe id, ne podle náhody cyklu).
    fn unknown(&self, truth: &Truth) -> bool {
        self.world.unknown_pct > 0
            && derive(self.seed, 0x0DD + truth.id as u64) % 100 < self.world.unknown_pct as u64
    }

    /// Signály jednoho cyklu (čas `t0` + posun uvnitř cyklu).
    pub fn cycle(
        &mut self,
        cycle: u32,
        t0: i64,
        truths: &[Truth],
        masked: &HashSet<u32>,
        ips: &[String],
    ) -> Vec<OpsSignal> {
        let catalog = Catalog::shared();
        let mut out = Vec::new();
        let mut counts: std::collections::HashMap<u32, u32> = Default::default();
        for t in truths {
            let Kind::Attack(family) = t.kind else {
                continue;
            };
            let Family::Var(i) = family else {
                continue;
            };
            let spec = variants::spec(i);
            let mut r = Rng::new(derive(
                derive(self.seed, 0xFA17 + t.id as u64),
                cycle as u64,
            ));
            let affected: Vec<u32> = t
                .victim_devices
                .iter()
                .copied()
                .chain(t.attacker_device)
                .collect();
            let host_scope = scope_of(&affected, ips, false);
            let net_scope = scope_of(&affected, ips, true);
            if host_scope.is_empty() {
                continue;
            }
            match spec.cat {
                Category::OpsFault | Category::BenignChange => {
                    if cycle < t.start_cycle || cycle > t.end_cycle || masked.contains(&t.id) {
                        continue;
                    }
                    if self.unknown(t) {
                        // anomálie bez shody v katalogu (např. neznámá chybová zpráva)
                        if self.covered(OpsSource::Syslog) && r.chance(0.6) {
                            *counts.entry(t.id).or_default() += 1;
                            out.push(OpsSignal {
                                at: t0 + r.range(0, 59) as i64,
                                key: "sys_unclassified_error".into(),
                                value: 1.0,
                                scope: host_scope.clone(),
                            });
                        }
                        continue;
                    }
                    let Some(entry) = catalog.by_variant(spec.label) else {
                        continue;
                    };
                    for (key, w) in &entry.ops_signals {
                        if !self.covered(source_of(key)) {
                            continue;
                        }
                        let p = match w {
                            3 => 0.9,
                            2 => 0.6,
                            _ => 0.35,
                        };
                        if r.chance(p) {
                            *counts.entry(t.id).or_default() += 1;
                            out.push(OpsSignal {
                                at: t0 + r.range(0, 59) as i64,
                                key: key.clone(),
                                value: 1.0,
                                scope: if SUBNET_KEYS.contains(&key.as_str()) {
                                    net_scope.clone()
                                } else {
                                    host_scope.clone()
                                },
                            });
                        }
                    }
                }
                Category::Security => {
                    // zavádějící signály: porucha, která se k útoku jen přimíchala
                    if self.world.noise > 1.0
                        && cycle >= t.start_cycle
                        && cycle <= t.end_cycle
                        && !masked.contains(&t.id)
                        && r.chance(0.15 * (self.world.noise - 1.0).min(4.0))
                        && !self.all_keys.is_empty()
                    {
                        let key =
                            &self.all_keys[r.range(0, self.all_keys.len() as u64 - 1) as usize];
                        if self.covered(source_of(key)) {
                            out.push(OpsSignal {
                                at: t0 + r.range(0, 59) as i64,
                                key: key.clone(),
                                value: 1.0,
                                scope: host_scope.clone(),
                            });
                        }
                    }
                }
            }
        }
        for (id, n) in counts {
            *self.delivered.entry(id).or_default() += n;
        }
        // šum pozadí: nesouvisející signál na náhodném zařízení
        let mut r = Rng::new(derive(derive(self.seed, 0x1015E), cycle as u64));
        if !ips.is_empty()
            && !self.all_keys.is_empty()
            && r.chance((NOISE_P * self.world.noise * ips.len() as f64).min(0.9))
        {
            let key = &self.all_keys[r.range(0, self.all_keys.len() as u64 - 1) as usize];
            if self.covered(source_of(key)) {
                out.push(OpsSignal {
                    at: t0 + r.range(0, 59) as i64,
                    key: key.clone(),
                    value: 1.0,
                    scope: vec![ips[r.range(0, ips.len() as u64 - 1) as usize].clone()],
                });
            }
        }
        out
    }
}
