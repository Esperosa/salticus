//! Krok 22 (B5): svět simulace v2 (`--world-v2`). Kalendář provozu je **příčina**
//! neškodných jevů, ne jejich popis: generátor nejdřív podle rolí sítě naplánuje úlohy
//! (záloha, autorizovaný sken, dávka, patch okno), z nich vzniknou neškodné jevy a záznamy
//! kontextu s nedokonalostí zapsanou předem (`docs/diplomka/eval/impl-krok22.md`, 5.2).
//! Útoky se plánují nezávisle (stejný proud jako ve v1); malý předem daný podíl útoků
//! vychází z infrastruktury (kompromitace zálohovacího serveru nebo skeneru) v jejím okně.

use std::collections::BTreeSet;

use chrono::{Datelike, Weekday};

use crate::{
    context_gate::ContextKind,
    soak::{
        netmodel::{NetworkModel, Role},
        rng::{Rng, derive},
        traffic::{CYCLE_SECS, EPOCH0, Family, Kind, Lookalike, Truth, public_ip, ts},
    },
};

/// Podíly nedokonalosti kalendáře (předregistrace 5.2, ne laděno).
pub const NO_RECORD: f64 = 0.10;
pub const CANCELLED: f64 = 0.05;
pub const SHIFTED: f64 = 0.05;
/// Posun záznamu o ± 1 h.
pub const SHIFT_CYCLES: u32 = 2;
/// Podíl útoků vybraných rodin z infrastruktury.
pub const INFRA_SHARE: f64 = 0.02;
/// Mimořádné patch okno: pravděpodobnost za týden.
pub const EXTRA_PATCH_PER_WEEK: f64 = 0.1;

/// Druhy jevů, které ve v2 vznikají jen z kalendáře.
pub fn calendar_kind(look: Lookalike) -> bool {
    matches!(
        look,
        Lookalike::Backup
            | Lookalike::AuthorizedScanner
            | Lookalike::BatchJob
            | Lookalike::PatchWindow
    )
}

/// Záznam kalendáře. Zařízení se na adresy převádějí až v cyklu (kalendář vede CMDB).
#[derive(Debug, Clone)]
pub struct CalRecord {
    pub kind: ContextKind,
    pub host_devices: Vec<u32>,
    /// Rozsah zadaný adresou nebo CIDR (skener: podsítě a vnější cíle).
    pub host_nets: Vec<String>,
    pub source_devices: Vec<u32>,
    pub source_external: Vec<String>,
    /// Okno práce v cyklech (včetně); deklarované okno je o cyklus širší (`SimContext`).
    pub start: u32,
    pub end: u32,
}

/// Čítače světa pro validitu (V1, V2).
#[derive(Debug, Clone, Default)]
pub struct CalStats {
    pub jobs: u64,
    pub recorded: u64,
    pub cancelled: u64,
    pub shifted: u64,
    pub infra_attacks: u64,
    pub attacks: u64,
    pub attacks_in_window: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CalendarPlan {
    pub records: Vec<CalRecord>,
    pub stats: CalStats,
    pub backup_server: Option<u32>,
    pub scanner: Option<u32>,
}

struct Job {
    look: Lookalike,
    kind: ContextKind,
    source: Option<u32>,
    victims: Vec<u32>,
    host_nets: Vec<String>,
    source_external: Vec<String>,
    external: Option<String>,
}

/// Cyklus místní hodiny `hour` dne `day` (cyklus 0 = půlnoc UTC, jako `night_cycle` ve v1).
fn local_cycle(model: &NetworkModel, hours: u32, day: u32, hour: i64) -> u32 {
    let days = (hours as i64 / 24).max(1);
    let secs = -(model.tz_hours * 3600) + day as i64 * 86_400 + hour * 3600;
    ((secs.rem_euclid(86_400 * days) / CYCLE_SECS) as u32).min(hours * 2 - 1)
}

/// Naplánuje kalendář, odstraní náhodně losované jevy kalendářových druhů a přidá jevy z
/// kalendáře; vybraným útokům dá zdroj v infrastruktuře. Volá se jednou za epizodu.
pub fn plan_calendar(
    model: &NetworkModel,
    truths: &mut Vec<Truth>,
    hours: u32,
    start_offset_s: i64,
) -> CalendarPlan {
    let cycles = hours * 2;
    let days = (hours / 24).max(1);
    let mut rng = Rng::new(derive(model.seed, 0xCA1E_2022));
    truths.retain(|t| !matches!(t.kind, Kind::Benign(look) if calendar_kind(look)));
    let mut next_id = truths.iter().map(|t| t.id + 1).max().unwrap_or(0);

    let live = |d: &&crate::soak::netmodel::Device| d.up;
    let servers: Vec<u32> = model
        .devices
        .iter()
        .filter(live)
        .filter(|d| d.role.is_server() && d.id != model.gateway && d.id != model.dns)
        .map(|d| d.id)
        .collect();
    let clients: Vec<u32> = model
        .devices
        .iter()
        .filter(live)
        .filter(|d| !d.role.is_server())
        .map(|d| d.id)
        .collect();
    let first_role = |roles: &[Role], except: Option<u32>| {
        servers
            .iter()
            .copied()
            .find(|s| roles.contains(&model.devices[*s as usize].role) && Some(*s) != except)
    };
    let backup_server = first_role(&[Role::FileServer], None).or_else(|| servers.first().copied());
    let mut backup_targets: Vec<u32> = servers
        .iter()
        .copied()
        .filter(|s| Some(*s) != backup_server)
        .collect();
    for pick in rng.sample_distinct(clients.len(), clients.len().min(20)) {
        backup_targets.push(clients[pick]);
    }
    let scanner = model
        .devices
        .iter()
        .filter(live)
        .find(|d| d.role == Role::Jump)
        .map(|d| d.id)
        .or_else(|| (!clients.is_empty()).then(|| *rng.pick(&clients)));
    let scan_externals = [public_ip(&mut rng), public_ip(&mut rng)];
    let mut scan_scope: Vec<String> = model.scope().iter().map(|n| n.to_string()).collect();
    scan_scope.extend(scan_externals.iter().cloned());
    let batch_host = first_role(&[Role::Database], None).or_else(|| servers.first().copied());
    let batch_target = first_role(&[Role::FileServer, Role::Database], batch_host);
    let patch_group: Vec<u32> = if servers.len() >= 2 {
        let n = ((servers.len() as f64 / 3.0).ceil() as usize).clamp(2, 40);
        rng.sample_distinct(servers.len(), n.min(servers.len()))
            .into_iter()
            .map(|p| servers[p])
            .collect()
    } else {
        Vec::new()
    };
    let repo = public_ip(&mut rng);
    let scan_day = rng.range(0, 6) as u32;

    // (den, hodina, uloha, delka)
    let mut schedule: Vec<(u32, i64, Job, u32)> = Vec::new();
    for day in 0..days {
        if let Some(server) = backup_server.filter(|_| !backup_targets.is_empty()) {
            let len = rng.range(1, 3) as u32;
            schedule.push((
                day,
                2,
                Job {
                    look: Lookalike::Backup,
                    kind: ContextKind::Backup,
                    source: Some(server),
                    victims: backup_targets.clone(),
                    host_nets: Vec::new(),
                    source_external: Vec::new(),
                    external: None,
                },
                len,
            ));
        }
        if let (Some(host), Some(target)) = (batch_host, batch_target) {
            let len = rng.range(1, 6) as u32;
            schedule.push((
                day,
                4,
                Job {
                    look: Lookalike::BatchJob,
                    kind: ContextKind::BatchJob,
                    source: Some(host),
                    victims: vec![target],
                    host_nets: Vec::new(),
                    source_external: Vec::new(),
                    external: None,
                },
                len,
            ));
        }
        if day % 7 == scan_day
            && let Some(scanner) = scanner
        {
            let len = rng.range(1, 2) as u32;
            schedule.push((
                day,
                3,
                Job {
                    look: Lookalike::AuthorizedScanner,
                    kind: ContextKind::AuthorizedScanner,
                    source: Some(scanner),
                    victims: Vec::new(),
                    host_nets: scan_scope.clone(),
                    source_external: Vec::new(),
                    external: Some(scan_externals[(day / 7) as usize % 2].clone()),
                },
                len,
            ));
        }
        if !patch_group.is_empty() {
            let date = ts(EPOCH0 + start_offset_s + day as i64 * 86_400).date_naive();
            let second_tuesday = date.weekday() == Weekday::Tue && (8..=14).contains(&date.day());
            let extra = rng.chance(EXTRA_PATCH_PER_WEEK / 7.0);
            if second_tuesday || extra {
                let len = rng.range(2, 5) as u32;
                schedule.push((
                    day,
                    4,
                    Job {
                        look: Lookalike::PatchWindow,
                        kind: ContextKind::PatchWindow,
                        source: None,
                        victims: patch_group.clone(),
                        host_nets: Vec::new(),
                        source_external: vec![repo.clone()],
                        external: Some(repo.clone()),
                    },
                    len,
                ));
            }
        }
    }

    let mut plan = CalendarPlan {
        backup_server,
        scanner,
        ..Default::default()
    };
    // okna uloh se zdrojem v infrastrukture (pro utoky z infrastruktury)
    let mut infra_windows: Vec<(u32, u32, u32)> = Vec::new();
    for (day, hour, job, len) in schedule {
        let start = local_cycle(model, hours, day, hour);
        let end = (start + len - 1).min(cycles - 1);
        let no_record = rng.chance(NO_RECORD);
        let cancelled = !no_record && rng.chance(CANCELLED);
        let shifted = !no_record && !cancelled && rng.chance(SHIFTED);
        let shift_up = rng.chance(0.5);
        if !cancelled {
            plan.stats.jobs += 1;
            plan.stats.recorded += (!no_record) as u64;
            if let Some(source) = job.source
                && matches!(job.look, Lookalike::Backup | Lookalike::AuthorizedScanner)
            {
                infra_windows.push((source, start, end));
            }
            let cov = crate::soak::coverage::TruthCoverage {
                calendar: true,
                ..Default::default()
            };
            truths.push(Truth {
                id: next_id,
                kind: Kind::Benign(job.look),
                start_cycle: start,
                end_cycle: end,
                intensity: rng.range_f(0.4, 1.0),
                attacker_device: job.source,
                attacker_external: None,
                victim_devices: job.victims.clone(),
                target_external: job.external.clone().or_else(|| Some(public_ip(&mut rng))),
                ids_visible: false,
                touched_ips: BTreeSet::new(),
                cycle_targets: Default::default(),
                cycle_sources: Default::default(),
                flows_emitted: 0,
                flows_blocked: 0,
                first_emit_cycle: None,
                blocked_at_cycle: None,
                cov,
            });
            next_id += 1;
        } else {
            plan.stats.cancelled += 1;
        }
        if no_record {
            continue;
        }
        let (rs, re) = if shifted {
            plan.stats.shifted += 1;
            if shift_up {
                (
                    (start + SHIFT_CYCLES).min(cycles - 1),
                    (end + SHIFT_CYCLES).min(cycles - 1),
                )
            } else {
                (
                    start.saturating_sub(SHIFT_CYCLES),
                    end.saturating_sub(SHIFT_CYCLES),
                )
            }
        } else {
            (start, end)
        };
        plan.records.push(CalRecord {
            kind: job.kind,
            host_devices: job.victims,
            host_nets: job.host_nets,
            source_devices: job.source.into_iter().collect(),
            source_external: job.source_external,
            start: rs,
            end: re,
        });
    }

    // kompromitace infrastruktury: vlastni proud, nezavisly na kalendari
    let mut infra_rng = Rng::new(derive(model.seed, 0xCA1E_2023));
    for truth in truths.iter_mut() {
        let Kind::Attack(family) = truth.kind else {
            continue;
        };
        let eligible = matches!(
            family,
            Family::PortScanVertical
                | Family::PortScanHorizontal
                | Family::SlowScan
                | Family::SshBrute
                | Family::Lateral
                | Family::Exfil
                | Family::C2Beacon
        );
        if !eligible || !infra_rng.chance(INFRA_SHARE) || infra_windows.is_empty() {
            continue;
        }
        let want = if infra_rng.chance(0.5) {
            backup_server
        } else {
            scanner
        };
        let pool: Vec<&(u32, u32, u32)> = infra_windows
            .iter()
            .filter(|(s, _, _)| Some(*s) == want)
            .collect();
        let pool = if pool.is_empty() {
            infra_windows.iter().collect()
        } else {
            pool
        };
        let &&(source, ws, _) = pool
            .iter()
            .min_by_key(|(_, s, _)| s.abs_diff(truth.start_cycle))
            .expect("neprazdne");
        let len = truth.end_cycle - truth.start_cycle;
        truth.start_cycle = ws;
        truth.end_cycle = (ws + len).min(cycles - 1);
        truth.attacker_device = Some(source);
        truth.attacker_external = None;
        truth.victim_devices.retain(|v| *v != source);
        plan.stats.infra_attacks += 1;
    }

    // V2: podil utoku, jejichz zdroj nebo cil lezi v aktivnim okne zaznamu
    for truth in truths.iter() {
        let Kind::Attack(_) = truth.kind else {
            continue;
        };
        plan.stats.attacks += 1;
        let hit = plan.records.iter().any(|r| {
            truth.start_cycle <= r.end + 1
                && truth.end_cycle + 1 >= r.start
                && (truth
                    .attacker_device
                    .is_some_and(|a| r.source_devices.contains(&a) || r.host_devices.contains(&a))
                    || truth
                        .victim_devices
                        .iter()
                        .any(|v| r.host_devices.contains(v))
                    || (r.kind == ContextKind::AuthorizedScanner
                        && (!truth.victim_devices.is_empty()
                            || truth
                                .target_external
                                .as_ref()
                                .is_some_and(|t| r.host_nets.contains(t)))))
        });
        plan.stats.attacks_in_window += hit as u64;
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soak::{netmodel::NetworkModel, traffic::plan_episode};

    fn world(seed: u64) -> (NetworkModel, Vec<Truth>, CalendarPlan) {
        let mut rng = Rng::new(seed);
        let model = NetworkModel::generate(seed, 0);
        let telemetry = crate::soak::traffic::random_telemetry(&mut rng, 4);
        let mut truths = plan_episode(&model, &mut rng, 168, &telemetry);
        let plan = plan_calendar(&model, &mut truths, 168, 0);
        (model, truths, plan)
    }

    #[test]
    fn calendar_world_is_deterministic_and_replaces_random_calendar_kinds() {
        let (_, a, pa) = world(20_269_801);
        let (_, b, pb) = world(20_269_801);
        assert_eq!(a.len(), b.len());
        assert_eq!(pa.records.len(), pb.records.len());
        let calendar: Vec<&Truth> = a
            .iter()
            .filter(|t| matches!(t.kind, Kind::Benign(l) if calendar_kind(l)))
            .collect();
        assert!(!calendar.is_empty());
        assert!(calendar.iter().all(|t| t.cov.calendar));
        let ids: BTreeSet<u32> = a.iter().map(|t| t.id).collect();
        assert_eq!(ids.len(), a.len(), "id jsou jedinecna");
    }

    #[test]
    fn calendar_imperfection_matches_preregistered_shares_on_many_networks() {
        let mut stats = CalStats::default();
        for seed in 0..300u64 {
            let (_, _, plan) = world(1_000 + seed);
            stats.jobs += plan.stats.jobs;
            stats.recorded += plan.stats.recorded;
            stats.cancelled += plan.stats.cancelled;
            stats.shifted += plan.stats.shifted;
        }
        let share = stats.recorded as f64 / stats.jobs as f64;
        assert!(stats.jobs > 2_000, "{stats:?}");
        assert!((share - 0.90).abs() < 0.02, "{share} {stats:?}");
        let cancelled = stats.cancelled as f64 / (stats.jobs + stats.cancelled) as f64;
        assert!((cancelled - 0.045).abs() < 0.015, "{cancelled}");
    }
}

#[cfg(test)]
mod context_tests {
    use super::*;
    use crate::context_gate::{ContextGate, GateInput, GatePolicy};
    use crate::model::Severity;
    use crate::soak::{netmodel::NetworkModel, traffic::plan_episode, v3::SimContext};

    /// Záznam zálohy z kalendáře vysvětlí objemový nález cíle se zdrojem zálohovacího serveru
    /// (kontrola napojení světa v2 na kontextovou bránu, ne ladění brány).
    #[test]
    fn calendar_backup_record_reaches_context_gate() {
        let seed = 20_269_801;
        let mut rng = Rng::new(seed);
        let model = NetworkModel::generate(seed, 0);
        let telemetry = crate::soak::traffic::random_telemetry(&mut rng, 4);
        let mut truths = plan_episode(&model, &mut rng, 168, &telemetry);
        let plan = plan_calendar(&model, &mut truths, 168, 0);
        let ips: Vec<String> = (0..model.devices.len() as u32)
            .map(|d| model.ip_of(d))
            .collect();
        let record = plan
            .records
            .iter()
            .find(|r| r.kind == ContextKind::Backup)
            .expect("zaloha");
        let cycle = record.start;
        let context = SimContext::for_cycle(
            &truths,
            &model,
            &ips,
            0,
            336,
            &Default::default(),
            &[],
            cycle,
            false,
            Some(&plan),
        );
        let host = vec![ips[record.host_devices[0] as usize].clone()];
        let sources = vec![ips[record.source_devices[0] as usize].clone()];
        let mut gate = ContextGate::new(GatePolicy::for_engine(&crate::engine::EngineConfig::v3()));
        let at = ts(crate::soak::traffic::cycle_start_abs(0, cycle));
        let decision = gate.explain_decision(
            &context,
            &GateInput {
                finding_type: "inductive_volume_anomaly",
                host_ids: &host,
                targets: &[],
                sources: &sources,
                severity: Severity::Medium,
                at,
                protected: false,
            },
        );
        assert!(decision.explanation.is_some(), "{decision:?} {record:?}");
    }
}
