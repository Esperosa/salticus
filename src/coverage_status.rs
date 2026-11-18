//! Viditelnost degradace pokrytí (krok 7, A4; docs/diplomka/eval/impl-krok7.md).
//!
//! Engine nesmí mlčky předstírat plné pokrytí: když chybí IDS, profily jsou nezralé,
//! v telemetrii je mezera nebo je málo dat průmyslových protokolů, report (API a data
//! UI) to řekne a nasazení s mezerou, kterou tokový detektor nenahradí, se označí
//! jako blokované. Vzhled UI se tu neřeší, jen pole.

use serde::{Deserialize, Serialize};

/// Porty průmyslových protokolů (Modbus, S7, DNP3, EtherNet/IP, OPC UA, BACnet).
pub const ICS_PORTS: &[u16] = &[502, 102, 20000, 44818, 4840, 47808];
/// Pod tolika toky průmyslových protokolů v okně jsou data ICS „málo“.
pub const ICS_MIN_FLOWS: usize = 10;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CoverageStatus {
    pub degraded: bool,
    /// `no_ids`, `immature_profiles`, `telemetry_gap`, `low_ics_data`
    pub reasons: Vec<String>,
    /// Nasazení s touto mezerou nemá plný deklarovaný rozsah (exploit bez IDS, okno
    /// bez dat): vyžaduje vědomé rozhodnutí člověka.
    pub deployment_blocking: bool,
    /// Vnitřní hosté v tocích okna s profilem mladším než 48 h (z kolika).
    pub immature_hosts: usize,
    pub observed_hosts: usize,
    pub ics_devices: usize,
    pub ics_flows: usize,
    /// `exploit_attempt` (IDS typy) se vždy ukáže člověku a nikdy se nezavře (A1, P3).
    pub exploit_always_shown: bool,
    /// Krok 12: hosté z inventáře, kteří byli v telemetrii aktivní a pak umlkli
    /// (nejvýš 50, vzestupně). Detekce na nich není garantovaná.
    #[serde(default)]
    pub silent_hosts: Vec<String>,
    /// Krok 12: segmenty (/24), jejichž převážná část inventářových hostů umlkla.
    #[serde(default)]
    pub dark_segments: Vec<String>,
    /// Krok 12: co s tím (umístění senzoru, logy); text je obecný, ne podle sítě.
    #[serde(default)]
    pub sensor_advice: Vec<String>,
}

/// Vstupy jednoho běhu.
#[derive(Debug, Clone, Default)]
pub struct CoverageInput {
    pub ids_configured: bool,
    pub sensor_gap: bool,
    pub flows_in_window: usize,
    pub observed_hosts: usize,
    pub immature_hosts: usize,
    pub ics_devices: usize,
    pub ics_flows: usize,
    pub protect: bool,
    pub silent_hosts: Vec<String>,
    pub dark_segments: Vec<String>,
}

pub fn assess(input: &CoverageInput) -> CoverageStatus {
    let mut reasons = Vec::new();
    if !input.ids_configured {
        reasons.push("no_ids".to_string());
    }
    if input.observed_hosts > 0 && input.immature_hosts > 0 {
        reasons.push("immature_profiles".to_string());
    }
    let gap = input.sensor_gap || input.flows_in_window == 0;
    if gap {
        reasons.push("telemetry_gap".to_string());
    }
    if input.ics_devices > 0 && input.ics_flows < ICS_MIN_FLOWS {
        reasons.push("low_ics_data".to_string());
    }
    if !input.silent_hosts.is_empty() {
        reasons.push("silent_hosts".to_string());
    }
    if !input.dark_segments.is_empty() {
        reasons.push("dark_segments".to_string());
    }
    let mut sensor_advice = Vec::new();
    if !input.silent_hosts.is_empty() || !input.dark_segments.is_empty() {
        sensor_advice.push(
            "Hosty a segmenty bez telemetrie: umistit tap nebo SPAN na uplink a na prepinac \
             segmentu, overit, ze sensor vidi oba smery, a zapnout logy conn, ssl, x509, dns \
             a http (Zeek) nebo tls, dns, http, fileinfo (Suricata EVE). Vice logu je lepsi \
             nez chybejici: bez nich detekce v danem miste neni garantovana."
                .to_string(),
        );
    }
    CoverageStatus {
        degraded: !reasons.is_empty(),
        deployment_blocking: !input.ids_configured || gap,
        reasons,
        immature_hosts: input.immature_hosts,
        observed_hosts: input.observed_hosts,
        ics_devices: input.ics_devices,
        ics_flows: input.ics_flows,
        exploit_always_shown: input.protect,
        silent_hosts: input.silent_hosts.iter().take(50).cloned().collect(),
        dark_segments: input.dark_segments.iter().take(50).cloned().collect(),
        sensor_advice,
    }
}

/// Krok 12: pokrytí senzorů po hostech a segmentech. Hostitel z inventáře, který byl
/// aspoň `min_active` oken aktivní a pak `silent_windows` oken po sobě nemá v telemetrii
/// žádný tok (jako zdroj ani cíl), je „umlklý“. Segment /24, kde je aspoň
/// `dark_min_hosts` inventářových hostů a z nich `dark_share` umlklo, je „temný“.
/// Slepé místo se hlásí vždy, nikdy se nezakrývá.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SensorCoverage {
    pub min_active: u32,
    pub silent_windows: u64,
    pub dark_min_hosts: usize,
    pub dark_share: f64,
    pub max_hosts: usize,
    /// host -> (okna s aktivitou, poslední okno s aktivitou)
    seen: std::collections::BTreeMap<String, (u32, u64)>,
    window: u64,
}

impl Default for SensorCoverage {
    fn default() -> Self {
        Self {
            min_active: 4,
            silent_windows: 6,
            dark_min_hosts: 3,
            dark_share: 0.8,
            max_hosts: 200_000,
            seen: Default::default(),
            window: 0,
        }
    }
}

fn segment_of(ip: &str) -> Option<String> {
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let o = addr.octets();
    Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
}

impl SensorCoverage {
    /// Jedno okno: `active` = adresy, které se v okně objevily v tocích; `inventory` =
    /// adresy známé z inventáře. Vrací (umlklé hosty, temné segmenty).
    pub fn observe<'a>(
        &mut self,
        active: impl Iterator<Item = &'a str>,
        inventory: &[String],
    ) -> (Vec<String>, Vec<String>) {
        self.window += 1;
        let known: std::collections::BTreeSet<&str> =
            inventory.iter().map(String::as_str).collect();
        for ip in active {
            if !known.contains(ip)
                && !self.seen.contains_key(ip)
                && self.seen.len() >= self.max_hosts
            {
                continue;
            }
            let e = self.seen.entry(ip.to_string()).or_insert((0, 0));
            e.0 = e.0.saturating_add(1);
            e.1 = self.window;
        }
        let mut silent: Vec<String> = Vec::new();
        for ip in &known {
            if let Some((n, last)) = self.seen.get(*ip)
                && *n >= self.min_active
                && self.window - last >= self.silent_windows
            {
                silent.push((*ip).to_string());
            }
        }
        silent.sort();
        let mut per_seg: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for ip in &known {
            if let Some(seg) = segment_of(ip) {
                per_seg.entry(seg).or_default().0 += 1;
            }
        }
        for ip in &silent {
            if let Some(seg) = segment_of(ip) {
                per_seg.entry(seg).or_default().1 += 1;
            }
        }
        let dark: Vec<String> = per_seg
            .into_iter()
            .filter(|(_, (all, quiet))| {
                *all >= self.dark_min_hosts && *quiet as f64 >= self.dark_share * *all as f64
            })
            .map(|(seg, _)| seg)
            .collect();
        (silent, dark)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_hosts_and_dark_segments_are_reported_never_hidden() {
        let inventory: Vec<String> = (1..=4)
            .map(|i| format!("10.0.1.{i}"))
            .chain(["10.0.2.1".to_string()])
            .collect();
        let mut cov = SensorCoverage::default();
        for _ in 0..5 {
            let all: Vec<&str> = inventory.iter().map(String::as_str).collect();
            let (s, d) = cov.observe(all.into_iter(), &inventory);
            assert!(s.is_empty() && d.is_empty());
        }
        let mut last = (vec![], vec![]);
        for _ in 0..6 {
            last = cov.observe(["10.0.2.1"].into_iter(), &inventory);
        }
        assert_eq!(last.0.len(), 4);
        assert_eq!(last.1, vec!["10.0.1.0/24".to_string()]);
        let status = assess(&CoverageInput {
            ids_configured: true,
            flows_in_window: 10,
            silent_hosts: last.0,
            dark_segments: last.1,
            ..Default::default()
        });
        assert!(status.degraded && status.reasons.contains(&"dark_segments".to_string()));
        assert!(!status.sensor_advice.is_empty());
        let (s, _) = cov.observe(["10.0.2.1"].into_iter(), &["10.0.9.9".to_string()]);
        assert!(s.is_empty());
    }

    #[test]
    fn full_coverage_is_not_degraded_and_gaps_are_named() {
        let ok = assess(&CoverageInput {
            ids_configured: true,
            flows_in_window: 100,
            observed_hosts: 5,
            protect: true,
            ..Default::default()
        });
        assert!(!ok.degraded && !ok.deployment_blocking && ok.exploit_always_shown);
        let bad = assess(&CoverageInput {
            ids_configured: false,
            flows_in_window: 0,
            observed_hosts: 5,
            immature_hosts: 2,
            ics_devices: 1,
            ics_flows: 3,
            ..Default::default()
        });
        assert!(bad.degraded && bad.deployment_blocking);
        assert_eq!(
            bad.reasons,
            vec![
                "no_ids",
                "immature_profiles",
                "telemetry_gap",
                "low_ics_data"
            ]
        );
    }
}
