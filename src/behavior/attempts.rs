//! Opakovaná krátká spojení na službu pro přihlášení (hádání hesel; krok 27).
//!
//! Měření kroku 26 ukázalo, že hrubá síla na SSH se zachytí jen tehdy, když v okně existují
//! jiné klíče na stejném portu (baseline „skupina_sluzeb“ v `anomaly_v3`). Bez vrstevníků je
//! to jen nízké „neočekávané spojení“. Toto pravidlo nezávisí na vrstevnících: počítá spojení
//! téhož zdroje na stejný cíl a port přihlašovací služby v klouzavém časovém úseku.
//!
//! Pravidlo: aspoň `min_flows` TCP spojení ze zdroje na `(cíl, port)` služby z [`ATTEMPT_PORTS`]
//! během `span_s` sekund, přičemž medián doby trvání je nejvýš `max_median_s` (krátké pokusy,
//! ne dlouhé relace). Zvyklost hostu (`habit`) pravidlo tlumí. Prahy jsou volba autora, před
//! měřením stanovená a neladěná na pravdě; výchozí stav přepínače je vypnuto.
//!
//! Nález je chráněný typ (`protection`), takže se nikdy nezavře automaticky.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, finding},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

/// Služby, na kterých se přihlašuje heslem (FTP, SSH, Telnet, POP3, IMAP, SMB, MSSQL, MySQL,
/// RDP, PostgreSQL, VNC, WinRM).
pub const ATTEMPT_PORTS: &[u16] = &[
    21, 22, 23, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 5985,
];

pub const ATTEMPT_TYPES: &[&str] = &["bruteforce_attempts"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AttemptsThresholds {
    /// Nejmenší počet spojení na dvojici (zdroj, cíl:port) v úseku.
    pub min_flows: usize,
    /// Délka úseku (s).
    pub span_s: i64,
    /// Nejvyšší medián doby trvání spojení (s); delší jsou relace, ne pokusy.
    pub max_median_s: f64,
}

impl Default for AttemptsThresholds {
    fn default() -> Self {
        Self {
            min_flows: 50,
            span_s: 600,
            max_median_s: 10.0,
        }
    }
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    match values.len() {
        0 => 0.0,
        n if n % 2 == 1 => values[n / 2],
        n => (values[n / 2 - 1] + values[n / 2]) / 2.0,
    }
}

/// Hledá úseky opakovaných spojení. `internal` a `inbound` jsou toky s cílem v rozsahu;
/// odchozí provoz (cíl venku) se nehodnotí, protože cíl není pod správou.
///
/// Aktér nálezu: u vnitřního toku zdroj (hostitel, který pokusy posílá, a zvyk hostu se
/// hledá na dvojici zdroj → cíl), u příchozího toku cíl (oběť uvnitř rozsahu, protože zdroj
/// je venku). `service_key` má tvar `attempts/<protějšek>/tcp/<port>` jako ostatní
/// behaviorální nálezy, takže ho žebřík umí rozebrat (`profile::case_pair`).
///
/// Bez stavu mezi okny: dávka rozdělená hranicí okna se nespojí.
pub fn detect(
    t: &AttemptsThresholds,
    internal: &[ConnectionObservation],
    inbound: &[ConnectionObservation],
    habit: &dyn Fn(&str, &str, &str, u16) -> bool,
) -> Vec<BehaviorFinding> {
    // (zdroj, cíl, port, příchozí) -> (čas, doba trvání)
    type Key<'a> = (&'a str, &'a str, u16, bool);
    let mut rels: BTreeMap<Key<'_>, Vec<(i64, f64)>> = BTreeMap::new();
    for (is_inbound, flows) in [(false, internal), (true, inbound)] {
        for flow in flows {
            let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
                continue;
            };
            if flow.proto != "tcp" || !ATTEMPT_PORTS.contains(&port) {
                continue;
            }
            rels.entry((src, flow.dst_ip.as_str(), port, is_inbound))
                .or_default()
                .push((flow.timestamp.timestamp(), flow.duration_s.unwrap_or(0.0)));
        }
    }
    let k = t.min_flows.max(2);
    let mut out = Vec::new();
    for ((src, dst, port, is_inbound), mut flows) in rels {
        if flows.len() < k || habit(src, dst, "tcp", port) {
            continue;
        }
        flows.sort_by_key(|f| f.0);
        // první úsek `k` po sobě jdoucích spojení, který je dost těsný a jehož medián
        // doby trvání odpovídá krátkým pokusům (dlouhé relace před útokem ho nezakryjí)
        let found = flows.windows(k).find(|w| {
            w[k - 1].0 - w[0].0 <= t.span_s && {
                let mut durations: Vec<f64> = w.iter().map(|f| f.1).collect();
                median(&mut durations) <= t.max_median_s
            }
        });
        let Some(window) = found else {
            continue;
        };
        let span = (window[k - 1].0 - window[0].0).max(1);
        let (actor, peer) = if is_inbound { (dst, src) } else { (src, dst) };
        out.push(BehaviorFinding {
            finding: finding(
                "bruteforce_attempts",
                actor,
                &format!("attempts/{peer}/tcp/{port}"),
                Severity::Medium,
                Confidence::Low,
                format!(
                    "{k} krátkých spojení z {src} na {dst}:{port} za {span} s (možné hádání hesel)"
                ),
                format!(
                    "Zdroj {src} navázal aspoň {k} krátkých TCP spojení na přihlašovací službu \
                     {dst}:{port} do {} s. Takový vzor odpovídá opakovanému zkoušení přihlášení. \
                     Neškodně ho ale vyrobí i monitorování (kontrola služby po pár sekundách), \
                     skripty bez sdíleného spojení (Ansible, rsync po souborech, zálohy), aplikace \
                     bez fronty spojení k databázi, skenery zranitelností a vlastní nmap správce.",
                    t.span_s
                ),
                vec![format!(
                    "{src} -> {dst}:{port}/tcp: {k} spojení za {span} s, celkem {} v okně",
                    flows.len()
                )],
                "Zkontrolovat protokol přihlášení cílové služby, ověřit, zda je zdroj známý \
                 (správce, monitorování); jinak omezit přístup ke službě.",
            ),
            sources: vec![peer.to_string()],
            targets: vec![(dst.to_string(), port)],
            count: u32::try_from(flows.len()).unwrap_or(u32::MAX),
            actor: actor.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::*;

    fn flow(src: &str, dst: &str, port: u16, at: i64, dur: f64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: DateTime::from_timestamp(1_800_000_000 + at, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(dur),
            orig_bytes: Some(1200),
            resp_bytes: Some(900),
            total_bytes: None,
            orig_pkts: Some(14),
            resp_pkts: Some(12),
            total_pkts: None,
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: None,
        }
    }

    fn many(n: usize, step: i64, port: u16, dur: f64) -> Vec<ConnectionObservation> {
        (0..n)
            .map(|i| flow("192.168.1.9", "192.168.1.20", port, i as i64 * step, dur))
            .collect()
    }

    fn none(_: &str, _: &str, _: &str, _: u16) -> bool {
        false
    }

    #[test]
    fn many_short_connections_to_ssh_are_reported() {
        let found = detect(
            &AttemptsThresholds::default(),
            &many(60, 2, 22, 0.8),
            &[],
            &none,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].finding.finding_type, "bruteforce_attempts");
        // vnitřní tok: aktér je zdroj, protějšek cíl
        assert_eq!(found[0].actor, "192.168.1.9");
        assert_eq!(found[0].sources, vec!["192.168.1.20".to_string()]);
        assert_eq!(
            found[0].finding.service_key.as_deref(),
            Some("192.168.1.9/attempts/192.168.1.20/tcp/22")
        );
        assert_eq!(found[0].targets, vec![("192.168.1.20".to_string(), 22)]);
    }

    #[test]
    fn inbound_attempts_from_outside_are_reported() {
        let flows: Vec<_> = (0..60)
            .map(|i| flow("203.0.113.5", "192.168.1.20", 3389, i * 3, 1.0))
            .collect();
        let found = detect(&AttemptsThresholds::default(), &[], &flows, &none);
        assert_eq!(found.len(), 1);
        // příchozí tok: aktér je oběť uvnitř rozsahu, protějšek vnější zdroj
        assert_eq!(found[0].actor, "192.168.1.20");
        assert_eq!(found[0].sources, vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn few_connections_are_not_reported() {
        let found = detect(
            &AttemptsThresholds::default(),
            &many(20, 2, 22, 0.8),
            &[],
            &none,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn slow_trickle_over_hours_is_not_reported() {
        // 60 spojení rozložených na 3 hodiny: nikdy 50 během 10 minut
        let found = detect(
            &AttemptsThresholds::default(),
            &many(60, 180, 22, 0.8),
            &[],
            &none,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn long_sessions_are_not_attempts() {
        let found = detect(
            &AttemptsThresholds::default(),
            &many(60, 2, 22, 3600.0),
            &[],
            &none,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn non_login_port_and_udp_are_ignored() {
        let mut udp = many(60, 2, 22, 0.8);
        for f in &mut udp {
            f.proto = "udp".to_string();
        }
        assert!(
            detect(
                &AttemptsThresholds::default(),
                &many(60, 2, 8080, 0.8),
                &[],
                &none
            )
            .is_empty()
        );
        assert!(detect(&AttemptsThresholds::default(), &udp, &[], &none).is_empty());
    }

    #[test]
    fn habitual_relation_is_damped() {
        let habit = |src: &str, dst: &str, proto: &str, port: u16| {
            src == "192.168.1.9" && dst == "192.168.1.20" && proto == "tcp" && port == 22
        };
        let found = detect(
            &AttemptsThresholds::default(),
            &many(60, 2, 22, 0.8),
            &[],
            &habit,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn threshold_boundaries_are_inclusive_for_count_and_span() {
        let t = AttemptsThresholds::default();
        assert!(detect(&t, &many(49, 1, 22, 0.8), &[], &none).is_empty());
        assert_eq!(detect(&t, &many(50, 1, 22, 0.8), &[], &none).len(), 1);
        // 50 spojení přesně za 600 s (krok 600/49 nejde celé číslo: první a poslední 600 s od sebe)
        let mut edge = many(50, 12, 22, 0.8); // 49 * 12 = 588 s
        edge[49].timestamp += chrono::Duration::seconds(12); // 600 s
        assert_eq!(detect(&t, &edge, &[], &none).len(), 1);
        edge[49].timestamp += chrono::Duration::seconds(1); // 601 s
        assert!(detect(&t, &edge, &[], &none).is_empty());
    }

    #[test]
    fn median_duration_boundary_and_missing_duration() {
        let t = AttemptsThresholds::default();
        assert_eq!(detect(&t, &many(60, 2, 22, 10.0), &[], &none).len(), 1);
        assert!(detect(&t, &many(60, 2, 22, 10.1), &[], &none).is_empty());
        let mut none_dur = many(60, 2, 22, 0.8);
        for f in &mut none_dur {
            f.duration_s = None;
        }
        assert_eq!(detect(&t, &none_dur, &[], &none).len(), 1);
    }

    #[test]
    fn long_sessions_before_the_burst_do_not_hide_it() {
        // 30 dlouhých relací, potom 60 krátkých pokusů: první úsek 50 spojení by měl vysoký
        // medián, ale pozdější čistě krátký úsek se musí najít
        let mut flows: Vec<_> = (0..30)
            .map(|i| flow("192.168.1.9", "192.168.1.20", 22, i * 2, 3600.0))
            .collect();
        flows.extend((0..60).map(|i| flow("192.168.1.9", "192.168.1.20", 22, 100 + i * 2, 0.8)));
        assert_eq!(
            detect(&AttemptsThresholds::default(), &flows, &[], &none).len(),
            1
        );
    }

    #[test]
    fn unsorted_input_is_handled() {
        let mut flows = many(60, 2, 22, 0.8);
        flows.reverse();
        assert_eq!(
            detect(&AttemptsThresholds::default(), &flows, &[], &none).len(),
            1
        );
    }

    #[test]
    fn habit_for_another_port_does_not_damp() {
        let habit = |_: &str, _: &str, _: &str, port: u16| port == 3306;
        assert_eq!(
            detect(
                &AttemptsThresholds::default(),
                &many(60, 2, 22, 0.8),
                &[],
                &habit
            )
            .len(),
            1
        );
    }

    #[test]
    fn finding_type_is_protected_and_switch_is_off_in_presets() {
        assert!(crate::protection::is_protected_type("bruteforce_attempts"));
        assert!(crate::behavior::is_behavior_type("bruteforce_attempts"));
        use crate::engine::V3Features;
        assert!(!V3Features::recommended().attempts);
        assert!(!V3Features::all().attempts);
        assert!(!V3Features::none().attempts);
        assert!(!V3Features::step6().attempts);
    }
}
