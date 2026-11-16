use super::*;
use crate::incident_catalog::Catalog;

fn store_with(keys: &[&str], scope: &str, now: i64) -> OpsStore {
    let mut s = OpsStore::new(Limits::default());
    for src in OpsSource::ALL {
        s.heartbeat(src, now);
    }
    for k in keys {
        assert!(s.ingest(
            OpsSignal {
                at: now - 60,
                key: (*k).to_string(),
                value: 1.0,
                scope: vec![scope.to_string()],
            },
            now
        ));
    }
    s
}

#[test]
fn catalog_signals_are_valid_and_every_type_identifies_itself() {
    let c = Catalog::embedded();
    let idx = Index::build(&c);
    let policy = DiagPolicy::default();
    let mut ambiguous = Vec::new();
    for e in &c.incidents {
        assert!(!e.ops_signals.is_empty(), "{} bez signálů", e.id);
        for (k, w) in &e.ops_signals {
            assert!(valid_key(k, 48), "{k}");
            assert!((1..=3).contains(w), "{k}");
        }
        let keys: Vec<&str> = e.ops_signals.iter().map(|(k, _)| k.as_str()).collect();
        let s = store_with(&keys, "10.0.0.5", 10_000);
        let d = diagnose(
            &idx,
            &s,
            "unexpected_traffic",
            &["10.0.0.5".into()],
            false,
            10_000,
            &policy,
        );
        let want = match e.category.as_str() {
            "porucha" => "porucha",
            "neskodna_zmena" => "zmena",
            _ => "nejednoznacne",
        };
        if d.catalog_id.as_deref() != Some(e.id.as_str()) {
            ambiguous.push((
                e.id.clone(),
                d.catalog_id.clone(),
                d.class.clone(),
                d.candidates.contains(&e.id),
            ));
        } else {
            assert_eq!(d.class, want, "{}", e.id);
        }
    }
    // úplná sada signálů musí typ poznat. Typy se sdílenými signály (OPS-027 a CHG-006, OPS-045 a OPS-020,
    // OPS-033 a OPS-034 ...) nemají v katalogu rozlišující signál: smí vyjít „nejednoznačné“ nebo
    // sousední typ téže třídy, nikdy jistě jiná třída.
    for (id, got, class, in_candidates) in &ambiguous {
        let e = c.get(id).unwrap();
        let want = match e.category.as_str() {
            "porucha" => "porucha",
            "neskodna_zmena" => "zmena",
            _ => "nejednoznacne",
        };
        assert!(
            class == "nejednoznacne"
                || class == "neurceno"
                || (class == want && (got.is_some() || *in_candidates)),
            "{id}: {got:?} {class} {in_candidates}"
        );
    }
    assert!(ambiguous.len() <= 20 && ambiguous.iter().all(|a| a.3 || a.2 == "nejednoznacne"), "{ambiguous:?}");
}

/// Krok 15 (P3, `ops_symptoms`): porucha infrastruktury (saturace uplinku, OPS-011)
/// vysvetli timeouty a objem, ne novy vztah; bez prepinace vysvetlila i `unexpected_traffic`
/// (drzene seedy: snmp_walk a smtp_auth_spray zarazeny jako porucha podle signalu v /24).
#[test]
fn fault_explains_only_the_symptom_groups_of_its_mechanism() {
    let idx = Index::shared();
    let s = store_with(&["if_util_high", "if_out_discards", "qos_drop"], "10.0.0.0/24", 10_000);
    let on = DiagPolicy {
        symptoms: true,
        ..DiagPolicy::default()
    };
    let off = DiagPolicy::default();
    let ips = vec!["10.0.0.5".to_string()];
    let d = diagnose(idx, &s, "unexpected_traffic", &ips, false, 10_000, &off);
    assert_eq!(d.class, "porucha", "puvodni chovani: {d:?}");
    let d = diagnose(idx, &s, "unexpected_traffic", &ips, false, 10_000, &on);
    assert_eq!(d.class, "utok", "{d:?}");
    assert!(d.explains_partly, "signaly poruchy zustavaji jako poznamka");
    let d = diagnose(idx, &s, "connection_timeout_burst", &ips, false, 10_000, &on);
    assert_eq!((d.class.as_str(), d.catalog_id.as_deref()), ("porucha", Some("OPS-011")), "{d:?}");
}

/// Krok 15 (P3, `ops_symptoms`): uplna sada signalu typu, jehoz signaly jsou nadmnozinou
/// jineho typu (OPS-016 app_server_crash_cascade nad OPS-054 health_check_failing), urci typ:
/// podmnozinovy kandidat je dominovany (pokryva min z tehoz dukazu). Bez prepinace vyjde
/// dvojice kandidatu bez `catalog_id` (drzene seedy: catalog_id 1,6 % u 375 nalezu).
#[test]
fn superset_type_wins_over_its_dominated_subset_candidate() {
    let c = Catalog::embedded();
    let idx = Index::build(&c);
    let big = c.get("OPS-016").unwrap();
    let small = c.get("OPS-054").unwrap();
    let small_keys: Vec<&str> = small.ops_signals.iter().map(|(k, _)| k.as_str()).collect();
    let big_keys: Vec<&str> = big.ops_signals.iter().map(|(k, _)| k.as_str()).collect();
    assert!(small_keys.iter().all(|k| big_keys.contains(k)), "predpoklad testu: podmnozina");
    let s = store_with(&big_keys, "10.0.0.5", 10_000);
    let ips = vec!["10.0.0.5".to_string()];
    let off = diagnose(&idx, &s, "service_unreachable", &ips, false, 10_000, &DiagPolicy::default());
    assert!(off.catalog_id.is_none() && off.candidates.contains(&"OPS-016".to_string()), "puvodni chovani: {off:?}");
    let on = diagnose(
        &idx,
        &s,
        "service_unreachable",
        &ips,
        false,
        10_000,
        &DiagPolicy {
            symptoms: true,
            ..DiagPolicy::default()
        },
    );
    assert_eq!(on.catalog_id.as_deref(), Some("OPS-016"), "{on:?}");
    // opacne: jen signaly podmnoziny -> podmnozinovy typ (nadmnozine chybi silne signaly)
    let s = store_with(&small_keys, "10.0.0.5", 10_000);
    let on = diagnose(
        &idx,
        &s,
        "service_unreachable",
        &ips,
        false,
        10_000,
        &DiagPolicy {
            symptoms: true,
            ..DiagPolicy::default()
        },
    );
    assert_eq!(on.catalog_id.as_deref(), Some("OPS-054"), "{on:?}");
}

/// Krok 15 (P3, `ops_blast`): signal o brane (flapping pateřního smerovace, OPS-002) plati pro
/// hosty, ktere na ni zavisi; bez prepinace je timeout klienta „bez provozniho dukazu“
/// (drzene seedy: core_router_flapping zarazen jako utok u nalezu klientu).
#[test]
fn infrastructure_signal_reaches_dependent_hosts_only_with_blast_radius() {
    let idx = Index::shared();
    let s = store_with(&["if_flap", "route_adj_change", "sys_link_down"], "10.0.0.1", 10_000);
    let client = vec!["10.0.0.57".to_string()];
    let off = diagnose(idx, &s, "connection_timeout_burst", &client, false, 10_000, &DiagPolicy::default());
    assert_eq!(off.class, "utok", "{off:?}");
    let on = DiagPolicy {
        blast: true,
        infra: ["10.0.0.1".to_string()].into_iter().collect(),
        ..DiagPolicy::default()
    };
    let d = diagnose(idx, &s, "connection_timeout_burst", &client, false, 10_000, &on);
    assert_eq!((d.class.as_str(), d.catalog_id.as_deref()), ("porucha", Some("OPS-002")), "{d:?}");
    // adresa, ktera neni infrastrukturni, dosah nema
    let other = DiagPolicy {
        blast: true,
        infra: ["10.0.0.99".to_string()].into_iter().collect(),
        ..DiagPolicy::default()
    };
    let d = diagnose(idx, &s, "connection_timeout_burst", &client, false, 10_000, &other);
    assert_eq!(d.class, "utok", "{d:?}");
}

#[test]
fn attack_types_are_never_reclassified() {
    let idx = Index::shared();
    let s = store_with(
        &["bcast_pps", "mac_flap", "stp_tc", "cpu_high"],
        "10.0.0.5",
        10_000,
    );
    let d = diagnose(
        idx,
        &s,
        "port_scan_horizontal",
        &["10.0.0.5".into()],
        false,
        10_000,
        &DiagPolicy::default(),
    );
    assert_eq!(d.class, "utok");
    assert!(d.catalog_id.is_none());
    assert!(d.explains_partly);
}

#[test]
fn missing_telemetry_is_reported_not_guessed() {
    let idx = Index::shared();
    let s = OpsStore::new(Limits::default());
    let d = diagnose(
        idx,
        &s,
        "service_unreachable",
        &["10.0.0.5".into()],
        true,
        10_000,
        &DiagPolicy::default(),
    );
    assert_eq!(d.class, "neurceno");
    assert!(d.reason.contains("chybí telemetrie"));
    assert!(d.missing.contains(&"snmp".to_string()));
    // typ nedostupnosti bez signálu a bez primárního zdroje: poruchu nelze vyloučit ani bez tokového vzoru
    let d = diagnose(idx, &s, "service_unreachable", &["10.0.0.5".into()], false, 10_000, &DiagPolicy::default());
    assert_eq!(d.class, "neurceno");
    // objemová anomálie bez tokového vzoru poruchy zůstává podezřením na útok
    let d = diagnose(idx, &s, "unexpected_traffic", &["10.0.0.5".into()], false, 10_000, &DiagPolicy::default());
    assert_eq!(d.class, "utok");
}

#[test]
fn behavioral_types_need_strong_match_and_signature_types_never_move() {
    let idx = Index::shared();
    // sken schválený správcem: jediný signál typu s jedním signálem stačí (CHG-011)
    let s = store_with(&["sys_scanner_job"], "10.0.0.5", 10_000);
    let d = diagnose(idx, &s, "scan_attempts", &["10.0.0.5".into()], false, 10_000, &DiagPolicy::default());
    assert_eq!((d.class.as_str(), d.catalog_id.as_deref()), ("zmena", Some("CHG-011")), "{d:?}");
    // slabý jediný signál typu s mnoha signály behaviorální nález nepřeřadí
    let s = store_with(&["uptime_reset"], "10.0.0.5", 10_000);
    let d = diagnose(idx, &s, "novel_fanout", &["10.0.0.5".into()], false, 10_000, &DiagPolicy::default());
    assert_eq!(d.class, "utok");
    // signaturní typ se nepřeřadí ani při dokonalé shodě
    let s = store_with(&["sys_scanner_job"], "10.0.0.5", 10_000);
    let d = diagnose(idx, &s, "suricata_alert", &["10.0.0.5".into()], false, 10_000, &DiagPolicy::default());
    assert_eq!(d.class, "utok");
}

#[test]
fn unknown_signals_are_undetermined_and_scope_is_respected() {
    let idx = Index::shared();
    let s = store_with(&["zzz_unknown"], "10.0.0.5", 10_000);
    let d = diagnose(
        idx,
        &s,
        "unexpected_traffic",
        &["10.0.0.5".into()],
        false,
        10_000,
        &DiagPolicy::default(),
    );
    assert_eq!(d.class, "neurceno");
    // jiný host: signál se netýká
    let d = diagnose(
        idx,
        &s,
        "unexpected_traffic",
        &["10.0.0.9".into()],
        false,
        10_000,
        &DiagPolicy::default(),
    );
    assert_eq!(d.class, "utok");
    // CIDR rozsah
    let s = store_with(&["if_oper_down", "snmp_timeout"], "10.0.0.0/24", 10_000);
    let d = diagnose(
        idx,
        &s,
        "unexpected_traffic",
        &["10.0.0.77".into()],
        false,
        10_000,
        &DiagPolicy::default(),
    );
    assert_eq!(d.catalog_id.as_deref(), Some("OPS-001"));
}

#[test]
fn store_limits_and_silent_sources() {
    let mut s = OpsStore::new(Limits {
        max_signals: 3,
        ..Limits::default()
    });
    for i in 0..5 {
        s.ingest(
            OpsSignal {
                at: 1000 + i,
                key: "cpu_high".into(),
                value: 1.0,
                scope: vec!["*".into()],
            },
            1000,
        );
    }
    assert_eq!(s.len(), 3);
    assert_eq!(s.evicted, 2);
    assert!(!s.ingest(
        OpsSignal {
            at: 1000,
            key: "Bad Key!".into(),
            value: 1.0,
            scope: vec![]
        },
        1000
    ));
    assert!(!s.ingest(
        OpsSignal {
            at: 1000,
            key: "cpu_high".into(),
            value: f64::NAN,
            scope: vec![]
        },
        1000
    ));
    assert!(s.silent_sources(1000).contains(&OpsSource::Dhcp));
    assert!(!s.silent_sources(1000).contains(&OpsSource::Snmp));
}

#[test]
fn adapters_parse_reference_lines() {
    use adapters::*;
    let r = |h: &str| (h == "sw1").then(|| "10.0.0.2".to_string());
    let a = parse_syslog(
        "<189>Nov 15 10:00:01 sw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
        5,
        &r,
    )
    .unwrap();
    assert_eq!(
        (a.key.as_str(), a.scope[0].as_str()),
        ("sys_link_down", "10.0.0.2")
    );
    let b = parse_syslog(
        "<34>1 2026-11-15T10:00:00Z db1 postgres - - - FATAL: too many open files",
        5,
        &|_| None,
    )
    .unwrap();
    assert_eq!(b.key, "sys_fd_limit");
    assert_eq!(b.at, 1_794_736_800);
    assert_eq!(
        parse_snmp("10.0.0.2 IF-MIB::ifOperStatus.3 = INTEGER: 2", 7)
            .unwrap()
            .key,
        "if_oper_down"
    );
    assert!(parse_snmp("10.0.0.2 IF-MIB::ifOperStatus.3 = INTEGER: 1", 7).is_none());
    assert_eq!(
        parse_prometheus("node_cpu_usage_percent{instance=\"10.0.0.7:9100\"} 97.5", 9)
            .unwrap()
            .scope[0],
        "10.0.0.7"
    );
    assert_eq!(
        parse_nagios(
            "[1700000000] SERVICE ALERT: web1;HTTP;CRITICAL;HARD;3;timeout",
            1
        )
        .unwrap()
        .key,
        "probe_http_fail"
    );
    assert_eq!(
        parse_dhcp(
            "dhcpd: DHCPDISCOVER from aa:bb:cc via 10.0.0.1: network 10.0.0.0/24: no free leases",
            3
        )
        .unwrap()
        .key,
        "dhcp_no_free"
    );
    assert_eq!(
        parse_chrony(
            "System time     : 0.500000000 seconds slow of NTP time",
            3,
            "h"
        )
        .unwrap()
        .value,
        -0.5
    );
    assert!(
        parse_chrony(
            "System time     : 0.000010000 seconds fast of NTP time",
            3,
            "h"
        )
        .is_none()
    );
}

#[test]
fn fuzz_adapters_never_panic() {
    use adapters::*;
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let words = [
        "<34>1",
        "sw1",
        "link",
        "down",
        "=",
        "INTEGER:",
        "ifOperStatus",
        "{",
        "}",
        "\"",
        ";",
        "[",
        "]",
        "10.0.0.1",
        "\u{1F600}",
        "-1e999",
        "NaN",
        "SERVICE ALERT:",
        "no free leases",
    ];
    let fuzz_n: u64 = std::env::var("SALTICUS_FUZZ_N").ok().and_then(|v| v.parse().ok()).unwrap_or(30_000);
    for _ in 0..fuzz_n {
        let n = (next() % 12) as usize;
        let mut line = String::new();
        for _ in 0..n {
            if next() % 3 == 0 {
                let b = (next() % 256) as u8;
                line.push(char::from(b));
            } else {
                line.push_str(words[(next() % words.len() as u64) as usize]);
                line.push(' ');
            }
        }
        for f in [
            Format::Syslog,
            Format::Snmp,
            Format::Prometheus,
            Format::Nagios,
            Format::Dhcp,
            Format::Arp,
        ] {
            let _ = parse_lines(f, &line, 0);
        }
        let _ = parse_chrony(&line, 0, "h");
    }
    let huge = "a".repeat(MAX_LINE + 10);
    assert!(parse_syslog(&huge, 0, &|_| None).is_none());
}
