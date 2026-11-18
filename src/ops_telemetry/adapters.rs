//! Adaptéry provozní telemetrie: text nebo JSON z nástrojů -> `OpsSignal`.
//!
//! Vstup je nedůvěryhodný: řádek ≤ 8 KiB, nikdy panika, neznámý řádek = `None`.
//! Formáty: syslog (RFC 5424 i BSD RFC 3164), SNMP (`snmpwalk`/`snmpget` text a JSON),
//! Prometheus text exposition (node_exporter, blackbox_exporter), Nagios (status a
//! notifikační řádky), DHCP (ISC dhcpd a Kea), chrony `tracking`, tabulka ARP.
//! Tabulky vzorů jsou záměrně prosté podřetězce malými písmeny: srozumitelné, testovatelné,
//! bez regex. Hodnoty prahů (např. chyby rozhraní, zaplnění poolu) jsou v `thresholds`.

use super::OpsSignal;

pub const MAX_LINE: usize = 8 * 1024;

/// Prahy převodu veličiny na signál. Zdroje (studie 14-provozni-telemetrie, řádky extrakce P14-xxx):
/// Zabbix šablony `{$IF.ERRORS.WARN}` = 2 a `{$IF.UTIL.MAX}` = 95 (P14-031), komunitní pravidla
/// Prometheus: chyby rozhraní > 1 % paketů, využití > 80 % (P14-023, komunitní výchozí hodnoty, ne
/// norma); NTP STEPT 125 ms (RFC 5905, P14-011); Kerberos toleruje typicky 5 minut (P14-014).
/// Prahy jsou volba autora podložená těmito zdroji a měří se citlivostní analýzou, ne předpokládají.
pub mod thresholds {
    /// Zaplnění CPU, paměti, disku v procentech (Zabbix triggery a node_exporter pravidla: 90 %).
    pub const UTIL_PCT: f64 = 90.0;
    /// Využití linky v procentech: komunitní Prometheus 80 % (Zabbix 95 %).
    pub const IF_UTIL_PCT: f64 = 80.0;
    /// Využití DHCP poolu v procentech (volba autora; ISC dhcpd a Kea mají čítače, ne práh).
    pub const DHCP_POOL_PCT: f64 = 95.0;
    /// Offset hodin v sekundách: NTP STEPT 125 ms (RFC 5905).
    pub const NTP_OFFSET_S: f64 = 0.125;
    /// Chyby rozhraní za sekundu (jakákoli trvalá nenula u média je porucha; Zabbix WARN = 2).
    pub const IF_ERR_RATE: f64 = 0.1;
}

/// Syslog zpráva -> klíč signálu. Pořadí je pořadí přednosti (specifické před obecným).
const SYSLOG: &[(&[&str], &str)] = &[
    (&["late collision"], "if_late_collision"),
    (&["duplex mismatch"], "if_duplex_mismatch"),
    (&["crc", "fcs"], "if_crc"),
    (&["input errors"], "if_in_errors"),
    (&["native vlan mismatch"], "sys_native_vlan_mismatch"),
    (&["dhcp snooping", "untrusted"], "sys_dhcp_snoop_viol"),
    (&["port-security"], "sys_port_sec_viol"),
    (&["psecure"], "sys_port_sec_viol"),
    (&["duplicate address"], "sys_dup_addr"),
    (&["duplicate ip"], "sys_dup_addr"),
    (&["mac flapping"], "mac_flap"),
    (&["is flapping between port"], "mac_flap"),
    (&["topology change"], "stp_tc"),
    (&["stp", "tcn"], "stp_tc"),
    (&["no free leases"], "dhcp_no_free"),
    // krok 17: dnsmasq „DHCPDISCOVER(eth0) MAC no address available“ = vyčerpaný pool
    (&["no address available"], "dhcp_no_free"),
    // krok 17: klient se vzdal bez nabídky (busybox udhcpc, ISC dhclient)
    (&["no lease, forking"], "dhcp_no_offer"),
    (&["no dhcpoffers received"], "dhcp_no_offer"),
    (&["dhcp", "service stopped"], "dhcp_service_down"),
    // krok 17: DHCP server dnsmasq ukončen („dnsmasq-dhcp ... exiting on receipt of SIGTERM“)
    (&["dnsmasq-dhcp", "exiting on receipt"], "dhcp_service_down"),
    // krok 17: unbound „error: SERVFAIL <name>: all the configured stub or forward servers failed“
    (&["error: servfail"], "dns_servfail"),
    // krok 17: supervisord „exited: app (terminated by SIGKILL; not expected)“, „entered FATAL state“
    (&["exited:", "not expected"], "sys_proc_crash"),
    (&["entered fatal state"], "sys_proc_crash"),
    (&["helper-address"], "dhcp_relay_missing"),
    (&["certificate has expired"], "sys_cert_expired"),
    (&["certificate expired"], "sys_cert_expired"),
    (&["unable to get local issuer"], "sys_cert_chain"),
    (&["krb_ap_err_skew"], "sys_krb_skew"),
    (&["clock skew too great"], "sys_krb_skew"),
    (&["kdc", "unreachable"], "sys_krb_dc_error"),
    (&["ike", "fail"], "sys_ike_fail"),
    (&["ike", "negotiation"], "sys_ike_fail"),
    (&["license", "expired"], "sys_license_expired"),
    (&["oom-killer"], "sys_oom"),
    (&["out of memory"], "sys_oom"),
    (&["no space left"], "sys_disk_full"),
    (&["too many open files"], "sys_fd_limit"),
    (&["nf_conntrack", "table full"], "sys_conntrack_full"),
    (&["slow query"], "sys_slow_query"),
    (&["process", "crashed"], "sys_proc_crash"),
    (&["segfault"], "sys_proc_crash"),
    (&["scheduled restart"], "sys_service_restart"),
    (&["restart counter"], "sys_service_restart"),
    (&["health check failed"], "sys_health_fail"),
    (&["backend", "marked down"], "lb_backend_down"),
    (&["ap lost controller"], "sys_ap_lost_ctrl"),
    (&["capwap", "lost"], "sys_ap_lost_ctrl"),
    (&["queue", "deferred"], "sys_mail_deferred"),
    (&["backup", "failed"], "sys_backup_fail"),
    (&["backup job still running"], "backup_running_long"),
    (&["backup job"], "sys_backup_job"),
    (&["update failed"], "sys_update_failed"),
    (&["update installed"], "sys_update_installed"),
    (&["pending reboot"], "sys_pending_reboot"),
    (&["change ticket"], "sys_change_ticket"),
    (&["waf", "block"], "sys_waf_block"),
    (&["http 5", "upstream"], "sys_http_5xx"),
    (&["icmp", "frag needed"], "sys_icmp_frag_blocked"),
    (&["icmp", "deny"], "sys_icmp_deny"),
    (&["null0"], "sys_route_null0"),
    (&["out-of-state"], "sys_oos_drop"),
    (&["accepted publickey"], "sys_sshd_key_accept"),
    (&["scanner", "started"], "sys_scanner_job"),
    (&["directory sync"], "sys_dir_sync"),
    (&["replication stream"], "sys_repl_stream"),
    (&["replication lag"], "repl_lag"),
    (&["boot", "system restarted"], "sys_boot"),
    (&["%sys-5-restart"], "sys_boot"),
    (&["link down"], "sys_link_down"),
    (&["changed state to down"], "sys_link_down"),
    (&["linkdown"], "sys_link_down"),
    (&["power", "fail"], "power_fail"),
    (&["adjacency", "down"], "route_adj_change"),
    (&["neighbor", "down"], "route_adj_change"),
    (&["qos", "drop"], "qos_drop"),
];

fn lower_clip(line: &str) -> Option<String> {
    if line.len() > MAX_LINE || line.trim().is_empty() {
        return None;
    }
    Some(line.to_ascii_lowercase())
}

/// Čas z RFC 5424 hlavičky `<PRI>1 TIMESTAMP HOST ...`; jinak `fallback`.
fn syslog_time(line: &str, fallback: i64) -> i64 {
    let mut it = line.split_whitespace();
    let first = it.next().unwrap_or("");
    if first.starts_with('<')
        && first.contains('>')
        && first.ends_with('1')
        && let Some(ts) = it.next()
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts)
    {
        return dt.timestamp();
    }
    fallback
}

/// Hostitel zdroje z hlavičky (RFC 5424: třetí pole; RFC 3164: čtvrté po času `Mmm dd hh:mm:ss`).
fn syslog_host(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    let host = if first.starts_with('<') && first.contains('>') && first.ends_with('1') {
        parts.nth(1)
    } else {
        // BSD: [<PRI>]Mmm dd hh:mm:ss host ...
        // měsíc (PRI může lepit na měsíc), den, čas, host; `first` je měsíc
        parts.nth(2)
    }?;
    let ok = host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
    ok.then(|| host.to_string())
}

/// Jeden řádek syslogu -> signál. `device_ips` převádí jméno hosta na IP (jinak se hostname
/// použije jako rozsah). `fallback` = čas příjmu.
pub fn parse_syslog(
    line: &str,
    fallback: i64,
    resolve: &dyn Fn(&str) -> Option<String>,
) -> Option<OpsSignal> {
    let low = lower_clip(line)?;
    let key = SYSLOG
        .iter()
        .find(|(needles, _)| needles.iter().all(|n| low.contains(n)))?
        .1;
    let host = syslog_host(line)?;
    let scope = resolve(&host).unwrap_or(host);
    Some(OpsSignal {
        at: syslog_time(line, fallback),
        key: key.to_string(),
        value: 1.0,
        scope: vec![scope],
    })
}

/// Veličina (jméno metriky z Prometheus/Zabbix/SNMP) a hodnota -> signál, pokud překročí práh.
pub fn metric_signal(name: &str, value: f64, at: i64, scope: &str) -> Option<OpsSignal> {
    if !value.is_finite() {
        return None;
    }
    let n = name.to_ascii_lowercase();
    let t = thresholds::UTIL_PCT;
    let key = if n.contains("ifoperstatus") || n.contains("ifoper") {
        // IF-MIB ifOperStatus: 1 up, 2 down (RFC 2863)
        (value == 2.0 || value == 7.0).then_some("if_oper_down")
    } else if n.contains("node_network_up") || n == "up" {
        (value == 0.0).then_some("if_oper_down")
    } else if n.contains("ifinerrors")
        || n.contains("node_network_receive_errs")
        || n.contains("dot3statsalignmenterrors")
    {
        (value >= thresholds::IF_ERR_RATE).then_some("if_in_errors")
    } else if n.contains("dot3statsfcserrors") {
        (value >= thresholds::IF_ERR_RATE).then_some("if_crc")
    } else if n.contains("dot3statslatecollisions") {
        (value >= 1.0).then_some("if_late_collision")
    } else if n.contains("ifoutdiscards") {
        (value >= thresholds::IF_ERR_RATE).then_some("if_out_discards")
    } else if n.contains("util") && n.contains("if") {
        (value >= thresholds::IF_UTIL_PCT).then_some("if_util_high")
    } else if n.contains("cpu") {
        (value >= t).then_some("cpu_high")
    } else if n.contains("iowait") || n.contains("io_wait") {
        (value >= 30.0).then_some("io_wait_high")
    } else if n.contains("memory") || n.contains("mem_used") {
        (value >= t).then_some("mem_high")
    } else if (n.contains("filesystem") || n.contains("disk") || n.contains("storage"))
        && (n.contains("pct")
            || n.contains("percent")
            || n.contains("pused")
            || n.contains("used_ratio"))
    {
        // jen procento zaplnění; syrové bajty (node_filesystem_avail_bytes, hrStorageUsed v blocích)
        // nejsou procento a nesmí se porovnávat s prahem 90 (chyba kroku 14: vždy nad prahem).
        let pct = if n.contains("ratio") {
            value * 100.0
        } else {
            value
        };
        (pct >= t).then_some("disk_high")
    } else if n.contains("conntrack") {
        (value >= t).then_some("conntrack_high")
    } else if n.contains("sysuptime") || n.contains("node_boot_time") {
        // pokles uptime (reset) hlásí zdroj jako zápornou deltu
        (value < 0.0).then_some("uptime_reset")
    } else if n.contains("dhcp") && n.contains("pool") {
        (value >= thresholds::DHCP_POOL_PCT).then_some("dhcp_pool_high")
    } else if n.contains("ntp") && (n.contains("offset") || n.contains("skew")) {
        (value.abs() >= thresholds::NTP_OFFSET_S).then_some("ntp_offset")
    } else if n.contains("probe_success") {
        (value == 0.0).then_some("probe_http_fail")
    } else if n.contains("ssl_earliest_cert_expiry") || n.contains("cert_days_left") {
        (value <= 0.0).then_some("probe_tls_expired")
    } else if n.contains("topologychange") || n.contains("stp_tc") {
        (value >= 1.0).then_some("stp_tc")
    } else if n.contains("repl") && n.contains("lag") {
        (value >= 60.0).then_some("repl_lag")
    } else {
        None
    }?;
    Some(OpsSignal {
        at,
        key: key.to_string(),
        value,
        scope: vec![scope.to_string()],
    })
}

/// Prometheus text exposition: `metric{labels} value [ts]`; `instance` štítek = rozsah.
pub fn parse_prometheus(line: &str, now: i64) -> Option<OpsSignal> {
    if line.len() > MAX_LINE {
        return None;
    }
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (head, rest) = match line.find('}') {
        Some(i) => (&line[..=i], line[i + 1..].trim()),
        None => {
            let mut it = line.splitn(2, char::is_whitespace);
            (it.next()?, it.next()?.trim())
        }
    };
    let name = head.split('{').next()?;
    let labels = head.get(name.len()..).unwrap_or("");
    let value: f64 = rest.split_whitespace().next()?.parse().ok()?;
    let instance = labels
        .split("instance=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.split(':').next().unwrap_or(s))
        .unwrap_or("*");
    metric_signal(name, value, now, instance)
}

/// SNMP text `host oid = TYPE: value` (po `snmpwalk -On`/`-OQ`) -> signál.
pub fn parse_snmp(line: &str, now: i64) -> Option<OpsSignal> {
    if line.len() > MAX_LINE {
        return None;
    }
    let (left, right) = line.split_once('=')?;
    let mut lp = left.split_whitespace();
    let host = lp.next()?;
    let oid = lp.next()?;
    let value: f64 = right
        .rsplit(|c: char| c == ':' || c.is_whitespace() || c == '(')
        .find(|t| !t.is_empty())?
        .trim_end_matches(')')
        .parse()
        .ok()?;
    metric_signal(oid, value, now, host)
}

/// Nagios: `[ts] SERVICE ALERT: host;service;CRITICAL;HARD;n;output` a `HOST ALERT: host;DOWN;...`.
pub fn parse_nagios(line: &str, now: i64) -> Option<OpsSignal> {
    if line.len() > MAX_LINE {
        return None;
    }
    let at = line
        .strip_prefix('[')
        .and_then(|s| s.split(']').next())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(now);
    let (kind, rest) = line.split_once(": ").map(|(a, b)| {
        let k = a.rsplit(']').next().unwrap_or(a).trim();
        (k, b)
    })?;
    let f: Vec<&str> = rest.split(';').collect();
    let host = f.first()?.trim();
    if host.is_empty() {
        return None;
    }
    let key = match kind {
        "HOST ALERT"
            if f.get(1)
                .is_some_and(|s| *s == "DOWN" || *s == "UNREACHABLE") =>
        {
            "probe_icmp_fail"
        }
        "SERVICE ALERT" if f.get(2).is_some_and(|s| *s == "CRITICAL") => {
            let svc = f.get(1)?.to_ascii_lowercase();
            let out = f.get(5).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
            if svc.contains("http") || svc.contains("web") {
                "probe_http_fail"
            } else if svc.contains("dns") {
                // check_dns se shodou proti autoritě: „expected X but got Y“ = zastaralý/špatný
                // záznam resolveru; „N seconds response time“ nad kritickým prahem = latence
                // (krok 17: dříve padalo na nedostupnost); SERVFAIL; jinak nedostupnost.
                if out.contains("expected") && out.contains("but got") {
                    "dns_stale_record"
                } else if out.contains("response time") {
                    if let Some(v) = out
                        .split("critical -")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .and_then(|s| s.parse::<f64>().ok())
                    {
                        return Some(OpsSignal {
                            at,
                            key: "dns_latency".to_string(),
                            value: v,
                            scope: vec![host.to_string()],
                        });
                    }
                    "probe_dns_fail"
                } else if out.contains("servfail") {
                    "dns_servfail"
                } else {
                    "probe_dns_fail"
                }
            } else if svc.contains("ntp") || svc.contains("time") {
                // check_ntp_time: „Offset N secs“ -> ntp_offset s číselnou hodnotou; bez čísla
                // (žádná odpověď) spadne na nedostupnost.
                if let Some(v) = out
                    .split("offset")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .and_then(|s| s.parse::<f64>().ok())
                {
                    return Some(OpsSignal {
                        at,
                        key: "ntp_offset".to_string(),
                        value: v,
                        scope: vec![host.to_string()],
                    });
                }
                "ntp_unreach"
            } else if svc.contains("ping") || svc.contains("icmp") {
                "probe_icmp_fail"
            } else if svc.contains("cert") {
                // krok 17: prošlý certifikát jen podle textu; „connection failed“/timeout je
                // nedostupnost služby, ne certifikát (dříve chybně probe_tls_expired)
                if out.contains("expired") || out.contains("not yet valid") {
                    "probe_tls_expired"
                } else {
                    "probe_http_fail"
                }
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(OpsSignal {
        at,
        key: key.to_string(),
        value: 1.0,
        scope: vec![host.to_string()],
    })
}

/// DHCP: ISC dhcpd (`DHCPDISCOVER ... no free leases`) a Kea (`DHCP4_...`).
pub fn parse_dhcp(line: &str, now: i64) -> Option<OpsSignal> {
    let low = lower_clip(line)?;
    let key = if low.contains("no free leases")
        || low.contains("dhcp4_lease_alloc_fail")
        || low.contains("no address available")
    {
        "dhcp_no_free"
    } else if low.contains("no lease, forking") || low.contains("no dhcpoffers received") {
        // krok 17: klient se vzdal bez nabídky (udhcpc, dhclient)
        "dhcp_no_offer"
    } else if low.contains("dnsmasq") && low.contains("exiting on receipt") {
        // krok 17: DHCP server dnsmasq ukončen
        "dhcp_service_down"
    } else if low.contains("pool") && (low.contains("exhaust") || low.contains("100%")) {
        "dhcp_pool_high"
    } else if low.contains("dhcpoffer") && low.contains("unknown server") {
        "dhcp_rogue_offer"
    } else if low.contains("bad lease") || low.contains("wrong network") {
        "dhcp_bad_lease"
    } else if low.contains("dhcpdiscover") && low.contains("no dhcpoffer") {
        "dhcp_no_offer"
    } else {
        return None;
    };
    let mut ips = Vec::new();
    super::ips_in(line, &mut ips);
    Some(OpsSignal {
        at: now,
        key: key.to_string(),
        value: 1.0,
        scope: if ips.is_empty() {
            vec!["*".to_string()]
        } else {
            ips.truncate(4);
            ips
        },
    })
}

/// chrony `tracking`: `System time     : 0.000012345 seconds fast of NTP time`.
pub fn parse_chrony(line: &str, now: i64, host: &str) -> Option<OpsSignal> {
    if line.len() > MAX_LINE {
        return None;
    }
    let l = line.trim();
    if !l.starts_with("System time") {
        return None;
    }
    let v: f64 = l
        .split(':')
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let slow = l.contains("slow");
    let off = if slow { -v } else { v };
    (off.abs() >= thresholds::NTP_OFFSET_S).then(|| OpsSignal {
        at: now,
        key: "ntp_offset".into(),
        value: off,
        scope: vec![host.to_string()],
    })
}

/// ARP/ND: `ip mac state` řádek; konflikt = dvě MAC pro jednu IP, předává volající po sloučení.
pub fn parse_arp(line: &str, now: i64) -> Option<OpsSignal> {
    let low = lower_clip(line)?;
    // arpwatch: „flip flop“ = jedna IP střídá dvě MAC (duplicitní adresa nebo ARP spoofing);
    // „changed ethernet address“ = nová MAC pro známou IP.
    let key = if low.contains("duplicate") || low.contains("conflict") || low.contains("flip flop")
    {
        "arp_conflict"
    } else if low.contains("new station")
        || low.contains("new mac")
        || low.contains("changed ethernet address")
    {
        "arp_new_mac"
    } else {
        return None;
    };
    let mut ips = Vec::new();
    super::ips_in(line, &mut ips);
    Some(OpsSignal {
        at: now,
        key: key.to_string(),
        value: 1.0,
        scope: if ips.is_empty() {
            vec!["*".to_string()]
        } else {
            ips.truncate(4);
            ips
        },
    })
}

/// Format vstupu pro společný příjem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Syslog,
    Snmp,
    Prometheus,
    Nagios,
    Dhcp,
    Arp,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "syslog" => Ok(Format::Syslog),
            "snmp" => Ok(Format::Snmp),
            "prometheus" => Ok(Format::Prometheus),
            "nagios" => Ok(Format::Nagios),
            "dhcp" => Ok(Format::Dhcp),
            "arp" => Ok(Format::Arp),
            other => Err(format!(
                "neznamy format {other} (syslog | snmp | prometheus | nagios | dhcp | arp)"
            )),
        }
    }
}

/// Dávka řádků jednoho formátu; vrací signály, počet neznámých/odmítnutých řádků zbývá volajícímu.
pub fn parse_lines(format: Format, text: &str, now: i64) -> Vec<OpsSignal> {
    text.lines()
        .take(50_000)
        .filter_map(|l| match format {
            Format::Syslog => parse_syslog(l, now, &|_| None),
            Format::Snmp => parse_snmp(l, now),
            Format::Prometheus => parse_prometheus(l, now),
            Format::Nagios => parse_nagios(l, now),
            Format::Dhcp => parse_dhcp(l, now),
            Format::Arp => parse_arp(l, now),
        })
        .collect()
}
