//! Adaptéry linuxové koncové telemetrie (krok 14, A): Falco (JSON), Tetragon (JSON export),
//! auditd (textové záznamy `type=EXECVE`, `SYSCALL`, `SOCKADDR`).
//!
//! Stejná pravidla jako ostatní adaptéry: nedůvěryhodný vstup, žádná panika, neznámé záznamy
//! `Ok(None)`. Podpis binárky Linux nepřináší (`signed = None`); proces z balíčku se pozná podle
//! cesty (`known_signed`: `/usr/`, `/bin/`, `/sbin/`, `/lib/`). Zdroje formátů: dokumentace Falco
//! (pole `output_fields`, `priority`), Tetragon (`process_exec`, `process_kprobe tcp_connect`),
//! auditd (`audit.log` záznamy sdružené podle sériového čísla události).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{
    EndpointEvent, EndpointSource, ParseError, ParseResult, child, field,
    model::{Conn, EventKind, HostRef, Process, clip},
    parse_time, port, valid_ip,
};

/// Priorita Falco -> úroveň pravidla (stupnice Wazuh, 0 až 15).
fn falco_level(priority: &str) -> u8 {
    match priority.to_ascii_lowercase().as_str() {
        "emergency" | "alert" => 14,
        "critical" => 12,
        "error" => 10,
        "warning" => 8,
        "notice" => 6,
        "informational" | "info" => 4,
        _ => 3,
    }
}

fn host_ref(name: Option<String>) -> Result<HostRef, ParseError> {
    let name = name.ok_or_else(|| ParseError("chybi hostitel".into()))?;
    Ok(HostRef {
        hostname: Some(name.to_ascii_lowercase()),
        ..Default::default()
    })
}

/// Falco `json_output`: `{"time", "rule", "priority", "output", "hostname", "tags", "output_fields"}`.
/// Spojení (`evt.type` connect s `fd.sip`) je `NetConnect`, ostatní pravidla `Alert`.
pub fn parse_falco(map: &Map<String, Value>) -> ParseResult {
    let ts = field(map, &["time"])
        .and_then(|t| parse_time(&t))
        .ok_or_else(|| ParseError("chybi cas".into()))?;
    let rule = field(map, &["rule"]).ok_or_else(|| ParseError("chybi pravidlo".into()))?;
    let fields = child(map, "output_fields");
    let get = |k: &str| fields.and_then(|f| field(f, &[k]));
    let host = host_ref(field(map, &["hostname"]).or_else(|| get("evt.hostname")))?;
    if let (Some(sip), Some(sport)) = (get("fd.sip"), port(get("fd.sport")))
        && let Some(dst) = valid_ip(&sip)
        && get("evt.type").is_some_and(|t| t.starts_with("connect"))
    {
        return Ok(Some(EndpointEvent {
            source: EndpointSource::Falco,
            host,
            ts,
            kind: EventKind::NetConnect(Conn {
                image: get("proc.exepath").or_else(|| get("proc.name")),
                proto: get("fd.l4proto").unwrap_or_else(|| "tcp".into()),
                src_ip: get("fd.cip").and_then(|s| valid_ip(&s)),
                src_port: port(get("fd.cport")),
                dst_ip: dst,
                dst_port: sport,
                vendor: None,
                signed: None,
            }),
        }));
    }
    let tags: Vec<String> = map
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .take(16)
                .map(clip)
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(EndpointEvent {
        source: EndpointSource::Falco,
        host,
        ts,
        kind: EventKind::Alert {
            rule_id: clip(&rule),
            level: falco_level(&field(map, &["priority"]).unwrap_or_default()),
            groups: tags,
            description: clip(&field(map, &["output"]).unwrap_or_default()),
        },
    }))
}

/// Tetragon export: `process_exec` -> `ProcessCreate`, `process_kprobe` `tcp_connect` -> `NetConnect`.
pub fn parse_tetragon(map: &Map<String, Value>) -> ParseResult {
    let ts = field(map, &["time"])
        .and_then(|t| parse_time(&t))
        .ok_or_else(|| ParseError("chybi cas".into()))?;
    let host = host_ref(field(map, &["node_name"]))?;
    if let Some(exec) = child(map, "process_exec") {
        let process = child(exec, "process").ok_or_else(|| ParseError("chybi process".into()))?;
        let binary = field(process, &["binary"]).ok_or_else(|| ParseError("chybi binary".into()))?;
        let args = field(process, &["arguments"]).unwrap_or_default();
        return Ok(Some(EndpointEvent {
            source: EndpointSource::Tetragon,
            host,
            ts,
            kind: EventKind::ProcessCreate(Process {
                parent_image: child(exec, "parent").and_then(|p| field(p, &["binary"])),
                cmdline: clip(&format!("{binary} {args}").trim().to_string()),
                image: binary,
                user: field(process, &["uid"]).map(|u| format!("uid:{u}")),
                signed: None,
                vendor: None,
                hash: None,
            }),
        }));
    }
    if let Some(kp) = child(map, "process_kprobe") {
        if field(kp, &["function_name"]).as_deref() != Some("tcp_connect") {
            return Ok(None);
        }
        let process = child(kp, "process");
        let sock = kp
            .get("args")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find_map(|x| child(x.as_object()?, "sock_arg")));
        let Some(sock) = sock else {
            return Ok(None);
        };
        let dst = field(sock, &["daddr"])
            .and_then(|s| valid_ip(&s))
            .ok_or_else(|| ParseError("chybi cil".into()))?;
        return Ok(Some(EndpointEvent {
            source: EndpointSource::Tetragon,
            host,
            ts,
            kind: EventKind::NetConnect(Conn {
                image: process.and_then(|p| field(p, &["binary"])),
                proto: "tcp".into(),
                src_ip: field(sock, &["saddr"]).and_then(|s| valid_ip(&s)),
                src_port: port(field(sock, &["sport"])),
                dst_ip: dst,
                dst_port: port(field(sock, &["dport"])).ok_or_else(|| ParseError("chybi port".into()))?,
                vendor: None,
                signed: None,
            }),
        }));
    }
    Ok(None)
}

/// Hodnota `key=value` nebo `key="value"` z auditd řádku.
fn kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!(" {key}=");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()
    } else {
        rest.split_whitespace().next()
    }
}

/// `msg=audit(1700000000.123:456)` -> (čas, sériové číslo).
fn audit_stamp(line: &str) -> Option<(i64, String)> {
    let start = line.find("msg=audit(")? + "msg=audit(".len();
    let rest = &line[start..];
    let (time, serial) = rest.split(')').next()?.split_once(':')?;
    Some((time.parse::<f64>().ok()? as i64, serial.to_string()))
}

/// IPv4 `saddr` z SOCKADDR: `02 family`, port 2 bajty, adresa 4 bajty (hex, 8+ znaků po rodině).
fn sockaddr_v4(hex: &str) -> Option<(String, u16)> {
    let h = hex.trim();
    if h.len() < 16 || !h.bytes().all(|b| b.is_ascii_hexdigit()) || &h[..4] != "0200" {
        return None;
    }
    let port = u16::from_str_radix(&h[4..8], 16).ok()?;
    let a = u8::from_str_radix(&h[8..10], 16).ok()?;
    let b = u8::from_str_radix(&h[10..12], 16).ok()?;
    let c = u8::from_str_radix(&h[12..14], 16).ok()?;
    let d = u8::from_str_radix(&h[14..16], 16).ok()?;
    Some((format!("{a}.{b}.{c}.{d}"), port))
}

/// Dávka auditd záznamů; záznamy téže události se sdružují podle sériového čísla.
/// `host` doplní volající (auditd ho ve výchozím stavu nenese; pole `node=` má přednost).
pub fn parse_auditd(text: &str, host: Option<&str>) -> Vec<Result<EndpointEvent, ParseError>> {
    #[derive(Default)]
    struct Group {
        ts: i64,
        host: Option<String>,
        exe: Option<String>,
        comm: Option<String>,
        uid: Option<String>,
        ppid: Option<String>,
        syscall: Option<String>,
        success: bool,
        argv: BTreeMap<usize, String>,
        sockaddr: Option<(String, u16)>,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for line in text.lines().take(200_000) {
        if line.len() > 8 * 1024 {
            continue;
        }
        let Some((ts, serial)) = audit_stamp(line) else {
            continue;
        };
        let g = groups.entry(serial).or_default();
        g.ts = ts;
        if let Some(n) = kv(line, "node") {
            g.host = Some(n.to_string());
        }
        let ty = line
            .strip_prefix("type=")
            .and_then(|r| r.split_whitespace().next())
            .unwrap_or("");
        match ty {
            "SYSCALL" => {
                g.exe = kv(line, "exe").map(str::to_string);
                g.comm = kv(line, "comm").map(str::to_string);
                g.uid = kv(line, "uid").map(str::to_string);
                g.ppid = kv(line, "ppid").map(str::to_string);
                g.syscall = kv(line, "syscall").map(str::to_string);
                g.success = kv(line, "success") == Some("yes");
            }
            "EXECVE" => {
                for i in 0..64usize {
                    match kv(line, &format!("a{i}")) {
                        Some(v) => {
                            g.argv.insert(i, v.to_string());
                        }
                        None => break,
                    }
                }
            }
            "SOCKADDR" => {
                g.sockaddr = kv(line, "saddr").and_then(sockaddr_v4);
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for g in groups.into_values() {
        let hostname = match g.host.clone().or_else(|| host.map(str::to_string)) {
            Some(h) => h,
            None => {
                out.push(Err(ParseError("auditd: chybi hostitel (node=)".into())));
                continue;
            }
        };
        let host_ref = HostRef {
            hostname: Some(hostname.to_ascii_lowercase()),
            ..Default::default()
        };
        // connect(2) na x86_64 je syscall 42; vyžaduje SOCKADDR
        if g.syscall.as_deref() == Some("42")
            && g.success
            && let Some((ip, p)) = g.sockaddr.clone()
        {
            out.push(Ok(EndpointEvent {
                source: EndpointSource::Auditd,
                host: host_ref,
                ts: g.ts,
                kind: EventKind::NetConnect(Conn {
                    image: g.exe.clone(),
                    proto: "tcp".into(),
                    src_ip: None,
                    src_port: None,
                    dst_ip: ip,
                    dst_port: p,
                    vendor: None,
                    signed: None,
                }),
            }));
            continue;
        }
        if !g.argv.is_empty() {
            let cmd = g.argv.values().cloned().collect::<Vec<_>>().join(" ");
            let image = g
                .exe
                .clone()
                .or_else(|| g.argv.get(&0).cloned())
                .or(g.comm.clone());
            if let Some(image) = image {
                out.push(Ok(EndpointEvent {
                    source: EndpointSource::Auditd,
                    host: host_ref,
                    ts: g.ts,
                    kind: EventKind::ProcessCreate(Process {
                        image,
                        parent_image: g.ppid.as_ref().map(|p| format!("pid:{p}")),
                        cmdline: clip(&cmd),
                        user: g.uid.as_ref().map(|u| format!("uid:{u}")),
                        signed: None,
                        vendor: None,
                        hash: None,
                    }),
                }));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(s: &str) -> Map<String, Value> {
        serde_json::from_str::<Value>(s)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn falco_alert_and_connect() {
        let a = parse_falco(&obj(
            r#"{"time":"2026-11-15T10:00:00Z","rule":"Terminal shell in container","priority":"Notice","output":"shell spawned","hostname":"K8S-1","tags":["container","shell"],"output_fields":{"proc.name":"bash"}}"#,
        ))
        .unwrap()
        .unwrap();
        assert!(matches!(&a.kind, EventKind::Alert { level: 6, .. }));
        assert_eq!(a.host.hostname.as_deref(), Some("k8s-1"));
        let c = parse_falco(&obj(
            r#"{"time":"2026-11-15T10:00:01Z","rule":"Outbound","priority":"Warning","output":"x","hostname":"h","output_fields":{"evt.type":"connect","fd.sip":"203.0.113.9","fd.sport":"4444","proc.exepath":"/tmp/x"}}"#,
        ))
        .unwrap()
        .unwrap();
        assert!(matches!(&c.kind, EventKind::NetConnect(Conn { dst_port: 4444, .. })));
        assert!(parse_falco(&obj(r#"{"rule":"x"}"#)).is_err());
    }

    #[test]
    fn tetragon_exec_and_connect() {
        let e = parse_tetragon(&obj(
            r#"{"process_exec":{"process":{"binary":"/bin/sh","arguments":"-c id","uid":0},"parent":{"binary":"/usr/sbin/nginx"}},"node_name":"n1","time":"2026-11-15T10:00:00Z"}"#,
        ))
        .unwrap()
        .unwrap();
        match &e.kind {
            EventKind::ProcessCreate(p) => {
                assert_eq!(p.parent_image.as_deref(), Some("/usr/sbin/nginx"));
                assert_eq!(p.cmdline, "/bin/sh -c id");
            }
            other => panic!("{other:?}"),
        }
        let c = parse_tetragon(&obj(
            r#"{"process_kprobe":{"function_name":"tcp_connect","process":{"binary":"/usr/bin/curl"},"args":[{"sock_arg":{"saddr":"10.0.0.5","daddr":"198.51.100.7","sport":40000,"dport":443}}]},"node_name":"n1","time":"2026-11-15T10:00:00Z"}"#,
        ))
        .unwrap()
        .unwrap();
        assert!(matches!(&c.kind, EventKind::NetConnect(Conn { dst_port: 443, .. })));
        assert!(parse_tetragon(&obj(r#"{"process_kprobe":{"function_name":"other"},"node_name":"n","time":"2026-11-15T10:00:00Z"}"#)).unwrap().is_none());
    }

    #[test]
    fn auditd_groups_records_by_serial() {
        let text = "\
type=SYSCALL msg=audit(1700000000.100:10): arch=c000003e syscall=59 success=yes exit=0 ppid=77 pid=88 uid=33 comm=\"sh\" exe=\"/bin/dash\" node=web1\n\
type=EXECVE msg=audit(1700000000.100:10): argc=3 a0=\"sh\" a1=\"-c\" a2=\"id\"\n\
type=SYSCALL msg=audit(1700000001.200:11): arch=c000003e syscall=42 success=yes exit=0 uid=33 comm=\"curl\" exe=\"/usr/bin/curl\" node=web1\n\
type=SOCKADDR msg=audit(1700000001.200:11): saddr=0200115CC6336407\n";
        let events: Vec<_> = parse_auditd(text, None).into_iter().map(Result::unwrap).collect();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0].kind, EventKind::ProcessCreate(p) if p.cmdline == "sh -c id"));
        match &events[1].kind {
            EventKind::NetConnect(c) => assert_eq!((c.dst_ip.as_str(), c.dst_port), ("198.51.100.7", 4444)),
            other => panic!("{other:?}"),
        }
        // bez node= a bez hostitele od volajícího je to chyba, ne panika
        let only = "type=SYSCALL msg=audit(1700000000.100:10): syscall=59 success=yes exe=\"/bin/sh\"\ntype=EXECVE msg=audit(1700000000.100:10): argc=1 a0=\"sh\"\n";
        assert!(parse_auditd(only, None)[0].is_err());
        assert!(parse_auditd(only, Some("h"))[0].is_ok());
    }

    #[test]
    fn fuzz_linux_adapters_never_panic() {
        let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let words = ["type=SYSCALL", "msg=audit(", "1700000000.1:2)", "a0=\"", "saddr=0200", "node=", "{", "}", "\"", "process_exec", "time", "\u{1F600}"];
        for _ in 0..30_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % 14) as usize;
            let mut line = String::new();
            for i in 0..n {
                line.push_str(words[((x >> (i * 3)) % words.len() as u64) as usize]);
                line.push(if x & 1 == 0 { ' ' } else { '=' });
            }
            let _ = parse_auditd(&line, Some("h"));
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&line) {
                let _ = parse_falco(&m);
                let _ = parse_tetragon(&m);
            }
        }
    }
}
