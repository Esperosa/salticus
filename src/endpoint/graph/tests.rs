use super::*;
use crate::endpoint::{
    correlate::{Limits, Resolution},
    model::{Conn, EndpointSource, HostRef, Logon, Process},
};

const T0: i64 = 1_800_000_000;

fn put(store: &mut EndpointStore, host: &str, ts: i64, kind: EventKind) {
    let e = EndpointEvent {
        source: EndpointSource::Sim,
        host: HostRef {
            hostname: Some(host.into()),
            ..Default::default()
        },
        ts,
        kind,
    };
    store.ingest(e, &Resolution::Unique(host.into()), T0 + 1000);
}

fn proc(image: &str, parent: &str, cmd: &str, user: &str, hash: Option<&str>) -> EventKind {
    EventKind::ProcessCreate(Process {
        image: image.into(),
        parent_image: Some(parent.into()),
        cmdline: cmd.into(),
        user: Some(user.into()),
        signed: Some(true),
        vendor: Some("Veeam Software".into()),
        hash: hash.map(str::to_string),
    })
}

fn conn(image: &str, dst: &str) -> EventKind {
    EventKind::NetConnect(Conn {
        image: Some(image.into()),
        proto: "tcp".into(),
        src_ip: None,
        src_port: None,
        dst_ip: dst.into(),
        dst_port: 443,
        vendor: None,
        signed: None,
    })
}

#[test]
fn cmdline_secrets_are_redacted() {
    let r = redact_cmdline(
        "curl.exe -u admin --password hunter2 https://x/?token=abc123 -p s3cr3t --flag ok",
    );
    assert!(
        !r.contains("hunter2") && !r.contains("abc123") && !r.contains("s3cr3t"),
        "{r}"
    );
    assert!(r.contains("--flag ok"));
    let enc = "A".repeat(60);
    assert!(!redact_cmdline(&format!("powershell -nop {enc}")).contains(&enc));
    assert!(!redact_cmdline("powershell -EncodedCommand SQBFAFgA").contains("SQBFAFgA"));
    assert_eq!(redact_cmdline("notepad.exe a.txt"), "notepad.exe a.txt");
}

#[test]
fn users_are_pseudonymized_stably_with_salt() {
    let a = Privacy {
        salt: "s1".into(),
        ..Privacy::default()
    };
    let b = Privacy {
        salt: "s2".into(),
        ..Privacy::default()
    };
    assert_eq!(a.user("CORP\\Alice"), a.user("alice"));
    assert_ne!(a.user("alice"), b.user("alice"));
    assert_eq!(a.user("NT AUTHORITY\\SYSTEM"), "SYSTEM");
    assert!(a.user("bob").starts_with("u-"));
}

#[test]
fn connection_is_bound_to_process_with_context() {
    let mut s = EndpointStore::new(Limits::default());
    let h = "10.0.0.5";
    put(
        &mut s,
        h,
        T0 - 600,
        proc(
            "C:\\x\\rclone.exe",
            "C:\\Windows\\explorer.exe",
            "rclone copy D:\\data remote: --password=zz",
            "CORP\\carol",
            Some(&"a".repeat(64)),
        ),
    );
    put(&mut s, h, T0, conn("C:\\x\\rclone.exe", "52.1.1.1"));
    let p = Privacy::default();
    let ctx = bind_process(&s, h, "52.1.1.1", Some(443), T0 + 20, &p).unwrap();
    assert_eq!(ctx.image, "C:\\x\\rclone.exe");
    assert_eq!(
        ctx.parent_image.as_deref(),
        Some("C:\\Windows\\explorer.exe")
    );
    assert!(!ctx.cmdline.contains("zz"));
    assert!(ctx.user.as_deref().unwrap().starts_with("u-"));
    // jiná protistrana nebo moc daleký čas nic nesváže
    assert!(bind_process(&s, h, "9.9.9.9", None, T0, &p).is_none());
    assert!(bind_process(&s, h, "52.1.1.1", None, T0 + 2 * BIND_WINDOW_S, &p).is_none());
}

#[test]
fn allowlist_needs_signature_hash_owner_and_expiry() {
    let hash = "b".repeat(64);
    let ctx = ProcessContext {
        host: "h".into(),
        image: "veeam.exe".into(),
        parent_image: None,
        cmdline: String::new(),
        user: None,
        signed: Some(true),
        vendor: Some("Veeam Software".into()),
        hash: Some(hash.clone()),
        connected_at: T0,
    };
    let entry = AllowEntry {
        hash: hash.clone(),
        vendor: Some("Veeam Software".into()),
        peer: "10.9.0.0/16".into(),
        owner: "backup-team".into(),
        expires_at: T0 + 100,
    };
    let list = Allowlist {
        entries: vec![entry.clone()],
    };
    assert!(list.permits(&ctx, "10.9.3.4", T0).is_some());
    assert!(
        list.permits(&ctx, "10.8.3.4", T0).is_none(),
        "jiná protistrana"
    );
    assert!(
        list.permits(&ctx, "10.9.3.4", T0 + 200).is_none(),
        "prošlá expirace"
    );
    let unsigned = ProcessContext {
        signed: Some(false),
        ..ctx.clone()
    };
    assert!(list.permits(&unsigned, "10.9.3.4", T0).is_none());
    let nohash = ProcessContext {
        hash: None,
        ..ctx.clone()
    };
    assert!(list.permits(&nohash, "10.9.3.4", T0).is_none());
    let noowner = Allowlist {
        entries: vec![AllowEntry {
            owner: " ".into(),
            ..entry.clone()
        }],
    };
    assert!(noowner.permits(&ctx, "10.9.3.4", T0).is_none());
    let forever = Allowlist {
        entries: vec![AllowEntry {
            expires_at: 0,
            ..entry
        }],
    };
    assert!(forever.permits(&ctx, "10.9.3.4", T0).is_none());
}

#[test]
fn graph_has_causal_chain_first_seen_and_bounds() {
    let mut s = EndpointStore::new(Limits::default());
    let h = "10.0.0.5";
    put(
        &mut s,
        h,
        T0,
        proc("w3wp.exe", "services.exe", "w3wp.exe", "svc", None),
    );
    put(
        &mut s,
        h,
        T0 + 10,
        proc("cmd.exe", "w3wp.exe", "cmd /c whoami", "svc", None),
    );
    put(&mut s, h, T0 + 20, conn("cmd.exe", "203.0.113.9"));
    put(
        &mut s,
        h,
        T0 + 30,
        EventKind::Logon(Logon {
            user: "svc".into(),
            logon_type: 3,
            src_ip: Some("10.0.0.9".into()),
            success: true,
        }),
    );
    let g = Graph::build(&s, &[h.to_string()], T0 - 1, T0 + 100, &Privacy::default());
    let chain = g.chain(&format!("proc:{h}:w3wp.exe"));
    let kinds: Vec<EdgeKind> = chain.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EdgeKind::Spawned, EdgeKind::Connected]);
    assert!(g.edges.iter().any(|e| e.kind == EdgeKind::MovedTo));
    assert_eq!(g.first_seen_in(T0 + 15, T0 + 25).len(), 1);
    assert!(g.to_dot().starts_with("digraph"));
    // meze: graf se ořezává
    let mut big = Graph::default();
    for i in 0..(MAX_NODES + 50) {
        big.touch(format!("n{i}"), NodeKind::Peer, "x", i as i64);
    }
    assert_eq!(big.nodes.len(), MAX_NODES);
    assert!(big.truncated);
}

#[test]
fn agent_mismatch_flags_blind_and_silent_hosts() {
    let mut s = EndpointStore::new(Limits::default());
    put(&mut s, "10.0.0.5", T0 - 5000, conn("a.exe", "1.1.1.1"));
    put(&mut s, "10.0.0.6", T0 - 10, conn("a.exe", "1.1.1.1"));
    let active = vec![
        "10.0.0.5".to_string(),
        "10.0.0.6".to_string(),
        "10.0.0.7".to_string(),
    ];
    let m = agent_mismatch(&s, &active, T0, 3600);
    assert_eq!(m.len(), 2);
    assert!(
        m.iter()
            .any(|x| x.host == "10.0.0.5" && x.kind == "silent" && x.peers_alive)
    );
    assert!(m.iter().any(|x| x.host == "10.0.0.7" && x.kind == "blind"));
}

#[test]
fn fuzz_redaction_never_panics() {
    let mut x: u64 = 88172645463325252;
    for _ in 0..50_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = (x % 40) as usize;
        let s: String = (0..n)
            .map(|i| char::from_u32(((x >> (i % 50)) as u32 % 0x2FF).max(1)).unwrap_or('a'))
            .collect();
        let _ = redact_cmdline(&s);
        let _ = Privacy::default().user(&s);
    }
}

#[test]
fn extended_indicators_fire_on_cloud_dns_and_drop_and_run_patterns() {
    use crate::endpoint::correlate::{Policy, assess};
    let host = "10.0.0.5";
    let mut s = EndpointStore::new(Limits::default());
    let ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    put(
        &mut s,
        host,
        T0,
        proc(
            "C:\\Users\\svc\\AppData\\Local\\Temp\\rclone.exe",
            ps,
            "rclone.exe copy D:\\share remote:b",
            "svc",
            None,
        ),
    );
    let p = Policy {
        extended: true,
        ..Policy::default()
    };
    let a = assess(host, s.events_of(host), T0 + 60, &p);
    assert!(
        a.indicators.iter().any(|i| i.code == "cloud_sync_tool"),
        "{:?}",
        a.indicators
    );
    assert!(a.suspicious(&p), "{:?}", a.indicators);
    // bez rozšířeného režimu se nic nového neprojeví (krok 8 beze změny)
    let off = assess(host, s.events_of(host), T0 + 60, &Policy::default());
    assert!(!off.indicators.iter().any(|i| i.code == "cloud_sync_tool"));
    // průzkum cloudovým CLI: aspoň tři různé příkazy
    let mut s2 = EndpointStore::new(Limits::default());
    for (n, sub) in [
        "iam list-users",
        "s3 ls",
        "ec2 describe-instances",
        "sts get-caller-identity",
    ]
    .iter()
    .enumerate()
    {
        put(
            &mut s2,
            host,
            T0 + n as i64,
            proc(
                "C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe",
                ps,
                &format!("aws {sub}"),
                "svc",
                None,
            ),
        );
    }
    let a2 = assess(host, s2.events_of(host), T0 + 60, &p);
    assert!(
        a2.indicators
            .iter()
            .any(|i| i.code == "cloud_cli_discovery"),
        "{:?}",
        a2.indicators
    );
    // stažení a spuštění
    let mut s3 = EndpointStore::new(Limits::default());
    put(
        &mut s3,
        host,
        T0,
        EventKind::FileCreate {
            image: Some("msedge.exe".into()),
            path: "C:\\Users\\a\\Downloads\\setup.exe".into(),
        },
    );
    put(
        &mut s3,
        host,
        T0 + 5,
        proc(
            "C:\\Users\\a\\Downloads\\setup.exe",
            "explorer.exe",
            "setup.exe",
            "a",
            None,
        ),
    );
    let a3 = assess(host, s3.events_of(host), T0 + 60, &p);
    assert!(
        a3.indicators.iter().any(|i| i.code == "drop_and_run"),
        "{:?}",
        a3.indicators
    );
    assert!(a3.suspicious(&p), "{:?}", a3.indicators);
}
