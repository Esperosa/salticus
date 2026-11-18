//! Krok 12: simulace metadat TLS a DNS ke generovaným tokům (svět `--l7`).
//!
//! Metadata se odvozují z pozorovaných toků po degradaci telemetrie: tok, který se do
//! telemetrie nedostal, nemá ani TLS ani DNS záznam. Model je obecný, bez znalosti
//! rodin útoků:
//!
//! - **Pozadí.** Každý vnitřní host má stabilní otisk klienta z malé množiny (prohlížeč,
//!   systémový agent). Cíle TLS jsou jména z dlouhého chvostu (Zipf) a mnoho adres sdílí
//!   jedno jméno (CDN). Certifikát je starý, od velkého vydavatele.
//! - **Neškodné změny** (zálohy, aktualizace, pošta, replikace): sdílená jména služeb,
//!   otisk klienta hosta, starý certifikát.
//! - **Útok.** Cíl je ve 30 % případů populární sdílené jméno (cloud, CDN), jinak nové
//!   vzácné jméno; otisk klienta je nástrojový (sdílený mezi útoky) ve 75 %, jinak
//!   otisk hosta; masking (`blend`) vždy použije otisk hosta a populární jméno
//!   (útočník žijící z krajiny). Certifikát je u vzácného jména ve 2/3 čerstvý nebo
//!   self-signed.
//! - **DNS.** Vnitřní klienti ptají se vnitřního resolveru na jména z chvostu
//!   (NXDOMAIN 5 %). Vnější zdroje dotazující vnitřní DNS: resolvery (NXDOMAIN 10 %,
//!   mnoho jmen) a útok vyčítající zónu (jména po řadě, NXDOMAIN 55 %, 10 % ANY, 5 % AXFR).
//!
//! Čísla jsou první kalibrace z literatury a z dokumentace nástrojů, ne z naměřených
//! dat; porovnání s veřejnými daty je v `k9/realismus.md` (krok 12, část C).

use std::collections::HashMap;

use crate::{
    l7::{DnsMeta, L7Event, TlsMeta},
    passive::ConnectionObservation,
    soak::{
        rng::{Rng, derive, mix},
        traffic::{Family, Kind, Truth},
    },
};

pub type FlowKey = (String, u16, String, u16, i64);

pub fn key_of(o: &ConnectionObservation) -> Option<FlowKey> {
    Some((
        o.src_ip.clone()?,
        o.src_port?,
        o.dst_ip.clone(),
        o.dst_port?,
        o.timestamp.timestamp(),
    ))
}

/// Porty, na kterých se očekává TLS (včetně STARTTLS pošty).
fn tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 465 | 587 | 993 | 995 | 853 | 8883)
}

const HOST_PRINTS: [&str; 4] = [
    "ja4:t13d1516h2_browser_a",
    "ja4:t13d1516h2_browser_b",
    "ja4:t13d1715h2_system_agent",
    "ja4:t12d1209h1_updater",
];
const TOOL_PRINTS: [&str; 5] = [
    "ja4:t13d311100_tool_a",
    "ja4:t12d190800_tool_b",
    "ja4:t13d1313h1_tool_c",
    "ja4:t10d070600_tool_d",
    "ja4:t13d4907h2_tool_e",
];
const POPULAR: [&str; 24] = [
    "cdn.static-assets.example",
    "storage.cloud-a.example",
    "api.cloud-a.example",
    "updates.vendor-a.example",
    "dl.vendor-b.example",
    "mail.relay-a.example",
    "smtp.relay-b.example",
    "sync.office-suite.example",
    "telemetry.os-vendor.example",
    "bucket.storage-b.example",
    "images.cdn-b.example",
    "login.idp-a.example",
    "backup.provider-a.example",
    "repo.packages.example",
    "meet.video-a.example",
    "chat.messenger-a.example",
    "maps.service-a.example",
    "fonts.static-b.example",
    "ocsp.ca-a.example",
    "ntp.time-a.example",
    "search.web-a.example",
    "video.stream-a.example",
    "app.saas-a.example",
    "files.share-a.example",
];

fn unit(h: u64) -> f64 {
    (h >> 11) as f64 / (1u64 << 53) as f64
}

/// Zipf podobný výběr indexu z `n` jmen podle hashe (chvost je dlouhý).
fn zipf(h: u64, n: usize) -> usize {
    let u = unit(h).max(1e-9);
    (((n as f64).powf(u) - 1.0) as usize).min(n - 1)
}

fn host_print(host: &str, salt: u64) -> &'static str {
    let h = host.bytes().fold(salt, |a, b| derive(a, u64::from(b)));
    HOST_PRINTS[(mix(h) % 3) as usize]
}

fn rare_name(h: u64) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let n = 8 + (mix(h) % 8) as usize;
    let label: String = (0..n)
        .map(|i| A[(derive(h, i as u64) % A.len() as u64) as usize] as char)
        .collect();
    let tld = ["example", "test", "invalid"][(mix(h ^ 7) % 3) as usize];
    format!("{label}.{tld}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Background,
    Benign(u64),
    Attack { id: u64, blend: bool },
}

fn class_of(truth: Option<&Truth>) -> Class {
    match truth {
        None => Class::Background,
        Some(t) => match t.kind {
            Kind::Benign(_) => Class::Benign(u64::from(t.id)),
            Kind::Attack(f) => {
                let hard = matches!(f, Family::Var(i) if {
                    let s = crate::soak::variants::spec(i);
                    s.cat == crate::soak::variants::Category::BenignChange
                        || s.cat == crate::soak::variants::Category::OpsFault
                });
                if hard {
                    // plánovaná neškodná změna nebo porucha: obyčejný provoz hosta
                    // (třída podle štítku služby, ne podle jména scénáře)
                    let label = match f {
                        Family::Var(i) => crate::soak::variants::spec(i).label,
                        _ => "",
                    };
                    let id = label.bytes().fold(17u64, |a, b| derive(a, u64::from(b)));
                    Class::Benign(id)
                } else {
                    let blend = t.cov.variation.is_some_and(|v| v.blend);
                    Class::Attack {
                        id: u64::from(t.id),
                        blend,
                    }
                }
            }
        },
    }
}

/// Vytvoří L7 záznamy pro toky, které přežily degradaci.
pub fn synthesize(
    seed: u64,
    observations: &[ConnectionObservation],
    tags: &HashMap<FlowKey, usize>,
    truths: &[Truth],
    internal: &dyn Fn(&str) -> bool,
    cal: bool,
) -> Vec<L7Event> {
    let mut out = Vec::new();
    for o in observations {
        let (Some(src), Some(dport)) = (o.src_ip.as_deref(), o.dst_port) else {
            continue;
        };
        let class = class_of(
            key_of(o)
                .and_then(|k| tags.get(&k))
                .and_then(|i| truths.get(*i)),
        );
        let key = derive(
            seed,
            derive(
                mix(o.timestamp.timestamp() as u64),
                u64::from(o.src_port.unwrap_or(0)),
            ),
        );
        let mut rng = Rng::new(key);
        let ts = o.timestamp.timestamp();
        if o.proto == "tcp" && tls_port(dport) && internal(src) && !internal(&o.dst_ip) {
            out.push(L7Event::Tls(tls_for(class, src, o, key, &mut rng, ts, cal)));
        } else if o.proto == "udp" && dport == 53 {
            out.push(L7Event::Dns(dns_for(
                class, src, o, key, &mut rng, ts, internal, cal,
            )));
        }
    }
    out
}

fn tls_for(
    class: Class,
    src: &str,
    o: &ConnectionObservation,
    key: u64,
    rng: &mut Rng,
    ts: i64,
    cal: bool,
) -> TlsMeta {
    let day = 86_400i64;
    let mature_cert = |h: u64| {
        (
            ts - (200 + (mix(h) % 400) as i64) * day,
            ts + (30 + (mix(h ^ 1) % 300) as i64) * day,
        )
    };
    let (sni, print, nb_na, issuer, subject) = match class {
        Class::Background => {
            // adresa urcuje jmeno: mnoho adres sdili jedno jmeno (CDN)
            let h = o.dst_ip.bytes().fold(5u64, |a, b| derive(a, u64::from(b)));
            let name = POPULAR[zipf(h, POPULAR.len())].to_string();
            let long_tail = rng.chance(0.55);
            let sni = if long_tail {
                format!("host{}.tail.example", zipf(h ^ 99, 3000))
            } else {
                name
            };
            if cal {
                // krok 13: podíly z CTU-Normal-20 (bez SNI 1,5 %, self-signed 3,0 %)
                // jde o vlastnost cíle (adresy), ne náhodu každého spojení: self-signed
                // certifikát má cíl, ne tok; jinak by dlouhá skupina spojení na jeden cíl
                // skoro jistě obsahovala self-signed spojení
                let no_sni = unit(derive(h, 77)) < 0.015;
                let selfsigned = unit(derive(h, 78)) < 0.03;
                let sni = if no_sni { None } else { Some(sni) };
                if selfsigned {
                    let cn = format!("CN=dev{}.local", h % 997);
                    return finish_tls(
                        o,
                        src,
                        ts,
                        sni,
                        host_print(src, 1),
                        (ts - 30 * day, ts + 3650 * day),
                        cn.clone(),
                        Some(cn),
                    );
                }
                return finish_tls(
                    o,
                    src,
                    ts,
                    sni,
                    host_print(src, 1),
                    mature_cert(h),
                    "CN=Large Public CA".to_string(),
                    None,
                );
            }
            (
                Some(sni),
                host_print(src, 1),
                mature_cert(h),
                "CN=Large Public CA".to_string(),
                String::new(),
            )
        }
        Class::Benign(id) => {
            // krok 13: 13,4 % spojení reálného hosta míří na jméno, které před tím neviděl
            // (CTU-Normal-20); neškodná změna proto občas jde na nové jméno
            let fresh = cal && rng.chance(0.134);
            let name = if fresh {
                rare_name(id ^ key)
            } else {
                POPULAR[(mix(id) % POPULAR.len() as u64) as usize].to_string()
            };
            (
                Some(name),
                host_print(src, 1),
                mature_cert(id),
                "CN=Large Public CA".to_string(),
                String::new(),
            )
        }
        Class::Attack { id, blend } => {
            let popular = blend || unit(derive(id, 11)) < 0.30;
            let tool = !blend && unit(derive(id, 13)) < 0.75;
            let sni = if popular {
                POPULAR[(mix(id ^ 5) % POPULAR.len() as u64) as usize].to_string()
            } else {
                rare_name(id)
            };
            let print = if tool {
                TOOL_PRINTS[(mix(id ^ 3) % TOOL_PRINTS.len() as u64) as usize]
            } else {
                host_print(src, 1)
            };
            let r = unit(derive(id, 17));
            let (nb_na, issuer, subject) = if popular || r < 0.33 {
                (
                    mature_cert(id),
                    "CN=Large Public CA".to_string(),
                    String::new(),
                )
            } else if r < 0.66 {
                let age = 1 + (mix(id ^ 9) % 20) as i64;
                (
                    (ts - age * day, ts + 70 * day),
                    "CN=Free Short CA".to_string(),
                    String::new(),
                )
            } else {
                let name = format!("CN={sni}");
                ((ts - day, ts + 3650 * day), name.clone(), name)
            };
            (Some(sni), print, nb_na, issuer, subject)
        }
    };
    let _ = key;
    finish_tls(
        o,
        src,
        ts,
        sni,
        print,
        nb_na,
        issuer,
        (!subject.is_empty()).then_some(subject),
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_tls(
    o: &ConnectionObservation,
    src: &str,
    ts: i64,
    sni: Option<String>,
    print: &str,
    nb_na: (i64, i64),
    issuer: String,
    subject: Option<String>,
) -> TlsMeta {
    TlsMeta {
        ts,
        src_ip: src.to_string(),
        src_port: o.src_port,
        dst_ip: o.dst_ip.clone(),
        dst_port: o.dst_port,
        sni,
        ja3: None,
        ja4: Some(print.to_string()),
        alpn: Some("h2".to_string()),
        version: Some("TLSv13".to_string()),
        not_before: Some(nb_na.0),
        not_after: Some(nb_na.1),
        issuer: Some(issuer),
        subject,
        cert_fuid: None,
    }
}

fn dns_for(
    class: Class,
    src: &str,
    o: &ConnectionObservation,
    key: u64,
    rng: &mut Rng,
    ts: i64,
    internal: &dyn Fn(&str) -> bool,
    cal: bool,
) -> DnsMeta {
    let from_inside = internal(src);
    let (qname, qtype, rcode) = match (class, from_inside) {
        (Class::Attack { id, .. }, false) => {
            // vycet zony: jmena po rade pod jednou zonou
            let n = (key % 100_000) as usize;
            let t = rng.f64();
            let qtype = if t < 0.05 {
                "AXFR"
            } else if t < 0.15 {
                "ANY"
            } else {
                "A"
            };
            let rc = if rng.chance(0.55) {
                "NXDOMAIN"
            } else {
                "NOERROR"
            };
            (format!("h{n}.zone{}.example", id % 7), qtype, rc)
        }
        (Class::Attack { .. }, true) => {
            let len = 20 + (key % 20) as usize;
            let label: String = (0..len)
                .map(|i| (b'a' + (derive(key, i as u64) % 26) as u8) as char)
                .collect();
            (format!("{label}.tun.example"), "TXT", "NOERROR")
        }
        (_, true) => {
            let h = derive(key, 3);
            // krok 13: NXDOMAIN 1 % a pošta (TXT) 0,5 % z reálných zachycení; bez `cal` původní 5 % a 2 %
            let rc = if rng.chance(if cal { 0.01 } else { 0.05 }) {
                "NXDOMAIN"
            } else {
                "NOERROR"
            };
            let t = rng.f64();
            let mail_end = if cal { 0.045 } else { 0.06 };
            if t < 0.04 {
                // CDN a reklama: dlouha hashovana znacka, ale typ A
                (
                    format!("{:016x}{:016x}.cdn.example", derive(key, 7), derive(key, 8)),
                    "A",
                    rc,
                )
            } else if t < mail_end {
                // pošta: SPF, DKIM (typ TXT) na beznych jmenech
                (format!("mail{}.tail.example", zipf(h, 200)), "TXT", rc)
            } else {
                // krok 13: AAAA tvoří u moderního klienta ~ 24 % dotazů (CTU-Normal-20)
                let qtype = if cal && rng.chance(0.20) { "AAAA" } else { "A" };
                (format!("host{}.tail.example", zipf(h, 3000)), qtype, rc)
            }
        }
        (_, false) => {
            // vnejsi resolver dotazuje vnitrni autoritativni DNS
            let rc = if rng.chance(0.10) {
                "NXDOMAIN"
            } else {
                "NOERROR"
            };
            (format!("svc{}.corp.example", derive(key, 5) % 400), "A", rc)
        }
    };
    DnsMeta {
        ts,
        src_ip: src.to_string(),
        dst_ip: o.dst_ip.clone(),
        qname: qname.to_string(),
        qtype: qtype.to_string(),
        rcode: Some(rcode.to_string()),
        answers: u32::from(rcode == "NOERROR"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn flow(src: &str, dst: &str, sp: u16, dp: u16, proto: &str, at: i64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: chrono::Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(sp),
            dst_ip: dst.into(),
            proto: proto.into(),
            dst_port: Some(dp),
            duration_s: Some(1.0),
            orig_bytes: Some(100),
            resp_bytes: Some(100),
            total_bytes: Some(200),
            orig_pkts: None,
            resp_pkts: None,
            total_pkts: None,
            conn_state: Some("SF".into()),
            history: None,
            missed_bytes: None,
        }
    }

    #[test]
    fn synthesis_is_deterministic_and_covers_tls_and_dns_only() {
        let flows = vec![
            flow("10.0.0.5", "198.51.100.9", 40000, 443, "tcp", 1_800_000_000),
            flow("10.0.0.5", "10.0.0.2", 40001, 53, "udp", 1_800_000_001),
            flow("10.0.0.5", "198.51.100.9", 40002, 22, "tcp", 1_800_000_002),
            flow("198.51.100.4", "10.0.0.2", 40003, 53, "udp", 1_800_000_003),
        ];
        let internal = |ip: &str| ip.starts_with("10.");
        let a = synthesize(7, &flows, &HashMap::new(), &[], &internal, false);
        let b = synthesize(7, &flows, &HashMap::new(), &[], &internal, false);
        assert_eq!(a, b);
        assert_eq!(a.len(), 3, "22/tcp nema TLS ani DNS");
        assert!(matches!(a[0], L7Event::Tls(_)));
        assert!(a.iter().filter(|e| matches!(e, L7Event::Dns(_))).count() == 2);
    }
}
