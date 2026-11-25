//! Potvrzení slabé síťové vazby druhým zdrojem (krok 46): autentizační log.
//!
//! Zapíná se jen souborem z proměnné prostředí `SALTICUS_AUTH_LOG` (text, formát `sshd`
//! v syslogu: `Mon DD HH:MM:SS host sshd[pid]: Accepted/Failed ... for USER from IP port P
//! ssh2[: otisk klíče]`). Bez ní beze změny (stejné pravidlo jako `SALTICUS_KNOWN_ACTIVITY`).
//!
//! Zjištěné na reálných datech (`impl-krok46.md`, DAPT2021 `10.1.1.11`): pár adres, kde JSOU
//! VŠECHNA pozorovaná přihlášení přijatá, se stejným otiskem klíče, a je jich dost, je
//! potvrzený administrativní kanál, ne útočník. Takový pár se z korelace odstraní jako hrana
//! (`Options.veto_pairs`); nikdy nemaže nález ani nemění závažnost nebo zavření — jen brání
//! tomu, aby přes něj vznikla vazba incidentu.

use std::collections::{BTreeMap, BTreeSet};

/// Jedno pozorování autentizace: kdo (`peer`) se přihlásil na koho (`host`), čím účtem,
/// s jakým výsledkem a (u přijatých) otiskem klíče.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthObservation {
    pub ts: i64,
    pub host: String,
    pub peer: String,
    pub account: String,
    pub success: bool,
    pub key: Option<String>,
}

fn month_num(m: &str) -> Option<u32> {
    const NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    NAMES.iter().position(|n| *n == m).map(|p| p as u32 + 1)
}

/// Syslog čas bez roku (`Mon DD HH:MM:SS`) na epoch; rok se dodá parametrem (log sám rok nenese).
fn parse_syslog_ts(line: &str, year: i32) -> Option<i64> {
    let mut it = line.split_whitespace();
    let mon = month_num(it.next()?)?;
    let day: u32 = it.next()?.parse().ok()?;
    let time = it.next()?;
    let mut hms = time.split(':');
    let h: u32 = hms.next()?.parse().ok()?;
    let m: u32 = hms.next()?.parse().ok()?;
    let s: u32 = hms.next()?.parse().ok()?;
    let date = chrono::NaiveDate::from_ymd_opt(year, mon, day)?;
    let dt = date.and_hms_opt(h, m, s)?;
    Some(dt.and_utc().timestamp())
}

/// Rozparsuje text autentizačního logu (sshd styl syslogu) pro hostitele `host`. Neznámé a
/// nerozpoznané řádky se tiše vynechají (nedůvěryhodný vstup, žádná panika). `year` je rok
/// logu (syslog ho sám nenese); běh dodá aktuální rok nebo rok známý z dat.
pub fn parse_sshd_auth_log(text: &str, host: &str, year: i32) -> Vec<AuthObservation> {
    let mut out = Vec::new();
    for line in text.lines().take(500_000) {
        if line.len() > 2 * 1024 {
            continue;
        }
        let Some(idx) = line.find("sshd[") else {
            continue;
        };
        let msg = &line[idx..];
        let Some(ts) = parse_syslog_ts(line, year) else {
            continue;
        };
        let accepted = msg.contains("Accepted");
        let failed = msg.contains("Failed password") || msg.contains("Invalid user");
        if !accepted && !failed {
            continue;
        }
        // "... for USER from IP port PORT ssh2[: otisk]" (Invalid user: "Invalid user USER from IP port PORT")
        let rest = msg.splitn(2, "from ").nth(1).unwrap_or("");
        let peer = rest.split_whitespace().next().unwrap_or("");
        if peer.is_empty() || peer.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let account = if let Some(p) = msg.find("for ") {
            msg[p + 4..].split_whitespace().next().unwrap_or("?")
        } else if let Some(p) = msg.find("user ") {
            msg[p + 5..].split_whitespace().next().unwrap_or("?")
        } else {
            "?"
        };
        let key = msg
            .find("SHA256:")
            .map(|p| msg[p..].split_whitespace().next().unwrap_or("").to_string());
        out.push(AuthObservation {
            ts,
            host: host.to_string(),
            peer: peer.to_string(),
            account: account.to_string(),
            success: accepted,
            key,
        });
    }
    out
}

/// Nejmenší počet pozorování, než se pár uzná za potvrzený administrativní kanál (předem daná
/// hodnota, ne ladění na datech; na reálném záznamu šlo o 50 pozorování).
pub const MIN_OBSERVATIONS: usize = 10;

/// Z pozorování odvodí potvrzené administrativní dvojice (hostitel, protějšek) beze směru:
/// pár se uzná, jen když má aspoň `min_observations` záznamů, VŠECHNY jsou přijaté a se stejným
/// otiskem klíče (nebo všechny beze klíče, ale stejným účtem) — jediný neúspěch nebo jiný klíč
/// pár zamítne, protože to už není jistota, že jde jen o administrátora.
pub fn corroborated_admin_pairs(
    obs: &[AuthObservation],
    min_observations: usize,
) -> BTreeSet<(String, String)> {
    let mut by_pair: BTreeMap<(String, String), Vec<&AuthObservation>> = BTreeMap::new();
    for o in obs {
        let pair = if o.host <= o.peer {
            (o.host.clone(), o.peer.clone())
        } else {
            (o.peer.clone(), o.host.clone())
        };
        by_pair.entry(pair).or_default().push(o);
    }
    let mut out = BTreeSet::new();
    for (pair, events) in by_pair {
        if events.len() < min_observations || events.iter().any(|e| !e.success) {
            continue;
        }
        let first_key = &events[0].key;
        let first_acct = &events[0].account;
        let consistent = events
            .iter()
            .all(|e| &e.key == first_key && (e.key.is_some() || &e.account == first_acct));
        if consistent {
            out.insert(pair);
        }
    }
    out
}

/// Načte `SALTICUS_AUTH_LOG` (jedna cesta, syslog-sshd formát), rozparsuje a odvodí potvrzené
/// páry; bez platné proměnné nebo při chybě čtení vrátí `None` a korelace se nezmění.
pub fn load_veto_pairs_from_env() -> Option<BTreeSet<(String, String)>> {
    let path = std::env::var_os("SALTICUS_AUTH_LOG")?;
    let path = std::path::PathBuf::from(path);
    let host = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("auth")
        .to_string();
    let host_env = std::env::var("SALTICUS_AUTH_LOG_HOST").ok();
    let host = host_env.unwrap_or(host);
    let year: i32 = std::env::var("SALTICUS_AUTH_LOG_YEAR")
        .ok()
        .and_then(|y| y.parse().ok())
        .unwrap_or_else(|| {
            chrono::Utc::now()
                .format("%Y")
                .to_string()
                .parse()
                .unwrap_or(2026)
        });
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let obs = parse_sshd_auth_log(&text, &host, year);
            let pairs = corroborated_admin_pairs(&obs, MIN_OBSERVATIONS);
            tracing::info!(
                observations = obs.len(),
                pairs = pairs.len(),
                "SALTICUS_AUTH_LOG nacten, potvrzene administrativni pary odvozeny"
            );
            Some(pairs)
        }
        Err(error) => {
            tracing::warn!(%error, "SALTICUS_AUTH_LOG se nenacetl, potvrzeni druhym zdrojem vypnuto");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skutečné řádky (format a hodnoty) z DAPT2021 `10.1.1.11/auth-logs/auth.log.2`, které
    /// motivovaly tento krok (`impl-krok46.md`): 2 ze 2 vzorků v testu jsou přijaté stejným
    /// klíčem ze stejné adresy.
    const SAMPLE: &str = "\
Jun 30 08:53:24 ubuntu sshd[8214]: Accepted publickey for ubuntu from 10.1.1.18 port 53488 ssh2: RSA SHA256:ggWxiKkap37z5f9+WVtULBRC4JGMpTmmQp0e2DOqg+Q
Jul  1 08:55:36 ubuntu sshd[4514]: Accepted publickey for ubuntu from 10.1.1.18 port 34224 ssh2: RSA SHA256:ggWxiKkap37z5f9+WVtULBRC4JGMpTmmQp0e2DOqg+Q
Jun 30 09:10:00 ubuntu sshd[9999]: Failed password for root from 203.0.113.9 port 4000 ssh2
Jun 30 09:10:05 ubuntu sshd[10000]: Invalid user admin from 203.0.113.9 port 4001
";

    #[test]
    fn parses_real_sshd_log_lines() {
        let obs = parse_sshd_auth_log(SAMPLE, "10.1.1.11", 2021);
        assert_eq!(obs.len(), 4);
        assert!(obs[0].success && obs[0].peer == "10.1.1.18" && obs[0].account == "ubuntu");
        assert_eq!(
            obs[0].key.as_deref(),
            Some("SHA256:ggWxiKkap37z5f9+WVtULBRC4JGMpTmmQp0e2DOqg+Q")
        );
        assert_eq!(obs[0].ts, parse_syslog_ts("Jun 30 08:53:24", 2021).unwrap());
        assert!(!obs[2].success && obs[2].peer == "203.0.113.9");
        assert!(!obs[3].success && obs[3].account == "admin");
    }

    #[test]
    fn repeated_accepted_same_key_is_corroborated_admin_channel() {
        let mut lines = String::new();
        for k in 0..12 {
            lines.push_str(&format!(
                "Jun {:02} 08:00:00 ubuntu sshd[{k}]: Accepted publickey for ubuntu from 10.1.1.18 port {} ssh2: RSA SHA256:same\n",
                10 + k, 50000 + k
            ));
        }
        let obs = parse_sshd_auth_log(&lines, "10.1.1.11", 2021);
        let pairs = corroborated_admin_pairs(&obs, MIN_OBSERVATIONS);
        assert!(pairs.contains(&("10.1.1.11".to_string(), "10.1.1.18".to_string())));
    }

    #[test]
    fn a_single_failure_or_different_key_refutes_the_pair() {
        let obs = parse_sshd_auth_log(SAMPLE, "10.1.1.11", 2021);
        // vlastní pár s jediným neúspěchem v 11 jinak čistých přihlášeních se nepotvrdí
        let mut many = Vec::new();
        for _ in 0..11 {
            many.push(AuthObservation {
                ts: 0,
                host: "h".into(),
                peer: "p".into(),
                account: "a".into(),
                success: true,
                key: Some("K1".into()),
            });
        }
        many.push(AuthObservation {
            ts: 0,
            host: "h".into(),
            peer: "p".into(),
            account: "a".into(),
            success: false,
            key: None,
        });
        assert!(corroborated_admin_pairs(&many, MIN_OBSERVATIONS).is_empty());
        // dva různé klíče stejným účtem taky ne
        let mut mixed_key = many[..11].to_vec();
        mixed_key[5].key = Some("K2".into());
        assert!(corroborated_admin_pairs(&mixed_key, MIN_OBSERVATIONS).is_empty());
        // pod MIN_OBSERVATIONS se nepotvrdí ani s čistou historií
        assert!(corroborated_admin_pairs(&obs[..1], MIN_OBSERVATIONS).is_empty());
    }

    #[test]
    fn unparseable_or_unrelated_lines_are_silently_skipped() {
        let noisy = "garbage\nJun 30 CRON[1]: session opened\nnot-a-log-line-at-all\n";
        assert!(parse_sshd_auth_log(noisy, "h", 2021).is_empty());
    }
}
