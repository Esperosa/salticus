//! Případová složka pro seniora (krok 16, `docs/diplomka/rozsah-autonomie.md`).
//!
//! Senior nedostává alert, ale vyšetřený případ: shrnutí a doporučený krok, časovou osu,
//! aktéry, hypotézy s typovanou nejistotou, důkazy pro a proti s původem a nezávislostí,
//! co bylo ověřeno a co zbývá (cena, riziko), slepá místa, souvislosti a důvod předání.
//! Zavřený případ (L1) nese důkaz neškodnosti, vlastníka a expiraci.
//!
//! Čistá funkce bez I/O, času a náhody: stejný vstup dá bajtově stejnou složku. Složka nic
//! nerozhoduje ani nespouští. Co nejde doložit, je výslovně „nelze urcit“ s důvodem;
//! `validate` hlídá úplnost, shodu s verdiktem enginu a to, že složka netvrdí víc než důkazy.

use serde::{Deserialize, Serialize};

use crate::{
    case_file::{self, DataRequest},
    context_gate::ContextEntry,
    coverage_status::CoverageStatus,
    finding_memory::LifecycleRecord,
    model::Finding,
    ops_telemetry::OpsDiagnosis,
    retro::Incident,
    verification_chain::CheckKind,
    verify_ladder::{CheckId, Decision, Status, StepNote, benign_group, competing_kind},
};

pub const SCHEMA: &str = "salticus.case_folder/1";
pub const UNKNOWN: &str = "nelze urcit";
const MAX_TEXT: usize = 240;
const MAX_ITEMS: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// `confirmed` | `refuted` | `escalated` | `open` (verdikt enginu beze změny).
    pub status: String,
    /// L1 zavřel program, L2 v šetření, L3 rozhoduje člověk.
    pub level: String,
    pub posterior_attack: f64,
    pub checks: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Čas (epoch s) nebo cyklus žebříku podle `unit`.
    pub at: i64,
    pub unit: String,
    pub what: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actor {
    /// `host` | `uzivatel` | `proces` | `spojeni` | `protejsek`
    pub role: String,
    pub id: String,
    pub pseudonymized: bool,
    pub source: String,
}

/// Jeden typ nejistoty: hodnota, nebo `None` a důvod („nelze urcit“).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Quantity {
    pub value: Option<f64>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Uncertainty {
    pub aleatoric: Quantity,
    pub epistemic: Quantity,
    pub identity: Quantity,
    pub observation: Quantity,
    pub interpretation: Quantity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HypothesisEntry {
    pub rank: usize,
    pub hypothesis: String,
    pub probability: f64,
    /// Odkud pravděpodobnost je (`verdikt enginu`, `rovnomerne bez rozlisujiciho dukazu`, ...).
    pub basis: String,
    pub prediction: String,
    /// `podporena` | `oslabena` | `neoverena`
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub check: String,
    pub level: String,
    /// `sit` | `l7` | `endpoint` | `provoz` | `kontext` | `externi` | `aktivni`
    pub origin: String,
    /// Skupina nezávislosti (důkazy téže skupiny nejsou nezávislé).
    pub group: String,
    /// První důkaz své skupiny v tomto směru nese plnou váhu, další jen zeslabenou.
    pub independent: bool,
    /// Silný neškodný důkaz (kontext, provozní příčina, koncová telemetrie).
    pub strong: bool,
    pub lr: f64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedCheck {
    pub check: String,
    pub level: String,
    /// `podezrele` | `neskodne` | `bez vysledku` | `neprovedeno` | `ceka`
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingCheck {
    pub check: String,
    /// Relativní cena 0 až 1 (`verification_chain::CheckKind::cost`).
    pub cost: f64,
    pub needs_approval: bool,
    pub risk: String,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Related {
    pub incidents: Vec<String>,
    pub findings: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Closure {
    pub proof: Vec<Evidence>,
    pub owner: String,
    pub expires: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseFolder {
    pub schema: String,
    pub case_id: String,
    pub finding_type: String,
    pub host: String,
    pub summary: String,
    pub recommended_step: String,
    pub verdict: Verdict,
    pub timeline: Vec<TimelineEntry>,
    pub actors: Vec<Actor>,
    /// Aktéři, které nelze určit (`uzivatel: nelze urcit, chybi ...`).
    pub actors_missing: Vec<String>,
    pub hypotheses: Vec<HypothesisEntry>,
    pub uncertainty: Uncertainty,
    pub evidence_for: Vec<Evidence>,
    pub evidence_against: Vec<Evidence>,
    pub verified: Vec<VerifiedCheck>,
    pub to_verify: Vec<PendingCheck>,
    pub blind_spots: Vec<String>,
    pub data_requests: Vec<DataRequest>,
    pub related: Related,
    /// Proč případ jde na člověka (prázdné jen u zavřeného).
    pub handoff: Vec<String>,
    pub closure: Option<Closure>,
}

/// Vstup složky. Co volající nezná, předá jako `None` (složka pak řekne „nelze urcit“).
pub struct FolderInput<'a> {
    pub decision: &'a Decision,
    pub finding: Option<&'a Finding>,
    pub lifecycle: Option<&'a LifecycleRecord>,
    pub ops: Option<&'a OpsDiagnosis>,
    pub coverage: Option<&'a CoverageStatus>,
    /// Host má koncovou telemetrii (`None` = neznámo).
    pub endpoint_covered: Option<bool>,
    pub contexts: &'a [ContextEntry],
    /// `None` = historie incidentů nebyla k dispozici.
    pub incidents: Option<&'a [Incident]>,
    pub pseudonymize_users: bool,
    /// Krok 15 `endpoint_weak`: neškodný koncový signál mimo seznam povolených je slabý.
    pub endpoint_weak: bool,
    /// Krok 19: uživatelé hosta z koncové telemetrie (už pseudonymizovaní volajícím podle
    /// nastavení soukromí); `None` = host bez živé koncové telemetrie nebo neznámo.
    pub endpoint_users: Option<Vec<String>>,
}

/// Krok 19: kontrola „rozlišuje“, když její výsledek může změnit rozhodnutí o případu
/// (kladná hrubá hodnota informace, EVOI bez ceny, tabulky kroku 12); neutrální tabulka
/// (poměr 1) i kontrola, která P(útok) přes žádnou hranici rozhodnutí neposune, dají 0.
const MIN_INFO: f64 = 1e-4;
/// Začátek důvodu u zbývající kontroly, která rozlišuje (validátor a skript ho hledají).
pub const DISCRIMINATES: &str = "neprovedeno; rozlisuje";

/// Hrubá hodnota informace kontroly při P(útok) `p` (`competing::evoi` s nulovou cenou):
/// očekávané snížení ztráty rozhodnutí (uzavřít, potvrdit, předat) po jejím výsledku.
fn discrimination(p: f64, kind: CheckKind) -> f64 {
    let v = crate::competing::evoi(
        p.clamp(1e-6, 1.0 - 1e-6),
        &[],
        kind,
        crate::competing::measured_static(),
        &crate::competing::Costs::default(),
        0.0,
    );
    if v.is_finite() { v.max(0.0) } else { 0.0 }
}

/// P(útok) po jednom výsledku kontroly (změřené tabulky; pro text doporučení).
fn shifted(p: f64, kind: CheckKind, result: crate::competing::Result3) -> f64 {
    finite01(crate::competing::posterior_attack(
        p.clamp(1e-6, 1.0 - 1e-6),
        &[crate::competing::Obs { kind, result }],
        crate::competing::measured_static(),
    ))
}

/// Co má člověk udělat, aby kontrolu provedl (složka nic nespouští).
fn manual_step(kind: CheckKind) -> &'static str {
    match kind {
        CheckKind::DnsPivot => "projit DNS dotazy hosta kolem casu nalezu",
        CheckKind::TlsFingerprint => {
            "porovnat TLS otisk klienta a certifikat s obvyklymi pro hosta"
        }
        CheckKind::Timing => "posoudit pravidelnost spojeni (beacon)",
        CheckKind::GeoAsn => "overit zemi a ASN protejsku",
        CheckKind::HostBaseline => "porovnat s obvyklym chovanim hosta",
        CheckKind::PeerCompare => "porovnat s hosty stejneho typu v podsiti",
        CheckKind::EndpointTelemetry => "zkontrolovat procesy a prihlaseni na hostu (EDR, Sysmon)",
        CheckKind::CaseHistory => "dohledat drivejsi vyskyty u hosta",
        CheckKind::Reputation => "overit reputaci protejsku (TI zdroj)",
        CheckKind::ConfigContext => "dohledat schvalenou zmenu nebo okno udrzby (CMDB, kalendar)",
        CheckKind::RepeatMeasure => "pockat a overit, zda se jev opakuje",
        CheckKind::ActiveReadOnly => "aktivne overit dostupnost sluzby (jen cteni)",
        CheckKind::OpsTelemetry => "zkontrolovat syslog a SNMP zarizeni na ceste",
    }
}

fn kind_named(name: &str) -> Option<CheckKind> {
    CheckKind::ALL
        .into_iter()
        .find(|k| format!("{k:?}") == name)
}

/// Text doporučené kontroly: co udělat, cena a jak by výsledek posunul P(útok).
fn step_text(p: f64, c: &PendingCheck) -> String {
    let Some(kind) = kind_named(&c.check) else {
        return format!("Overit: {} (cena {:.2}).", c.check, c.cost);
    };
    use crate::competing::Result3;
    // rozsah, ne směr: u některých kontrol je „podezřelý“ výsledek ve změřených tabulkách
    // častější u neškodných případů (historie), takže popisek směru by byl zavádějící
    let a = shifted(p, kind, Result3::Suspicious);
    let b = shifted(p, kind, Result3::Benign);
    format!(
        "Rucne {} ({}, cena {:.2}{}); vysledek posune P(utok) z {:.2} na {:.2} az {:.2}.",
        manual_step(kind),
        c.check,
        c.cost,
        if c.needs_approval {
            ", se schvalenim"
        } else {
            ""
        },
        p,
        a.min(b),
        a.max(b),
    )
}

fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_TEXT {
        return text.to_string();
    }
    let mut out: String = text.chars().take(MAX_TEXT - 3).collect();
    out.push_str("...");
    out
}

fn finite01(x: f64) -> f64 {
    if x.is_finite() {
        x.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Confirmed => "confirmed",
        Status::Refuted => "refuted",
        Status::Escalated => "escalated",
        Status::Open => "open",
    }
}

fn level_of(s: Status) -> &'static str {
    match s {
        Status::Refuted => "L1",
        Status::Open => "L2",
        Status::Confirmed | Status::Escalated => "L3",
    }
}

fn origin_of(check: CheckId) -> &'static str {
    match check {
        CheckId::Endpoint => "endpoint",
        CheckId::L7 => "l7",
        CheckId::Ops => "provoz",
        CheckId::Context => "kontext",
        CheckId::Reputation | CheckId::Intel => "externi",
        CheckId::Liveness => "aktivni",
        CheckId::History
        | CheckId::Profile
        | CheckId::Peers
        | CheckId::Persistence
        | CheckId::DeviceProfile
        | CheckId::Pivot => "sit",
    }
}

fn group_of(check: CheckId) -> String {
    match competing_kind(check) {
        Some(kind) => format!("{:?}", kind.group()).to_lowercase(),
        None => format!("vlastni:{}", check.label()),
    }
}

fn result_label(tag: &str) -> &'static str {
    match tag {
        "malicious" => "podezrele",
        "benign" => "neskodne",
        "undetermined" => "bez vysledku",
        "unavailable" => "neprovedeno",
        _ => "ceka",
    }
}

fn evidence_of(notes: &[StepNote], malicious: bool, endpoint_weak: bool) -> Vec<Evidence> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for n in notes {
        let Some(lr) = n.lr else { continue };
        if !lr.is_finite()
            || (malicious != (n.tag == "malicious"))
            || !matches!(n.tag, "malicious" | "benign")
        {
            continue;
        }
        let group = group_of(n.check);
        let independent = !seen.contains(&group);
        if independent {
            seen.push(group.clone());
        }
        let weak_endpoint = endpoint_weak
            && n.check == CheckId::Endpoint
            && !n.detail.starts_with("seznam povolenych");
        let strong =
            !malicious && matches!(benign_group(n.check), Some(1 | 2 | 4)) && !weak_endpoint;
        out.push(Evidence {
            check: n.check.label().to_string(),
            level: n.check.level().label().to_string(),
            origin: origin_of(n.check).to_string(),
            group,
            independent,
            strong,
            lr,
            detail: clip(&n.detail),
        });
    }
    out.truncate(MAX_ITEMS);
    out
}

/// Vlastník z textu důkazu (`schvalil X`, `vlastnik X`), jinak `None`.
fn owner_in(detail: &str) -> Option<String> {
    for key in ["schvalil ", "vlastnik "] {
        if let Some(i) = detail.find(key) {
            let rest = &detail[i + key.len()..];
            let end = rest.find([',', ')', ';']).unwrap_or(rest.len());
            let owner = rest[..end].trim();
            if !owner.is_empty() {
                return Some(owner.to_string());
            }
        }
    }
    None
}

/// Expirace z textu důkazu (`do Y`), jinak `None`.
fn expiry_in(detail: &str) -> Option<String> {
    let i = detail.find(", do ")?;
    let rest = &detail[i + 5..];
    let end = rest.find([')', ';']).unwrap_or(rest.len());
    let exp = rest[..end].trim();
    (!exp.is_empty()).then(|| exp.to_string())
}

fn closure_of(proof: Vec<Evidence>, contexts: &[ContextEntry], host: &str) -> Closure {
    let mut owner = None;
    let mut expires = None;
    for e in &proof {
        if owner.is_none() {
            owner = owner_in(&e.detail);
        }
        if expires.is_none() {
            expires = expiry_in(&e.detail);
        }
        if e.check == "context" && expires.is_none() {
            // záznam kontextu se stejným schvalovatelem a hostem (nebo bez hostů)
            expires = contexts
                .iter()
                .filter(|c| owner.as_deref() == Some(c.approved_by.as_str()))
                .filter(|c| c.hosts.is_empty() || c.hosts.iter().any(|h| h == host))
                .map(|c| c.expires.to_rfc3339())
                .min();
        }
    }
    let mut note = Vec::new();
    if owner.is_none() {
        note.push(
            "vlastnik: nelze urcit (dukaz neskodnosti nema schvalovatele, napr. provozni pricina)",
        );
    }
    if expires.is_none() {
        note.push("expirace: nelze urcit (dukaz nema platnost; audit vzorku plati dal)");
    }
    Closure {
        proof,
        owner: owner.unwrap_or_else(|| UNKNOWN.to_string()),
        expires: expires.unwrap_or_else(|| UNKNOWN.to_string()),
        note: if note.is_empty() {
            "zavreno na pozitivni dukaz neskodnosti s vlastnikem a expiraci".into()
        } else {
            note.join("; ")
        },
    }
}

fn explained_by(
    notes: &[StepNote],
    ops: Option<&OpsDiagnosis>,
) -> Option<crate::competing::Hypothesis> {
    use crate::competing::Hypothesis as H;
    for n in notes.iter().filter(|n| n.tag == "benign") {
        let d = n.detail.to_lowercase();
        if n.check == CheckId::Context || n.check == CheckId::Endpoint {
            if d.contains("sken") || d.contains("scan") {
                return Some(H::ScheduledScan);
            }
            if d.contains("zaloh") || d.contains("backup") {
                return Some(H::Backup);
            }
            if d.contains("aktualiz") || d.contains("update") || d.contains("patch") {
                return Some(H::Update);
            }
        }
        if n.check == CheckId::Context && d.contains("outage") {
            return Some(H::Fault);
        }
        if n.check == CheckId::Liveness {
            return Some(H::Fault);
        }
    }
    match ops.map(|o| o.class.as_str()) {
        Some("porucha") => Some(H::Fault),
        Some("zmena") => Some(H::Misconfig),
        _ => None,
    }
}

fn hypotheses_of(
    open: bool,
    p: f64,
    notes: &[StepNote],
    ops: Option<&OpsDiagnosis>,
    has_for: bool,
    has_against: bool,
) -> Vec<HypothesisEntry> {
    use crate::competing::Hypothesis as H;
    let explained = explained_by(notes, ops);
    let rest = 1.0 - p;
    let basis = if open {
        "apriorni pravdepodobnost (zebrik zatim nerozhodl)"
    } else {
        "verdikt enginu (P(utok) zebriku)"
    };
    let mut list: Vec<(H, f64, String)> = vec![(H::Attack, p, basis.into())];
    // neškodné druhy: rovnoměrný podíl (číslo jejich rozdělení data nedávají); druh, na který
    // ukazuje neškodný důkaz, se jen označí jako podporovaný a při shodě jde první
    let share = rest / H::BENIGN.len() as f64;
    for x in H::BENIGN {
        let note = if Some(x) == explained {
            format!(
                "neskodne celkem {rest:.3}, rozdeleni rovnomerne; tuto pricinu podporuje neskodny dukaz"
            )
        } else {
            format!("neskodne celkem {rest:.3}, rozdeleni rovnomerne (druhy nerozliseny)")
        };
        list.push((x, share, note));
    }
    list.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then((Some(b.0) == explained).cmp(&(Some(a.0) == explained)))
            .then(a.0.cmp(&b.0))
    });
    list.into_iter()
        .enumerate()
        .map(|(i, (h, prob, basis))| {
            let status = match h {
                H::Attack if has_for => "podporena",
                H::Attack if has_against => "oslabena",
                _ if Some(h) == explained => "podporena",
                _ if h != H::Attack && has_for && !has_against => "oslabena",
                H::Attack => "neoverena",
                _ => "nerozlisena",
            };
            HypothesisEntry {
                rank: i + 1,
                hypothesis: h.label().to_string(),
                probability: finite01(prob),
                basis,
                prediction: h.prediction().to_string(),
                status: status.to_string(),
            }
        })
        .collect()
}

fn ips_of(f: &Finding) -> Vec<String> {
    crate::correlation_layer::indicators_of(f)
}

pub fn build(input: &FolderInput<'_>) -> CaseFolder {
    let d = input.decision;
    let p = finite01(d.posterior);
    let host = if d.host_ip.trim().is_empty() {
        UNKNOWN.to_string()
    } else {
        d.host_ip.clone()
    };
    let evidence_for = evidence_of(&d.notes, true, input.endpoint_weak);
    let evidence_against = evidence_of(&d.notes, false, input.endpoint_weak);

    // časová osa: nález, kroky žebříku, rozhodnutí
    let mut timeline = Vec::new();
    if let Some(lc) = input.lifecycle {
        timeline.push(TimelineEntry {
            at: lc.first_seen.timestamp(),
            unit: "epoch_s".into(),
            what: format!("nalez poprve viden ({} vyskytu)", lc.occurrences),
            source: "pamet nalezu".into(),
        });
        if lc.last_seen > lc.first_seen {
            timeline.push(TimelineEntry {
                at: lc.last_seen.timestamp(),
                unit: "epoch_s".into(),
                what: format!("posledni vyskyt ({})", lc.disposition),
                source: "pamet nalezu".into(),
            });
        }
    }
    timeline.push(TimelineEntry {
        at: d.opened as i64,
        unit: "cyklus".into(),
        what: "pripad otevren k overeni".into(),
        source: "zebrik".into(),
    });
    for n in d.notes.iter().take(MAX_ITEMS) {
        timeline.push(TimelineEntry {
            at: n.cycle as i64,
            unit: "cyklus".into(),
            what: clip(&format!(
                "{} {}: {} ({})",
                n.check.level().label(),
                n.check.label(),
                result_label(n.tag),
                n.detail
            )),
            source: origin_of(n.check).into(),
        });
    }
    timeline.push(TimelineEntry {
        at: d.decided as i64,
        unit: "cyklus".into(),
        what: format!("rozhodnuto: {} (P(utok) = {p:.3})", status_label(d.status)),
        source: "zebrik".into(),
    });

    // aktéři
    let mut actors = vec![Actor {
        role: "host".into(),
        id: host.clone(),
        pseudonymized: false,
        source: "zebrik".into(),
    }];
    let mut actors_missing = Vec::new();
    match input.finding {
        Some(f) => {
            if let Some(svc) = f.service_key.as_deref().filter(|s| !s.is_empty()) {
                actors.push(Actor {
                    role: "spojeni".into(),
                    id: clip(svc),
                    pseudonymized: false,
                    source: "nalez".into(),
                });
            }
            for ip in ips_of(f).into_iter().filter(|ip| *ip != d.host_ip).take(6) {
                actors.push(Actor {
                    role: "protejsek".into(),
                    id: ip,
                    pseudonymized: false,
                    source: "nalez".into(),
                });
            }
        }
        None => actors_missing
            .push("spojeni a protejsky: nelze urcit, nalez neni k dispozici".to_string()),
    }
    let endpoint_note = d
        .notes
        .iter()
        .find(|n| n.check == CheckId::Endpoint && n.lr.is_some());
    match endpoint_note {
        Some(n) => actors.push(Actor {
            role: "proces".into(),
            id: clip(&n.detail),
            pseudonymized: false,
            source: "endpoint".into(),
        }),
        None => actors_missing.push(match input.endpoint_covered {
            Some(true) => {
                "proces: nelze urcit, koncova telemetrie hosta k pripadu nic nenesla".to_string()
            }
            Some(false) => "proces: nelze urcit, chybi koncova telemetrie hosta".to_string(),
            None => "proces: nelze urcit, pokryti koncovou telemetrii nezname".to_string(),
        }),
    }
    // uživatel: jen z koncové telemetrie hosta (síťová data ho nenesou)
    match input.endpoint_users.as_deref() {
        Some(users) if !users.is_empty() => {
            for u in users.iter().take(3) {
                actors.push(Actor {
                    role: "uzivatel".into(),
                    id: clip(u),
                    pseudonymized: input.pseudonymize_users,
                    source: "endpoint".into(),
                });
            }
        }
        Some(_) => actors_missing.push(
            "uzivatel: nelze urcit, koncova telemetrie hosta v okne neuvadi zadneho uzivatele"
                .to_string(),
        ),
        None => actors_missing.push(match input.endpoint_covered {
            Some(false) => {
                "uzivatel: nelze urcit, host nema zivou koncovou telemetrii (sitova data uzivatele nenesou)"
                    .to_string()
            }
            _ => "uzivatel: nelze urcit, koncova telemetrie neni k dispozici (sitova data uzivatele nenesou)"
                .to_string(),
        }),
    }

    // ověřeno a slepá místa
    let verified: Vec<VerifiedCheck> = d
        .notes
        .iter()
        .take(MAX_ITEMS)
        .map(|n| VerifiedCheck {
            check: n.check.label().to_string(),
            level: n.check.level().label().to_string(),
            result: result_label(n.tag).to_string(),
            detail: clip(&n.detail),
        })
        .collect();
    // slepé místo = chybějící telemetrie nebo kontrola, kterou nešlo provést (pravidlo 5
    // rozsahu); kontrola, která proběhla a nic nerozlišila (`undetermined`), slepé místo není
    let mut blind_spots: Vec<String> = Vec::new();
    for n in d.notes.iter().filter(|n| n.tag == "unavailable") {
        let line = clip(&format!("{}: nelze provest, {}", n.check.label(), n.detail));
        if !blind_spots.contains(&line) {
            blind_spots.push(line);
        }
    }
    let blind_host = input.coverage.is_some_and(|c| {
        c.silent_hosts.contains(&d.host_ip)
            || c.dark_segments.iter().any(|s| {
                d.host_ip
                    .rsplit_once('.')
                    .is_some_and(|(p, _)| s.starts_with(p))
            })
    });
    if blind_host {
        blind_spots
            .push("host nebo segment nema sitovou telemetrii; detekce zde neni garantovana".into());
    }
    if input.coverage.is_none() {
        blind_spots.push("stav pokryti senzory: nelze urcit (neni k dispozici)".into());
    }
    if input.endpoint_covered == Some(false) {
        blind_spots.push("koncova telemetrie hosta chybi: proces a uzivatel nelze urcit".into());
    }
    if let Some(o) = input.ops
        && !o.missing.is_empty()
    {
        blind_spots.push(clip(&format!(
            "provozni telemetrie: nelze urcit, chybi {}",
            o.missing.join(", ")
        )));
    }
    blind_spots.truncate(MAX_ITEMS);

    // co zbývá ověřit: nejdřív druhy kontrol, které v případu vůbec neproběhly; kontroly
    // provedené bez výsledku až za nimi (bez nových dat by znovu nic nezjistily). U chráněného
    // nálezu se nenabízí kontext ani provozní telemetrie (nejsou tu důkazem neškodnosti).
    let tried: Vec<CheckKind> = d
        .notes
        .iter()
        .filter(|n| n.lr.is_some())
        .filter_map(|n| competing_kind(n.check))
        .collect();
    let performed: Vec<CheckKind> = d
        .notes
        .iter()
        .filter_map(|n| competing_kind(n.check))
        .collect();
    let mut ranked = CheckKind::ALL
        .into_iter()
        .filter(|k| !tried.contains(k))
        .filter(|k| {
            !(d.protected && matches!(k, CheckKind::ConfigContext | CheckKind::OpsTelemetry))
        })
        .map(|k| {
            let (cost, approval) = k.cost();
            let info = discrimination(p, k);
            let rank = if performed.contains(&k) {
                2u8
            } else if info > MIN_INFO {
                0
            } else {
                1
            };
            (
                rank,
                info,
                PendingCheck {
                    check: format!("{k:?}"),
                    cost,
                    needs_approval: approval,
                    risk: if approval {
                        "aktivni cteci kontrola: jen se schvalenim, krehke zarizeni muze reagovat"
                            .into()
                    } else {
                        "pasivni: bez vlivu na provoz".into()
                    },
                    why: match rank {
                        0 => format!(
                            "{DISCRIMINATES}: vysledek muze zmenit rozhodnuti (EVOI {info:.2})"
                        ),
                        1 => "neprovedeno; rozhodnuti nezmeni nebo nezmereno".into(),
                        _ => "provedeno bez vysledku: znovu ma smysl az s novymi daty".into(),
                    },
                },
            )
        })
        .collect::<Vec<(u8, f64, PendingCheck)>>();
    // nejdřív neprovedené, které rozlišují (nejvíc informace na cenu), pak neprovedené bez
    // změřené rozlišovací schopnosti, pak provedené bez výsledku
    ranked.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(b.1.total_cmp(&a.1))
            .then(a.2.cost.total_cmp(&b.2.cost))
            .then(a.2.check.cmp(&b.2.check))
    });
    let mut to_verify: Vec<PendingCheck> = ranked.into_iter().map(|(_, _, c)| c).collect();
    if d.status == Status::Refuted {
        to_verify.clear();
    }
    let unavailable: Vec<CheckKind> = d
        .notes
        .iter()
        .filter(|n| n.lr.is_none())
        .filter_map(|n| competing_kind(n.check))
        .collect();
    let data_requests = match input.coverage {
        Some(c) => case_file::data_requests(&d.host_ip, &unavailable, c, blind_host),
        None => {
            case_file::data_requests(&d.host_ip, &unavailable, &CoverageStatus::default(), false)
        }
    };

    // souvislosti
    let related = match input.incidents {
        Some(incidents) => {
            let hits: Vec<&Incident> = incidents
                .iter()
                .filter(|i| i.findings.contains(&d.finding_id))
                .collect();
            let mut findings: Vec<String> = hits
                .iter()
                .flat_map(|i| i.findings.iter())
                .filter(|f| **f != d.finding_id)
                .cloned()
                .collect();
            findings.sort();
            findings.dedup();
            findings.truncate(MAX_ITEMS);
            Related {
                incidents: hits
                    .iter()
                    .map(|i| {
                        format!(
                            "incident-{} ({}, faze {})",
                            i.id,
                            format!("{:?}", i.cause).to_lowercase(),
                            i.phases.join(">")
                        )
                    })
                    .collect(),
                note: if hits.is_empty() {
                    "zadny souvisejici incident v historii".into()
                } else {
                    format!("soucast {} incidentu", hits.len())
                },
                findings,
            }
        }
        None => Related {
            incidents: Vec::new(),
            findings: Vec::new(),
            note: "souvislosti: nelze urcit (historie incidentu neni k dispozici)".into(),
        },
    };

    // hypotézy a nejistota
    let hypotheses = hypotheses_of(
        d.status == Status::Open,
        p,
        &d.notes,
        input.ops,
        !evidence_for.is_empty(),
        !evidence_against.is_empty(),
    );
    let performed = d.notes.len();
    let empty = d.notes.iter().filter(|n| n.lr.is_none()).count();
    let margin = match (hypotheses.first(), hypotheses.get(1)) {
        (Some(a), Some(b)) => Some(finite01(a.probability - b.probability)),
        _ => None,
    };
    let uncertainty = Uncertainty {
        aleatoric: Quantity {
            value: None,
            note: "nelze urcit z jednoho pripadu".into(),
        },
        epistemic: Quantity {
            value: None,
            note: format!(
                "nelze urcit; tabulky verohodnosti jsou ze simulace, nezavislych skupin dukazu {}",
                evidence_for.iter().chain(&evidence_against).filter(|e| e.independent).count()
            ),
        },
        identity: Quantity {
            value: None,
            note: match (input.finding.and_then(|f| f.host_key.as_ref()), input.endpoint_covered) {
                (Some(_), Some(true)) => "host prirazen inventarem i koncovou telemetrii".into(),
                (Some(_), _) => "host prirazen inventarem; koncova telemetrie prirazeni nepotvrzuje".into(),
                (None, _) => "nelze urcit; nalez nema klic hosta".into(),
            },
        },
        observation: if performed == 0 {
            Quantity {
                value: None,
                note: "nelze urcit; zadna kontrola neprobehla".into(),
            }
        } else {
            Quantity {
                value: Some(empty as f64 / performed as f64),
                note: format!("{empty} z {performed} kontrol bez vysledku"),
            }
        },
        interpretation: Quantity {
            value: margin,
            note: "rozdil pravdepodobnosti dvou nejpravdepodobnejsich hypotez (mala hodnota = nerozlisene)".into(),
        },
    };

    // důvod předání a uzávěr
    let mut handoff = Vec::new();
    let mut closure = None;
    if d.status == Status::Refuted {
        let proof: Vec<Evidence> = evidence_against
            .iter()
            .filter(|e| e.strong)
            .cloned()
            .collect();
        closure = Some(closure_of(
            if proof.is_empty() {
                evidence_against.clone()
            } else {
                proof
            },
            input.contexts,
            &d.host_ip,
        ));
    } else {
        if d.prior_hold {
            handoff.push(match d.pending_check {
                Some(check) => format!(
                    "nepotvrzeno: vysoka apriorni P bez pozitivniho dukazu z nezavisleho zdroje, ceka na kontrolu {}",
                    check.label()
                ),
                None => "nepotvrzeno: vysoka apriorni P bez pozitivniho dukazu z nezavisleho zdroje, nutne rucni overeni".into(),
            });
        }
        if d.status == Status::Confirmed && evidence_for.is_empty() {
            handoff.push(
                "potvrzeno bez dukazu z kontrol: jen apriorni pravdepodobnost, overit pred zasahem"
                    .into(),
            );
        } else if d.status == Status::Confirmed {
            handoff.push("potvrzene podezreni: rozhodnuti o zasahu je na cloveku".into());
        }
        if d.protected {
            handoff.push("chraneny prostredek: automaticke zavreni zakazano".into());
        }
        if d.high_impact {
            handoff.push("vysoky dopad: zobrazeno uz pri otevreni".into());
        }
        if d.reason.contains("pozitivni dukaz neskodnosti nestaci") {
            handoff.push("neskodny dukaz nestaci k zavreni (mene nez dve nezavisle skupiny nebo zadna silna)".into());
        } else if evidence_against.iter().all(|e| !e.strong) && d.status != Status::Confirmed {
            handoff.push("chybi pozitivni dukaz neskodnosti".into());
        }
        if !evidence_for.is_empty() && !evidence_against.is_empty() {
            handoff.push("konflikt hypotez: dukazy pro i proti utoku".into());
        }
        if d.budget_escalation {
            handoff.push("rozpocet kontrol vycerpan".into());
        }
        let blind = blind_spots
            .iter()
            .filter(|b| !b.starts_with("stav pokryti"))
            .count();
        if blind > 0 && d.status != Status::Confirmed {
            handoff.push(format!("slepa mista: {blind} (rozhodnuti bez nich nelze)"));
        }
        if d.status == Status::Open {
            handoff.push("v setreni: zebrik jeste nerozhodl".into());
        }
        if handoff.is_empty() {
            handoff.push(
                "ocekavana ztrata automatickeho rozhodnuti je vyssi nez predani cloveku".into(),
            );
        }
    }

    // shrnutí a doporučený krok
    let kind = &d.finding_type;
    // doporučit jen kontrolu, která útok od neškodného rozliší; pasivní přednostně
    let next = to_verify
        .iter()
        .find(|c| !c.needs_approval && c.why.starts_with(DISCRIMINATES))
        .or_else(|| to_verify.iter().find(|c| c.why.starts_with(DISCRIMINATES)));
    let summary = match d.status {
        Status::Confirmed if evidence_for.is_empty() => format!(
            "Zebrik oznacil {kind} na hostu {host} za utok jen podle apriorni pravdepodobnosti (P(utok) = {p:.2}), bez podezreleho dukazu z kontrol; nutno overit."
        ),
        Status::Confirmed => format!(
            "Podezreni na utok ({kind}) na hostu {host} potvrdil zebrik (nezavislych podezrelych skupin: {}), P(utok) = {p:.2}.",
            evidence_for.iter().filter(|e| e.independent).count()
        ),
        Status::Refuted => format!(
            "Nalez {kind} na hostu {host} program zavrel jako neskodny na pozitivni dukaz ({}), P(utok) = {p:.3}.",
            closure
                .as_ref()
                .and_then(|c| c.proof.first())
                .map_or_else(|| UNKNOWN.to_string(), |e| e.check.clone())
        ),
        Status::Escalated => format!(
            "Nerozhodnuty pripad {kind} na hostu {host}: P(utok) = {p:.2}, {}.",
            handoff.first().map_or(UNKNOWN, |s| s.as_str())
        ),
        Status::Open => format!(
            "Pripad {kind} na hostu {host} je v setreni, zebrik zatim nerozhodl (apriorni P(utok) = {p:.2})."
        ),
    };
    let recommended_step = match d.status {
        Status::Confirmed if evidence_for.is_empty() => match next {
            Some(c) => format!(
                "Pred zasahem: {} Bez podezreleho vysledku nezasahovat.",
                step_text(p, c)
            ),
            None => format!("Pred zasahem rucne overit aktivitu hosta {host}; podezrely dukaz z kontrol chybi."),
        },
        Status::Confirmed => format!(
            "Overit dopad na hostu {host} a rozhodnout o zasahu (izolace, blokace protejsku); program sam nezasahuje."
        ),
        Status::Refuted => {
            "Bez zasahu; zavreni podleha auditu vzorku a plati do expirace podkladu.".to_string()
        }
        Status::Escalated | Status::Open => match (next, evidence_for.is_empty()) {
            (Some(c), _) => step_text(p, c),
            (None, false) => {
                format!("Zadna dalsi dostupna kontrola pripad nerozlisi; rozhodnout podle dukazu pro utok na hostu {host}.")
            }
            (None, true) => {
                "Zadna dalsi dostupna kontrola pripad nerozlisi a dukaz pro utok chybi; rozhodnout podle P(utok) a dopadu.".to_string()
            }
        },
    };

    CaseFolder {
        schema: SCHEMA.into(),
        case_id: d.finding_id.clone(),
        finding_type: kind.clone(),
        host,
        summary: clip(&summary),
        recommended_step: clip(&recommended_step),
        verdict: Verdict {
            status: status_label(d.status).into(),
            level: level_of(d.status).into(),
            posterior_attack: p,
            checks: d.checks,
        },
        timeline,
        actors,
        actors_missing,
        hypotheses,
        uncertainty,
        evidence_for,
        evidence_against,
        verified,
        to_verify,
        blind_spots,
        data_requests,
        related,
        handoff,
        closure,
    }
}

/// Porušení pravidel složky (prázdné = složka vyhovuje K16-1, K16-3 a K16-4).
pub fn validate(f: &CaseFolder, d: &Decision) -> Vec<String> {
    let mut v = Vec::new();
    let empty = |s: &str| s.trim().is_empty();
    for (name, value) in [
        ("schema", &f.schema),
        ("case_id", &f.case_id),
        ("finding_type", &f.finding_type),
        ("host", &f.host),
        ("summary", &f.summary),
        ("recommended_step", &f.recommended_step),
        ("related.note", &f.related.note),
    ] {
        if empty(value) {
            v.push(format!("prazdne pole {name}"));
        }
    }
    if f.schema != SCHEMA {
        v.push("jina verze schematu".into());
    }
    if f.timeline.is_empty() {
        v.push("prazdna casova osa".into());
    }
    if !f.actors.iter().any(|a| a.role == "host") {
        v.push("chybi akter host".into());
    }
    if !f.actors_missing.iter().any(|a| a.starts_with("uzivatel"))
        && !f.actors.iter().any(|a| a.role == "uzivatel")
    {
        v.push("uzivatel ani vyslovne nelze urcit".into());
    }
    if f.hypotheses.is_empty() || f.hypotheses.first().is_some_and(|h| h.rank != 1) {
        v.push("hypotezy chybi nebo nejsou serazene".into());
    }
    for q in [
        &f.uncertainty.aleatoric,
        &f.uncertainty.epistemic,
        &f.uncertainty.identity,
        &f.uncertainty.observation,
        &f.uncertainty.interpretation,
    ] {
        if q.value.is_none() && empty(&q.note) {
            v.push("nejistota bez hodnoty i bez duvodu".into());
        }
        if q.value
            .is_some_and(|x| !x.is_finite() || !(0.0..=1.0).contains(&x))
        {
            v.push("nejistota mimo [0, 1]".into());
        }
    }
    for h in &f.hypotheses {
        if !h.probability.is_finite() || !(0.0..=1.0).contains(&h.probability) {
            v.push("pravdepodobnost hypotezy mimo [0, 1]".into());
        }
    }
    // K16-3: shoda s verdiktem enginu
    if f.verdict.status != status_label(d.status) || f.verdict.level != level_of(d.status) {
        v.push("stav nebo uroven se lisi od verdiktu".into());
    }
    if (f.verdict.posterior_attack - finite01(d.posterior)).abs() > 1e-12 {
        v.push("P(utok) se lisi od verdiktu".into());
    }
    if f.case_id != d.finding_id || f.verdict.checks != d.checks {
        v.push("identita pripadu nebo pocet kontrol se lisi".into());
    }
    let attack = f.hypotheses.iter().find(|h| h.hypothesis == "utok");
    if attack.is_none_or(|h| (h.probability - f.verdict.posterior_attack).abs() > 1e-12) {
        v.push("hypoteza utok nema P(utok) verdiktu".into());
    }
    match (d.status, &f.closure) {
        (Status::Refuted, None) => v.push("zavreny pripad bez uzaveru".into()),
        (Status::Refuted, Some(c)) => {
            if !c.proof.iter().any(|e| e.strong) {
                v.push("zavreno bez silneho dukazu neskodnosti".into());
            }
            if empty(&c.owner) || empty(&c.expires) {
                v.push("uzaver bez vlastnika nebo expirace (ani nelze urcit)".into());
            }
            if !f.handoff.is_empty() {
                v.push("zavreny pripad s duvodem predani".into());
            }
        }
        (_, Some(_)) => v.push("uzaver u nezavreneho pripadu".into()),
        (_, None) => {
            if f.handoff.is_empty() {
                v.push("predany pripad bez duvodu predani".into());
            }
        }
    }
    // K16-4: každý důkaz má provedený krok se stejným směrem a LR
    for (list, tag) in [
        (&f.evidence_for, "malicious"),
        (&f.evidence_against, "benign"),
    ] {
        for e in list {
            let backed = d.notes.iter().any(|n| {
                n.check.label() == e.check
                    && n.tag == tag
                    && n.lr.is_some_and(|lr| (lr - e.lr).abs() < 1e-12)
            });
            if !backed {
                v.push(format!("dukaz {} bez provedeneho kroku", e.check));
            }
        }
    }
    let s = f.summary.to_lowercase();
    if d.status == Status::Escalated && (s.contains("potvrdil") || s.contains("jako neskodny")) {
        v.push("shrnuti eskalovaneho pripadu tvrdi verdikt".into());
    }
    if d.status != Status::Confirmed && s.contains("potvrdil") {
        v.push("shrnuti tvrdi potvrzeni bez potvrzeni".into());
    }
    // krok 19: doporučená kontrola musí rozlišovat a nesmí být už provedená s výsledkem
    for c in CheckKind::ALL {
        if f.recommended_step.contains(&format!("({c:?},")) {
            let listed = f
                .to_verify
                .iter()
                .any(|t| t.check == format!("{c:?}") && t.why.starts_with(DISCRIMINATES));
            if !listed {
                v.push(format!(
                    "doporucena kontrola {c:?} nerozlisuje nebo uz probehla"
                ));
            }
        }
    }
    // krok 19: slepé místo jen z kontroly, kterou nešlo provést
    for b in &f.blind_spots {
        if let Some((label, _)) = b.split_once(": nelze provest") {
            if !d
                .notes
                .iter()
                .any(|n| n.check.label() == label && n.tag == "unavailable")
            {
                v.push(format!("slepe misto {label} bez nedostupne kontroly"));
            }
        }
    }
    // krok 19: uživatel jako aktér jen z koncové telemetrie
    if f.actors
        .iter()
        .any(|a| a.role == "uzivatel" && a.source != "endpoint")
    {
        v.push("uzivatel mimo koncovou telemetrii".into());
    }
    // potvrzení bez podezřelého důkazu smí složka uvést jen jako apriorní, ne jako doklad
    if d.status == Status::Confirmed
        && f.evidence_for.is_empty()
        && !s.contains("bez podezreleho dukazu")
    {
        v.push("potvrzeno bez dukazu pro utok".into());
    }
    v
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Čitelný text složky (stejný obsah jako JSON).
pub fn render_text(f: &CaseFolder) -> String {
    let mut o = String::new();
    let mut line = |s: String| {
        o.push_str(&s);
        o.push('\n');
    };
    line(format!(
        "== Pripad {} ({}, host {}) ==",
        f.case_id, f.finding_type, f.host
    ));
    line(format!("Shrnuti: {}", f.summary));
    line(format!("Doporuceny krok: {}", f.recommended_step));
    line(format!(
        "Verdikt: {} ({}), P(utok) = {:.3}, kontrol {}",
        f.verdict.status, f.verdict.level, f.verdict.posterior_attack, f.verdict.checks
    ));
    if !f.handoff.is_empty() {
        line(format!("Proc clovek: {}", f.handoff.join("; ")));
    }
    if let Some(c) = &f.closure {
        line(format!(
            "Uzaver: vlastnik {}, plati do {}; {}",
            c.owner, c.expires, c.note
        ));
        for e in &c.proof {
            line(format!(
                "  dukaz neskodnosti: {} [{}] LR {:.2}: {}",
                e.check, e.origin, e.lr, e.detail
            ));
        }
    }
    line("Casova osa:".into());
    for t in &f.timeline {
        line(format!("  {} {}: {} [{}]", t.unit, t.at, t.what, t.source));
    }
    line("Akteri:".into());
    for a in &f.actors {
        line(format!(
            "  {}: {}{} [{}]",
            a.role,
            a.id,
            if a.pseudonymized { " (pseudonym)" } else { "" },
            a.source
        ));
    }
    for m in &f.actors_missing {
        line(format!("  {m}"));
    }
    line("Hypotezy:".into());
    for h in &f.hypotheses {
        line(format!(
            "  {}. {} {:.3} ({}, {}): {}",
            h.rank, h.hypothesis, h.probability, h.status, h.basis, h.prediction
        ));
    }
    let q = |name: &str, x: &Quantity| match x.value {
        Some(v) => format!("  {name}: {v:.2} ({})", x.note),
        None => format!("  {name}: {}", x.note),
    };
    line("Nejistota:".into());
    line(q("aleatorni", &f.uncertainty.aleatoric));
    line(q("epistemicka", &f.uncertainty.epistemic));
    line(q("identita", &f.uncertainty.identity));
    line(q("pozorovani", &f.uncertainty.observation));
    line(q("interpretace", &f.uncertainty.interpretation));
    for (title, list) in [
        ("Dukazy PRO utok:", &f.evidence_for),
        ("Dukazy PROTI utoku:", &f.evidence_against),
    ] {
        line(title.into());
        if list.is_empty() {
            line("  zadne".into());
        }
        for e in list {
            line(format!(
                "  {} {} [{}; skupina {}{}] LR {:.2}: {}",
                e.level,
                e.check,
                e.origin,
                e.group,
                if e.independent { "" } else { ", zavisly" },
                e.lr,
                e.detail
            ));
        }
    }
    line("Overeno:".into());
    for c in &f.verified {
        line(format!(
            "  {} {}: {} ({})",
            c.level, c.check, c.result, c.detail
        ));
    }
    line("Zbyva overit:".into());
    for c in &f.to_verify {
        line(format!(
            "  {} cena {:.2}{}: {} ({})",
            c.check,
            c.cost,
            if c.needs_approval {
                ", se schvalenim"
            } else {
                ""
            },
            c.risk,
            c.why
        ));
    }
    line("Slepa mista:".into());
    if f.blind_spots.is_empty() {
        line("  zadna zjistena".into());
    }
    for b in &f.blind_spots {
        line(format!("  {b}"));
    }
    for r in &f.data_requests {
        line(format!(
            "  zadost: {} ({}, {}): {}",
            r.log, r.scope, r.sensor, r.why
        ));
    }
    line(format!("Souvislosti: {}", f.related.note));
    for i in &f.related.incidents {
        line(format!("  {i}"));
    }
    if !f.related.findings.is_empty() {
        line(format!(
            "  souvisejici nalezy: {}",
            f.related.findings.join(", ")
        ));
    }
    o
}

/// Jednoduché HTML bez stylů (nemění design UI; jen čitelný export).
pub fn render_html(folders: &[CaseFolder]) -> String {
    let mut o = String::from(
        "<!doctype html><html lang=\"cs\"><meta charset=\"utf-8\"><title>Pripadove slozky</title><body>\n",
    );
    for f in folders {
        o.push_str(&format!(
            "<section id=\"{}\"><pre>{}</pre></section>\n",
            esc(&f.case_id),
            esc(&render_text(f))
        ));
    }
    o.push_str("</body></html>\n");
    o
}

#[cfg(test)]
mod tests;
