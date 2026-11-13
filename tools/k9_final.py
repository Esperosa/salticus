#!/usr/bin/env python3
"""Zaverecne vyhodnoceni kroku 9 a 10 (tabulky do docs/diplomka/eval/k9 a k10).

Pouziti:
  python tools/k9_final.py --families TSV --base NAZEV DIR[,DIR...] --cand NAZEV DIR[,DIR...] --out MD [--title T]

Pro obe ramena: souhrn (utoky, detekce s Wilsonem, FP na sit-den s bootstrapem po sitich,
zobrazene polozky, zavreno omylem, chranena automaticka zavreni, paniky), tri-stavovy
vysledek zebriku (potvrzeno / vyvraceno / eskalovano) a jeho presnost, tabulka po
rodinach pred a po, souhrn po taktikach a po kategoriich a registr slepych mist.
Jen standardni knihovna Pythonu 3.
"""
import argparse
import os
import random
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak_k9 as k  # noqa: E402
from soak_coverage import attacks, load, wilson  # noqa: E402

# Varianty, ktere se od legitimniho provozu lisi jen obsahem (DNS, TLS, cloudove logy, DHCP/DNS dotazy),
# a proto jsou v zaznamech toku principialne nerozlisitelne (kategorie c, viz k9/realismus.md).
CONTENT_ONLY = {
    "c2_dns_txt_beacon", "exfil_dns_slow", "exfil_icmp_payload", "drive_by_bulk_download",
    "clicks_to_rare_destination", "cloud_api_discovery_burst", "dns_zone_enum_burst",
    "c2_cloud_storage_dead_drop", "exfil_cloud_storage_upload", "vendor_remote_access_odd_hours",
    "cert_expired_internal_service", "dns_slow_resolution", "dns_partial_failure", "ntp_unreachable",
    "mssql_login_failures", "telnet_iot_login", "vpn_password_spray_slow", "mail_forward_smtp_exfil",
    "insider_after_hours_cloud_sync", "c2_high_jitter", "oauth_token_abuse_periodic",
}


def pc(x):
    return k.pc(x)


def net_stats(rows):
    """Na sit: (utoky, zasahy, fp, dny, zobrazeno, omylem)."""
    out = []
    for key in sorted(rows):
        r = rows[key]
        items = [a for a in r.get("attacks", []) if a.get("emitted") and a.get("cf") is not None]
        o = r["output"]
        out.append(dict(
            n=len(items), hit=sum(1 for a in items if a["cf"]),
            fp=o.get("displayed_fp_suspect", o.get("displayed_fp", 0)),
            days=r.get("virtual_days", 0), shown=o.get("displayed", 0),
            wrong=sum(1 for a in items if (a.get("k7") or {}).get("wrong_closed", 0) > 0),
        ))
    return out


def ratio_ci(base, cand, field, boot=2000, seed=20261402):
    """Parovy pomer FP na sit-den (kandidat / zaklad) s bootstrapem po sitich."""
    keys = sorted(set(base) & set(cand))
    a = net_stats({x: base[x] for x in keys})
    b = net_stats({x: cand[x] for x in keys})
    def stat(idx):
        da = sum(a[i]["days"] for i in idx)
        db = sum(b[i]["days"] for i in idx)
        fa = sum(a[i][field] for i in idx) / max(da, 1e-9)
        fb = sum(b[i][field] for i in idx) / max(db, 1e-9)
        return fb / fa if fa > 0 else float("nan")
    full = stat(range(len(keys)))
    rng = random.Random(seed)
    vals = []
    for _ in range(boot):
        v = stat([rng.randrange(len(keys)) for _ in keys])
        if v == v:
            vals.append(v)
    vals.sort()
    if not vals:
        return full, float("nan"), float("nan")
    return full, vals[int(0.025 * len(vals))], vals[min(len(vals) - 1, int(0.975 * len(vals)))]


def sums(rows):
    t = defaultdict(float)
    for r in rows.values():
        o = r["output"]
        t["nets"] += 1
        t["panics"] += r.get("panics", 0)
        t["viol"] += r.get("violations", 0)
        t["days"] += r.get("virtual_days", 0)
        for key in ("ladder_cases", "ladder_confirmed", "ladder_refuted", "ladder_escalated",
                    "ladder_refuted_wrong_cf", "ladder_escalated_attack", "ladder_decided_attack", "ladder_confirmed_attack",
                    "auto_closures", "auto_closures_wrong_cf"):
            t[key] += o.get(key, 0)
        t["prot"] += (o.get("k7") or {}).get("protected_auto_closed", 0)
        outcome = o.get("ladder_outcome_truth") or {}
        t["cases_attack"] += outcome.get("_cases|attack", 0)
        t["cases_benign"] += outcome.get("_cases|benign", 0)
    return t


def render(args):
    table = k.read_families(args.families)
    base_name, base_dirs = args.base[0], args.base[1].split(",")
    cand_name, cand_dirs = args.cand[0], args.cand[1].split(",")
    base, cand = load(base_dirs), load(cand_dirs)
    keys = set(base) & set(cand)
    base = {x: base[x] for x in keys}
    cand = {x: cand[x] for x in keys}
    tb, tc = k.totals(base), k.totals(cand)
    sb, sc = sums(base), sums(cand)
    out = [f"# {args.title}", "",
           f"Rameno `{base_name}` (základ) proti `{cand_name}` (kandidát), párově po sítích: {len(keys)} sítí, "
           f"{tc['n']} útoků a poruch s toky, {sc['days']:.0f} virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, "
           "bootstrap po sítích (B = 2000) pro poměry.", "",
           "## Souhrn", "",
           "| ukazatel | základ | kandidát | poznámka |", "|---|---|---|---|"]
    out.append(f"| detekce útoků | {k.ci(tb['hit'], tb['n'])} | {k.ci(tc['hit'], tc['n'])} | kontrafaktuální zobrazená detekce |")
    fr, flo, fhi = ratio_ci(base, cand, "fp")
    sr, slo, shi = ratio_ci(base, cand, "shown")
    out.append(f"| zobrazené FP na síť-den | {tb['fp'] / max(tb['days'], 1e-9):.2f} | {tc['fp'] / max(tc['days'], 1e-9):.2f} | poměr {fr:.3f} ({flo:.3f} až {fhi:.3f}); práh K9-3 ≤ 1,15 |".replace(".", ","))
    out.append(f"| všechny zobrazené položky na síť-den | {tb['shown'] / max(tb['days'], 1e-9):.1f} | {tc['shown'] / max(tc['days'], 1e-9):.1f} | poměr {sr:.3f} ({slo:.3f} až {shi:.3f}) |".replace(".", ","))
    out.append(f"| útoky s omylem zavřeným nálezem | {tb['wrong']} ({pc(tb['wrong'] / max(tb['n'], 1))} %) | {tc['wrong']} ({pc(tc['wrong'] / max(tc['n'], 1))} %) | práh K9-4 ≤ 2,2 % |")
    out.append(f"| chráněná automatická zavření | {int(sb['prot'])} | {int(sc['prot'])} | práh K9-5 = 0 |")
    out.append(f"| paniky / porušené invarianty | {int(sb['panics'])} / {int(sb['viol'])} | {int(sc['panics'])} / {int(sc['viol'])} | práh K9-7 = 0 |")
    out += ["", "## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto", "",
            "Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).", "",
            "| ukazatel | základ | kandidát |", "|---|---|---|"]
    for name, key in (("případů", "ladder_cases"), ("potvrzeno", "ladder_confirmed"), ("vyvráceno", "ladder_refuted"),
                      ("eskalováno (nerozhodnuto)", "ladder_escalated"), ("vyvráceno omylem (kontrafaktuál)", "ladder_refuted_wrong_cf")):
        out.append(f"| {name} | {int(sb[key])} | {int(sc[key])} |")
    for nm, s in ((base_name, sb), (cand_name, sc)):
        n = s["cases_attack"] + s["cases_benign"]
        out.append(f"| podíl případů pravdivého útoku mezi případy žebříku ({nm}) | {pc(s['cases_attack'] / max(n, 1))} % z {int(n)} | |".replace("| |", "|"))
    out += ["", "Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): " +
            f"základ {int(sb['ladder_refuted'] - sb['ladder_refuted_wrong_cf'])} z {int(sb['ladder_refuted'])}, "
            f"kandidát {int(sc['ladder_refuted'] - sc['ladder_refuted_wrong_cf'])} z {int(sc['ladder_refuted'])}. "
            "Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: " +
            f"základ {int(sb['ladder_confirmed_attack'])} z {int(sb['ladder_confirmed'])}, "
            f"kandidát {int(sc['ladder_confirmed_attack'])} z {int(sc['ladder_confirmed'])}. "
            "Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).", ""]
    # po rodinach
    rb, rc = k.per_family(base, table), k.per_family(cand, table)
    out += ["## Tabulka po rodinách a variantách (před a po)", "",
            "Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.", "",
            "| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |",
            "|---|---|---|---|---:|---|---|---|---|---|"]
    below = []
    for label in sorted(rc, key=lambda x: (rc[x]["info"]["category"], x)):
        c = rc[label]
        b = rb.get(label)
        info = c["info"]
        st = k.status(c)
        p, lo, _ = wilson(c["hit"], c["n"])
        reg = "-"
        if c["n"] >= 50 and (p < 0.90 or lo < 0.85):
            if label in CONTENT_ONLY:
                reg = "c (obsahový rozdíl neviditelný v tocích)"
            elif b and c["hit"] / max(c["n"], 1) > b["hit"] / max(b["n"], 1) + 1e-9:
                reg = "b (zmírněno, zbývá mezera)"
            else:
                reg = "c (otevřené)"
            below.append((label, c["n"], p, reg, info["category"]))
        out.append(f"| {label} | {info['category']} | {info['attack'] or '-'} | {info.get('tactic', '')} | {c['n']} | "
                   f"{k.ci(b['hit'], b['n']) if b else '-'} | {k.ci(c['hit'], c['n'])} | {k.ci(c['typed'], c['n'])} | {st} | {reg} |")
    # po taktikach a kategoriich
    out += ["", "## Souhrn po taktikách (kandidát)", "", "| taktika | n | detekce před | detekce po | správný typ po |", "|---|---:|---|---|---|"]
    agg = defaultdict(lambda: [0, 0, 0, 0, 0])
    for lab, c in rc.items():
        t = c["info"].get("tactic") or "none"
        b = rb.get(lab, dict(n=0, hit=0, typed=0))
        a = agg[t]
        a[0] += c["n"]; a[1] += c["hit"]; a[2] += c["typed"]; a[3] += b["n"]; a[4] += b["hit"]
    for t in sorted(agg):
        a = agg[t]
        out.append(f"| {t} | {a[0]} | {k.ci(a[4], a[3])} | {k.ci(a[1], a[0])} | {k.ci(a[2], a[0])} |")
    out += ["", "## Souhrn po kategoriích (kandidát)", "",
            "Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).", "",
            "| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |", "|---|---:|---|---|---|---|"]
    cat = defaultdict(lambda: [0, 0, 0, 0, 0, 0])
    for lab, c in rc.items():
        a = cat[c["info"]["category"]]
        b = rb.get(lab, dict(n=0, hit=0))
        a[0] += c["n"]; a[1] += c["hit"]; a[2] += c["typed"]; a[3] += b["n"]; a[4] += b["hit"]; a[5] += c["ops_shown"]
    for name in sorted(cat):
        a = cat[name]
        out.append(f"| {name} | {a[0]} | {k.ci(a[4], a[3])} | {k.ci(a[1], a[0])} | {k.ci(a[2], a[0])} | {pc(a[5] / max(a[0], 1))} % |")
    # protokol LOTO a LOFO (impl-krok10.md, C): predregistrovane foldy
    loto = ["credential-access", "discovery", "lateral-movement"]
    lofo = ["c2_slow_long_interval", "ssh_spray_slow_distributed", "data_staging_smb_internal",
            "kerberos_ticket_request_burst", "ics_attack", "cloud_api_discovery_burst", "rdp_bruteforce",
            "ddos_syn_flood_distributed"]
    out += ["", "## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)", "",
            "Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.", "",
            "| fold | n | detekce před | detekce po | správný typ po | K10-1 |", "|---|---:|---|---|---|---|"]
    def fold_row(name, labels):
        n = sum(rc[l]["n"] for l in labels if l in rc)
        hit = sum(rc[l]["hit"] for l in labels if l in rc)
        typed = sum(rc[l]["typed"] for l in labels if l in rc)
        nb = sum(rb[l]["n"] for l in labels if l in rb)
        hb = sum(rb[l]["hit"] for l in labels if l in rb)
        if n == 0:
            return f"| {name} | 0 | - | - | - | nepokryto v běhu |"
        p, lo, _ = wilson(hit, n)
        ok = "splněno" if (n >= 50 and p >= 0.90 and lo >= 0.85) else ("nedostatek dat" if n < 50 else "nedosaženo")
        return f"| {name} | {n} | {k.ci(hb, nb)} | {k.ci(hit, n)} | {k.ci(typed, n)} | {ok} |"
    for t in loto:
        out.append(fold_row("taktika " + t, [l for l, c in rc.items() if c["info"].get("tactic") == t and c["info"]["category"] == "security"]))
    for fam in lofo:
        out.append(fold_row("rodina " + fam, [fam]))
    out += ["", "## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)", "",
            "| rodina | n | detekce % | kategorie slepého místa |", "|---|---:|---:|---|"]
    for label, n, p, reg, cat_name in sorted(below, key=lambda x: x[2]):
        out.append(f"| {label} ({cat_name}) | {n} | {pc(p)} | {reg} |")
    out.append("")
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")
    print(f"zapsano {args.out}: {len(below)} rodin pod prahem z {len(rc)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--base", nargs=2, required=True)
    ap.add_argument("--cand", nargs=2, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="Výsledky kroku 9")
    render(ap.parse_args())


if __name__ == "__main__":
    main()
