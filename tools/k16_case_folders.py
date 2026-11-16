#!/usr/bin/env python3
"""Krok 16: mereni pripadovych slozek (K16-1 az K16-9) nad dumpem soaku nebo reporty.

Pouziti:
  k16_case_folders.py soak  DUMP.jsonl [...]        souhrn metrik ze soaku (K16_CASE_DUMP)
  k16_case_folders.py runs  WORKSPACE [...]          souhrn z report.json (produkcni cesta)
  k16_case_folders.py sample N SEED DUMP.jsonl [...] vyber pro senior review (kompaktni vypis)
  k16_case_folders.py same  A.jsonl B.jsonl          determinismus dvou dumpu (K16-7)

Pravidla nezavisle na Rust validatoru (ten je v dumpu jako `violations`): povinna pole,
smer dukazu proti krokum, uzaver jen u vyvracenych se silnym dukazem, shrnuti netvrdi verdikt.
"""
import glob
import json
import os
import random
import statistics
import sys
from collections import Counter

UNKNOWN = "nelze urcit"


def folders_from_dump(paths):
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)


def checks(f):
    """Nezavisla kontrola jedne slozky; vraci seznam poruseni."""
    v = []
    for key in ("schema", "case_id", "finding_type", "host", "summary", "recommended_step"):
        if not str(f.get(key, "")).strip():
            v.append(f"prazdne {key}")
    if not f["timeline"]:
        v.append("prazdna casova osa")
    roles = {a["role"] for a in f["actors"]}
    missing = " ".join(f["actors_missing"])
    for role, word in (("host", "host"), ("uzivatel", "uzivatel"), ("proces", "proces")):
        if role not in roles and word not in missing:
            v.append(f"akter {role} chybi bez vysvetleni")
    if "spojeni" not in roles and "protejsek" not in roles and "spojeni" not in missing:
        v.append("spojeni chybi bez vysvetleni")
    for name, q in f["uncertainty"].items():
        if q["value"] is None and not q["note"].strip():
            v.append(f"nejistota {name} bez hodnoty i duvodu")
    if not f["hypotheses"] or f["hypotheses"][0]["rank"] != 1:
        v.append("hypotezy")
    attack = [h for h in f["hypotheses"] if h["hypothesis"] == "utok"]
    if not attack or abs(attack[0]["probability"] - f["verdict"]["posterior_attack"]) > 1e-12:
        v.append("P(utok) hypotezy != verdikt")
    verified = {(c["check"], c["result"]) for c in f["verified"]}
    for e in f["evidence_for"]:
        if (e["check"], "podezrele") not in verified:
            v.append("dukaz pro bez kroku")
    for e in f["evidence_against"]:
        if (e["check"], "neskodne") not in verified:
            v.append("dukaz proti bez kroku")
    status = f["verdict"]["status"]
    if status == "refuted":
        c = f["closure"]
        if not c or not any(e["strong"] for e in c["proof"]):
            v.append("zavreno bez silneho dukazu")
        if f["handoff"]:
            v.append("zavreno s duvodem predani")
    else:
        if f["closure"]:
            v.append("uzaver u nezavreneho")
        if not f["handoff"]:
            v.append("predano bez duvodu")
    s = f["summary"].lower()
    if status == "escalated" and ("potvrdil" in s or "jako neskodny" in s):
        v.append("shrnuti tvrdi verdikt")
    if status == "confirmed" and not f["evidence_for"] and "bez podezreleho dukazu" not in s:
        v.append("potvrzeno bez dukazu, shrnuti to neuvadi")
    if not f["related"]["note"].strip():
        v.append("souvislosti bez poznamky")
    return v


def pct(a, b):
    return f"{100.0 * a / b:.1f} %" if b else "-"


def summarize(rows, label):
    n = len(rows)
    print(f"## {label}: {n} slozek")
    if not n:
        return
    status = Counter(r["folder"]["verdict"]["status"] for r in rows)
    print("stav:", dict(status))
    rust = [r for r in rows if r.get("violations")]
    py = [(r, checks(r["folder"])) for r in rows]
    py_bad = [(r, v) for r, v in py if v]
    print(f"K16-1/3/4 Rust validator: {len(rust)} porušení ({pct(n - len(rust), n)} bez porušení)")
    print(f"K16-1/4 nezavisla kontrola: {len(py_bad)} slozek s porusenim; typy: {Counter(x for _, v in py_bad for x in v).most_common(8)}")
    sizes = sorted(r.get("bytes") or len(json.dumps(r["folder"], ensure_ascii=False).encode()) for r in rows)
    p95 = sizes[min(len(sizes) - 1, int(0.95 * len(sizes)))]
    print(f"K16-6 velikost B: p50 {statistics.median(sizes):.0f}, p95 {p95}, max {sizes[-1]}")
    closed = [r["folder"] for r in rows if r["folder"]["verdict"]["status"] == "refuted"]
    if closed:
        own = sum(1 for f in closed if f["closure"]["owner"] != UNKNOWN)
        exp = sum(1 for f in closed if f["closure"]["expires"] != UNKNOWN)
        print(f"K16-8 uzavery L1: {len(closed)}, s vlastnikem {pct(own, len(closed))}, s expiraci {pct(exp, len(closed))}; dukaz: {Counter(f['closure']['proof'][0]['check'] for f in closed if f['closure']['proof']).most_common(5)}")
    handed = [r["folder"] for r in rows if r["folder"]["verdict"]["status"] != "refuted"]
    reasons = Counter(h.split(":")[0].split(" (")[0] for f in handed for h in f["handoff"])
    print("duvody predani:", reasons.most_common(10))
    blind = sum(1 for f in handed if any(not b.startswith("stav pokryti") for b in f["blind_spots"]))
    print(f"predane se slepym mistem: {pct(blind, len(handed))}; s doporucenou dalsi kontrolou: {pct(sum(1 for f in handed if f['to_verify']), len(handed))}")
    nofor = sum(1 for f in handed if not f["evidence_for"] and not f["evidence_against"])
    print(f"predane bez jakehokoli dukazu (jen apriorni): {pct(nofor, len(handed))}")
    if "truth_cf" in rows[0]:
        wrong_closed = sum(1 for r in rows if r["folder"]["verdict"]["status"] == "refuted" and r["truth_cf"])
        att = Counter((r["folder"]["verdict"]["status"], bool(r["truth_cf"])) for r in rows)
        print(f"pravda (kontrafaktual): {dict(att)}; zavrene, ktere byly utok: {wrong_closed}")


def cmd_soak(paths):
    rows = list(folders_from_dump(paths))
    summarize(rows, "soak " + ", ".join(os.path.basename(p) for p in paths))
    by_arm = Counter(os.path.basename(p).split("-")[0] for p in paths)
    print("ramena:", dict(by_arm))


def cmd_runs(workspaces):
    rows = []
    missing = 0
    mismatched = 0
    dropped = 0
    for ws in workspaces:
        for path in sorted(glob.glob(os.path.join(ws, "runs", "*", "report.json"))):
            with open(path, encoding="utf-8") as handle:
                report = json.load(handle)
            corr = report.get("correlation") or {}
            folders = {f["case_id"]: f for f in corr.get("caseFolders", [])}
            dropped += corr.get("caseFoldersDropped", 0)
            for d in report.get("verificationDecisions", []):
                f = folders.get(d["finding_id"])
                if f is None:
                    missing += 1
                    continue
                if f["verdict"]["posterior_attack"] != d["posterior"] or f["verdict"]["status"] != d["status"].lower():
                    mismatched += 1
            shown = [r for r in report.get("finding_lifecycle", report.get("findingLifecycle", [])) if r.get("displayed")]
            missing += sum(1 for r in shown if r["finding_id"] not in folders)
            rows.extend({"folder": f} for f in folders.values())
    print(f"K16-2 rozhodnuti/zobrazene bez slozky: {missing}; zahozeno stropem: {dropped}; K16-3 neshoda s verdiktem: {mismatched}")
    summarize(rows, "reporty " + ", ".join(workspaces))


def compact(r):
    f = r["folder"]
    out = [f"### {f['case_id']} | {f['finding_type']} | {f['verdict']['status']} {f['verdict']['level']} P={f['verdict']['posterior_attack']:.3f} | pravda: {'utok' if r.get('truth_cf') else 'neskodne'} ({r.get('truth_family')})"]
    out.append("S: " + f["summary"])
    out.append("K: " + f["recommended_step"])
    if f["handoff"]:
        out.append("H: " + "; ".join(f["handoff"]))
    if f["closure"]:
        c = f["closure"]
        out.append(f"U: vlastnik {c['owner']}, do {c['expires']}; " + "; ".join(f"{e['check']}: {e['detail'][:90]}" for e in c["proof"]))
    out.append("Hyp: " + ", ".join(f"{h['hypothesis']} {h['probability']:.2f} {h['status']}" for h in f["hypotheses"][:3]))
    out.append("PRO: " + ("; ".join(f"{e['check']}[{e['origin']}] {e['detail'][:80]}" for e in f["evidence_for"]) or "-"))
    out.append("PROTI: " + ("; ".join(f"{e['check']}[{e['origin']}{'' if e['strong'] else ',slaby'}] {e['detail'][:80]}" for e in f["evidence_against"]) or "-"))
    out.append("Zbyva: " + (", ".join(c["check"] for c in f["to_verify"][:3]) or "-") + " | Slepa: " + ("; ".join(b[:80] for b in f["blind_spots"][:3]) or "-"))
    out.append("Akteri: " + ", ".join(f"{a['role']}={a['id'][:40]}" for a in f["actors"][:4]))
    return "\n".join(out)


def cmd_sample(n, seed, paths):
    rows = list(folders_from_dump(paths))
    rng = random.Random(seed)
    strata = {}
    for r in rows:
        key = (r["folder"]["verdict"]["status"], bool(r.get("truth_cf")), r.get("truth_family") is not None)
        strata.setdefault(key, []).append(r)
    picked = []
    keys = sorted(strata, key=str)
    while len(picked) < n and any(strata.values()):
        for k in keys:
            if strata[k] and len(picked) < n:
                pool = strata[k]
                # ruzne rodiny: preferuj rodinu, ktera jeste nebyla
                fams = {p.get("truth_family") for p in picked}
                fresh = [p for p in pool if p.get("truth_family") not in fams] or pool
                choice = rng.choice(fresh)
                pool.remove(choice)
                picked.append(choice)
    for r in picked:
        print(compact(r))
        print()


def cmd_same(a, b):
    def load(p):
        return sorted(json.dumps(r, sort_keys=True) for r in folders_from_dump([p]))
    la, lb = load(a), load(b)
    print(f"K16-7 dump A {len(la)} radek, B {len(lb)} radek, shodne: {la == lb}")


if __name__ == "__main__":
    mode, args = sys.argv[1], sys.argv[2:]
    if mode == "soak":
        cmd_soak(args)
    elif mode == "runs":
        cmd_runs(args)
    elif mode == "sample":
        cmd_sample(int(args[0]), int(args[1]), args[2:])
    elif mode == "same":
        cmd_same(args[0], args[1])
