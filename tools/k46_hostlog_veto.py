#!/usr/bin/env python3
"""Krok 46 (diagnostická ablace, post-hoc, ne nový běh): veto potvrzeného admin kanálu.

Zdroj: DAPT2021 raw/host-logs/10_1_1_11/auth-logs (sshd). Za celé okno 27.6.-4.7.2021 je
VŠECH 50 přijatých přihlášení k 10.1.1.11 ze stejné adresy 10.1.1.18, se stejným otiskem
klíče, 0 neúspěchů -> potvrzený administrativní kanál, ne útočník. Hostitel 10.1.1.11 je
v impl-krok41.md jmenován jako součást velkého "znečištěného" incidentu (47/42 incidentů,
kontaminace 0,39-0,56).

Tento skript NEOPAKUJE běh Salticusu. Vezme existující `result.json` (z kroku 41/42) a
přepočítá seskupení B1b/INC s jedinou změnou: pár adres (10.1.1.18, 10.1.1.11) se z indikátorů
nálezu odstraní před seskupením, takže přes něj nálezy nejde spojit. Je to spodní odhad dopadu
(jen jeden potvrzený pár, ostatní hostitelé v incidentu mají jen syslog bez autentizace, takže
jejich kanály nejde potvrdit ani vyvrátit).
"""
import copy
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


k33 = load("k33_corr")
k35 = load("k35_corr")
VETO = {("10.1.1.18", "10.1.1.11"), ("10.1.1.11", "10.1.1.18")}


def strip_veto(shown):
    """Kopie `shown` bez textové zmínky vetovaného partnera, jen pro nálezy, které zmiňují
    OBĚ adresy páru současně (jinak by se odstranila i jiná, nesouvisející zmínka adresy)."""
    out = []
    for f in shown:
        g = dict(f)
        ips = k33.ips_of(f["text"])
        if any(a in ips and b in ips for a, b in VETO):
            text = f["text"]
            for a, b in VETO:
                text = text.replace(a, "0.0.0.0").replace(b, "0.0.0.0") if a in ips and b in ips else text
            g["text"] = f["text"]
            # jednodušeji a bezpečně: odstraní obě adresy párů jen z tohoto nálezu
            t = f["text"]
            for a, b in {("10.1.1.18", "10.1.1.11")}:
                if a in ips and b in ips:
                    t = t.replace(a, "veto").replace(b, "veto")
            g["text"] = t
        out.append(g)
    return out


def arm_stats(shown, truth_eval, chain):
    arms = {"B1b": k35.groups_ip_window(shown), "B1": k33.groups_ip(shown)}
    out = {}
    for name, groups in arms.items():
        groups = [g for g in groups if len(g) >= 2]
        ci = [g for g in groups if any(f in chain for f in g)]
        tot = sum(len(g) for g in ci)
        non = sum(1 for g in ci for f in g if f not in chain)
        out[name] = {
            "incidents": len(groups), "chain_incidents": len(ci),
            "contamination": round(non / tot, 3) if tot else 0.0,
            "largest": max((len(g) for g in groups), default=0),
            "completeness": round(max((sum(1 for f in g if f in chain) for g in ci), default=0) / len(chain), 3) if chain else 0.0,
        }
    return out


def main():
    result_path, truth_path, chain_kind = sys.argv[1], sys.argv[2], sys.argv[3]
    res = json.load(open(result_path, encoding="utf-8"))
    shown = res["shown"]
    if chain_kind == "dapt":
        truth = json.load(open(truth_path, encoding="utf-8"))
        camp = set(truth["campaign_ips"])
        chain = {f["id"] for f in shown if k33.ips_of(f["text"]) & camp}
    else:
        truth = json.load(open(truth_path, encoding="utf-8"))
        chain = {f["id"] for f in shown if len(k33.chain_of(f["text"], truth)) >= 1}
    before = arm_stats(shown, truth, chain)
    after = arm_stats(strip_veto(shown), truth, chain)
    affected = sum(
        1 for f in shown
        if {"10.1.1.18", "10.1.1.11"} <= k33.ips_of(f["text"])
    )
    print(json.dumps({"shown": len(shown), "chain_findings": len(chain),
                      "findings_mentioning_vetoed_pair": affected,
                      "before": before, "after": after}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
