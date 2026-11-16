#!/usr/bin/env python3
"""Krok 15 (P3): pole `explains` v katalogu provozních incidentů.

Každý typ katalogu dostane seznam příznakových skupin nálezů, které jeho mechanismus
vyvolává. Odvozuje se z povahy původce a tvaru provozu varianty simulátoru
(`src/soak/variants.rs`: `A::Fault` = porucha infrastruktury bez původce v hostu,
jinak host sám vytváří nový provoz) a z ruční korekce u poruch, které mění cesty
(nový resolver, nová brána): ty vyvolávají i novost vztahů.

Skupiny (viz `ops_telemetry::symptom_groups`): `availability` (nedostupnost, timeouty,
přetížení), `volume` (objem, tempo), `broadcast` (bouře), `novelty` (nový partner,
nová služba, nečekaný provoz), `periodic` (pravidelný maják), `scan` (rozptyl cílů,
pokusy o sken).

Pravidlo: porucha infrastruktury (`Fault`) nevysvětlí novost, maják ani sken; to dělá
jen změna nebo porucha, která hostům mění cesty. K tomu se přidají skupiny podle
autorského popisu typu v katalogu (`signals.flows` a `confusable_with_attack`: s čím
se typ plete, to i vyvolává; např. „vlny nových spojení“, „vypadá jako beaconing“,
„přepnutí na záložní region“), takže zdrojem je text katalogu, ne výstup simulátoru.
Použití: python -I tools/k15_catalog_explains.py [--write]
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "incident-catalog.json"
VARIANTS = ROOT / "src" / "soak" / "variants.rs"

# porucha, ktera hostum meni cesty (novy resolver, brana, VLAN): vyvola i novost vztahu
PATH_CHANGING = {
    "OPS-028", "OPS-029", "OPS-030", "OPS-033", "OPS-034", "OPS-036", "OPS-037",
    "OPS-041", "OPS-042", "OPS-038", "OPS-003",
}
FAULT_PATTERN = {
    "Outage": ["availability"],
    "Degrade": ["availability", "volume"],
    "Flap": ["availability"],
    "Cascade": ["availability"],
    "Saturate": ["availability", "volume"],
    "Drift": ["availability"],
    "Storm": ["broadcast", "volume", "availability"],
    "Peak": ["volume", "availability"],
}
# klicova slova autorskeho popisu (signals.flows, confusable_with_attack) -> skupina
TEXT_GROUPS = [
    ("periodic", ("beacon", "pravideln", "periodick", "c2 ", "kanál", "kanal")),
    ("availability", ("dos", "ddos", "blok", "tarpit", "filtrov", "izolac", "výpad", "vypad", "timeout", "rst", "selh", "zamrz", "neodpov")),
    ("volume", ("exfiltr", "objem", "staging", "stahov", "stažen", "saturac", "záplav", "zaplav", "flood", "amplifik")),
    ("scan", ("sken", "scan", "sweep", "recon", "enumer", "spray", "brute", "stuffing", "lateral", "pokus", "přihlášen", "prihlasen", "starvation", "fuzzing")),
    ("novelty", ("mitm", "spoof", "hijack", "rogue", "podvrž", "podvrz", "nov", "neznám", "neznam", "dga", "tunel", "fuzzing", "ciz", "přesměrov", "presmerov", "přepnut", "prepnut", "jinam", "záložn", "zalozn", "re-auth", "deauth", "mac ")),
]


def text_groups(entry):
    text = (entry["signals"]["flows"] + " " + entry["confusable_with_attack"]).lower()
    out = []
    for group, words in TEXT_GROUPS:
        if any(w in text for w in words):
            out.append(group)
    return out


HOST_PATTERN = {
    "Periodic": ["periodic", "novelty"],
    "Burst": ["volume", "novelty"],
    "BulkIn": ["volume", "novelty"],
    "BulkOut": ["volume", "novelty"],
    "Trickle": ["novelty", "periodic"],
    "Sweep": ["scan", "novelty"],
    "PortSweep": ["scan", "novelty"],
    "FanOut": ["scan", "novelty"],
    "Flood": ["volume", "availability"],
    "SlowConn": ["availability", "volume"],
}


def main() -> int:
    src = VARIANTS.read_text(encoding="utf-8")
    specs = {
        name: (actor, pattern)
        for name, pattern, actor in re.findall(
            r'sp\(\s*"([a-z0-9_]+)",\s*"[^"]*",\s*\w+,\s*P::(\w+),\s*A::(\w+)', src
        )
    }
    cat = json.loads(CATALOG.read_text(encoding="utf-8"))
    changed = 0
    for e in cat["incidents"]:
        v = e.get("sim_variant")
        if v not in specs:
            print(f"{e['id']}: bez varianty simulatoru, explains se nenastavuje", file=sys.stderr)
            continue
        actor, pattern = specs[v]
        if actor == "Fault":
            groups = list(FAULT_PATTERN[pattern])
            if e["id"] in PATH_CHANGING:
                groups.append("novelty")
        else:
            groups = list(HOST_PATTERN[pattern])
            if e["id"] in PATH_CHANGING and "novelty" not in groups:
                groups.append("novelty")
        for g in text_groups(e):
            if g not in groups:
                groups.append(g)
        if e.get("explains") != groups:
            changed += 1
        e["explains"] = groups
        print(f"{e['id']:8} {e['category']:15} {v:34} {actor:12} {pattern:10} -> {','.join(groups)}")
    if "--write" in sys.argv:
        cat["catalog_version"] = "1.2.0"
        CATALOG.write_text(json.dumps(cat, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"zapsano {CATALOG} (zmeneno {changed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
