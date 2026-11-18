"""SbÄ›raÄŤ SNMP (obdoba Zabbix/Cacti): po 10 s ÄŤte IF-MIB a HOST-RESOURCES-MIB, ÄŤĂ­taÄŤe pĹ™evĂˇdĂ­ na rychlost.

VĂ˝stup /out/logs/snmp.log: `EPOCH<TAB>host oid = TYPE: value` (ÄŤas sbÄ›ru, pak Ĺ™Ăˇdek ve tvaru snmpget).
VyuĹľitĂ­ linky = rychlost / znĂˇmĂˇ rychlost linky z inventĂˇĹ™e (smÄ›rovaÄŤ: emulovanĂˇ WAN 20 Mbit/s).
"""
import os, subprocess, time

LOG = "/out/logs/snmp.log"
SPEED = {"10.77.2.254": 20e6, "10.77.2.10": 10e9}
prev = {}
os.makedirs(os.path.dirname(LOG), exist_ok=True)

def walk(host, oid):
    r = subprocess.run(["snmpwalk", "-v2c", "-c", "lab", "-t", "2", "-r", "1", "-On", "-Oq", host, oid],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0].rsplit(".", 1)[-1]] = parts[1].strip().strip('"')
    return out

def write(lines):
    with open(LOG, "a") as f:
        for l in lines:
            f.write(f"{int(time.time())}\t{l}\n")

while True:
    now = time.time()
    lines = []
    for host in ("10.77.2.254", "10.77.2.10"):
        descr = walk(host, ".1.3.6.1.2.1.2.2.1.2")
        if descr is None:
            lines.append(f"# {host} snmp timeout")
            continue
        oper = walk(host, ".1.3.6.1.2.1.2.2.1.8") or {}
        cnt = {n: walk(host, o) or {} for n, o in (("in", ".1.3.6.1.2.1.31.1.1.1.6"), ("out", ".1.3.6.1.2.1.31.1.1.1.10"),
                                                     ("inerr", ".1.3.6.1.2.1.2.2.1.14"), ("outdisc", ".1.3.6.1.2.1.2.2.1.19"))}
        for idx, name in descr.items():
            if name == "lo":
                continue
            st = oper.get(idx, "")
            lines.append(f"{host} IF-MIB::ifOperStatus.{idx} = INTEGER: {1 if st.startswith('up') or st == '1' else 2}")
            for n, label in (("inerr", "IF-MIB::ifInErrors"), ("outdisc", "IF-MIB::ifOutDiscards"), ("in", "in"), ("out", "out")):
                try:
                    v = float(cnt[n][idx])
                except (KeyError, ValueError):
                    continue
                key = (host, idx, n)
                if key in prev:
                    pv, pt = prev[key]
                    rate = max(0.0, (v - pv) / max(1e-3, now - pt))
                    if n in ("inerr", "outdisc"):
                        lines.append(f"{host} {label}.{idx} = Counter32: {rate:.3f}")
                    else:
                        pct = 100.0 * rate * 8 / SPEED[host]
                        lines.append(f"{host} ifUtil{n.capitalize()}Pct.{idx} = Gauge32: {pct:.1f}")
                prev[key] = (v, now)
        if host == "10.77.2.10":
            # HOST-RESOURCES-MIB hrStorage: obsazení /data v procentech (used / size, jako šablony Zabbix)
            sd = walk(host, ".1.3.6.1.2.1.25.2.3.1.3") or {}
            size = walk(host, ".1.3.6.1.2.1.25.2.3.1.5") or {}
            used = walk(host, ".1.3.6.1.2.1.25.2.3.1.6") or {}
            for idx, d in sd.items():
                if d == "/data" and idx in size and idx in used and float(size[idx]) > 0:
                    pct = 100.0 * float(used[idx]) / float(size[idx])
                    lines.append(f"{host} hrStorageUsedPct.{idx} = Gauge32: {pct:.1f}")
    write(lines)
    time.sleep(max(1.0, 10 - (time.time() - now)))
