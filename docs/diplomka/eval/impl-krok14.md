# Krok 14 (zatím nezačato)

Krok 14 nezačal; zde je jen závazný protokol měření převzatý z kroku 13.

## Protokol měření (závazný od 2026-11-15, schváleno uživatelem)

Platí pro zbytek kroku 13 a pro krok 14. Porovnání verzí se nedělá jedním seedem, ale maticí.

- **Matice.** 10 seedů x 3 konfigurace sítě: small = Soho, Smb, IotHeavy; medium = Enterprise, Campus, Hospital, Industrial; large = Datacenter, Cloud, Metro; XXXL a XXL se hlásí zvlášť jako stres (`size_class`). Konfiguraci generátor neumí vynutit, odvozuje se po běhu z archetypu sítě (`tools/k13_matrix.py`, `config_of`); sítí na buňku je tedy tolik, kolik jich seed vylosoval.
- **Cíl rozsahu.** 600 až 1 000 sítí na rameno. **Nesplněno**: stroj dává ~1 síť za minutu při 6 vláknech (Idle), tj. 600 sítí = ~10 h na rameno. Zvolený rozsah a stav jsou v tabulce níže; maticová verze se pouští po částech.
- **Párování.** Základ a kandidát na stejných seedech, stejných sítích (`run_seed`, `network_id`), liší se jen přepínačem (`--v3-on`). Nepárové sítě se vynechají a spočtou. Běhy s různými seedy se nikdy nesrovnávají.
- **Jednotka analýzy** je síť. Poměrové ukazatele jsou součty přes sítě (poměr součtů). Intervaly 95 %: bootstrap po sítích stratifikovaný po seed x konfigurace, B = 2000, pevný seed, stejné vzorkování pro obě ramena; Wilson jen doplňkově. Hlásí se celek, konfigurace, rozptyl mezi seedy a rodiny zvlášť.
- **Dvě sady seedů.** Ladicí (smí se ladit): 20261102, 20261103, 20266101, 20266102, 20266103, 20266104, 20266105, 20266106, 20266107, 20266108. Držené (zapsáno dopředu, použít jednou na konci, nikdy nepoužity): 20265101, 20265102, 20265201, 20265202, 20265301, 20265302, 20265401, 20265402, 20265501, 20265502. hn_* ladicí (hn_cdn_update_download, hn_mail_newsletter_burst, hn_admin_bulk_ssh, hn_authorized_internal_scan) a držené (hn_nightly_cloud_backup_upload, hn_db_replication_bulk, hn_monitoring_snmp_sweep, hn_password_sync_periodic) zvlášť jako dosud.
- **Rozsah ladicí sady (plán):** 20261102 a 20261103 po 40 sítích, osm dalších seedů po 20 sítích = 240 sítí na rameno. Držená sada: 10 seedů po 20 sítích = 200 sítí na rameno (po částech).
- **Dlouhé běhy** (soak 72 h) jen jako test stability a objemu, ne pro porovnání verzí.
- **Nástroj:** `tools/k13_matrix.py --families TSV --base DIRS --cand DIRS` (párové srovnání po sítích, tabulky po konfiguracích, seedech a rodinách). Stav: viz „Stav matice“ níže.
