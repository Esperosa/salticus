# Koncová a provozní telemetrie: nasazení, soukromí, retence

Dokument shrnuje, co nasazení koncové (Sysmon, Wazuh, osquery, Falco, Tetragon, auditd, EVTX) a provozní (SNMP, syslog, DHCP, DNS, ARP, NTP, probes) telemetrie znamená pro data, a které volby se nastavují. **Nejde o právní stanovisko.** Odkazy na předpisy jsou převzaté z rešerše `docs/diplomka/studie/14-endpoint-a-graf-aktiv.md` (oddíl 3.5, řádky E14-044 a E14-045) a o tom, zda je splněn zákonný důvod, rozhoduje provozovatel s právníkem.

## Co se sbírá

| zdroj | pole, která se ukládají | citlivé |
|---|---|---|
| procesy (Sysmon 1, Falco, Tetragon, auditd, osquery) | cesta obrazu, rodič, příkazová řádka, uživatel, podpis, výrobce, SHA-256 | příkazová řádka může obsahovat hesla a tokeny, uživatel je osobní údaj |
| spojení (Sysmon 3, osquery, Tetragon, auditd) | obraz, cílová IP a port | cíl může prozradit osobní aktivitu |
| přihlášení (Windows 4624, 4625) | uživatel, typ, zdrojová IP | osobní údaj |
| soubory (Sysmon 11) | cesta a proces | cesta může obsahovat jméno uživatele |
| provozní telemetrie | klíč signálu, čas, rozsah (IP nebo podsíť), hodnota | IP adresy zařízení |

Obsah souborů, e-mailů a prohlížení se nesbírá. Příkazová řádka se při uložení do nálezu a do grafu redaktuje (`endpoint::graph::redact_cmdline`: klíč=hodnota u klíčů heslo, token, secret, key, auth; hodnoty za příznaky `-p`, `--password`, `--token`, `-EncodedCommand`; řetězce base64 delší než 40 znaků; `Authorization: Bearer`). Redakce je hrubá (raději smazat víc) a nenahrazuje filtr u zdroje.

## Co nastavit

| volba | výchozí | poznámka |
|---|---|---|
| pseudonymizace uživatelů (`Privacy.pseudonymize_users`) | zapnuto | solená funkce (`Privacy.salt`); sůl musí být tajná a stálá v rámci instalace; bez soli nejsou pseudonymy srovnatelné mezi instalacemi; systémové účty (SYSTEM, root, účty končící `$`) zůstávají čitelné |
| redakce příkazové řádky (`Privacy.redact_cmdline`) | zapnuto | vypnutí jen s vědomým rozhodnutím provozovatele |
| retence událostí (`Privacy.retention_s`, `Limits.max_age_s`) | 24 h, strop 500 000 řádků | tabulka `endpoint_events` v `engine-state.sqlite`; provozní signály `ops_signals` 24 h, strop 200 000 |
| seznam povolených (`Allowlist`) | prázdný | položka bez vlastníka, bez expirace, s neplatným hashem nebo s protistranou `*` se nepřijímá; expirace je povinná (doporučeno do 90 dnů) |
| příjem | `POST /api/endpoint/ingest`, `POST /api/ops/ingest` | oprávnění `findings.write`, ochrana CSRF, tělo nejvýš 8 MiB (koncové) a 4 MiB (provozní) |
| čtení grafu | `GET /api/endpoint/graph?hosts=...` | oprávnění `runs.read`; graf nenese příkazové řádky, uživatelé jsou pseudonymizovaní |

## Doporučení pro dokumentaci nasazení (z rešerše, k doplnění provozovatelem)

1. Zapsat účel (detekce incidentů a provozních poruch) a právní základ. Pro zaměstnance zákoník práce § 316 odst. 2 omezuje sledování soukromí bez závažného důvodu a odst. 3 ukládá informovat zaměstnance o rozsahu a způsobu kontroly (E14-044). Zda jde o „závažný důvod“, určí právník.
2. Minimalizace a omezení uložení podle čl. 5 odst. 1 písm. c) a e) GDPR (E14-045): sbírat jen pole z tabulky výše, držet surové události krátce a nálezy déle.
3. Posouzení vlivu na ochranu osobních údajů (čl. 35) zvážit tam, kde agent běží na pracovních stanicích zaměstnanců (E14-045).
4. Informovat zaměstnance předem o seznamu sbíraných polí, době uchování a tom, kdo má k datům přístup.
5. Agent na hostu je bod důvěry: kompromitovaný host může lhát nebo mlčet (`agent_mismatch` hlásí hosta s provozem v síti a mlčícím agentem jako slepé místo, příčinu neurčuje).

## Co se neověřilo

Znění WP249, rozsudku Bărbulescu a stanovisek ÚOOÚ je v rešerši na úrovni V1 (nečteno z primárního zdroje). Právní věty výše jsou jen odkazy, ne závěry.
