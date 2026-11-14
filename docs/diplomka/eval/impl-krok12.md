# Implementace, krok 12: chybějící vstupy, politika zavírání, pokrytí senzorů

Datum 2026-11-14. Navazuje na krok 11. Studie: `../studie/12-telemetrie-a-zavirani.md`. **Tato předregistrace vznikla před jakýmkoli kódem kroku 12** (v repu k tomuto commitu není žádná změna `src/`).

## 0) Stav práce (aktualizuje se; navázání po přerušení)

| část | stav |
|---|---|
| A studie | hotová; pole Zeek, Suricata, JA3, JA4 a RITA ověřena proti primárním stránkám (studie, oddíl 7); SOC zavírání je moje syntéza, citace chybí |
| D politika zavírání | `strict_close` implementován a otestován (commit `feat(context_gate)`); **ověření na datech běží** (rameno `sA`, seedy 20263101 a 20263102) |
| B vstupy | `src/l7.rs` (parsery Zeek ssl/x509/dns/http a EVE tls/dns/http, fuzz test), `behavior/l7.rs` (`tls_rare_transfer`, `tls_novel_burst`, `dns_zone_enumeration`), přepínače `l7_tls`, `l7_dns`, inbound toky a L7 v `BehaviorInput`, načítání z `zeek_dir` a EVE; endpointová telemetrie z kroku 8 je přepínač `endpoint`, beze změny |
| C simulace | svět `--l7 on` (`soak/l7sim.rs`): TLS a DNS metadata ke tokům po degradaci. **Nehotové:** kalibrace na veřejných datech, datasety, reálné přehrání, příčina LUFlow 1/259 |
| E pokrytí senzorů | nezačato |
| F žebřík s ECE, incident_id | nezačato |
| měření na držených seedech, soak verify, celý test | nezačato |

Důvod: rozsah (nové datové typy napříč parserem, modelem, behaviorální vrstvou, žebříkem a simulátorem, plus stahování a zpracování datasetů) přesahuje jeden průchod; raději stav přiznávám, než abych odevzdal polovinu jako hotovou.

## 1) Prahy (předregistrované, hodnoty se po měření nemění)

| id | práh | splněno, když |
|---|---|---|
| K12-1 | omylem zavřené útoky na všech sadách | 0 pozorováno; uvést horní mez Wilson 95 % (≈ 3,7/N). 0 pozorováno neznamená 0 zaručeno |
| K12-2 | detekce rodin s pozorovatelným útokem (`visible_flows` > 0) | ≥ 90 % u každé rodiny a dolní mez Wilson ≥ 85 % tam, kde n ≥ 50 |
| K12-3 | zobrazené FP na síť-den proti k8ref | poměr ≤ 1,15 |
| K12-4 | neškodné hn_* z **držené** poloviny | podíl zobrazených nejvýš o 10 p. b. nad základem k8ref |
| K12-5 | paniky, porušené invarianty, chráněná zavření | 0 |
| K12-6 | determinismus | `soak verify` zelený s novými přepínači |
| K12-7 | parsery TLS/DNS/HTTP | fuzz test (náhodné a poškozené vstupy), 0 paniků |
| K12-8 | zákaz paměti | `no_memory` zelený |
| K12-9 | LOFO a leave-one-tactic-out nových detektorů | detekce na rodinách mimo ladicí množinu ≥ 85 %, bez zhoršení základu o víc než 3 p. b. |
| K12-10 | žebřík L0 až L4: nejisté případy rozhodnuté správně, ECE, čas | změřit a hlásit; cíl správně ≥ 80 % rozhodnutých, ECE ≤ 0,10 |
| K12-11 | pokrytí senzorů | každý host a segment bez telemetrie v okně je v hlášení; slepý útok nevyvolá tichý nález |

## 2) Pravidla měření

- **Rozdělení hn_* na ladicí a držené.** Ladicí: hn_cdn_update_download, hn_mail_newsletter_burst, hn_admin_bulk_ssh, hn_authorized_internal_scan. Držené (nesmí se použít k ladění, jen jednou na konci): hn_nightly_cloud_backup_upload, hn_db_replication_bulk, hn_monitoring_snmp_sweep, hn_password_sync_periodic. Nové hn_* scénáře se přidávají s realistickými TLS a DNS poli a stejným rozdělením.
- Seedy: ladicí 20262301 až 20262302 a 20261102 až 20261104 (již viděné, jen ladění). **Nové držené seedy nikým neviděné: 20264101, 20264102, 20264201, 20264202, 20264301, 20264302**, pustí se jednou na konci. Seedy 20263101 až 20263302 jsou po kroku 11 spotřebované a nepoužijí se jako držené.
- Základ k8ref a poslední preset; kandidát = nové přepínače, výchozí vypnuto.
- LOFO: nové detektory se ladí bez rodin z množiny LOFO kroku 10 a bez taktik credential-access, discovery, lateral-movement; vyhodnocení po rodinách a taktikách.
- Provoz: Idle priorita, nejvýš 6 vláken, jedno rameno najednou; PID 118652 se nedotýká.

## 3) Návrh oprav (před kódem)

1. **Zavírání** (`context_gate.rs`, `closure_audit.rs`): kontext zavře nález jen pokud (a) záznam má vlastníka a expiraci, (b) **všechny** zdroje i cíle nálezu leží v rozsahu záznamu, (c) nález má identifikovaný zdroj. Jinak zůstane zobrazen s poznámkou. Audit log každého zavření, vzorek pro člověka. Regresní test: souběh skeneru a útoku z jiného zdroje se nezavře.
2. **Vstupy**: nové pole `TlsMeta`, `DnsMeta`, `HttpMeta` v `ConnectionObservation` (nebo souběžná tabulka), adaptéry Zeek `ssl/x509/dns/http` a Suricata EVE `tls/dns/http/fileinfo/anomaly`, fuzz test. Přepínače `tls_meta`, `dns_meta`, `http_meta`, `inbound`.
3. **Detektory** (každé aspoň dva nezávislé rysy, žádný port): šifrované stažení = rarita SNI v síti × poměr směrů × nový JA3 nebo čerstvý certifikát; zone enum = AXFR/IXFR nebo vysoký počet unikátních jmen s NXDOMAIN od vnějšího zdroje; shluk toků na nový cíl = rarita SNI + shluk + chybějící předchozí DNS.
4. **Pokrytí senzorů**: stav pokrytí po segmentech a hostech (poslední viděný tok, očekávaná aktivita), viditelný nález „bez telemetrie“, doporučení umístění tapu a zapnutých logů.
5. **Žebřík**: nové kontroly (TLS, DNS, endpoint) jako nezávislé druhy důkazu; `incident_id` v generátoru poruch a metriky seskupení.

## 4) Poznámky a odchylky

(zapisuje se průběžně)

## 5) Fáze „chytřejší korelace a práce s nejistotou“ (předregistrace, před kódem této fáze)

Studie: `../studie/12b-korelace-a-nejistota.md`. Přepínače: `hypotheses`, `evidence_lr`, `ladder_chain`, `retro`, `reopen`, `conformal`, `case_file`, `forensic_requests`; všechny výchozí vypnuto.

Metriky a prahy (hodnoty se po měření nemění):

| id | metrika | práh |
|---|---|---|
| K12-12 | správné rozhodnutí u případů, které žebřík dnes nechává nerozhodnuté (kontrafaktuální pravda) | ≥ 80 % z rozhodnutých; podíl rozhodnutých se hlásí zvlášť |
| K12-13 | ECE posteriorů žebříku (10 košů) a spolehlivostní diagram | ECE ≤ 0,10; Brier a log-loss vedle |
| K12-14 | autonomní zavření neškodného případu: omylem zavřený útok | 0 pozorováno, horní mez Wilson 95 % uvést; cíl horní meze ≤ 0,5 % při N ≥ 600 autonomních zavření, jinak „záruka nedosažena, rozhoduje člověk“ |
| K12-15 | omylem eskalovaný neškodný případ z autonomních rozhodnutí | horní mez Wilson 95 % ≤ 5 % |
| K12-16 | podíl autonomních rozhodnutí a podíl předaných člověku podle důvodu | hlásit; bez prahu (měření hranice automatizace) |
| K12-17 | konformální pokrytí na držených seedech | empirické pokrytí ≥ nominální 90 % − 2 p. b. |
| K12-18 | čas k rozhodnutí (cykly) a počet kontrol na případ | hlásit medián a p90; cíl: bez nárůstu mediánu o víc než 20 % proti stavu bez fáze |
| K12-19 | čistota seskupení do incidentů (podíl nálezů incidentu patřících jedné pravdě) a nálezů na incident; čas k prvnímu nálezu | čistota ≥ 90 %; ostatní hlásit |
| K12-20 | správné oddělení útoku od poruchy (kontrafaktuál, jen případy s oběma typy ve stejném okně) | ≥ 85 % |
| K12-21 | audit: každé autonomní rozhodnutí a každé přehodnocení má záznam s důkazy | 100 % |
| K12-22 | forenzní žádost bez schválení nikdy neprovedena | 0 provedení |

Provedení: A/B proti rameni bez fáze (stejné seedy, svět k10 s `--l7 on`), ladění na ladicích seedech a ladicích hn_*, držené seedy 20264101 až 20264302 a držené hn_* jednou; leave-one-family-out stejné rodiny jako K10-1; kombinace útok + porucha + šum 10× a XXXL jednou na konci. Soak musí od této fáze ukládat posteriory žebříku (`ladder_posteriors` v `networks.jsonl`), jinak ECE nejde změřit.

### Stav fáze

| úkol | stav |
|---|---|
| rešerše 12b | hotová, zdroje ověřeny s uvedenými výhradami |
| 1 konkurenční hypotézy a EVOI | nezačato |
| 2 sekvenční vážení | nezačato |
| 3 žádost o chybějící data | nezačato |
| 4 retrospektivní vyhledávání | nezačato |
| 5 znovuotevření a audit | nezačato |
| 6 kalibrace, ECE, konformální, ukládání posteriorů | nezačato |
| 7 spis případu | nezačato |
| 8 forenzní žádosti | nezačato |
