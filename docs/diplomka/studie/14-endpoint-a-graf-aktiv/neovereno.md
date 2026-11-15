# Studie 14 (endpoint a graf aktiv): neověřeno (V1/V0)

Co je tady, **nesmí být v závěrech**. Důvod je u každé položky. Datum 2026-11-15.

| # | tvrzení nebo zdroj | úroveň | důvod |
|---|---|---|---|
| 1 | ATLAS (Alsaheel et al., USENIX Security 2021): precision 91,06 %, recall 97,29 %, F1 93,76 % na 10 APT scénářích | V1 | jen shrnutí vyhledávače; PDF na umass.edu vrátilo 404 (řádek E14-028 je označen V1) |
| 2 | CAPTAIN „NDSS 2022“ (zadání) | V0 | takový článek nenalezen; CAPTAIN je NDSS 2025 (arXiv 2404.14720), čteno v E14-022 |
| 3 | Wazuh: integrace Sysmon přes `eventchannel`, pravidla `sysmon_event1`, ID pravidla 20485 | V1 | jen blogy a fórum; oficiální stránku se Sysmon pravidly vyhledávač nevrátil |
| 4 | osquery `process_open_sockets`: sloupce pid, fd, socket, family, protocol, local/remote address a port, path | V1 | `osquery.io/schema` a GitHub raw spec vrátily 404; sloupce jen ze shrnutí vyhledávače; že jde o snímek v době dotazu, je v dokumentaci process-auditing nepřímo (socket_events je event tabulka) |
| 5 | osquery sloupce `socket_events` a mapování na Community ID | V1 | nečteno; Community ID spec uvádí podporu v osquery 4.2.0+ (V3 E14-012) |
| 6 | Fleet (fleetdm): plánování dotazů, objem výsledků | V0 | stránka nenačtena |
| 7 | Elastic Defend: pole `process.entity_id` v síťových událostech, `community_id` | V1 | oficiální stránka vrátila 404, event-capture stránka pole neuvádí |
| 8 | Elastic Defend: Tamper Protection dostupné jen v placené úrovni | V1 | jen výsledek vyhledávače |
| 9 | Timesketch: analyzátory Sigma, Tagger, Similarity Scorer | V1 | jen neoficiální stránky; oficiální import (V3 E14-051) tyto analyzátory nepopisuje |
| 10 | Security Onion: spojení Elastic Agent a Sysmon přes Community ID | V0 | stránka Community ID Elastic Agent ani Sysmon nezmiňuje |
| 11 | CrowdStrike Falcon: pole NetworkConnectIP4 (ContextProcessId aj.) | V1 | oficiální dokumentace vyžaduje přihlášení; jen třetí strany |
| 12 | SentinelOne Deep Visibility: korelace IP connect a procesu | V1 | jen integrace třetích stran |
| 13 | Objem Sysmon: 5 až 20 MB/host/den (laděná konfigurace), 50 až 200 MB (výchozí), 160 GB/den na 1000 hostů se SwiftOnSecurity, 20 až 25 GB/den na 6000 hostů | V1 | fóra Splunk a blogy; zdroje se liší o řád; nepoužito |
| 14 | Zeek conn.log 10 až 20 GB/den na 1 Gbit/s | V1 | tvrzení výrobce (Corelight), bez dat |
| 15 | Silent agent: 1 až 3 % flotily je normální základ, práh 15 minut mezery v telemetrii, cíl SLO < 2 % | V1 | praktické blogy výrobců, bez měření |
| 16 | Vypínání ETW a Sysmon driveru, EDR-Freeze, BYOVD | V1 | blogy; akademicky jen Karantzas, Patsakis (V3 E14-040/041), který nepokrývá Sysmon |
| 17 | WP29 Opinion 2/2017 (WP249): čtyři otázky legality, souhlas zaměstnance zpravidla nestačí | V1 | jen sekundární komentáře; plný text nezískán |
| 18 | Bărbulescu v. Rumunsko (ESLP, Velký senát 2017, č. 61496/08): šest kritérií přiměřenosti | V1 | jen sekundární shrnutí; HUDOC nečten |
| 19 | ÚOOÚ: stanoviska k monitorování zaměstnanců | V1 | jen komerční články a prezentace; stanovisko na uoou.gov.cz nečteno |
| 20 | Sampling: Mai et al. a další citace uvnitř Sci Rep 2023 (přesnost 85 % při 1/100 aj.) | V1 | citace druhého řádu, originály nečteny |
| 21 | NodeMerge (CCS 2018): redukce až 75,7x | V1 | jen výsledek vyhledávače |
| 22 | Computer Networks 2023 (Campazas-Vega et al., vliv vzorkovací frekvence na detekci) | V1 | jen bibliografický záznam, plný text nečten |
| 23 | Splunk, ExtraHop: NOC/SOC konvergence zkracuje MTTD až o 65 % | V1 | tvrzení výrobce |
| 24 | Kairos, Flash, Magic, Orthrus, NodLink: čísla z původních prací | V0 | nečteno; zmíněny jen jako řádky v tabulkách CAPTAIN a průmyslového hodnocení (V3, druhý řád) |
| 25 | Mimicry útoky na provenance IDS | V0 | cílený dotaz nic nenašel |
| 26 | Číselné stránky (strany PDF) u Unicorn, SIGL, HOLMES | V0 | pdftotext uchovává jen označení tabulek, ne spolehlivě čísla stran; v extrakci jsou tabulky bez stran |
