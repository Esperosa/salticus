# Krok 13: reálná data, incidenty a posun k 100 % (předregistrace a stav)

Zadáno 2026-11-15. Omezení: proces Idle, max 6 vláken, jedno rameno, nic se nepushuje, commity lokálně bez stopy nástroje, data do `F:\Projekty\bakula-datasets`, licence ověřit před stažením, žádné registrace ani formuláře, `audit-pokryti.md` se nekomituje.

## Předregistrace (před kódem)

**Hypotézy a prahy**
- H1 (kalibrace): po odvození rozdělení z reálných logů (NXDOMAIN, TXT, délka a entropie jmen, SNI, stáří certifikátů, self-signed) se parametry pozadí simulátoru dostanou do pásma ±2× od reálné hodnoty u každé veličiny, kterou zdroj pokrývá. Co zdroj nepokrývá, se nekalibruje a zapíše se jako nekalibrované. Kalibrace se nesmí opírat o jediný host (min. 3 nezávislé zdroje na veličinu, jinak jen „orientační“).
- H2 (incidenty): nové seskupení za přepínačem `incident_v2` zvýší čistotu seskupení ze 59 % (nejlepší stávající, odstup 30 min) na ≥ 80 % na ladicím seedu a drží ≥ 70 % na držených; nálezů na incident nesmí klesnout pod 2 (jinak triviální řešení „každý nález zvlášť“); čistota se počítá stejnou metrikou jako dosud (podíl nálezů největší pravdy; nepřipsaný nález = vlastní štítek). Cíl ≥ 90 % z zadání se hlásí zvlášť a nepovažuje se za splněný, pokud ho nedosáhneme na držených.
- H3 (posun k 100 %): opravy jen takové, které mají oporu v reálných datech nebo v logice detektoru, ne ladění na testovací scénář. Stráže: omylem zavřené = 0 (horní mez se hlásí), FP poměr ≤ 1,15 proti základu, hn_* (hard-negative) hlášené zvlášť pro ladicí a držené seedy.
- H4 (reálné přehrání): pcap → Zeek → Salticus se změří u každého zpracovaného datasetu na úrovni hostů; rozdíl proti simulaci se hlásí kvalitativně, protože reálné pcapy nemají štítky incidentů v našem smyslu (jen botnet vs. normální host).

**Datová pravidla.** Nové držené seedy: `20265101, 20265102, 20265201, 20265202` (nikdy nepoužity, použít jednou, na konci). Ladění jen na `20261102` a `20261103`. LOFO pro nové detektory se hlásí tak, že každý detektor se vypne a měří se ztráta po rodinách; formální přeladění po rodinách není, pokud nejsou parametry po rodinách.

**Licence.** CTU-13 (Stratosphere IPS): CC-BY (stránka stratosphereips.org, ověřeno 2026-11-15), nutná citace Garcia et al. 2014. CTU-Normal-20: README bez uvedené licence, použito jen lokálně a pouze pro statistiky. CIRA-CIC-DoHBrw-2020 a CIC-Bell-DNS2021: text licence na unb.ca dovoluje redistribuci s citací, ale stažení vyžaduje formulář/registraci u UNB, což je vyloučeno; **nezpracováno**. MAWI: licenci neověřeno, nestaženo.

## Tabulka stavu

| bod | stav |
|---|---|
| 0 předregistrace a licence | hotovo (tento dokument) |
| 1 reálná data a kalibrace | rozpracováno: stažené CTU-13 pcapy 42, 43, 46, 54 (CC-BY). Zeek vydal logy jen pro 43 a 46 (1005 a 163 DNS řádků, 43 a 72 TLS); u 42 a 54 žádné logy dnes nevznikly (příčina neprověřena). Nástroj `tools/k13_real_stats.py`. Pro kalibraci chybí zdroje: dosud 3 zdroje (Normal-20, 43, 46) a jen s botnet hostem, tedy veličiny jsou orientační; **simulátor zatím nekalibrován** |
| 2 reálné přehrání | nezačato |
| 3 incidenty | nezačato |
| 4 posun k 100 % | nezačato |
| 5 držené seedy, LOFO, souhrn | nezačato |

## Naměřeno do tohoto bodu (reálné zdroje, Zeek)

| zdroj | DNS řádků | NXDOMAIN | TXT/NULL | AAAA | TLS spojení | bez SNI | self-signed x509 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CTU-Normal-20 (normální host, 3 h) | 15 089 | 0,013 % | 0 | 24,5 % | 2 464 | 1,5 % | 3,0 % |
| CTU-13 botnet 43 (Neris) | 1 005 | 0 | 0 | 0 | 43 | 97,7 % | 5,6 % |
| CTU-13 botnet 46 (fast-flux) | 163 | 2,0 % | 0 | 0 | 72 | 100 % | 0 |

Pozorování: botnetové TLS je téměř vždy bez SNI (98 až 100 %) proti 1,5 % u normálního hosta, tedy „TLS bez SNI“ je u reálných botnetů silný rys; simulace ho má u útoku, ale pozadí bez SNI by mělo být ~1,5 %. NXDOMAIN je i u botnetů nízký (≤ 2 %), tj. simulační pozadí 5 % NXDOMAIN je nadsazené. Tři zdroje stále neumožňují kalibraci distribucí (zdroje jsou malé a jednoúčelové).
