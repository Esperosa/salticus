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
| 1 reálná data a kalibrace | rozpracováno: CTU-13 pcapy 42, 43, 46, 54 se stahují |
| 2 reálné přehrání | nezačato |
| 3 incidenty | nezačato |
| 4 posun k 100 % | nezačato |
| 5 držené seedy, LOFO, souhrn | nezačato |
