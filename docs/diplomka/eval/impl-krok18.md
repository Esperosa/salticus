# Krok 18: politika potvrzování žebříku ověřování

Datum zahájení 2026-11-18. Výchozí stav: konec kroku 17 (commit `f4a44f3`). Zadání: `F:\work-tmp\briefs\krok18-politika-potvrzeni.txt`. Závazný rozsah: `docs/diplomka/rozsah-autonomie.md`. Nález, ze kterého krok vychází: v kroku 16 stálo 35 % (držené) až 68 % (ladicí) potvrzení žebříku jen na apriorní pravděpodobnosti, bez kontroly, která by podezření podpořila (`impl-krok16.md`, K16-4). To porušuje pravidlo „bez pozitivního důkazu se netvrdí“.

## 1. Kořenové příčiny (před kódem)

### Dumpy kroků 14 a 15 (souhrny `networks.jsonl`, bez nového běhu)

Dumpy kroků 14 a 15 (`F:\Projekty\bakula-soak\k14`, `k15`, ladicí i držené, 47 ramen) nenesou kroky jednotlivých rozhodnutí, jen souhrny. Z nich:

- Přesnost potvrzení (podíl potvrzených, které způsobil útok podle kontrafaktu) je ve všech ramenech 0,91 až 0,95 (`off` držené 27 138 potvrzení, přesnost 0,942; ladicí 5 904, 0,915).
- Z potvrzení zapsaných v `ladder_log` je 86 až 92 % rozhodnuto **ve stejném cyklu, ve kterém byl případ otevřen** (držené `off` 21 647 z 24 390). Z apriorní P 0,15 to jeden krok nedokáže (nejsilnější podezřelý LR 12 dává 0,68); takový případ tedy otevírá už s P ≥ 0,9.
- Omylem zavřené útoky: 0 ve všech ramenech mimo `elying` (3 vyvrácení, odstraněno v kroku 15) a `emimicallow`, `bothallow`, `e100allow` (seznam povolených, mimo preset).

### Forenzní stopa na ladicích seedech (nový krátký běh)

Kvůli krokům jednotlivých případů: binárka `f4a44f3` beze změny, `K15_TRACE`, ladicí seedy 20261102, 20261103, 20266101, 20266105, 20266106, ramena `off`, `ops`, `elying` (konfigurace `final` jako v kroku 15), po 2 sítích (`F:\work-tmp\k18\rca`). 23 179 rozhodnutí, 1 874 potvrzení.

| třída potvrzení | počet | podíl | přesnost |
|---|---:|---:|---:|
| bez jakéhokoli podezřelého výsledku (jen apriorní P) | 1 077 | 57,5 % | 0,929 |
| podezřelý výsledek jen z historie nebo přetrvání (týž tok dat jako detektor) | 132 | 7,0 % | 0,750 |
| aspoň jeden podezřelý výsledek z nezávislého zdroje | 665 | 35,5 % | 0,850 |

Příčiny:

1. **Apriorní P z paměti případů překročí práh potvrzení sama.** `learned_prior` (soak) bere P(útok) typu nálezu a třídy zařízení z verdiktů simulovaného analytika v paměti případů (`ladder:{typ}@{třída}`). V sítích, kde jeden typ nálezu opakovaně patří útoku, se odhad vyšplhá nad 0,9 (všech 1 077 případů: P 0,90 až 0,94).
2. **Pravidlo zastavení `posterior ≥ p_confirm` se testuje po každé kontrole bez ohledu na její výsledek.** Všech 1 077 potvrzení bez důkazu padlo po **jediné** kontrole, a ta byla vždy bez výsledku (`profile:undetermined` 778, `history:undetermined` 299). Kontrola nic neřekla, ale spustila test prahu.
3. Soustředění: `unexpected_traffic` 482 a `pivot_chain` 481 (dohromady 89 %), dále `unmapped_passive_event`, `suricata_alert`, `packet_rate_spike`, `connection_timeout_burst`, `service_unreachable`. Rodiny podle pravdy: `slow_scan` 218, `ransomware` 212, `fleet_beacon` 203, `lateral_wmi_dcom` 78, neškodné 68 (6,3 %). Jev je silný v sítích s mnoha útoky téhož typu (seedy 20266101, 20266106: 55 až 77 % potvrzení), v sítích s málo útoky skoro chybí (20261102, 20261103: 0 až 5 %). Je to tedy zpětná vazba učení, ne chyba jedné kontroly.
4. Druhá, menší díra: 7 % potvrzení stojí jen na historii („nový jev“) nebo přetrvání (týž detektor znovu) a má nejhorší přesnost (0,75). Oba výsledky pocházejí z téhož toku dat jako nález sám, nejsou nezávislým zdrojem.
5. Produkční pipeline (`pipeline/v3.rs`) otevírá případy s pevnou P 0,15, takže tam potvrzení jen z apriorní P dnes nevzniká; vznikne ve chvíli, kdy se do produkce přenese učená apriorní P (stejný kód žebříku). Pravidlo proto patří do žebříku, ne do soaku.

Pozorování, které mění očekávání: potvrzení jen z apriorní P mají vyšší přesnost (0,929) než potvrzení s nezávislým důkazem (0,850). Odebrání prvních tedy **sníží** změřenou přesnost zbylých potvrzení. Pravidlo není o přesnosti, ale o tom, co program smí tvrdit: P 0,93 z četnosti typu je předpověď, ne zjištění o tomto případu.

## 2. Návrh

Přepínač `V3Features::confirm_evidence` (výchozí vypnuto, mimo `recommended()`), politika `LadderPolicy::confirm_evidence`.

- **Pozitivní důkaz z nezávislého zdroje** = provedená kontrola s výsledkem `Evidence` a LR > 1 z kontroly, jejíž data nepocházejí z toku, který nález vytvořil, ani z paměti případů: reputace, intel (KEV, EPSS), profil zařízení, srovnání s peery, aktivní kontrola živosti, pivot po sousedech, koncová telemetrie, metadata TLS a DNS. **Nepočítá se** historie toků a naučený profil hostu (L0, týž tok dat), přetrvání (týž detektor znovu) ani apriorní P. Množina je pevná v kódu (`confirm_source`) a zapsaná zde před měřením.
- Stav `confirmed` vznikne jen s aspoň jedním takovým výsledkem. Pravidlo se vynucuje na jediném místě (`Ladder::finish`), takže platí pro všechny cesty (práh posteriory, režim konkurenčních hypotéz).
- Upřesnění při implementaci (před měřením): případ s P ≥ `p_confirm` bez nezávislého důkazu pokračuje v kontrolách téhož cyklu, dokud další kontrola plánu běží hned (ne přetrvání, které čeká na další cykly, a ne aktivní L3 s limitem za cyklus). Bez toho by „čeká na kontrolu“ ukazovalo na levnou pasivní kontrolu (reputace, intel), kterou program umí sám. Kontroly v jednom cyklu neposouvají okamžik rozhodnutí ani zobrazení.
- Případ, který by se potvrdil bez důkazu, se ve stejném cyklu předá člověku (stav `escalated`, příznak `prior_hold`) s důvodem „nepotvrzeno: P(útok) X jen z apriorní pravděpodobnosti, bez pozitivního důkazu z nezávislého zdroje; čeká na kontrolu Y (cena C)“. Y = první nezávislá kontrola zbývajícího plánu, jinak první zbývající kontrola, jinak „ruční ověření“. P zůstává v rozhodnutí, takže apriorní P dál zvedá pořadí (priorita), jen nepotvrzuje.
- Zachování ochrany před uzavřením: potvrzený klíč dnes paměť nálezů nedovolí automaticky vyvrátit. Předaný případ s `prior_hold` dostane v paměti příznak `hold` se stejným účinkem (ruší se uzavřením klíče). Předání ve stejném cyklu znamená, že se nemění okamžik zobrazení, a tedy ani detekce.

## 3. Předregistrace (zapsáno před implementací)

Žádné ladění prahů (`p_confirm`, LR, apriorní P) ani detektorů. Měřicí čítače soaku (`ladder_confirmed_prior_only`, `ladder_confirmed_no_susp`, `ladder_prior_held`, `ladder_prior_held_attack`) se počítají v obou ramenech a rozhodnutí neovlivní.

| práh | metrika | splněno, když |
|---|---|---|
| K18-1 | podíl potvrzení bez pozitivního důkazu z nezávislého zdroje | kandidát 0 % v každé konfiguraci (ladicí i držené); základ se hlásí |
| K18-2 | detekce po rodinách (zobrazeno, kontrafakt) | žádná rodina s ≥ 20 útoky nepoklesne o víc než 1 p. b. proti základu, nebo je pokles vysvětlen po případech; souhrnná detekce bez poklesu (95% interval rozdílu obsahuje 0 nebo je kladný) |
| K18-3 | omylem zavřené útoky (`auto_closures_wrong` + `ladder_refuted_wrong_cf`) | kandidát ≤ základ v každé konfiguraci; cíl 0 |
| K18-4 | nepotvrzené případy předané člověku (`prior_hold`) | hlásí se počet na síť-den a podíl útoků mezi nimi; celkový počet případů pro člověka (potvrzeno + eskalováno) se nesmí změnit o víc než 1 % |
| K18-5 | přesnost potvrzení | hlásí se základ a kandidát; očekávání podle kořenové analýzy: pokles (z ~0,93 na ~0,85), protože odcházejí přesnější potvrzení jen z apriorní P |
| K18-6 | zobrazené FP a `hn_*` | poměr zobrazených FP kandidát/základ v [0,99; 1,01] |
| K18-7 | invariant „confirmed ⇒ existuje pozitivní důkaz z nezávislého zdroje“ | property/fuzz test 20 000 náhodných případů (náhodné apriorní P, politiky, výsledky kontrol): 0 porušení, 0 paniků |
| K18-8 | regrese bez přepínače | `networks.jsonl` kandidátské binárky bez přepínače shodný se základní binárkou `f4a44f3` ve všech polích kromě časů a nových čítačů |

Měření (párově, stejné seedy a sítě v obou ramenech, jednotka = síť, bootstrap po sítích stratifikovaný podle seedu, `tools/soak_ab.py`):

- Konfigurace sítí (3): `off` (`final` kroku 15), `ops` (+ provozní telemetrie), `elying` (+ koncová telemetrie, agent na hostech útoku hlásí „vše v pořádku“, `endpoint_ext`). Ramena: základ = konfigurace, kandidát = konfigurace + `confirm_evidence`.
- **Ladicí seedy:** 20261102, 20261103, 20266101, 20266105, 20266106 (seedy kroků 14 až 16).
- **Nové držené seedy (zapsáno dopředu, použít jednou):** 20269601, 20269602, 20269603, 20269604, 20269605, 20269606, 20269607, 20269608, 20269609, 20269610.
- Každý seed 4 sítě (`--max-networks 4 --block-size 2`), kontrafakt u všech sítí, `--no-feedback`, Idle, maska 0x3FFFFC, nejvýš 8 procesů po 1 vlákně, odpojeně. Seed se sítí XXL, jejíž běh trvá přes 2 h, se vynechá v obou ramenech a zapíše.
- Po měření na držených seedech se kód nemění. Zhoršení se hlásí, prahy se neladí.

Omezení předem: Council a sol-loop se podle zadání nespouštějí (odchylka od `CLAUDE.md` daná zadáním); review dělá autor kódu. Hrozba validity: množinu nezávislých zdrojů zvolil autor podle povahy dat, ne z měření; simulace je jediný zdroj pravdy o tom, které potvrzení bylo správné.
