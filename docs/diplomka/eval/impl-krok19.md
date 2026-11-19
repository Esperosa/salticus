# Krok 19: výchozí preset a znovuověření případové složky

Datum zahájení 2026-11-19. Výchozí stav: konec kroku 18 (commit `30b76a7`, zdrojový kód shodný s `17bbd7e`). Zadání: `F:\work-tmp\briefs\krok19-preset-a-slozka.txt`. Závazný rozsah: `docs/diplomka/rozsah-autonomie.md`.

Dvě části: **A)** rozhodnutí, zda do `recommended()` patří `endpoint_weak`, `refute_episode` a `confirm_evidence` (návrhy z kroků 15 a 18); **B)** znovuověření případové složky (K16-4 a K16-9 z kroku 16 neprošly na držených seedech) a oprava tří slabin z kroku 16.

## 1. Předregistrace (zapsáno před kódem a před měřením)

### Část A: preset

Ramena, párově (stejný seed a síť v obou), základ = **současné `recommended()`** (soak bez `--v3-on`, tedy bez přepínačů konfigurace `final`), kandidát = základ + `endpoint_weak,refute_episode,confirm_evidence`:

| konfigurace sítě | základ | kandidát |
|---|---|---|
| `off` | `recommended()` | + 3 přepínače |
| `ops` | `recommended()` + `--ops-telemetry on` | + 3 přepínače |
| `elying` | `recommended()` + `endpoint_ext`, `--endpoint on --endpoint-agent ok` (agent na hostech útoku hlásí „vše v pořádku“) | + 3 přepínače |

Společné volby jako v kroku 18: `soak run --max-networks 4 --threads 1 --block-size 2 --no-legs --engine v3 --no-feedback --counterfactual --l7 cal --coverage k10`. Binárka `salticus-k18-17bbd7e.exe` (zdroj beze změny od `17bbd7e`). `endpoint_weak` má účinek jen s koncovou telemetrií (vyžaduje `endpoint`), tedy jen v `elying`; v `off` a `ops` je beze změny chování.

**Nové držené seedy (zapsáno dopředu, použít jednou): 20269701, 20269702, 20269703, 20269704, 20269705, 20269706, 20269707, 20269708, 20269709, 20269710.** 10 seedů x 4 sítě x 3 konfigurace x 2 ramena. Ladění se nedělá (žádné prahy, žádné ladicí běhy před drženými). Seed se sítí, jejíž běh trvá přes 2 h, se vynechá v obou ramenech a zapíše.

Kritéria (každé musí platit v každé ze tří konfigurací):

| práh | metrika | splněno, když |
|---|---|---|
| K19-A1 | omylem zavřené útoky (`auto_closures_wrong` + `ladder_refuted_wrong_cf`) | kandidát 0; hlásí se horní mez Wilson 95 % (jmenovatel = útoky) |
| K19-A2 | detekce po rodinách (zobrazeno, kontrafakt) | žádná rodina s ≥ 20 útoky nepoklesne o víc než 1 p. b. |
| K19-A3 | zobrazené FP | poměr kandidát/základ ≤ 1,01 |
| K19-A4 | případy pro člověka (potvrzeno + eskalováno) | nárůst ≤ 2 % |
| K19-A5 | zhoršení nad rámec rozptylu | párový bootstrap po sítích (stratifikovaný podle seedu, B = 2000, pevné semínko 19): 95% interval rozdílu souhrnné detekce nesmí ležet celý pod 0, intervaly relativní změny zobrazených FP a případů pro člověka nesmí ležet celé nad 0 |

Rozhodnutí: projdou-li všechna kritéria ve všech konfiguracích, `recommended()` se změní (s testem). Jinak zůstane beze změny a důvod se zapíše. Měřicí skript `tools/k19_preset.py`.

### Část B: případová složka

**Slabiny z kroku 16 a kořenové příčiny (z kódu `case_folder.rs`, před měřením):**

1. *Obecný doporučený krok.* Doporučení = „nejlevnější dosud neprovedená kontrola“ ze všech druhů `CheckKind`, bez ohledu na to, zda kontrola útok od neškodného vůbec rozliší. Druhy bez změřené tabulky věrohodnosti (`DnsPivot`, `Timing`, `GeoAsn`, `TlsFingerprint` mají neutrální tabulku s poměrem 1) vycházejí jako nejlevnější a žebřík je sám neumí; složka neříká, že jde o ruční krok, ani co by výsledek znamenal.
2. *Uživatel vždy „nelze určit“.* Složka nemá vstup, který by uživatele nesl: kroky žebříku jsou text a `EndpointSignal` uživatele nepředává, ačkoli koncová telemetrie ho v událostech má (vlastník procesu, přihlášení). V soaku se složce navíc nepředává ani pokrytí koncovou telemetrií (`endpoint_covered: None`).
3. *Slepé místo jako důvod předání v 99 %.* Za slepé místo se počítá každý krok s výsledkem `Undetermined`, tedy i kontrola, která proběhla a nic nerozlišila („služba odpovídá“, „jev se neopakoval“, „zdroj bez reputace“, „běžné pro typ zařízení“). Podle pravidla 5 rozsahu je slepé místo *chybějící telemetrie*, ne kontrola bez rozlišujícího výsledku.

**Opravy (rozhodnutí žebříku se nemění, jen obsah složky):**

- B-oprava 1: zbývající kontroly se řadí podle změřené informace na cenu (`competing::information_per_cost` při P(útok) případu, tabulky kroku 12): nejdřív neprovedené kontroly, které rozlišují (informace > 0), pak neprovedené bez změřené rozlišovací schopnosti, pak provedené bez výsledku. Doporučený krok jmenuje jen kontrolu, která rozlišuje; řekne, zda ji program dělá sám, nebo jde o ruční krok (s konkrétní instrukcí pro druh kontroly), a jak by výsledek posunul P(útok) (podezřelý / neškodný). Když žádná dostupná kontrola nerozlišuje, řekne to.
- B-oprava 2: koncová telemetrie sbírá uživatele hosta v okně posouzení (vlastník procesu, uživatel přihlášení); složka je uvede jako aktéra `uzivatel` (pseudonym, je-li nastaveno), jinak „nelze určit“ s přesným důvodem (chybí koncová telemetrie hosta / telemetrie uživatele nenese). Soak předá složce pokrytí a uživatele stejně jako pipeline.
- B-oprava 3: slepé místo = jen kontrola, kterou nešlo provést (`Unavailable`: chybí pokrytí, mimo rozsah, čeká na schválení), a mezery pokrytí (host bez senzoru nebo agenta, chybějící provozní telemetrie). Kontrola bez rozlišujícího výsledku zůstává v „ověřeno“ a v nejistotě pozorování. Důvod předání „slepá místa“ jen u případů s takovou mezerou.
- Validátor (`case_folder::validate`) a skript (`tools/k16_case_folders.py`) dostanou pravidla navíc: doporučený krok nejmenuje kontrolu bez rozlišovací schopnosti ani už provedenou; slepé místo nesmí pocházet z kroku `Undetermined`; uživatel jako aktér jen z koncové telemetrie.

Ladění oprav jen na ladicích seedech kroku 16 (20261102 `off`, 20261103 `ops`, 20266101 `elying`, 20266105 `mixops`, 20266106 `opsnoise`, po 2 sítích).

**Nové držené seedy pro složky (zapsáno dopředu, použít jednou): 20269801 a 20269802 `off`, 20269803 a 20269804 `ops`, 20269805 a 20269806 `elying`, 20269807 a 20269808 `mixops`, 20269809 a 20269810 `opsnoise`** (`opsnoise` = `--ops-telemetry on --ops-noise 3`, `mixops` = `--mix on --ops-telemetry on`), každý 2 sítě, konfigurace `final` (`recommended()` binárky na konci kroku 19 + `breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate`), kontrafakt, dump `K16_CASE_DUMP`. Pokud část A změní `recommended()`, držený běh B už ho obsahuje (to je produkt, který se ověřuje).

| práh | metrika | splněno, když |
|---|---|---|
| K19-B1 (= K16-4) | složka netvrdí víc než důkazy | 0 porušení validátoru i nezávislého skriptu |
| K19-B2 (= K16-9) | senior review 30 případů (semínko 16, `k16_case_folders.py sample`) | ≥ 80 % „senior ví, co dělat“, 0 zavádějících; každá chyba zapsána |
| K19-B3 | „slepá místa“ jako důvod předání | ≤ 50 % předaných a každý takový případ má krok `Unavailable` nebo mezeru pokrytí (hlásí se i před opravou na stejném dumpu přepočtem) |
| K19-B4 | doporučený krok předaných | 0 % doporučení kontroly bez rozlišovací schopnosti nebo už provedené; hlásí se rozdělení doporučených kontrol a podíl ručních |
| K19-B5 | uživatel jako aktér | v `elying` u případů, kde host má živou koncovou telemetrii s uživatelem, 100 % vyplněno; hlásí se podíl vyplněných celkem |
| K19-B6 | regrese K16-1, -2, -3, -5, -6, -7 | beze změny splněno (p95 ≤ 8 KiB, max ≤ 16 KiB); bez dumpu `networks.jsonl` shodný s binárkou `17bbd7e` (ladicí seed, 2 sítě, 3 konfigurace) |

Omezení předem: council, sol-loop a delegování se podle zadání nespouštějí (odchylka od `CLAUDE.md` daná zadáním); review dělá autor. K19-B2 posuzuje autor kódu, ne nezávislý senior, takže jde o horní odhad použitelnosti. Tabulky věrohodnosti pro řazení kontrol jsou ze simulace (krok 12).

## 2. Výsledky části A (držené seedy 20269701 až 20269710, použity jednou)

Binárka `salticus-k18-17bbd7e.exe`, 10 seedů x 4 sítě x 3 konfigurace x 2 ramena, 60 běhů, všechny doběhly (kód 0), 0 nespárovaných sítí, žádná síť nad 2 h. Na konfiguraci 40 párů sítí, 371 síť-dní, 3 443 útoků. Skript `tools/k19_preset.py`.

| konfigurace | omylem zavřeno základ → kandidát (Wilson horní mez kandidáta) | detekce | zobrazené FP (poměr; 95% interval) | případy pro člověka (95% interval) | rodina s poklesem > 1 p. b. | verdikt |
|---|---|---|---|---|---|---|
| `off` | 39 → **44** (1,71 %) | 81,88 → 81,99 % [+0,00; +0,23] | ×1,0052 [+0,04; +1,30] % | +0,26 % [−0,01; +0,65] | žádná | A1, A5 nesplněno |
| `ops` | 42 → **59** (2,20 %) | 82,05 → 82,05 % [−0,07; +0,07] | ×1,0027 [+0,08; +0,57] % | −0,29 % [−1,78; +0,71] | `credential_stuffing` 89,7 → 88,5 % (n = 78) | A1, A2, A5 nesplněno |
| `elying` | 39 → **50** (1,91 %) | 82,02 → 82,08 % [+0,00; +0,13] | ×1,0032 [+0,06; +0,63] % | +0,25 % [+0,01; +0,50] | žádná | A1, A5 nesplněno |

**Rozhodnutí: `recommended()` zůstává beze změny.** Žádná konfigurace nesplnila všechna kritéria.

- **K19-A1 nesplněno, a to už v základu.** Samotné `recommended()` (bez `strict_close` a `bulk_clear` z konfigurace `final`) zavírá útoky: 12 automatických zavření a 27 až 30 vyvrácení žebříkem na 3 443 útoků v každé konfiguraci (horní mez 1,5 až 1,6 %). V krocích 15 a 18 se kandidátní přepínače měřily nad `final`, kde přísné zavírání tyto cesty odstraňuje, proto tam nula vyšla.
- **Kandidát omylem zavřené útoky zvyšuje** (+5, +17, +11), vždy ve vyvráceních žebříkem: přibývají `unexpected_traffic|rogue_device_in_network` (10 → 15 ve všech konfiguracích) a `scan_attempts|c2_beacon` (0 → 7). Držení klíče z kroku 18 (`hold_refused`) neodmítlo ani jedno vyvrácení, takže přírůstek nevzniká v okně držení. Hypotéza (neověřená, stopy se v tomto běhu nesbíraly): potvrzený klíč je proti vyvrácení chráněn trvale, kdežto nepotvrzený případ s `prior_hold` jen 48 cyklů; bez přísného zavírání se po uplynutí okna takový klíč dá vyvrátit slabým neškodným důkazem.
- **K19-A5:** zobrazené FP rostou systematicky (interval celý nad 0 ve všech konfiguracích, +0,3 až +0,5 %), i když pod prahem A3 (1 %).
- Detekce se nezhoršila (+0,00 až +0,12 p. b.); případy pro člověka v pásmu ±0,3 %. Kandidát přesouvá 4 300 až 4 800 potvrzení do eskalací (nepotvrzené případy s `prior_hold`).

Co z toho plyne: návrh kroků 15 a 18 zapnout tři přepínače do `recommended()` platí jen nad `final`; nad samotným `recommended()` přepínače chybovost zavírání zhoršují. Smysluplnější preset k ověření je `final` (s přísným zavíráním) + tři přepínače; to je nový předregistrovaný krok, ne ladění na těchto seedech.

## 3. Část B: průběh na ladicích seedech (před drženým během)

Binárky: před opravou `17bbd7e`, po opravách `b159503`, `da017a9`, `d9731f9` (konečná). Ladicí seedy podle předregistrace, po 2 sítích, 8 168 složek v každém běhu.

| | před opravou | `b159503` | `da017a9` | `d9731f9` |
|---|---|---|---|---|
| porušení validátoru / skriptu | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| slepá místa jako důvod předání | 90,6 % | 2,0 % | 2,0 % | 2,0 % |
| doporučení bez rozlišující kontroly | 90,7 % „nejlevnější neprovedená“ | 0 % | 0 % | 0 % |
| žádná kontrola nerozliší (výslovně řečeno) | – | 2,0 % | 21,6 % | 53,4 % |
| uživatel vyplněn (vše / `elying`) | 0 % / 0 % | 14,4 % / 94,2 % | stejně | stejně |
| velikost p50 / p95 / max B | 7 276 / 8 159 / 8 592 | 6 996 / 7 766 / 8 201 | 7 073 / 7 811 / 8 274 | 7 032 / 7 753 / 8 203 |

`networks.jsonl` všech tří opravených binárek je s binárkou `17bbd7e` shodný ve všech 10 sítích (`off`, `ops`, `elying`, `mixops`, `opsnoise`; mimo časy), oprava rozhodnutí nemění (K19-B6). V `elying` mají uživatele všechny případy, jejichž host má živého agenta; zbylých 5,8 % jsou hosté bez agenta („host nema zivou koncovou telemetrii“).

**Odchylky od předregistrovaného návrhu opravy 1 (provedené na ladicích seedech, před drženým během):**

1. *Řazení podle informace na cenu nahrazeno hrubou hodnotou informace (EVOI s nulovou cenou, `competing::evoi`).* Ruční čtení 30 složek (semínko 16) po `b159503` ukázalo, že informace na cenu upřednostňuje levnou historii (`CaseHistory`), jejíž výsledek P(útok) posune jen o setiny a rozhodnutí nezmění, a že u historie je „podezřelý“ výsledek ve změřených tabulkách častější u neškodných případů (P po „podezřelém“ výsledku klesá). „Rozlišuje“ teď znamená „výsledek může změnit rozhodnutí (zavřít, potvrdit, předat)“.
2. *Text účinku jako rozsah* („výsledek posune P(útok) z X na A až B“) místo „podezřelý → A, neškodný → B“, ze stejného důvodu (směr by byl u historie zavádějící).
3. *Kontroly vázané na typ nálezu:* složka nedoporučí srovnání s peery ani aktivní kontrolu dostupnosti u typu, pro který je žebřík nepoužívá (sdílená funkce `verify_ladder::type_applies`, žebřík beze změny chování), a reputaci bez protějšku. Po `da017a9` složka doporučovala „aktivně ověřit dostupnost služby“ u úniku dat a tunelu.

Důsledek odchylek: u 53 % předaných případů složka na ladicích seedech výslovně říká, že žádná další dostupná kontrola rozhodnutí nezmění. To je poctivý stav enginu (nezávislé zdroje v simulaci většinou chybí, viz krok 18), ne vlastnost složky.

## 4. Výsledky části B (držené seedy 20269801 až 20269810, použity jednou)

Binárka `salticus-k19-d9731f9.exe` (`recommended()` beze změny, viz část A), konfigurace `final`, 10 seedů x 2 sítě, 10 běhů, všechny doběhly. 25 109 složek (3 796 potvrzeno, 21 310 eskalováno, 3 zavřeno).

| rameno | složek | porušení validátoru / skriptu | p50 / p95 / max B | slepá místa jako důvod předání (pravidlo kroku 16) | uživatel vyplněn |
|---|---|---|---|---|---|
| vše | 25 109 | 0 / 0 | 7 127 / 7 920 / 8 435 | 6,1 % (84,5 %) | 18,0 % |
| `off` | 6 746 | 0 / 0 | 6 854 / 7 629 / 7 873 | 0,2 % (78,1 %) | 0 % (bez koncové telemetrie) |
| `ops` | 1 800 | 0 / 0 | 7 154 / 7 738 / 8 083 | 0,1 % (98,8 %) | 0 % |
| `elying` | 4 890 | 0 / 0 | 7 631 / 7 990 / 8 435 | 8,4 % (89,9 %) | 92,6 % |
| `mixops` | 8 845 | 0 / 0 | 7 045 / 7 649 / 8 094 | 9,8 % (81,3 %) | 0 % |
| `opsnoise` | 2 828 | 0 / 0 | 7 137 / 7 750 / 8 146 | 8,0 % (91,6 %) | 0 % |

- **K19-B1 (= K16-4) splněno:** 0 porušení validátoru i nezávislého skriptu (krok 16 na držených seedech: 2 500, 7,0 %). Potvrzení jen podle apriorní P (2 280) složka všechna výslovně označuje.
- **K19-B3 splněno:** „slepá místa“ jako důvod předání u 6,1 % předaných (stejné složky pravidlem kroku 16: 84,5 %), validátor ověřil, že každé slepé místo pochází z kontroly, kterou nešlo provést.
- **K19-B4 splněno:** 0 doporučení kontroly, která nerozlišuje nebo už proběhla. Doporučení předaných: žádná další kontrola rozhodnutí nezmění 50,0 % (výslovně řečeno), reputace protějšku 22,2 %, procesy a přihlášení na hostu 16,4 %, provozní telemetrie 3,6 %, historie 1,0 %, aktivní kontrola dostupnosti 0,8 %; všechna jako ruční kroky.
- **K19-B5 splněno:** v `elying` mají uživatele všechny případy s živým agentem na hostu (92,6 % složek; zbylých 7,4 % jsou hosté bez agenta, důvod uveden). Mimo `elying` koncová telemetrie není, takže „nelze určit“ s tímto důvodem.
- **K19-B6 splněno:** K16-1, -2, -3, -5, -6 (p95 7 920 B ≤ 8 KiB, max 8 435 B ≤ 16 KiB) a -7 (shoda `networks.jsonl` na ladicích seedech, část 3).
- K16-8: 3 uzávěry L1 (2 výpadky služby podle živosti, 1 podle koncové telemetrie), 0 % s vlastníkem a expirací. **Jeden z nich je útok** (`scan_attempts`, rodina `lateral_cautious_one_target`, `elying`): lhoucí agent hlásí pravidelné spojení podepsaného `msedge.exe` a s historií to stačí k zavření. Je to přesně mechanismus kroku 15, který odstraňují `endpoint_weak` a `refute_episode`; ty v `final` nejsou.

### K19-B2 (= K16-9) senior review na držených seedech: nesplněno

30 složek (`k16_case_folders.py sample 30 16`), posuzuje autor kódu. Pravidlo posouzení stanovené před čtením: „ví, co dělat“, když složka dává konkrétní krok, nebo výslovně říká, že žádná kontrola nerozliší, a P(útok) je daleko od hranice (≤ 0,10 nebo ≥ 0,90); při P mezi tím a bez kontroly senior neví, jak rozhodnout. Zavádějící = složka vůči pravdě simulace tvrdí víc, než důkazy unesou.

**Ví, co dělat: 19 z 30 (63 %). Zavádějící: 4. Neví: 7.** (Krok 16 na držených: 17 z 30, 8 zavádějících.)

Chyby složky:

1. **Potvrzení stojící jen na závislém zdroji podané jako potvrzené podezření (3 případy, všechny neškodné):** `connection_timeout_burst` a dvakrát `service_unreachable`, jediný důkaz pro je historie „za N dní nikdy“. Složka píše „potvrdil žebřík (nezávislých podezřelých skupin: 1)“; „nezávislá“ tu znamená první důkaz své skupiny, ne nezávislý zdroj ve smyslu kroku 18 (historie je týž tok dat jako detektor). Zavádějící. Kořen: složka označuje jen potvrzení bez jakéhokoli podezřelého důkazu, ne potvrzení bez nezávislého (`verify_ladder::has_independent_evidence`). V `final` není `confirm_evidence`.
2. **Omylem zavřený útok (1 případ, viz výše):** složka věrně uvádí důkazy, ale jde o chybné L1 zavření enginu; počítá se jako zavádějící.
3. **Reputace protějšku doporučená tam, kde protějšek není (2 případy):** `unmapped_passive_event` na broadcastové adrese a `packet_rate_spike` bez protějšku. Kořen: pravidlo použitelnosti reputace pouští případ, jehož nález soak nenajde podle id (`finding = None`), jako použitelný.
4. **Nerozhodnutelné případy se středním P(útok) (5 případů, P 0,15 až 0,59):** složka správně říká, že žádná dostupná kontrola nerozliší, ale senior pak nemá podle čeho rozhodnout. Tři z nich jsou útoky (`share_encryption_wave_slow`, `lateral_smb_admin_shares`, `c2_ntp_port_misuse`). To je limit zdrojů enginu (krok 18, bod 1), ne textu složky.

Opravy bodů 1 a 3 jsou zřejmé (označit potvrzení bez nezávislého důkazu; reputace jen s protějškem), ale po drženém běhu se kód nemění; patří do dalšího kroku s novými drženými seedy.

## 5. Implementace a testy

- `endpoint::correlate`: `HostAssessment::users` (vlastník procesu, úspěšné přihlášení v okně), `EndpointView::users`; skóre ani signál se nemění.
- `case_folder`: aktér `uzivatel` z koncové telemetrie (pseudonym podle `Privacy::user`), slepé místo jen z kontroly `Unavailable`, zbývající kontroly řazené podle hrubé hodnoty informace (`competing::evoi`), použitelnost podle typu (`verify_ladder::type_applies`, vyčleněno z `checks_for` beze změny chování), doporučení jako ruční krok s rozsahem P(útok); validátor hlídá nová pravidla. Soak předává složce pokrytí a uživatele z koncové telemetrie.
- `tools/k16_case_folders.py`: stejná pravidla nezávisle, metriky K19-B3 až B5; `tools/k19_preset.py`: kritéria části A s Wilsonem a párovým bootstrapem.
- Testy: `inconclusive_check_is_not_a_blind_spot`, `recommendation_names_a_discriminating_check_and_its_effect`, `recommendation_respects_checks_applicable_to_finding_type`, `user_actor_comes_from_endpoint_telemetry`, `assessment_collects_users_without_changing_score`, fuzz složky rozšířen o uživatele (20 000 případů, 0 porušení). `cargo test --lib`: 663 prošlo, 6 selhalo (5 `broker::*` bez Redis jako dřív, `platform::tests::concurrent_claim_due_job_never_double_claims_across_real_threads` jen pod zátěží souběžných běhů, samostatně prochází); `tests/engine_v3.rs` 4 prošly; clippy bez varování ve změněných řádcích.

## 6. Závěr a co se nepodařilo

**A:** `recommended()` zůstává beze změny. Kombinace `endpoint_weak`, `refute_episode` a `confirm_evidence` nad samotným `recommended()` zvyšuje omylem zavřené útoky (39–42 → 44–59 na 3 443) a mírně zobrazené FP (+0,3 až +0,5 %, interval nad 0). Nula omylem zavřených neplatí ani pro současné `recommended()` (horní mez 1,5 až 1,6 %), protože neobsahuje přísné zavírání z `final`.

**B:** Tři slabiny kroku 16 mají opravené kořenové příčiny a na držených seedech prošly předregistrované prahy K19-B1 (0 porušení místo 7 %), B3 (slepá místa 6 % místo 85 %), B4 (0 nerozlišujících doporučení) a B5 (uživatel u 100 % případů s agentem) bez změny rozhodnutí. Senior review (B2) neprošlo: 63 % místo 80 %, 4 zavádějící.

Co se nepodařilo:

1. K19-A: žádná konfigurace nesplnila kritéria; preset se nemění. Mechanismus přírůstku omylem zavřených u kandidáta je jen hypotéza (konec okna držení), stopy se nesbíraly.
2. K19-B2: 19 z 30, 4 zavádějící (3 potvrzení jen na historii popsaná jako potvrzené podezření, 1 omylem zavřený útok lhoucím agentem). Hodnotitel je autor kódu, takže i 63 % je horní odhad.
3. Polovina předaných případů nemá žádnou kontrolu, která by rozhodnutí změnila; složka to teď říká, ale seniorovi u středního P(útok) nepomůže. Příčina je v pokrytí zdrojů (krok 18), ne ve složce.
4. Reputace se doporučuje i bez protějšku, když soak nenajde nález podle id (2 z 30).
5. Uživatel je jen tam, kde je koncová telemetrie (v simulaci jen `elying`); síťová data uživatele nenesou.
6. Na držených seedech B se objevil jeden omylem zavřený útok v `final` (lhoucí agent + historie), tedy mechanismus, který opravují `endpoint_weak` a `refute_episode`. Spolu s částí A to ukazuje, že doporučený preset je potřeba poskládat a ověřit jako celek (`final` + přepínače), ne po částech.
7. Opravy složky na ladicích seedech se odchýlily od předregistrovaného návrhu (EVOI místo informace na cenu, rozsah místo směru, použitelnost podle typu); odchylky jsou zapsané v části 3 a proběhly před drženým během.
8. Council, sol-loop ani delegování se podle zadání nespouštěly; review jen autorské.

Návrh dalšího kroku (neprovedeno): předregistrovat a na nových držených seedech ověřit preset `final` + `endpoint_weak`, `refute_episode`, `confirm_evidence` proti `final`, a ve složce označit potvrzení bez nezávislého důkazu a omezit reputaci na případy s protějškem.
