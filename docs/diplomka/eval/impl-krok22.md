# Krok 22: provedení (fáze DO a CHECK)

Plán: `plan-krok22.md` (schválen vedoucím). Pracovní data: `F:\work-tmp\k22`. Tento dokument se doplňuje po etapách; sekce 1 je zapsána a komitnuta **před** jakoukoli změnou kódu kroku 22.

## 1. Předregistrace (E0, zapsáno před kódem)

### 1.1 Prahy pro držený běh E3 (beze změny z plánu 1.5)

| práh | metrika | splněno, když |
|---|---|---|
| K22-1 | omylem zavřená (skutečná, ne stínová) zavření ve FG22 | 0 ve všech konfiguracích; hlásí se i n zavření a Wilson 95 % |
| K22-2 | detekce po rodinách a souhrnná, FG22 vs F22 | jako K20-2 (žádná rodina nižší o víc než 1 útok, souhrn ≥) |
| K22-3 | zobrazené FP | FG22/F22 ≤ 1,01 **a** F22c/F22 ≤ 1,00 |
| K22-4 | případy pro člověka FG22 vs F22 | nárůst ≤ 2 % |
| K22-5 | tabulka hranice (stín) | pro každou buňku (druh pozitivního důkazu × typ nálezu) n, správná, omylem (sjednocení cf a příčinně), horní mez Wilson 95 %; kandidát, když horní mez < 1 % (n ≥ 381 s 0 omyly) |
| K22-6 | regrese bez přepínačů | bitová shoda `networks.jsonl` s krokem 21 na ladicích seedech 20269701 a 20269703 (kromě časů) |
| K22-7 | svět v1 vs v2 (diagnostika) | hlásí se změna FP, detekce a počtu stínových lístků; bez prahu |

Předpověď (z plánu 1.5): F22c/F22 ≈ 0,95; ve světě v2 žádná buňka s n ≥ 381.

### 1.2 Seedy (zapsáno dopředu)

| sada | seedy | použití |
|---|---|---|
| ladicí | 20269701, 20269703 | K22-6, kontrola stínu |
| ladicí svět v2 | 20269801 až 20269805 | E2 |
| **držená** | **20270301 až 20270310** | jen E3, jednou, po zmrazení kódu a světa commitem |
| stopy | 20270207 (R), 20270208 (R, RG) | jen B1 a diagnostika B2 |
| laboratoř C | 22001 (ladicí), 22101 (držená) | B6 |

V E0 a E1 se držené seedy nepoužijí.

### 1.3 Kritéria etap E0 a E1 (zapsáno před kódem)

- **B1 (E0):** deterministické opakování R 20270207 (binárka `salticus-k21-224ed3e.exe`, `K15_TRACE`, jen síť 0, `--max-networks 1`; nejdřív se ověří shoda souhrnu sítě 0 s během `F:\work-tmp\k21\scan\off-R-20270207`). Přijato, když oba příčinně omylem vyvrácené případy mají příčinu z tabulky `impl-krok21.md` 6 b (slabé skupiny, bez pozitivního důkazu s vlastníkem) a brána na rekonstruovaném rozhodnutí vrátí `Refusal`. Zamítnuto (nový nález K22-N1, vysoká priorita), když některý obsahuje pozitivní důkaz s vlastníkem nebo dvě nezávislé skupiny.
- **B2 (N14):** přepínač `ctx_host_first` (V3Features, výchozí vypnuto). Jednotkové testy: (a) záznam jiného hostu → `ambiguous = false`, rozhodnutí jako bez záznamu; (b) záznam téhož hostu bez doloženého zdroje → `ambiguous = true`; (c) sonda `known_gap_strict_close_flags_ambiguous_from_other_host_record` převrácena na pozitivní test s přepínačem (bez přepínače zůstává chování kroku 21). Stopa 20270208/0, rameno RG s přepínačem: z nálezů `connection_timeout_burst`, které jsou `protected` jen v RG (162), jich zmizí ≥ 95 %.
- **B3 (N13):** za týmž přepínačem. `GateInput.targets`; u `AuthorizedScanner`: zdroj ∈ `sources` a **všechny** cíle ∈ rozsah (`hosts`, CIDR); prázdný rozsah = nedoloženo. Testy: sken ven přes bránu s rozsahem = vnější cíl a zdrojem = skener → vysvětleno; jeden cíl mimo rozsah → nevysvětleno; zdroj skeneru + nález jiného typu než sken → nevysvětleno/nezavřeno. Sonda `known_gap_scanner_scope_does_not_match_finding_host_of_egress_scan` převrácena. Měřicí přepínač `K21_SCANNER_SCOPE` zůstává do B5 (odstranění patří ke světu v2, E2; v E1 se simulace nemění).
- **B4 (stín):** přepínač `shadow` (výchozí vypnuto). Stín volá `admit_ladder`/`admit_context` nad týmiž vstupy, zapisuje `shadow_tickets.jsonl`, nic nezavírá, nemění zobrazení ani stav. Kritéria: K22-6 se stínem i bez něj (bitová shoda `networks.jsonl` kromě časů s krokem 21); kontrola smyslu: rameno R se stínem na seedech běhu `scan` kroku 21 musí ve stínu obsahovat všech 14 automatických zavření a 1 529 vyvrácení jako odmítnutá „bez pozitivního důkazu“ (shoda počtu ± 0), viz 1.4.
- **Testy:** `cargo test --lib` bez nových selhání (známá: 5 `broker::tests` bez Redis, 1 `identity_lab` bez Dockeru); `cargo fmt --check`, `cargo clippy` čisté.

### 1.4 Upřesnění kontroly smyslu stínu (zapsáno před kódem)

Plán (B4) žádá shodu stínu se 14 automatickými zavřeními a 1 529 vyvráceními z běhu `scan` ramene R (seedy 20270201 až 20270210, 40 sítí). Tyto seedy byly drženými seedy kroku 21; v kroku 22 se použijí jen jako diagnostika správnosti stínu (stejně jako stopy 20270207/08), ne pro rozhodnutí o prazích K22. Odhad ceny: 40 sítí × ≈ 76 s CPU ≈ 50 min CPU, 8 vláken. Pokud by cena výrazně překročila rozpočet E1, kontrola se zúží na seedy se stopou (20270203, 20270206, 20270209) a zapíše se to.

## 2. E0: rozbor dvou nerozebraných omylem vyvrácených (B1)

Běh: `F:\work-tmp\k22\trace\off-R-20270207` (binárka `salticus-k21-224ed3e.exe`, `--max-networks 1`, `K15_TRACE`), 20 s reálného času. Souhrn sítě 0 (`output` v `networks.jsonl`) je **shodný** s během `F:\work-tmp\k21\scan\off-R-20270207` ve všech polích (`ladder_refuted` 2, `ladder_refuted_wrong_causal` 2, nálezů 33 086). Rozbor `rca21.py`:

| cyklus | klíč | P | neškodné výsledky | zdroje nálezu | pravda |
|---|---|---|---|---|---|
| 636 | `asset:1\|unexpected_traffic\|host-only` (host 192.168.33.1, brána sítě) | 0,0264 | jen L1 kontext `authorized_scanner (schvalil sim-spravce)`, LR 0,30; historie a profil `nezjisteno` | 192.168.34.234, 192.168.33.119 | příčinně omyl; v okně benign `AuthorizedScanner` (id 25) a `CloudMigration` (id 81) |
| 637 | týž klíč | 0,0264 | totéž | | totéž |

**Výsledek proti kritériu (1.3): zamítnuto podle litery kritéria.** Případy **nemají** příčinu z tabulky `impl-krok21.md` 6 b (jedna slabá skupina): jedinou skupinou je schválený kontext s vlastníkem, tj. podle `closure_gate::positive` pozitivní důkaz s vlastníkem. Záznam je skener **bez rozsahu cílů** a nález má smíšené zdroje; bez `strict_close` (rameno R) stačí částečná shoda zdroje (`context_gate.rs:555`). Druhá podmínka kritéria platí: brána na rekonstruovaném rozhodnutí vrací `Refusal::TooFewGroups` a s přísným doložením (`close_gate` ⇒ `strict_close`, `engine.rs:909`) kontext nález ani nepodpoří (test `closure_gate::tests::k22_b1_scanner_context_without_scope_alone_is_refused`). Dvě nezávislé skupiny případ nemá.

**Nový nález K22-N1 (zapsán do registru až v Check kroku):** tvrzení kroku 21 „všechny omylem vyvrácené v R jsou jedna slabá skupina“ neplatí pro 2 ze 42 případů. Ty blokuje brána dvěma nezávislými mechanismy (pravidlo dvou skupin v `admit_ladder` a přísný kontext v kroku žebříku), ne chybějícím pozitivním důkazem. Slabé místo: `admit_ladder` pozná pozitivní kontext jen podle textu poznámky („schvalil“) a **sám neověřuje doložení zdroje**; spoléhá na to, že krok kontextu žebříku běží se stejnou `GatePolicy` (`for_engine`, v soaku `soak/v3.rs:77`, v produkci `pipeline/v3.rs:480`). Skener bez rozsahu + historie (druhá skupina) by bez přísné politiky lístek dostal. Dnes to nenastane (přísnost je s branou vynucená a testem připnutá), proto se E1 nezastavuje; obranná kontrola doložení přímo v `admit_ladder` je navržena jako první bod E2 (mění chování brány, potřebuje vlastní předregistraci).

Odchylka od Act plánu (zapsáno): plán pro zamítnutí říká „opravit dřív než cokoli dalšího“. Brána případ prokazatelně odmítá (test), vada je ve zdůvodnění tvrzení R1 a v obranné hloubce, ne v propustnosti brány; E1 (jen za vypnutými přepínači, bez vlivu na zavírání) proto pokračuje.

## 3. E1: kontext v2 a stín (B2, B3, B4)

Commity `ae9f1b2` (kód), `51a2a03` (fuzz stínu). Binárka `F:\work-tmp\k22\bin\salticus-k22-ae9f1b2.exe`. Běhy `F:\work-tmp\k22\{reg,regsh,shR,trace}`, 35 úloh (137 sítí), všechny s kódem 0, 14 min reálného času při 8 paralelních úlohách (Idle, maska 0x3FFFFC).

**Co se změnilo (vše za vypnutými přepínači, `recommended()` beze změny):**

- `ctx_host_first` (V3Features, výchozí vypnuto) → `GatePolicy::host_first`. V `explain_decision` pořadí: aktivní a pokrývá → `admits` → shoda hostu → shoda zdroje → přísné doložení; `ambiguous` nastaví jen záznam, který se nálezu týká (N14).
- `GateInput.targets` a `CaseInput.targets` (cíle nálezu z událostí téhož typu, `findings::finding_targets`, u behaviorálních nálezů cíle z vrstvy). S `host_first` platí pro `AuthorizedScanner` s rozsahem: všechny cíle v rozsahu (adresa nebo CIDR; bez známých cílů je cílem host nálezu) a všechny zdroje nálezu jsou zdroji skeneru (N13). Prázdný rozsah = nedoloženo. Plní se v soaku i v produkci (`pipeline/v3.rs`), jen když je přepínač zapnutý.
- Stín (B4): `closure_gate::shadow_ladder` a `shadow_context` volají `admit_ladder` / `admit_explanation` nad týmiž vstupy a vrací lístek nebo důvod odmítnutí, druh pozitivního důkazu, skupiny a vlastníka; čistě funkce bez přístupu k paměti. V soaku je zapíná `K22_SHADOW=soubor` (jako `K15_TRACE`): rozhodnutí žebříku se stavem `Refuted` nebo P ≤ 0,03 (před `settle`) a každé kontextové vysvětlení. Pravda se v enginu nedoplňuje.
- `K21_SCANNER_SCOPE` zůstává (odstraní se se světem v2 v E2, viz 1.3).

**Výsledky proti kritériím 1.3:**

| kritérium | výsledek | stav |
|---|---|---|
| B2 (a) záznam jiného hostu → `ambiguous = false`, rozhodnutí jako bez záznamu | test `k22_n14_other_host_record_does_not_make_finding_ambiguous` | splněno |
| B2 (b) záznam téhož hostu bez doloženého zdroje → `ambiguous = true` | týž test | splněno |
| B2 (c) sonda N14 převrácena; bez přepínače chování kroku 21 | týž test (obě větve) | splněno |
| B2 vlastnost: bez skeneru tatáž zavření jako krok 21, nejednoznačnost jen podmnožinou, záznamy jiných hostů v2 nemění | `k22_host_first_property_same_closures_fewer_ambiguous`, 5 000 náhodných kalendářů × 2 politiky, rozdíl nejednoznačnosti pokryt (> 100 případů) | splněno |
| B2 stopa 20270208/0 (RG + `ctx_host_first`, `b2_check.py`): z nálezů `connection_timeout_burst` chráněných jen v RG zmizí ≥ 95 % | 228 chráněných jen v RG (z toho 161 navíc zobrazených FP bez útoku v okně; krok 21 uvádí 162, rozdíl je v definici párování): v RGH chráněno **0 z 228** (100 %), z 161 FP zobrazeno 0. Zobrazené FP sítě 0: R 99, RG 158, RGH 99 (diagnostika, ne rozhodnutí) | splněno |
| B3 sken ven přes bránu (rozsah = vnější cíl, zdroj = skener) → vysvětleno, lístek vydán | `k22_n13_scanner_scope_matches_finding_targets` | splněno |
| B3 jeden cíl mimo rozsah → nevysvětleno; CIDR; prázdný rozsah → nedoloženo; bez přepínače krok 21 | týž test | splněno |
| B3 útok ze zařízení skeneru (typ mimo pokrytí, explicitní `covers`, smíšené zdroje, vysoká závažnost) → nezavřeno | `k22_n13_attack_from_scanner_device_inside_scope_is_not_closed` (smíšené zdroje: nezavřeno a `ambiguous`) | splněno |
| K22-6 bez přepínačů | 48 z 48 sítí shodných s `F:\work-tmp\k21\reg` ve všech polích kromě časů (`cmp22.py`) | splněno |
| K22-6 se stínem (`K22_SHADOW`) | 48 z 48 shodných; navíc 40 z 40 sítí ramene R se stínem shodných s `F:\work-tmp\k21\scan` | splněno |
| B4 kontrola smyslu (R, seedy 20270201 až 20270210, svět bez masky) | stín obsahuje **14** kontextových zavření (běh 14) a **1 529** vyvrácení (běh 1 529), shoda ± 0; lístek vydán **0** | splněno |
| fuzz brány se stínem | `gate_invariant_holds_under_random_operations_fuzz` (20 000 posloupností) nově ověřuje, že stín dává týž výsledek jako brána; 0 porušení | splněno |
| `cargo test --lib` | 692 prošlo, 7 selhalo: 5 `broker::tests` (Redis) a 1 `identity_lab` (Docker) známé, 1 `engine::tests::parse_mode_and_disable_list` (popisek `all()` s novým přepínačem; opraveno, 5/5 `engine::tests` prošlo) | splněno |
| `cargo fmt --check`, `cargo clippy --all-targets` | fmt čisté; clippy bez chyby a bez varování ve změněném kódu (repo má starší varování v jiných modulech, beze změny) | splněno |

**Rozklad odmítnutí ve stínu ramene R** (proč by brána nic z toho nezavřela): vyvrácení 1 407 „vysoký dopad“ (z toho 1 374 `packet_rate_spike` seedu 20270206), 120 „chybí pozitivní důkaz s vlastníkem“, 2 „méně než dvě skupiny“ (jsou to případy B1 se skenerem bez rozsahu); kontextová zavření 13 „zdroje nálezu nejsou celé v záznamu“ (skener bez rozsahu) a 1 „vysoký dopad“ (`batch_job`). Brána hlásí první porušenou podmínku; pozitivní důkaz má jen 2 z 1 529 vyvrácení. Plán čekal odmítnutí „bez pozitivního důkazu“ u všech; ve skutečnosti rozhoduje u většiny dřív R2 (vysoký dopad).

## 4. Check E0 a E1

| bod | výsledek |
|---|---|
| B1 | **zamítnuto podle litery kritéria** (pozitivní důkaz s vlastníkem v obou případech), brána je odmítá (`TooFewGroups`, přísný kontext); nový nález K22-N1 (2). |
| B2, B3, B4 | všechna předem zapsaná kritéria E1 splněna (3). |
| K22-6 | splněno (48/48, 48/48, 40/40). |

**Neúspěchy a omezení:** (1) B1 neprošlo kritériem; tvrzení kroku 21 o 42 omylem vyvrácených je třeba opravit (2 z 42 mají jedinou silnou skupinu). (2) `admit_ladder` sám neověřuje doložení zdroje kontextu (K22-N1); ochrana stojí na přísné politice kroku kontextu. (3) `K21_SCANNER_SCOPE` není odstraněn (patří ke světu v2). (4) Stopa B2 je diagnostika na jedné síti už použitého seedu; účinek N14 na zobrazené FP rozhodne až K22-3 v E3. (5) Účinek N13 v soaku nelze změřit, dokud simulace negeneruje rozsah skeneru (E2). (6) Nezávislé review diffu (`sol-loop`) zadání této fáze vylučuje; diff sahá na logiku zavírání, review má proběhnout v hlavní konverzaci před E2.

**Act (doporučení):** pokračovat do E2 s úpravou pořadí: nejdřív (a) review diffu E1, (b) obranná kontrola K22-N1 v `admit_ladder` s vlastní krátkou předregistrací (lístek z kontextu jen s doloženým zdrojem; K22-6 musí zůstat splněno), pak B6 (laboratoř C) a B5 (svět v2) podle plánu. Měřená cena soaku vyšla nižší, než plán předpokládal: 137 sítí za 14 min při 8 úlohách (≈ 49 s CPU na síť a 2 dny proti 76 s v plánu), rozpočet E2 a E3 tedy spíš horní mez.

## 5. Předregistrace dodatku K22-N1 a etapy E2 (zapsáno před kódem E2)

Vedoucí po E1 schválil pokračování. Review diffu E1 v hlavní konverzaci bez blokujícího nálezu, se dvěma body k ošetření: (a) `targets_in_scope` při prázdných cílech bere shodu kteréhokoli identifikátoru hostu; (b) zbytkové riziko kompromitovaného skeneru, který skenuje cíle v rozsahu. Tato sekce je zapsána a komitnuta před jakoukoli změnou kódu E2.

### 5.1 K22-N1: kontrola doloženého zdroje přímo v `admit_ladder`

- **Změna:** `ContextGate::supporting_context` u záznamu, který krok kontextu podpoří, spočítá doložení zdroje **nezávisle na `GatePolicy`** (bez ohledu na `strict_close` a `host_first`): u `AuthorizedScanner` neprázdný rozsah, všechny zdroje nálezu jsou zdroji skeneru a všechny cíle v rozsahu (týž výpočet jako kontext v2); u ostatních druhů `strictly_proven` (zdroje neprázdné a všechny v záznamu). Výsledek nese text kroku jako pevný prefix vytvořený kódem před textem z kalendáře (`[zdroj dolozen] `), takže ho nejde podvrhnout jménem schvalovatele. `admit_ladder` uzná schválený kontext jako pozitivní důkaz jen s tímto prefixem; nedoložený kontext s vlastníkem zůstává podpůrnou skupinou 1, ale ne pozitivním důkazem. Když je jediným pozitivním kandidátem nedoložený kontext, brána vrací nový důvod `Refusal::SourceNotProven` (štítek existující „zdroje nalezu nejsou cele v zaznamu“).
- **Kritéria (předem):** (1) rekonstrukce B1 (skener bez rozsahu) + druhá skupina (historie) → odmítnuto i s výchozí `GatePolicy` (bez `strict_close`); (2) doložený kontext zálohy + historie → lístek; (3) jméno schvalovatele obsahující text prefixu → odmítnuto; (4) bod (a): záznam skeneru s rozsahem, nález bez cílů na hostu v rozsahu se zdrojem mimo skener, se smíšenými zdroji a bez zdrojů → nevysvětleno, žádný lístek; shoda asset id hostu v rozsahu se zdrojem skeneru → vysvětleno (záměr); (5) K22-6 znovu: 48/48 bez přepínačů a 48/48 se stínem proti `F:\work-tmp\k21\reg`; (6) `cargo test --lib` bez nových selhání, `fmt` a `clippy` čisté ve změněném kódu.

### 5.2 Svět simulace v2 (B5): parametry zapsané předem

Zapíná ho volba soaku `--world-v2` (`WorldOptions::calendar_v2`, výchozí vypnuto; svět v1 beze změny kromě odstranění `K21_SCANNER_SCOPE`). Útoky se plánují stejným proudem jako ve v1 (stejný seed → stejné útoky); kalendář má vlastní odvozený proud náhody. Náhodně losované jevy `Backup`, `AuthorizedScanner`, `BatchJob` a `PatchWindow` z v1 se ve v2 nahradí jevy z kalendáře (ostatní neškodné jevy a jejich záznamy, např. výpadek služby, CMDB, senzor, fantomová údržba, zůstávají jako ve v1; omezení: tyto druhy jsou dál odvozené z pravdy).

| úloha | role (pevně za síť) | čas a délka | záznam |
|---|---|---|---|
| záloha | zálohovací server = první `FileServer`, jinak první server mimo bránu a DNS | denně 02:00 místního času, 1 až 3 cykly | `Backup`, `sources = [zálohovací server]`, `hosts` = cíle: všechny servery mimo bránu, DNS a sebe + až 20 klientů (pevný vzorek inventáře); provoz: server stahuje z cílů (tcp/445, velká odpověď) |
| autorizovaný sken | skener = první `Jump`, jinak pevně vylosovaná pracovní stanice | týdně, den v týdnu losovaný za síť, 03:00, 1 až 2 cykly | `AuthorizedScanner`, `sources = [skener]`, `hosts` = všechny vnitřní podsítě /24 (CIDR) + 2 pevné vnější cíle sítě; provoz: sken celé sítě jako ve v1 a navíc jednoho z vnějších cílů |
| dávka | hostitel dávky = první `Database`, jinak první server; cíl = první `FileServer`/`Database` různý od hostitele | denně 04:00, 1 až 6 cyklů | `BatchJob`, `sources = [hostitel]`, `hosts = [cíl]` |
| patch okno | skupina = třetina serverů (2 až 40, pevný vzorek), repozitář = pevná vnější adresa | druhé úterý v měsíci, pokud padne do horizontu, + mimořádné okno s p = 0,1 za týden; 04:00, 2 až 5 cyklů | `PatchWindow`, `sources = [repozitář]`, `hosts` = skupina |

- **Nedokonalost kalendáře (nezávislé losy na výskyt úlohy):** 10 % jevů bez záznamu, 5 % záznamů bez jevu (zrušené okno), 5 % záznamů posunutých o ± 1 h (2 cykly, znaménko náhodně). Deklarované okno je o cyklus širší než práce (jako ve v1), schvalovatel `sim-spravce`, expirace konec + 1 den.
- **Kompromitace infrastruktury:** každý útok rodin `PortScanVertical`, `PortScanHorizontal`, `SlowScan`, `SshBrute`, `Lateral`, `Exfil`, `C2Beacon` s p = 0,02 (vlastní proud) dostane jako zdroj zálohovací server nebo skener (50 : 50) a začátek v nejbližším okně dané úlohy. Ostatní překryvy útoků s okny vznikají přirozeně z nezávislého generátoru.
- **Horizont:** `--episode-hours 168` (7 dní). Tabulka hranice (stín) se počítá jen ze dnů 6 a 7 (cykly ≥ 240); souhrny `networks.jsonl` jsou za celý běh (rozdělení po dnech výstup nemá; hlásí se jako omezení).
- `K21_SCANNER_SCOPE` se odstraní; ve světě v1 zůstává rozsah skeneru podle `strict_close` jako dosud (bitová shoda K22-6).
- **Validita světa (kontroluje se na ramenech R a F před čtením výsledku brány, ladicí seedy 20269801 až 20269805):** V1 podíl jevů kalendáře se záznamem 90 % ± 2 % (čítače světa); V2 hlásí se podíl útoků, jejichž zdroj nebo cíl leží v aktivním okně kalendáře (bez cíle); V3 rameno R ve v2 má víc kontextových zavření než rameno R ve v1 na týchž seedech a horizontu. Neprojde-li validita, opraví se generátor (zapíše se) a ladicí běhy se opakují; parametry tabulky výše se kvůli výsledku brány nemění.
- **Ramena ladicích běhů (konfigurace `off`, 4 sítě, 168 h, `--threads 1`, společné volby kroku 21, vše se stínem):** v2: R, F22, F22c (`F` + `ctx_host_first`), FG22 (`F` + `close_gate` + `ctx_host_first`); v1 (168 h): R, F22, FG22 (pro V3 a K22-7). Držené seedy 20270301 až 20270310 se nepoužijí (E3 rozhodne vedoucí).
- **Pravda stínu:** soak k záznamu stínu doplní pravdu simulátoru (ne engine): u žebříku `cf` a `causal` z pravdy případu, u kontextu příčinnou shodu (útok v okně a shoda cíle nebo zdroje, jako u skutečných zavření) a `cf` z kontrafaktuálu. Omyl = sjednocení. Vyhodnocení `tools/k22_shadow.py` (buňka = druh pozitivního důkazu × typ nálezu, n, správná, omylem, Wilson 95 % horní mez, odmítnutí podle důvodu, potřebný objem pro n ≥ 381).

### 5.3 Laboratoř C (B6): sestava a kalendář zapsané předem

- **Sestava `labs/k22` (projekt `k22c`, obraz `k17lab:1`, nic se nestahuje ani neposílá ven):** sítě lan 10.77.1.0/24, srv 10.77.2.0/24, wan 10.77.9.0/24 (emulovaný vnějšek, směrovač zahazuje vše mimo 10.77.0.0/16); zachycení tcpdump na rozhraní lan směrovače. Servery: `fs` 10.77.2.20 a `app` 10.77.2.30 (sdílení tcp/445 vrací data, `fs` navíc „databáze“ tcp/5432 vrací výpis), `web` 10.77.2.10 (http). Lan: klienti `c1` 10.77.1.11 a `c2` 10.77.1.12 (pravidelný http), `backup` 10.77.1.20, `scanner` 10.77.1.30, `batch` 10.77.1.40. Wan: `sink` 10.77.9.9 (příjem tcp/443), `ext` 10.77.9.10 (vnější služba organizace, v rozsahu skeneru).
- **Odchylka od plánu B6 (zapsáno předem):** obraz nemá `rsync` ani PostgreSQL a nic se nestahuje (omezení „nic ven“); záloha je skutečný přenos dat po TCP (python klient stahuje soubory ze sdílení na 445), dávka je skutečný přenos výpisu z tcp/5432, sken je skutečný `nmap -sV`.
- **Kalendář (`context-calendar.json`, píše ho skript laboratoře před spuštěním první úlohy, z plánu slotů, s vlastníkem `lab-operator` a expirací konec + 1 den, okna = aktivní fáze slotu ± 30 s):** `Backup` sources `[10.77.1.20]`, hosts `[10.77.2.20, 10.77.2.30]`; `BatchJob` sources `[10.77.1.40]`, hosts `[10.77.2.20]`; `AuthorizedScanner` sources `[10.77.1.30]`, hosts `[10.77.2.0/24, 10.77.9.10]`.
- **Sloty (pořadí podle seedu sady; každý 120 s normál, 120 s úloha, 120 s po; zahřátí 300 s):** BK1 až BK3 záloha se záznamem; BKN záloha bez záznamu (čeká se „nelze určit“, žádný lístek); BA1, BA2 dávka se záznamem; SC1, SC2 sken se záznamem; SA1 až SA3 sken se záznamem + útok A (`c1`: `nmap -sS` na 10.77.2.0/24, porty 1 až 1024) + útok C (skener: `nmap -sS` na 10.77.9.9 mimo rozsah); BB1 až BB3 záloha se záznamem + útok B (zálohovací kontejner posílá 30 MB na `sink` tcp/443); SD1 sken se záznamem + útok D (skener: plný sken portů 1 až 65535 cílů v rozsahu; zbytkové riziko bodu (b)).
- **Vyhodnocení:** Zeek na pcap, okna podle fází, `beh spust` s `SALTICUS_REPLAY_NOW` = konec okna, konfigurace `protect`, `l7_dns`, `l7_tls`, `close_gate`, `ctx_host_first`, `K22_SHADOW` (stín i v produkční cestě). Nález je **útok**, když v okně útoku nese zdroj útočníka nebo cíl útoku (A: zdroj `c1`; B: cíl 10.77.9.9 se zdrojem `backup`; C: cíl 10.77.9.9 se zdrojem `scanner`; D: zdroj `scanner` v slotu SD1); **neškodný se záznamem**, když všechny jeho zdroje a cíle patří úloze slotu se záznamem a není útokem; ostatní se hlásí zvlášť.
- **Kritéria (z plánu, předem):** lístek (ve stínu) pro ≥ 90 % neškodných nálezů se záznamem; **0 lístků** na útocích A, B, C (každý aspoň 3 relace); BKN bez lístku. Útok D se hlásí zvlášť a **očekává se lístek** (sken v rozsahu v okně je z toku nerozlišitelný od autorizovaného skenu); jeho lístek není neúspěch kritéria B6, ale změřené zbytkové riziko (b). Jakýkoli lístek na A, B, C = nový nález, oprava před E3. Ladicí sada 22001 (smí se opakovat po opravě harnessu, ne brány); držená 22101 jednou.
- **Bod (b), návrh mitigace (jen návrh, neimplementuje se v E2):** záznam skeneru by nesl i deklarovaný profil (porty, rychlost, nástroj); sken mimo profil by záznam nevysvětlil. Změří se, zda ho svět v2 (útoky z infrastruktury) a laboratoř (D) zachytí jako omyl ve stínu.

## 6. K22-N1: výsledek (DO)

Commit `23d8378`, binárka `F:\work-tmp\k22\bin\salticus-k22-23d8378.exe`.

| kritérium (5.1) | výsledek | stav |
|---|---|---|
| (1) B1 + historie s výchozí `GatePolicy` → odmítnuto | `k22_n1_ladder_requires_independently_proven_context_source`: podpůrný kontext bez prefixu, `admit_ladder` → `SourceNotProven`, stín nevydá lístek | splněno |
| (2) doložená záloha + historie → lístek | týž test, vlastník `spravce`, stín hlásí `context:backup` | splněno |
| (3) prefix podvržený jménem schvalovatele → odmítnuto | týž test (text prefixu uvnitř jména, zdroj nedoložen) | splněno |
| (4) bod (a) review: útok z jiného zdroje na host v rozsahu (cizí zdroj, smíšené zdroje, bez zdrojů) → nevysvětleno a bez doložení; host jen jako asset id rozsah nesplní; záměr (IP hostu v rozsahu, zdroj = skener) vysvětlen a doložen | `k22_review_a_host_in_scope_does_not_admit_attack_from_other_source` | splněno; obejít `any` v `targets_in_scope` nejde, protože doložení skeneru vyžaduje všechny zdroje nálezu v `sources` skeneru |
| (5) K22-6 | `reg2` 48/48, `regsh2` 48/48 shodných sítí s `F:\work-tmp\k21\reg` (kromě časů) | splněno |
| (6) testy | `cargo test --lib`: 695 prošlo, 6 známých selhání (5 `broker` bez Redis, 1 `identity_lab` bez Dockeru); `fmt` čisté; `clippy` bez nového varování | splněno |

Vedlejší účinek (zapsáno): případy B1 brána nyní odmítá důvodem `SourceNotProven` místo `TooFewGroups` (první porušená podmínka je chybějící doložení). Test B1 upraven.

## 7. E2: svět simulace v2 na ladicích seedech (B5)

Commity `95928d4` (svět v2, pravda ke stínu, odstraněn `K21_SCANNER_SCOPE`), `86e22f5` (laboratoř C, stín v produkční cestě). Binárka `F:\work-tmp\k22\bin\salticus-k22-86e22f5.exe`. Běhy `F:\work-tmp\k22\e2` (35 úloh = 7 ramen × seedy 20269801 až 20269805, konfigurace `off`, 4 sítě, 168 h, se stínem) a `F:\work-tmp\k22\{reg3,regsh3}` (K22-6), všech 59 úloh s kódem 0, ≈ 50 min reálného času při 7 paralelních úlohách. Držené seedy nepoužity. Vyhodnocení `tools/k22_gate.py` (`F:\work-tmp\k22\e2-gate.txt`), `tools/k22_shadow.py`.

**K22-6 po všech změnách E2** (svět v1, bez přepínačů a se stínem, binárka `86e22f5`): `reg3` 48/48, `regsh3` 48/48 shodných sítí s krokem 21. Svět v1 se odstraněním `K21_SCANNER_SCOPE` nezměnil.

### 7.1 Validita světa (5.2)

| kritérium | výsledek | stav |
|---|---|---|
| V1 podíl jevů kalendáře se záznamem 90 % ± 2 % | 207 z 229 = 90,4 % (20 sítí; zrušených oken 15, posunutých záznamů 10) | splněno |
| V2 podíl útoků se zdrojem nebo cílem v aktivním okně (hlásí se) | 385 z 1 798 = 21,4 %; útoků z infrastruktury 4 | hlášeno |
| V3 rameno R ve v2 má víc kontextových zavření než ve v1 | R1 (v1, 168 h) **10** zavření (z toho 6 omylem), R2 (v2) **0** | **nesplněno** |

**Proč V3 neprošlo (rozbor stopy `F:\work-tmp\k22\trace\off-FG2-20269801`, síť 0):** záznamy kalendáře do brány dojdou (test `calendar_backup_record_reaches_context_gate`) a nálezy úloh mají správný host a zdroj, ale engine je nevysvětlí: z 673 nálezů zálohy a dávky (v okně úlohy, typ krytý druhem záznamu) je 487 vysoké závažnosti (s `protect` platí P6: vysvětlí je jen dva nezávislé druhy kontextu) a 409 je bez identifikovaného zdroje (s přísným doložením nedoloženo; bez zdroje opět P6); **všech 673** splňuje aspoň jednu z obou podmínek, takže kontext je nevysvětlí nikdy. Ve v1 R zavíral hlavně proto, že záznam byl odvozený z pravdy (6 z 10 zavření omylem). Příčina tedy není vada generátoru, ale pravidla jádra (P6, přísné doložení, chybějící zdroje u objemových nálezů). **Odchylka od předregistrace (zapsáno):** předregistrace pro neúspěch validity předepisuje opravu generátoru; generátor se neopravuje, protože každá změna, která by V3 splnila (menší objemy záloh, zdroje u objemových nálezů), by byla laděním světa podle toho, zda brána zavírá (kruhovost A1). Výsledek se hlásí jako neúspěch V3 se změřenou příčinou.

### 7.2 Prahy K22 na ladicích seedech (svět v2, `off`, 20 sítí; jen diagnostika, rozhodují až držené seedy E3)

| práh | výsledek | stav |
|---|---|---|
| K22-1 omylem zavřená ve FG2 | **3 ze 4** skutečných zavření (kontext `authorized_scanner`); 2 útoky s omylem zavřeným nálezem; 5 výskytů útoků pohlceno pod zavřeným klíčem | **nesplněno** |
| K22-2 detekce FG2 vs F2 | 85,32 → 85,37 % (+0,06 p. b.); žádná rodina nižší (počty útoků) | splněno |
| K22-3 FP | FG2/F2 = 1 353/1 365 = 0,991 (≤ 1,01); F2c/F2 = 0,991 (≤ 1,00) | splněno |
| K22-4 případy pro člověka | 22 274 → 22 272 (−0,01 %) | splněno |
| K22-5 tabulka hranice (stín) | dny 6 a 7: **žádný** stínový lístek ani kontextové vysvětlení v žádném rameni (40 síťodnů); všech 7 dní: 4 lístky, buňky `context:authorized_scanner × unexpected_traffic` (2, oba omylem) a `× scan_attempts` (2, 1 omylem); žebřík 0 lístků (odmítnutí: 411 vysoký dopad, 136 bez pozitivního důkazu, 62 chráněný nález) | žádný kandidát |
| K22-6 | 48/48 a 48/48 | splněno |
| K22-7 v1 vs v2 | F: FP 1 526 → 1 365 (×0,894); detekce 85,21 → 85,32 %; R: FP 1 472 → 1 326, kontextová zavření 10 → 0, vyvrácení 136 → 225; FG: zavření 0 → 4 (3 omylem); stínové lístky 0 → 4 | hlášeno |

**Rozbor tří omylem zavřených (K22-N2):**

| síť | cyklus | nález | zdroj | pravda | mechanismus |
|---|---|---|---|---|---|
| 20269801/0 | 144, 145 | `unexpected_traffic` na 10.188.2.53 (nízká závažnost) | 10.188.2.98 = autorizovaný skener | cf i příčinně: `ssh_bruteforce` (id 48) ze skeneru, začátek přesunut do okna skenu (kompromitace infrastruktury, 5.2) | záznam skeneru pokrývá `unexpected_traffic`, zdroj = skener, cíl v rozsahu → doloženo, lístek. Útok, který vůbec není sken, projde jako sken. |
| 20269803/2 | 170 | `scan_attempts` | 192.168.17.190 = skener (pracovní stanice, síť 14 zařízení) | jen příčinně (cf ne): současně běží `c2_irc_style_channel` ze stejného zařízení | přirozený překryv: skener je zároveň infikovaná stanice; nález sám vznikl ze skenu, ale zavření skryje aktivitu kompromitovaného zařízení |

Tím je bod (b) review změřen: **svět v2 zbytkové riziko zachytil** (2 omylem zavřené ze 4 zavření v 20 sítích a 7 dnech, 1 další přirozeným překryvem). Kandidátní buňka by po odečtení omylů nevznikla ani při libovolném objemu: horní mez Wilson pro 3 omyly ze 4 je 99,4 %.

**Potřebný objem:** pro buňky zálohy a dávky nebyl za 140 síťodnů (dny 1 až 7) ani 40 síťodnů (dny 6 a 7) vydán žádný lístek; horní mez míry (3/140 na síťoden) dává **≥ 17 800 síťodnů** na 381 zavření v jedné buňce při dnešních pravidlech P6 a přísném doložení, tj. na držené sadě (40 sítí × 7 dní = 280 síťodnů) nedosažitelné. Pro buňky skeneru je problémem chybovost, ne objem.

## 8. E2: laboratoř C (B6)

Sestava `labs/k22`, skripty `tools/k22_lab.py` (běh, kalendář před první úlohou) a `tools/k22_lab_eval.py` (Zeek, okna, `beh spust` s `K22_SHADOW`). Data jen v `F:\work-tmp\k22\lab`. Kontejnery jen na tomto počítači, sítě 10.77.0.0/16 bez NAT, nic ven.

**Úpravy harnessu na ladicí sadě (zapsáno, bez změny brány, kalendáře a provozu):** (1) zkušební běh `smoke` (3 sloty, fáze 25 s) ukázal, že bez inventáře produkční cesta zná služby jen jako `unmapped_passive_event` bez zdrojů; vyhodnocení proto dostává statický inventář nmap ze sestavy (znalost operátora, `HOSTS` v `k22_lab_eval.py`); (2) produkční stín loguje i nálezy, pro které kalendář má aktivní záznam krytého typu, ale brána je nevysvětlila (`context_none`, jen měření). Skript běhu laboratoře se mezi 22001 a 22101 neměnil.

### 8.1 Ladicí sada 22001 (15 slotů, fáze 120 s, 154 047 spojení Zeek, 47 oken, 695 nálezů)

| třída (5.3) | nálezů | stínový lístek | poznámka |
|---|---|---|---|
| neškodný se záznamem (sloty SC, SA) | 124 | **0** | 99 `unmapped_passive_event` (bez zdroje), 25 `connection_timeout_burst`; všechny **vysoké závažnosti** |
| útok A (sken z `c1` v okně skenu) | 5 | 0 | ve 3 slotech |
| útok B (exfiltrace ze zálohovacího kontejneru) | 3 | 0 | `identification_gap` (typ mimo pokrytí zálohy) |
| útok C (skener mimo rozsah) | 3 | 0 | `identification_gap` |
| útok D (kompromitovaný skener v rozsahu, smíšeno s autorizovaným skenem) | 16 | 0 | očekávaný lístek nevznikl: kryté typy (5 `connection_timeout_burst`, 1 `scan_attempts`) jsou vysoké závažnosti, ostatní typy záznam skeneru nepokrývá |
| BKN (záloha bez záznamu) | 0 krytých nálezů | 0 | |
| zálohy a dávky se záznamem (BK, BA, BB) | 0 krytých nálezů | – | skutečný přenos 80 MB na úlohu nevytvořil v produkční cestě žádný objemový nález (jen `identification_gap`, `management_surface_exposure`, `packet_loss_signal`) |

Všech 135 krytých nálezů v aktivním okně záznamu (všechny fáze, všechny vysoké závažnosti) brána nevysvětlila (`context_none`): u vysoké závažnosti vyžaduje vysvětlení explicitní `covers` a neprázdný rozsah (kalendář laboratoře má podle předregistrace `covers` prázdné) a i s ním by lístek odmítla R2 (vysoký dopad se nezavírá nikdy); u `unmapped_passive_event` chybí zdroj.

### 8.2 Držená sada 22101 (jednou; skript i vyhodnocení beze změny proti 22001; 146 941 spojení, 47 oken, 715 nálezů)

| třída | nálezů | stínový lístek |
|---|---|---|
| neškodný se záznamem (SC, SA) | 114 (89 `unmapped_passive_event` bez zdroje, 25 `connection_timeout_burst`; všechny vysoké závažnosti) | **0** |
| útok A | 17 | 0 |
| útok B | 3 | 0 |
| útok C | 3 | 0 |
| útok D (smíšeno) | 22 | 0 |
| BKN | 0 krytých nálezů | 0 |
| zálohy a dávky se záznamem | 0 krytých nálezů | – |

Kalendář měl pro 138 krytých nálezů aktivní záznam; brána nevysvětlila žádný (`context_none`).

### 8.3 Výsledek proti kritériím B6 (5.3)

| kritérium | 22001 | 22101 | stav |
|---|---|---|---|
| lístek pro ≥ 90 % neškodných nálezů se záznamem | 0 ze 124 | 0 ze 114 | **nesplněno** |
| 0 lístků na útocích A, B, C (každý ≥ 3 relace) | A 0/5, B 0/3, C 0/3 | A 0/17, B 0/3, C 0/3 | splněno |
| BKN bez lístku | splněno (žádný krytý nález) | splněno | splněno, ale bez síly (úloha nevytvořila nález) |
| D hlášeno zvlášť (očekáván lístek) | 0/16 | 0/22 | lístek nevznikl; zbytkové riziko (b) se v laboratoři neprojevilo, protože všechny kryté nálezy skenu jsou vysoké závažnosti |

**Závěr B6:** laboratoř nedoložila, že brána umí v reálném provozu správně zavřít: v produkční cestě jsou všechny nálezy skutečného skenu vysoké závažnosti (R2 a pravidlo explicitního pokrytí je nezavírají nikdy) nebo bez zdroje, a skutečná záloha a dávka (80 MB a 60 MB za 120 s) nevytvořily žádný nález krytý záznamem. Odmítnutí útoků v okně je doloženo, ale triviálně (brána nezavřela nic). Hrozba validity: krátké fáze (120 s) bez zahřáté základní linie objemu; sedmidenní stínový provoz (plán 4.2) by objemové nálezy záloh pravděpodobně vytvořil.

## 9. Check E2 (souhrn)

| bod | výsledek | stav |
|---|---|---|
| K22-N1 (5.1) | všech 6 kritérií; K22-6 48/48 a 48/48 (binárka `23d8378`) i po celé E2 (`86e22f5`) | splněno |
| bod (a) review | test: útok z jiného zdroje na host v rozsahu se nevysvětlí a nedoloží | splněno |
| bod (b) review | svět v2: 2 omylem zavřené (útok `ssh_bruteforce` z kompromitovaného skeneru v jeho okně, typ `unexpected_traffic`) + 1 příčinný překryv (skener zároveň infikovaná stanice); laboratoř D: 0 lístků (nálezy vysoké závažnosti) | změřeno: **riziko reálné**, zachytil ho svět v2 |
| validita světa V1 / V2 / V3 | 90,4 % / 21,4 % útoků v okně / R2 0 vs R1 10 zavření | V1 splněno, **V3 nesplněno** (příčina v pravidlech jádra, generátor neopravován, 7.1) |
| K22-1 (FG2, ladicí) | 3 omylem ze 4 zavření | **nesplněno** |
| K22-2, K22-3, K22-4 | +0,06 p. b., žádná rodina nižší; FP ×0,991 (FG2/F2 i F2c/F2); −0,01 % | splněno |
| K22-5 | dny 6 a 7: žádný lístek v žádném rameni; žádná buňka, žádný kandidát | bez kandidáta (předpověď „žádná buňka s n ≥ 381“ potvrzena, ale silněji: n = 0) |
| K22-6 | 48/48 + 48/48 (dvakrát) | splněno |
| K22-7 | 7.2 | hlášeno |
| B6 laboratoř C | 0 lístků na útocích; 0 lístků na neškodných (cíl ≥ 90 %) | **nesplněno** (pozitivní část) |

**Kolik zavření by která buňka potřebovala (K22-5):** kandidát = horní mez Wilson 95 % < 1 %, tj. 381 zavření s 0 omyly (563 s 1, 726 se 2, 878 se 3). Buňky skeneru (`context:authorized_scanner × unexpected_traffic`, `× scan_attempts`): dnes 3 omyly ze 4, tedy by potřebovaly ≥ 874 dalších správných zavření bez jediného omylu, a to při chybovosti blízké 75 % nenastane; nejde o objem, ale o vadu (K22-N2). Buňky zálohy a dávky: 0 lístků za 140 síťodnů → při horní mezi míry 3/140 na síťoden ≥ 17 800 síťodnů na buňku (držená sada E3 má 280). Žebřík: 0 lístků (rozhoduje R2 a chybějící pozitivní důkaz). Laboratoř: 0 lístků za 2 × 95 min.

**Nové nálezy (do registru v Check kroku):**

- **K22-N2 (vysoká priorita):** záznam autorizovaného skeneru vysvětlí (a brána zavře) i útok jiného druhu než sken, pokud vychází ze zařízení skeneru v jeho okně a cíl je v rozsahu (`unexpected_traffic` je v `default_covers` skeneru). Doloženo ve světě v2 (20269801/0, cykly 144 a 145).
- **K22-N3:** zařízení skeneru může být současně kompromitované; zavření nálezu skenu pak skryje souběžnou aktivitu útočníka (příčinný omyl 20269803/2).
- **K22-N4:** v produkční cestě jsou nálezy skenu i objemů záloh téměř vždy vysoké závažnosti nebo bez zdroje; kontextová brána je tak v reálném provozu (laboratoř) i ve světě v2 prakticky nepoužitelná pro zavření. Hranice automatizace kontextu je dnes ≈ 0, ne „malá“.

## 10. Act (doporučení vedoucímu)

1. **E3 (držené seedy 20270301 až 20270310) nespouštět.** K22-1 neprošel už na ladicích seedech (brána zavřela útok z kompromitovaného skeneru); plán (1.3) pro lístek na útoku předepisuje opravu brány před E3. Držený běh by jen potvrdil známou vadu a spotřeboval držené seedy.
2. **Oprava K22-N2 a K22-N3 s vlastní předregistrací (jeden malý krok):** (i) záznam skeneru vysvětlí jen tvar skenu: `scan_attempts`, `connection_timeout_burst` a `unmapped_passive_event` s převahou neúspěšných spojení, ne `unexpected_traffic` s navázanými relacemi (zúžit `default_covers` skeneru nebo vyžadovat explicitní `covers`); (ii) zdroj skeneru nesmí mít v okně jiný otevřený nález mimo pokrytí (jinak `ambiguous`); (iii) volitelně deklarovaný profil skenu (porty, rychlost). Kritérium: ve světě v2 na ladicích seedech 0 omylem zavřených a K22-6 beze změny. Odhad ≈ 60 tis. tokenů, 1 h stroje.
3. **Rozhodnout o smyslu měření hranice kontextu (K22-N4):** při dnešních pravidlech (R2, P6, přísné doložení) nevzniká v simulaci ani v laboratoři žádný správný lístek. Nezmírňovat bránu (pravidla R2 a P6 jsou bezpečnostní minimum). Poctivý závěr pro práci: automatické zavírání kontextem je v tomto návrhu nedosažitelné bez nezávislého zdroje pozitivního důkazu u objemových nálezů (zdroj toku a nižší závažnost u plánovaných přenosů); místo dalšího soaku doporučuji sedmidenní stínový provoz laboratoře (plán 4.2), který ukáže, zda zahřátá základní linie vytvoří zavíratelné nálezy záloh.
4. **V3 (validita světa v2):** přijmout svět v2 bez úprav generátoru a hlásit V3 jako nesplněné se změřenou příčinou, nebo V3 předregistrovat znovu jako „R2 má víc vysvětlitelných záznamů než R1“; úprava generátoru kvůli V3 by byla kruhová.
5. B7 až B9 dál odložit; B9 (registr chráněných prostředků) má smysl až po bodu 2.

**Neúspěchy a omezení E2:** K22-1 nesplněn (3/4 omylem); V3 nesplněno; B6 pozitivní část nesplněna (0/124, 0/114); K22-5 bez jediné buňky; laboratoř bez objemových nálezů záloh (krátké fáze); svět v2 dál odvozuje výpadky, CMDB a senzor z pravdy; tabulka hranice počítá síťodny z 20 sítí (nástroj hlásí jen sítě se záznamem stínu); nezávislé review diffu E2 (`sol-loop`) zadání vylučuje, diff sahá na logiku brány (K22-N1) a na produkční cestu (stín), review má proběhnout v hlavní konverzaci.

## 11. Předregistrace K22-N2 a K22-N3 (zapsáno před kódem a testem)

Vedoucí po E2 schválil Act: E3 (držené seedy 20270301 až 20270310) se nespouští, brána se nezmírňuje (R2 a P6 zůstávají). Tato sekce je komitnuta před jakoukoli změnou kódu.

**Přepínač:** nové pole `GatePolicy::scanner_guard`, zapínané spolu s `ctx_host_first` (kontext v2, `GatePolicy::for_engine`). Bez přepínače (výchozí `false`) se nemění žádná cesta: K22-6 musí zůstat 48/48 a 48/48.

### 11.1 K22-N2: záznam skeneru vysvětlí jen tvar skenu

- **Změna:** pevná množina skenových typů `SCAN_SHAPED = {scan_attempts, connection_timeout_burst, unmapped_passive_event}` (typy, které vznikají ze samotného sondování portů; `unexpected_traffic` je navázaný provoz, tedy ne tvar skenu). S `scanner_guard` pokrývá záznam `AuthorizedScanner` typ jen tehdy, když ho pokrývá podle `covers` (nebo `default_covers`) **a zároveň** typ leží v `SCAN_SHAPED`; explicitní `covers` množinu rozšířit nesmí. Platí pro vysvětlení (`explain_decision`) i podporu žebříku (`supporting_context`). Ostatní druhy kontextu beze změny.
- **Kritéria (předem):** (1) test: s přepínačem `unexpected_traffic` ze zdroje skeneru na cíl v rozsahu se nevysvětlí ani nepodpoří, i když ho záznam uvádí explicitně v `covers`; `scan_attempts` se dál vysvětlí a doloží; rekonstrukce případu 20269801/0 (cykly 144 a 145) bez lístku. (2) property test (≥ 5 000 náhodných kalendářů se skenerem i bez, typy, závažnosti, zdroje, cíle): s přepínačem žádné vysvětlení ani podpora druhu skeneru pro typ mimo `SCAN_SHAPED`; pro typy v `SCAN_SHAPED` a pro kalendáře bez skeneru je rozhodnutí s přepínačem a bez něj totožné (bez zaznamenané cizí aktivity); bez `host_first` přepínač nic nemění.

### 11.2 K22-N3: zavření skenu nesmí skrýt souběžnou aktivitu zdroje

- **Změna:** volající před rozhodováním cyklu zaregistruje v bráně všechny nálezy cyklu (`ContextGate::note_activity`: typ, zdroje, identifikátory hostu, cíle, čas); brána drží aktivitu posledních 48 h. S `scanner_guard` záznam skeneru `E` se zdrojem `S` nález nevysvětlí ani nepodpoří, když v okně `E` existuje zaznamenaná aktivita `A`, které se `S` účastní (je ve zdrojích, hostu nebo cílech `A`) a kterou by `E` sám nepokryl (typ mimo pokrytí podle 11.1, některý zdroj `A` není zdrojem skeneru, nebo cíl `A` mimo rozsah). Rozhodnutí je pak nejednoznačné (P5 → případ zobrazen člověku) s důvodem `skener: soubezna aktivita zdroje mimo pokryti zaznamu`; důvod jde do paměti (produkční cesta) a do stínu (soak, čítač `k22_scanner_foreign`).
- **Kritéria (předem):** (3) test: zdroj skeneru má v okně jiný nález mimo pokrytí (např. `c2_beacon` nebo `unexpected_traffic` se zdrojem `S`) → `scan_attempts` ze `S` nevysvětlen, nejednoznačný, s důvodem; zdroj skeneru jako cíl jiné aktivity → totéž; aktivita mimo okno záznamu nebo jiného zařízení → rozhodnutí beze změny; pořadí registrace nálezů v cyklu výsledek nemění. (4) ladicí seedy E2 (20269801 až 20269805, svět v2, `off`, 4 sítě, 168 h, se stínem), ramena F2c a FG2 znovu s novou binárkou, F2 z E2 jako základ (bez `ctx_host_first`, přepínač vypnut, kód beze změny): **0 omylem zavřených** (cf ani příčinně) ve FG2 i F2c, konkrétně 20269801/0 cykly 144 a 145 a 20269803/2 cyklus 170 bez zavření; K22-2 (detekce ne nižší než F2, žádná rodina o > 1 p. b. níž), K22-3 (FP FG2/F2 ≤ 1,01), K22-4 hlášeno. Pokud C2 aktivita kompromitovaného skeneru v 20269803/2 nevytvořila nález se zdrojem `S`, N3 ji z principu vidět nemůže: hlásí se jako neúspěch s příčinou (mez detekce), brána se kvůli tomu neupravuje. (5) K22-6: `reg4` 48/48 a `regsh4` 48/48 shodných sítí s `F:\work-tmp\k21\reg`. (6) `cargo test --lib` bez nových selhání, `fmt` a `clippy` čisté ve změněném kódu.
- **Laboratoř C se znovu nespouští:** N2 a N3 lístky jen ubírají a laboratoř nevydala žádný (8.3); výsledek B6 se tím nemůže změnit.
- **Omezení (předem):** produkční cesta zná jen nálezy aktuálního běhu (aktivita z dřívějších běhů v okně se neuchovává); záznam delší než 48 h vidí jen posledních 48 h aktivity.

### 11.3 K22-N4: jen analýza

Rozbor, kdo přiděluje nálezům záloh, dávek a skenu závažnost a zdroj (kód, ne výsledek brány); návrh opravy s měřením na ladicích seedech se jen zapíše, pravidla ani závažnosti se nemění.
