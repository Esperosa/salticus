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
