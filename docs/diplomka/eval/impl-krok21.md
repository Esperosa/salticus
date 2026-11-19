# Krok 21: nezávislá adversariální kontrola jádra

Datum zahájení 2026-11-19. Výchozí stav: konec kroku 20 (`5857c97`, rozhodování shodné s `fb1546c`). Zadání: `F:\work-tmp\briefs\krok21-nezavisla-kontrola.txt`. Závazný rozsah: `docs/diplomka/rozsah-autonomie.md`. Registr nálezů a rozhodnutí: `rozhodnuti-jadra.md`.

Úloha kroku: bránu zavření (`src/closure_gate.rs`) a závěry auditu (`audit-jadra.md`, `impl-krok20.md`) zpochybnit, ne potvrdit. Kontrolu dělá jiná instance než autor brány; nezávislost je omezená tím, že jde o tentýž model se stejnými podklady (viz sekce 6).

## 1. Metoda

1. Mapa cest k zavřenému nebo skrytému stavu znovu od nuly: grep všech zápisů `FindingState` a všech volajících `FindingMemory` (ne převzetí tabulky C1 až C14).
2. Sondy jako testy proti **pravdivému invariantu** R1 a R2 na úrovni klíče a v čase, ne proti tomu, co brána kóduje: `src/closure_gate/probes_k21.rs`, `verify_ladder::tests::audit_k21_*`. Fuzz se stínovým modelem (vlastní orákulum: byl klíč kdy High, byl v aktivním životě chráněný, byl podezřelý), s restarty (flush a načtení z SQLite) a s rozhodnutími žebříku, která nesou vysoký dopad a ochranu z prvního otevření případu (tak, jak je žebřík skutečně vydává).
3. Opravy jen tam, kde je příčina jasná a oprava malá, s testem, jen v režimu brány nebo bezpečným směrem.

## 2. Výsledek sond před opravou (2026-11-19, výstup `F:\work-tmp\k21\probe-before-fix.out`)

| sonda | výsledek | nález |
|---|---|---|
| `audit_k21_merge_keeps_stale_high_impact_and_protection` | potvrzeno: druhé `Ladder::open` téhož klíče jen slučuje zdroje, `high_impact` a `protected` zůstanou z prvního otevření, rozhodnutí je nese a `admit_ladder` ho přijme | N1, N2 |
| `k21_severity_escalated_key_is_not_refuted` | **selhalo**: klíč eskalovaný na High se vyvrátí (lístek vydán) | N1 |
| `k21_context_does_not_resolve_key_seen_high` | **selhalo**: kontext automaticky vyřeší klíč, který byl dřív High, když je aktuální výskyt Low | N1 |
| `k21_protection_signal_after_open_blocks_refute` | **selhalo**: signál P4/P5 po otevření případu vyvrácení nezastaví | N2 |
| `k21_suspicion_lock_survives_restart` | **selhalo**: `suspected` se do SQLite neukládá, po načtení je zámek pryč a vyvrácení projde | N3 |
| `k21_shield_survives_restart` | **selhalo** (totéž pro ochranu) | N2, N3 |
| fuzz 5 000 posloupností, pravdivý invariant | **selhalo**: 941× klíč s High zavřen, 559× chráněný klíč zavřen, 391× podezřelý klíč zavřen; 0× zavřeno bez pozitivního důkazu | N1 až N3 |
| `known_gap_ticket_is_not_persisted_closure_lasts_one_run` | potvrzeno: produkce načítá paměť v každém běhu, lístek se neukládá, vyvrácení platí jeden běh | N4 |
| `known_gap_concurrent_runs_lose_confirmation` | potvrzeno: dva běhy nad touž databází, pozdější zápis přepíše `confirmed`, po načtení `closed` | N5 |
| `known_gap_lying_agent_allowlist_plus_history_passes_gate` | potvrzeno: lhoucí agent („seznam povolených“) + historie = lístek | N6 |
| `known_gap_ticket_is_not_bound_to_key` | potvrzeno: lístek jednoho nálezu zavře jiný klíč (jen API; `settle` je konzistentní) | N7 |
| `known_gap_clock_jump_forward_drops_lock` | potvrzeno: skok hodin > 24 h uzavře klidem i podezřelý klíč, zámek padá | N8 |

Invariant kroku 20 (K20-5) tedy platil jen pro generátor, který vysoký dopad a ochranu vázal na klíč napevno a nikdy nerestartoval; pravidlo R1 v užším smyslu (zavřít jen s pozitivním důkazem) sondy neporušily.

## 3. Dodatek: opravy (předregistrováno před kódem)

Všechny opravy platí **jen v režimu brány** (`MemoryConfig::gate`, přepínač `close_gate`); bez něj se chování nemění (K21-6). Směr je vždy bezpečný: méně zavření, nic se nezavírá navíc.

- **O1 (N1, R2 na úrovni klíče):** paměť v režimu brány nezavře klíč, jehož `max_severity` je High, ani výskyt s High (kontext ani žebřík); zavřený klíč takový výskyt nepohltí. `gate_violations` hlásí zavřený klíč s High.
- **O2 (N2):** položka paměti dostane příznak `shield`, nastavený výskytem se signálem ochrany (`Observation::protected`) v režimu brány; klíč se štítem se nezavře a zavřený klíč výskyt se signálem ochrany nepohltí (eskalace). Štít padá spolu se zámkem podezření při zavření klidem (TTL). `gate_violations` hlásí zavřený klíč se štítem.
- **O3 (N3):** `suspected` a `shield` se ukládají do SQLite (schéma 2, migrace `ALTER TABLE ... DEFAULT 0` ze schématu 1). Lístek se dál **neukládá** (uložení by prodloužilo zavření, tedy nebezpečný směr; jen návrh, sekce 5).

Testy: sondy N1 až N3 a fuzz pravdivého invariantu musí po opravě projít; `known_gap_*` zůstávají (popisují neopravené mezery). Celý `cargo test --lib` bez nových selhání.

## 4. Předregistrace měření (zapsáno před během)

Opravy mění rozhodování jen v režimu brány, a to jen u klíčů, které byly High nebo chráněné nebo podezřelé; měří se proto jen tam, kde to ověří, že oprava neporušila kritéria kroku 20.

- **K21-6 regrese bez přepínače:** nová binárka, rameno R a F (bez `close_gate`), ladicí seedy 20269701 a 20269703, 3 konfigurace, 4 sítě: `networks.jsonl` shodný s krokem 20 (`F:\work-tmp\k20\reg`, `F:\work-tmp\k20\tune`) ve všech polích kromě časů.
- **Nové držené seedy (zapsáno dopředu, použít jednou): 20270201, 20270202, 20270203, 20270204, 20270205, 20270206, 20270207, 20270208, 20270209, 20270210.** Ramena: **F** (`final`), **FG20** (`final` + `close_gate`, binárka kroku 20 `salticus-k20-fb1546c.exe`), **FG21** (totéž, nová binárka). Konfigurace `off`, `ops`, `elying` a společné volby jako v kroku 20. Seed se sítí nad 2 h se vynechá ve všech ramenech a zapíše. RG se neměří (nebylo navrženo do presetu; zůstává neověřené).
- **Doplněno před během (otevřený bod 2, soak vs. produkce):** rameno **FG21P** = FG21 s proměnnou prostředí `K21_FIXED_PRIOR=1` (soak dá případu pevnou apriorní P 0,15 jako `pipeline/v3.rs`, naučené LR zůstávají). Měří, zda výsledek brány závisí na naučené apriorní P, kterou produkce nemá. Hlásí se K21-1 až K21-4 proti F (bez prahu pro rozhodnutí o presetu; jen diagnostika rozdílu).
- Žádné ladění; po drženém běhu se kód nemění.

| práh | metrika | splněno, když |
|---|---|---|
| K21-1 | omylem zavřené (definice kroku 19), útoky s omylem zavřeným nálezem, útoky s pohlceným výskytem | FG21 0 ve všech konfiguracích; Wilson 95 % |
| K21-2 | detekce po rodinách a souhrnná (FG21 vs. F) | jako K20-2 |
| K21-3 | zobrazené FP (FG21 vs. F) | poměr ≤ 1,02 |
| K21-4 | případy pro člověka (FG21 vs. F) | nárůst ≤ 2 % |
| K21-5 | invariant | fuzz pravdivého invariantu (5 000 posloupností s restarty) 0 porušení; K20-5 dál 0 |
| K21-7 | účinek opravy (FG21 vs. FG20, diagnostika) | hlásí se počet vyvrácení a automatických zavření, které oprava odmítla, a změna FP; bez prahu |

### Dodatek: otevřený bod 4, příčina +3 % FP u RG (zapsáno před během)

Rozklad držených běhů kroku 20 (R vs. RG, `F:\work-tmp\k21\fp_root.py`, data `F:\work-tmp\k20\held`) zpochybňuje vysvětlení kroku 20 („cena R1 za vyvrácení na závislém důkazu“): úbytek vyvrácení se mezi konfiguracemi liší (337, 432, 411), ale přírůstek zobrazených FP je téměř stejný (+196, +205, +192) a přírůstky podle důvodu zobrazení jsou **ve všech třech konfiguracích totožné** (`first` +1 269, `escalated_source` +890/891, `reopened` +208/203/206). Jediná změna nezávislá na konfiguraci je odstranění 39 kontextových zavření (všude 39 → 0), tj. záznamy autorizovaného skeneru, které v rameni R nemají rozsah cílů, protože simulace ho dává jen se `strict_close` (audit M4).

**Hypotéza H21-FP:** většina přírůstku FP u RG pochází z nálezů autorizovaného skeneru, které brána správně odmítá zavřít, protože simulovaný záznam skeneru nemá rozsah cílů; jde o artefakt vazby simulovaného světa na přepínač enginu, ne o cenu R1 za žebřík.

**Test (kauzální, jedna proměnná):** soak dostane měřicí přepínač prostředí `K21_SCANNER_SCOPE=1` (záznam skeneru má rozsah cílů bez ohledu na `strict_close`). Ramena na nových držených seedech 20270201 až 20270210, jen konfigurace `off` (přírůstek je na konfiguraci nezávislý): **R**, **RG**, **RS** (R + rozsah), **RGS** (RG + rozsah), binárka kroku 21 s tímto přepínačem (bez proměnné prostředí shodná s `2900ad1`). Předpověď H21-FP: FP poměr RG/R ≈ 1,03 (reprodukce) a **RGS/RS ≤ 1,01**. Vyvrácení: RGS/RS ≥ 1,02 (pak je příčina jinde, nejspíš žebřík, jak tvrdil krok 20). Hlásí se i K21-1 až K21-4 pro RGS/RS.

**Předpověď pro FG21P (analyticky před během):** s bránou rozhoduje o vyvrácení hlavně pozitivní důkaz (kontext LR 0,3, seznam povolených 0,05) a druhá skupina; z apriorní P 0,15 (šance 0,176) stačí kontext + historie (0,3 × 0,25) na P 0,013 ≤ 0,03, takže pro typy s naučenou P ≤ 0,15 se výsledek nezmění. U typů s naučenou P nad 0,15 (útokem zatížené typy) bude produkce s pevnou 0,15 vyvracet **snáz** než soak, tedy nebezpečným směrem. Očekávám víc vyvrácení u FG21P než u FG21 a otázku, zda některé z nich jsou omylem zavřené útoky (K21-1 pro FG21P).

**Předpověď:** v `final` je vysoká závažnost většinou už u otevření případu (žebřík ji nese), takže O1 změní jen klíče eskalované během života; O2 jen klíče s P4/P5 signálem po otevření; O3 se v soaku projeví jen při restartech (`restart_cycles`). Očekávám změnu zobrazených FP FG21 proti FG20 pod 0,5 % a K21-1 až K21-4 splněné.

## 5. Výsledky (2026-11-19)

Běhy: `F:\work-tmp\k21\reg` (12), `held` (120), `scan` (40); všechny s kódem 0, bez paniky a porušení. Binárky `salticus-k21-2900ad1.exe` (reg, held), `salticus-k21-224ed3e.exe` (scan, stopy). Souhrny: `held_sum.py`, `scan_sum.py`, `outcomes.py` (ve `F:\work-tmp\k21`). Žádný seed nepřekročil 2 h; nic se nevynechalo.

**K21-6 regrese bez přepínače:** 48 z 48 sítí shodných s krokem 20 ve všech polích kromě časů (`cmp_reg.py`). Splněno.

**Držené seedy 20270201 až 20270210** (součty za 40 sítí na rameno a konfiguraci):

| konf. | rameno | vyvráceno (omylem cf / příčinně) | autom. zavřeno | zobrazené FP | případy pro člověka | detekce zobrazené |
|---|---|---|---|---|---|---|
| elying | F | 18 (1 / 2) | 0 | 4577 | 46284 | 2562 |
| elying | FG20 = FG21 | 0 | 0 | 4577 | 46290 | 2562 |
| elying | FG21P | 0 | 0 | 4601 | 46306 | 2564 |
| off | F | 5 (0 / 0) | 0 | 4401 | 46052 | 2558 |
| off | FG20 = FG21 | 0 | 0 | 4401 | 46057 | 2558 |
| off | FG21P | 0 | 0 | 4423 | 46074 | 2560 |
| ops | F | 1 (0 / 0) | 0 | 4463 | 46050 | 2561 |
| ops | FG20 = FG21 | 0 | 0 | 4463 | 46051 | 2561 |
| ops | FG21P | 0 | 0 | 4491 | 46074 | 2563 |

| práh | výsledek | stav |
|---|---|---|
| K21-1 | FG21: 0 omylem zavřených ve všech konfiguracích, **ale z 0 zavření** (0 vyvrácení, 0 automatických zavření); Wilsonův interval pro podíl omylů mezi zavřenými nelze spočítat (n = 0) | formálně splněno, věcně **neprokazuje hranici** (sekce 6 a) |
| K21-2 | detekce FG21 = F ve všech konfiguracích i po seedech (10/10 shod) | splněno |
| K21-3 | FP poměr FG21/F 1,000 ve všech konfiguracích | splněno |
| K21-4 | případy pro člověka +0,01 % | splněno |
| K21-5 | fuzz pravdivého invariantu 5 000 posloupností s restarty 0 porušení; K20-5 0 (`probe2.out`) | splněno |
| K21-7 | FG21 vs FG20: **shodné ve všech 120 sítích**; O1 až O3 nemají na soaku měřitelný účinek (žádné vyvrácení ani automatické zavření, které by mohly odmítnout) | diagnostika |

**FG21P (pevná apriorní P 0,15):** předpověď „víc vyvrácení než FG21“ **se nepotvrdila**: 0 vyvrácení v obou ramenech, protože s bránou se k vyvrácení nedojde vůbec (6 a). Zobrazené FP +0,5 až 0,6 % (22 až 28 na konfiguraci), případy pro člověka +16 až +23, detekce +2. Otázka soak vs. produkce pro zavírání tak zůstává **neotestovaná**; měření ukázalo jen, že produkční apriorní P mírně zvyšuje zátěž.

**Rozsah skeneru (H21-FP), konfigurace `off`:**

| rameno | autom. zavřeno (omylem) | vyvráceno (omylem cf / příčinně) | zobrazené FP | případy pro člověka | detekce zobrazené |
|---|---|---|---|---|---|
| R | 14 (14) | 1529 (7 / 41) | 4126 | 45197 | 2512 |
| RS | shodné s R ve všech 40 sítích | | | | |
| RG | 0 | 0 | 4355 | 45304 | 2509 |
| RGS | shodné s RG ve všech 40 sítích | | | | |

RG/R = 1,056 (reprodukce nárůstu FP, větší než 3 % kroku 20). **Test H21-FP selhal jako test:** manipulace nic nezměnila (RS = R, RGS = RG), takže hypotézu nepotvrdil ani nevyvrátil. Příčina je v měřicím přepínači (6 c). Náhradní kauzální rozbor (6 d) našel jinou příčinu.

## 6. Kořenové příčiny (stopy `K15_TRACE`, `F:\work-tmp\k21\trace`)

Stopy jsou deterministické opakování týchž běhů (ověřeno: R 20270206 dává 1396/2/13, 9/0/2, 6/0/0 jako běh bez stopy); seedy se jimi neladí, jen čtou. Skripty: `ladder_block.py`, `rca21.py`, `scanner_trace.py`, `fp_pair.py`, `prot_check.py`.

### a) Proč brána na držených seedech nezavře nic

Brána sama nic neodmítla: `gate_refused` = 0 a `gate_bypass` = 0 ve všech gated ramenech. K bráně se nedostane žádné vyvrácení, protože `close_gate` zapíná `strict_refute` (`engine.rs:801`) a žebřík pak vyvrací jen se dvěma nezávislými skupinami, z nichž jedna je silná (`verify_ladder.rs:1392`). Rozklad případů RG, seed 20270203 (1 600 případů):

1. **≈ 99 % případů nikdy nedosáhne P ≤ 0,03.** Eskalují s krokem `profile [nezjisteno: profil hostu jeste nezraly]` (636), `profile [... nema jednu dvojici host-cil]` (351) nebo `history [nezjisteno: historie jen N dny]` (245). Síť v soaku má 2 virtuální dny (`virtual_days` 2,0), historie a profil nedozrají. **Artefakt horizontu simulace, ne brány.**
2. **≈ 1,2 % (19 případů) má P ≤ 0,03,** ale neškodný důkaz jen z jedné skupiny: samotná živost (8 benign, 1 útok), samotná historie (7 benign, 2 útoky), peeři (1). Žebřík správně eskaluje. **Oprávněně přísné:** přesně tento vzor (jedna slabá skupina) dává všech 40 omylem vyvrácených v R (b).
3. **Pozitivní důkaz s vlastníkem (podmínka lístku) v simulaci prakticky nevzniká.** Krok kontextu je s přísným doložením zdroje vždy `undetermined` (R bez přísnosti: 86 benign z 31 000). Simulované záznamy kalendáře (`soak/v3.rs:393-457`) mají jen hosty-oběti a prázdné `sources`, takže zdroj nálezu (protistrana) v záznamu není. Záznam skeneru je bez rozsahu, nebo s prázdným rozsahem (c). Seznam povolených existuje jen v `elying` (krok endpoint benign 167 případů). Bez přísnosti jsou kontextová zavření v R **14 ze 14 omylem** (b). **Částečně artefakt simulace** (záznamy bez zdrojů, sken jen ven), **částečně oprávněně přísné.**

Chyba brány se nenašla. Podmínka, která se nikdy nesplní, je „pozitivní důkaz s vlastníkem + druhá skupina při P ≤ 0,03“. Nesplní se hlavně proto, že simulace takový důkaz pro neškodné jevy negeneruje, a ve 2denním horizontu nedozraje ani podpůrný důkaz.

### b) Omylem zavřené v R (bez brány)

| co | počet | příčina | cesta v kódu |
|---|---|---|---|
| automaticky zavřeno omylem | 13 | záznam autorizovaného skeneru **bez rozsahu cílů** zavře nález, jehož zdroj je skener, i když ze stejného zařízení nebo na stejný cíl v tomtéž cyklu běží útok (`update_channel_compromise_fleet`, `fleet_beacon`, `c2_beacon`) | `context_gate.rs:547-558` (bez `strict_close` stačí shoda zdroje); `soak/v3.rs:418-432` |
| automaticky zavřeno omylem | 1 | záznam dávkové úlohy bez doložení zdroje | `context_gate.rs:540` (bez `strict_close` se nekontroluje) |
| vyvráceno omylem (ve stopách seedů 20270203, 06, 09: 7 cf + 33 jen příčinně; souhrn běhu 7 cf a 41 příčinně, definice se překrývají) | 40 | **jediná slabá skupina** (profil 18, historie 13, historie + profil 9) a apriorní P pod mezí (medián 0,032); žádná silná skupina; typy hlavně `packet_rate_spike` (fleet_beacon, slow_scan, c2_beacon) a `service_unreachable` (slow_scan, dns_tunnel) | `verify_ladder.rs:1392` (`proven` je bez `strict_refute` vždy pravda), `:1408-1410`; potvrzuje audit K20 (`audit_k20_competing_without_strict_closes_on_prior_alone`) |

Zbývající 2 příčinně omylem vyvrácené (seed 20270207, síť 0) nejsou ve stopách; jejich rozbor je **neověřen**. Všechny rozebrané případy brána i `strict_refute` zablokují (R1: chybí pozitivní důkaz s vlastníkem, resp. silná skupina); v RG je jich 0.

### c) Proč `K21_SCANNER_SCOPE` nic nemění

Přepínač se čte (název je v binárce a `run-jobs.ps1` proměnnou nastaví) a předá se do `SimContext::for_cycle`. Rozsah se ale bere z `truth.victim_devices`. Simulovaný autorizovaný skener skenuje **cíl mimo síť** (`target_external`), takže `victim_devices` je prázdné a záznam zůstane bez rozsahu. Ani s vyplněným rozsahem by nepomohl: host nálezu je brána (`10.37.38.1`), ne cíl, a `hosts` záznamu se porovnává s hostem nálezu (`context_gate.rs:550`). Test `known_gap_scanner_scope_does_not_match_finding_host_of_egress_scan` (K21-N13). **Chybná implementace měřicího přepínače i sémantiky rozsahu**, ne nespuštění.

### d) +3 až 5,6 % zobrazených FP u `recommended()` + brána

Párování nálezů R vs RG ze stop (seed 20270208, síť 0: 0 vyvrácení v obou ramenech, FP 99 → 158): RG navíc zobrazí 164 nálezů bez útoku v okně, z toho 162 `connection_timeout_burst`. V R jsou skryté do ověření (`verifying`), v RG mají `protected = true` a zobrazí se hned jako `first` (`episode.rs:1975`). Příčina: `close_gate` zapne `GatePolicy::strict_close` (`context_gate.rs:274`). V `explain_decision` se doložení zdroje kontroluje **před** shodou hostu (`:540` vs `:547`). Aktivní záznam, který typ pokrývá, ale týká se **jiného hostu**, proto nastaví `ambiguous = true`, a to se s `protect` stane signálem P5 (`episode.rs:1850`). Test `known_gap_strict_close_flags_ambiguous_from_other_host_record` (K21-N14).

Vysvětlení kroku 20 („cena R1 za vyvrácení na závislém důkazu“) je tím **vyvráceno jako hlavní příčina**: nárůst nastává i v sítích bez jediného vyvrácení a je na konfiguraci nezávislý, protože záznamy kontextu jsou ve všech konfiguracích stejné. Hypotéza H21-FP (skener bez rozsahu) je **nepotvrzená** (6 c). Na seedu 20270206 (1 396 vyvrácení v R) přispívá i ztráta vyvrácení (`escalated_source` +452). Podíl obou příčin na celku **není kvantifikován**. `final` má `strict_close` také, proto FG = F ve FP.

### e) Tichý dedup otevřeného klíče a f) soak vs. produkce

Nové měření nepřibylo; stav a návrh v `rozhodnuti-jadra.md` 4.1 a 4.2. FG21P (pevná apriorní P) test zavírání neumožnil (viz výše).

## 7. Co se nepodařilo a co zůstává neověřené

- **„0 omylem zavřených“ s bránou nastává zavřením ničeho.** Měřená hranice automatizace s bránou neexistuje; krok 21 neprokázal, že brána umí správně zavřít případ s pozitivním důkazem, protože v simulaci takový případ nevznikl.
- O1 až O3 jsou ověřeny jen sondami a fuzzem, ne soakem (K21-7: žádný rozdíl, protože nebylo co odmítnout).
- H21-FP neotestována (chybný přepínač); FG21P neotestovala zavírání.
- N14 a N13 nejsou opraveny: oprava N14 mění zobrazení i v `final` (`strict_close` bez brány), takže by porušila K21-6. Ověřit ji jde jen na nových držených seedech. Je jen navržena (`rozhodnuti-jadra.md` 6).
- `cargo test --lib`: 690 prošlo; selhává 5 testů `broker::tests` (stejně v běhu před změnou, `tlib.out`, vyžadují Redis) a 1 `identity_lab` (vyžaduje běžící Docker, samostatně selže při startu sítě). Nesouvisí s krokem.
- Review: zadání kroku zakazuje council a sol-loop; nezávislost kontroly je omezená (týž model, stejné podklady).
