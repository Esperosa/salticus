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
