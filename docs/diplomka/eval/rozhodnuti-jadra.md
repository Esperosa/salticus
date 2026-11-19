# Registr nálezů a rozhodnutí jádra (zavírání nálezů)

Založeno 2026-11-19 v kroku 21 (`impl-krok21.md`). Pokrývá nálezy forenzního auditu kroku 20 (`audit-jadra.md`: cesty C1 až C14, matice M1 až M19), rozhodnutí kroků 15 až 20 a vlastní nálezy kroku 21 (N1 až N12). Řádky se nemažou; změna stavu se připisuje s datem.

**Stav ověření:**
- **ověřeno nezávisle** = v kroku 21 znovu přečten kód na uvedeném místě nebo napsán vlastní test či měření (ne převzetí tvrzení ani testu autora);
- **z auditu převzato** = tvrzení a důkaz pochází z kroku 20, v kroku 21 se znovu neprověřovalo;
- **neověřeno** = tvrzení bez důkazu kódem nebo během.

Odkazy na řádky platí pro commit `2900ad1` (krok 21). „Sonda“ = test v `src/closure_gate/probes_k21.rs`, pokud není uvedeno jinak.

## 1. Cesty k zavřenému nebo skrytému stavu (audit C1 až C14)

Kontrola úplnosti mapy (krok 21): grep všech zápisů `FindingState::AutoResolved`/`Refuted` a všech volajících `FindingMemory` v `src/`. Stav paměti mění jen `finding_memory.rs`; volající jsou `pipeline/v3.rs`, `soak/episode.rs`, `soak/v3.rs`, `closure_gate.rs` a testy. `retro.rs`, `reassess.rs`, `case_memory.rs`, `case_folder.rs`, `server.rs`, `analyst_feedback.rs` stav paměti nemění (nevolají ji). Přímý SQL zápis do `finding_state` mimo `finding_memory.rs` neexistuje. Mapa auditu je tedy úplná co do míst zápisu; doplněny jsou časové a procesní cesty (N3, N5, N8, N9).

| ID | tvrzení auditu | důkaz | stav ověření | odmítnuté alternativy | riziko (po kroku 21) |
|---|---|---|---|---|---|
| C1 | kontext zavře nový i existující klíč; bez `strict_close` stačí jeden zdroj v záznamu, skener bez rozsahu vysvětlí vše | `finding_memory.rs` `observe_inner` (větev `None` a `(_, Some(reason), None)`), `context_gate.rs:321` `strictly_proven` (skener bez hostů = nedoloženo) | ověřeno nezávisle (čtení) | — | s bránou nízké: `admit_context` vyžaduje vlastníka, expiraci, doložené zdroje; bez brány trvá |
| C2 | žebřík vyvrací bez `strict_refute` na libovolný výsledek s LR < 1 | `verify_ladder.rs:1392` (`proven = !strict_refute || …`), `:1423` | ověřeno nezávisle (čtení); sonda autora `audit_k20_dependent_or_groupless_evidence_alone_refutes_without_strict` převzata | — | s bránou: `admit_ladder` vyžaduje pozitivní důkaz s vlastníkem a 2 skupiny; zbytková rizika N1, N2, N6, N12 |
| C3 | konkurenční režim zavře z apriorní P bez neškodného výsledku | `verify_ladder.rs:1402` (`CloseBenign if !shielded && proven`, žádná podmínka na `benign_evidence`) | ověřeno nezávisle (čtení) | — | s bránou zachyceno `admit_ladder` (žádný pozitivní důkaz = odmítnuto) |
| C4 | vyvrácený klíč tiše pohltí další výskyt | `observe_inner`, `(S::Refuted, _, None) => Suppressed` | ověřeno nezávisle (čtení, sonda `closed_key_absorbs_only_continuous_episode_with_ticket_sources` autora prošla i po opravě) | trvalé pohlcení (před krokem 15) | s bránou jen souvislá epizoda se zdroji z lístku; od kroku 21 ne výskyt s High ani se signálem ochrany |
| C5 | výskyt v platném kontextu zůstane vyřešený | `observe_inner` `(_, Some(reason), None)` | ověřeno nezávisle (čtení) | — | jako C1 |
| C6 | soak skryje nový nález „verifying“ do rozhodnutí; trvale, když případ nevznikl | `soak/episode.rs` (blok `if runtime.ladder.open(...)`, `shown_item.reason = "verifying"`), `verify_ladder.rs:1054` (`open` vrací `false` při sloučení i stropu) | ověřeno nezávisle (čtení); doplněno: skrytí platí **i s bránou** (není to zavření, brána ho neřeší) | — | jen soak; produkce zobrazuje hned → soak podhodnocuje zobrazení proti produkci, pokud se dosáhne stropu 5 000 případů (ve stopách nedosaženo, z auditu) |
| C7 | otevřený klíč pohltí nový výskyt bez eskalace | `observe_inner` `(_, None, None) => (Open, Suppressed)`; sonda `known_gap_open_key_absorbs_new_episode_silently` (odmlka 6 h, týž zdroj → `Suppressed`) | ověřeno nezávisle (sonda) | `redisplay`, `redisplay_age` (vypnuté) | **otevřené**, viz sekce 4.1 |
| C8 | TTL 24 h zavře aktivní klíč, retence 7 dní smaže | `sweep` | ověřeno nezávisle (čtení); doplněno N8: TTL ruší i zámek podezření a štít | — | bezpečný směr pro zobrazení, ale zámek padá (N8) |
| C9 | strop 50 000 klíčů vyřadí 10 % | `ensure_capacity` | ověřeno nezávisle (čtení); doplněno N9 | — | N9 |
| C10 | `reset_protected` | `reset_protected`, `observe_inner` (štít) | ověřeno nezávisle (čtení) | — | bezpečný směr |
| C11 | `ops_class` odkloní nález do fronty provoz | soak | z auditu převzato | — | mimo `final`; návrh smazat (audit sekce 4) |
| C12 | `held` 48 cyklů | `verify_ladder.rs:1471` (`held_refute`) | ověřeno nezávisle (čtení) | — | s bránou nahrazeno `suspected` v paměti; od kroku 21 přežije restart (O3) |
| C13 | audit uzavření jen v produkci | `pipeline/v3.rs:484–534`; v soaku volání `closure_audit` chybí | ověřeno nezávisle (čtení produkce); soak z auditu převzato | — | soak neměří fail-safe auditu |
| C14 | člověk `close`, `reopen`, `confirm` | grep: `FindingMemory::close/reopen` volají **jen testy**; `confirm` volá jen žebřík (`settle`, `pipeline/v3.rs:914`, `soak/episode.rs`) | **ověřeno nezávisle; oprava tvrzení auditu:** ruční cesta v produkci neexistuje (žádné API ani CLI); rozhodnutí člověka jdou do `closure_audit` a `case_memory`, ne do stavu paměti | — | člověk nemůže klíč potvrdit (a tím zamknout) ani znovu otevřít; zámek tak vzniká jen z žebříku |

## 2. Matice přepínačů (audit M1 až M19)

| ID | tvrzení | důkaz | stav ověření | odmítnuté alternativy | riziko / stav |
|---|---|---|---|---|---|
| M1 | `endpoint_weak` bez `strict_refute` mrtvý | sonda autora `audit_k20_endpoint_weak_is_inert_without_strict_refute`; `verify_ladder.rs:1392` | z auditu převzato (sonda), čtením potvrzeno, že skupiny čte jen `proven` | — | v režimu brány bez významu (brána skupiny počítá sama) |
| M2 | `refute_episode` bez `strict_close` převádí tiché pohlcení na počítaná vyvrácení | stopy kroku 20 | z auditu převzato | — | v režimu brány zahrnuto (epizoda 1 h) |
| M3 | `confirm_evidence`: dva zdroje pravdy o podezření | `finish`, `refute` | ověřeno nezávisle (čtení); s bránou jeden zdroj (`Entry::suspected`) | — | před krokem 21 se `suspected` neukládal (N3), opraveno O3 |
| M4 | `strict_close` mění 4 věci a vstup simulace (rozsah skeneru) | `engine.rs:854–855` (`escalate_first_source`, `reopen_stale`), `soak/episode.rs` volání `SimContext::for_cycle(.., strict_close)`, `soak/v3.rs:421` | ověřeno nezávisle (čtení) | — | **pravděpodobná hlavní příčina +3 % FP u RG** (H21-FP, sekce 4.4); měřeno v kroku 21 |
| M5 | `context_guard` se `strict_close` mrtvý | `GatePolicy::admits` | z auditu převzato | — | redundance |
| M6 | `sensor_strict` + `protect` redundantní | `admits` | z auditu převzato | — | redundance |
| M7 | `reopen_stale` (24 h) a `refute_episode` (1 h) řeší totéž | `observe_inner` (dvě po sobě jdoucí podmínky) | ověřeno nezávisle (čtení) | — | redundance |
| M8 | `ops_class` vs. `ops_annotate` | soak | z auditu převzato | — | mimo `final` |
| M9 | seznam povolených = dvě skupiny {1, 4} | `verify_ladder.rs:1341–1346` | ověřeno nezávisle (čtení); v bráně jedna skupina 4 (`closure_gate.rs` `positive`/`supporting`) | — | zbývá N6 (lhoucí agent) |
| M10 | apriorní P: soak naučená, produkce 0,15 | `soak/episode.rs` (`learned_prior`), `pipeline/v3.rs:750` (`DEFAULT_PRIOR`) | ověřeno nezávisle (čtení); měřeno ramenem FG21P (sekce 4.2) | — | viz 4.2 |
| M11 | uložený žebřík neobnoví `strict_refute`, `competing`, `l7` | `pipeline/v3.rs:544–589` | ověřeno nezávisle (čtení): s bránou se `strict_refute` vynutí (ř. 587), `competing` a `l7` se z konfigurace neobnoví nikdy; `strict_close` bez brány v běžící instalaci žebřík nezpřísní | — | otevřené (4.2) |
| M12 | `LifecycleRecord` se zapisuje před žebříkem | `pipeline/v3.rs:759` (smyčka nálezů) vs. `:836` (`ladder.step`) | ověřeno nezávisle (čtení) | — | otevřené (4.2) |
| M13 | soak ignoruje návrat `memory.refute` | `soak/episode.rs` (`memory.refute(...)` bez kontroly) | ověřeno nezávisle (čtení); s bránou `settle` vrací skutečný výsledek | — | jen bez brány |
| M14 | tichá 0,15 ve složce otevřených případů, jiný klíč | `pipeline/v3.rs` ř. ~1094–1106 (krok 20) | z auditu převzato | — | otevřené |
| M15 | `PROTECTED_TYPES` dvakrát | `protection.rs` | z auditu převzato | — | duplicita |
| M16 | chráněné prostředky (hosty) v kódu nejsou | `closure_gate::Subject` má jen `protected`, `high_impact`; grep bez registru hostů | ověřeno nezávisle (čtení) | — | otevřené (4.3) |
| M17 | metrika K19 počítá rozhodnutí, ne útoky, a nevidí pohlcení | `tools/k20_gate.py` doplnil úroveň útoků | z auditu převzato | — | vyřešeno metrikami K20-1b/1c |
| M18 | = C3 | | ověřeno nezávisle | | |
| M19 | `case_folder` bez `case_files` v soaku | soak dump | z auditu převzato | — | nekonzistence měření |

## 3. Rozhodnutí kroků 15 až 20

| ID | rozhodnutí | důkaz | stav ověření | odmítnuté alternativy | riziko |
|---|---|---|---|---|---|
| D15-1 | opravy kroku 15 jen za přepínači, nic do `recommended()` | `impl-krok15.md` ř. 3, 28 | z auditu převzato | rovnou měnit preset | — |
| D15-2 | návrh zapnout `endpoint_weak` a `refute_episode` | `impl-krok15.md` ř. 181 | **vyvráceno krokem 20** (M1 mrtvý bez `strict_refute`, M2 zhoršuje počítaná vyvrácení) | — | návrh neplatí |
| D15-3 | `upload_horizon`, `ops_symptoms`, `ops_blast` nezapínat | `impl-krok15.md` ř. 141, 155 | z auditu převzato | — | kandidáti na smazání |
| D16-1 | případová složka `case_folder` jako čistá funkce, přepínač vyžaduje `case_files` | `impl-krok16.md` | z auditu převzato | rozšířit `case_file` | M19 |
| D16-2 | K16-4 nesplněno (potvrzení bez důkazu) → krok 18 | `impl-krok16.md` ř. 70 | z auditu převzato | — | — |
| D17-1 | vlastní Docker laboratoř místo veřejných datasetů s osobními údaji | `impl-krok17.md` | z auditu převzato | veřejné DoH/tunel datasety (formulář s osobními údaji) | reprezentativnost laboratoře |
| D18-1 | `confirm_evidence`: potvrzení jen s nezávislým podezřelým důkazem; návrh do presetu | `impl-krok18.md` ř. 117, 129; `verify_ladder.rs:1468` | ověřeno nezávisle (čtení `finish`) | potvrzovat z apriorní P | v režimu brány zámek `suspected` (N3 opraveno) |
| D19-1 | `recommended()` beze změny | `impl-krok19.md` ř. 75 | z auditu převzato | kandidát R + 3 přepínače | — |
| D20-1 | jediná brána `close_gate`, výchozí vypnuto | `closure_gate.rs`, `impl-krok20.md` | ověřeno nezávisle (čtení, sondy) | víc přepínačů na kombinace | **invariant K20-5 platil jen pro generátor autora** (N1 až N3) |
| D20-2 | lístek se do SQLite neukládá (bezpečný směr) | `finding_memory.rs` `load` (`ticket: None`), `reset_unticketed` | ověřeno nezávisle (sonda `known_gap_ticket_is_not_persisted_closure_lasts_one_run`) | ukládat lístek | **N4:** v produkci vyvrácení platí jen jeden běh; soak tohle neměří |
| D20-3 | „vlastník“ = schvalovatel záznamu nebo položky seznamu povolených, rozpoznaný z textu kroku | `closure_gate.rs` `positive`, `after` | ověřeno nezávisle (čtení) | strukturované pole vlastníka v `StepNote` | N10 (vazba na formát textu), N6 |
| D20-4 | navrhnout `final` + `close_gate`; RG ne (FP +3 %) | `impl-krok20.md` sekce 5 | z auditu převzato (čísla); **vysvětlení FP zpochybněno** (H21-FP) | — | viz 4.4 |
| D20-5 | `recommended()` se nemění, po drženém běhu kód beze změny | `impl-krok20.md` | ověřeno (git log: po `fb1546c` jen dokumentace) | — | — |

## 4. Otevřené body (kořenová příčina, návrh, riziko)

### 4.1 Tichý dedup otevřeného klíče (C7)

**Kořenová příčina:** identita nálezu je klíč (entita | typ | služba) a otevřený stav nemá pojem epizody. Eskalace jen při vyšší závažnosti, novém zdroji nebo objemu ×4; `refute_episode` (1 h) se uplatní jen u zavřeného klíče. Útok, který se po odmlce objeví pod týmž otevřeným klíčem se stejným zdrojem, je pro paměť pokračováním staré události (sonda `known_gap_open_key_absorbs_new_episode_silently`). Klíč přitom zůstává otevřený ve frontě, ale nový výskyt se nezobrazí a nejde do žebříku.

**Návrh (pořadí 2):** sloučit `redisplay` a `redisplay_age` do jednoho pravidla epizody pro všechny stavy: výskyt po odmlce ≥ `episode_s` (shodně 1 h) je `Escalation::Episode` i u otevřeného klíče (zobrazí se a jde do žebříku). Měření: K20-2 a K20-3 proti F na nových držených seedech; očekávaný nárůst FP u periodických neškodných jevů (zálohy, aktualizace s mezerou > 1 h).

**Riziko:** nárůst FP a zátěže člověka; bez dedupu podle epizody ale zůstává slepé místo pro opakované útoky (krok 20: 2 poklesy rodin u RG).

### 4.2 Soak vs. produkce

**Kořenová příčina:** dvě kopie orchestrace (`soak/episode.rs`, `pipeline/v3.rs`). Konkrétní rozdíly ověřené v kroku 21:

1. apriorní P: soak naučená, produkce pevná 0,15 (M10); měřeno ramenem FG21P (`impl-krok21.md`);
2. produkce načítá paměť z SQLite v **každém běhu**, lístek se neukládá → vyvrácení a automatické vyřešení platí jeden běh, další výskyt je `Reopened` a zobrazí se (N4); soak paměť mezi cykly drží (načítá ji jen při `restart_cycles`), takže zobrazené FP v produkci s bránou budou vyšší, než soak měří;
3. uložený žebřík: `competing` a `l7` se nikdy neobnoví z konfigurace, `strict_refute` jen s bránou (M11);
4. `LifecycleRecord` (zobrazeno, stav) se zapisuje před žebříkem (M12);
5. lístek není svázán s klíčem (N7) a `CloseTicket` má `Deserialize`, takže „vzniká jen v bráně“ není vynuceno typem (N11).

**Návrh (pořadí 1):** jedna sdílená funkce cyklu (paměť → kontext → žebřík → `settle` → zobrazení) volaná ze soaku i produkce; produkce i soak se stejnou apriorní P (podle výsledku FG21P); lístek ukládat do SQLite s podpisem (HMAC s tajemstvím, které už má `closure_audit`), aby zavření v produkci platilo stejně dlouho jako v soaku, a zápis do DB nevyrobil platný lístek. Soak má mít režim „restart každý cyklus“ jako kontrolu produkčního chování. Měření: shoda výstupu sdílené funkce se současným soakem (K20-6 obdoba) a FG s restartem každý cyklus.

**Riziko:** uložení lístku prodlužuje zavření (nebezpečný směr), proto až se sdílenou funkcí a měřením; podpis řeší podvržení, ne chybu v bráně.

### 4.3 Chráněné prostředky (hosty)

**Kořenová příčina:** R2 je v kódu implementováno jen jako chráněné typy (P1 až P3), signály P4/P5 a vysoký dopad podle závažnosti nebo typu; inventář nemá atribut kritičnosti a `closure_gate::Subject` nemá hosta (M16, ověřeno čtením).

**Návrh (pořadí 4):** registr `protected-assets.json` se stejnými pravidly jako kalendář kontextu (asset ID a adresy, vlastník, důvod, expirace; odmítnutí bez vlastníka); `Subject.protected |= host ∈ registr` v obou branách; v paměti nastaví štít (O2), takže klíč chráněného hostu se nezavře ani po změně role. V simulaci role řadiče domény, souborového serveru a zálohovacího serveru jako chráněné, aby šla změřit cena (FP, zátěž člověka). Nejednoznačná identita (P5) musí chránit všechny kandidáty.

**Riziko:** neúplný registr dává falešný pocit ochrany; víc případů pro člověka.

### 4.4 Příčina +3 % zobrazených FP u `recommended()` + brána

**Tvrzení kroku 20:** cena R1 a R2 (zmizí 337 až 432 vyvrácení na závislém důkazu). **Stav: zpochybněno** rozkladem `F:\work-tmp\k21\fp_root.py` (sekce Dodatek v `impl-krok21.md`): přírůstek FP i přírůstky podle důvodu zobrazení jsou na konfiguraci nezávislé, ač úbytek vyvrácení závislý je; konfiguračně nezávislá je jen ztráta 39 kontextových zavření skeneru bez rozsahu (M4). Hypotéza H21-FP a její kauzální test (ramena R, RG, RS, RGS) jsou předregistrovány; výsledek v `impl-krok21.md` sekce 5.

## 5. Vlastní nálezy kroku 21

| ID (datum) | nález | důkaz | stav ověření | odmítnuté alternativy | riziko | stav |
|---|---|---|---|---|---|---|
| K21-N1 (2026-11-19) | R2 platila pro rozhodnutí, ne pro klíč: případ otevřený jako Low a pak eskalovaný na High se vyvrátí (žebřík při sloučení `open` nemění `high_impact`); kontext vyřeší klíč dřív pozorovaný s High | `verify_ladder::tests::audit_k21_merge_keeps_stale_high_impact_and_protection`; sondy `k21_severity_escalated_key_is_not_refuted`, `k21_context_does_not_resolve_key_seen_high` (před opravou selhaly) | ověřeno nezávisle | opravit sloučení v žebříku (mění rozhodování i bez brány, K21-6 by neplatilo) | vysoké (porušení R2) | **opraveno O1** (`2900ad1`): v režimu brány se klíč s `max_severity` High nezavře |
| K21-N2 (2026-11-19) | signál ochrany P4/P5, který přijde po otevření případu, vyvrácení nezastaví | sonda `k21_protection_signal_after_open_blocks_refute` | ověřeno nezávisle | totéž | vysoké (R2) | **opraveno O2** (štít `Entry::shield`) |
| K21-N3 (2026-11-19) | zámek podezření se neukládá; produkce načítá paměť v každém běhu, takže v produkci zámek nefungoval vůbec | sonda `k21_suspicion_lock_survives_restart`; `pipeline/v3.rs:481` | ověřeno nezávisle | — | vysoké v produkci | **opraveno O3** (schéma 2) |
| K21-N4 (2026-11-19) | lístek se neukládá → v produkci zavření platí jeden běh | sonda `known_gap_ticket_is_not_persisted_closure_lasts_one_run` | ověřeno nezávisle | ukládat lístek bez podpisu | bezpečný směr pro R1, ale soak neměří produkční FP | otevřené (4.2) |
| K21-N5 (2026-11-19) | dva souběžné běhy nad jednou DB: pozdější upsert přepíše `confirmed`, po načtení `closed` (ztráta potvrzení i zámku) | sonda `known_gap_concurrent_runs_lose_confirmation`; v kódu není zámek běhu ani optimistická kontrola verze řádku (grep) | ověřeno nezávisle | — | střední (záleží na nasazení; dvě instance, plánovač + ruční běh) | otevřené; návrh: zámek běhu (jako `case_memory.rs:604`) a `WHERE` na verzi řádku, pořadí 3 |
| K21-N6 (2026-11-19) | „seznam povolených“ jako pozitivní důkaz pochází z hlášení agenta na hostu; lhoucí agent + historie = lístek | sonda `known_gap_lying_agent_allowlist_plus_history_passes_gate` | ověřeno nezávisle (brána); v soaku `elying` nenastalo (FG 0 omylem zavřených, krok 20) | — | střední (R1 stojí na poctivosti kompromitovatelného zdroje) | otevřené; návrh: seznam povolených jen z agenta cíle (ne zdroje) nebo s druhou skupinou mimo host (kontext, živost), měřit `emimicallow` z kroku 14 |
| K21-N7 (2026-11-19) | lístek není svázán s klíčem | sonda `known_gap_ticket_is_not_bound_to_key` | ověřeno nezávisle | — | nízké (jediný volající `settle` je konzistentní) | otevřené; návrh: klíč v lístku a kontrola v `refute_gated`/`observe_gated` |
| K21-N8 (2026-11-19) | skok hodin o > 24 h uzavře klidem i podezřelý/potvrzený klíč a zámek padá; výskyt s časem před posledním viděním se bere jako souvislá epizoda | sonda `known_gap_clock_jump_forward_drops_lock` | ověřeno nezávisle | — | nízké až střední (NTP porucha, ruční nastavení času) | otevřené; návrh: monotónní čas běhu z úložiště, odmítnout běh s časem < poslední | 
| K21-N9 (2026-11-19) | vyřazení při stropu 50 000 řadí podezřelé a štítem chráněné klíče jako běžné otevřené (třída 2), takže zahlcení paměti klíči zruší zámek | `finding_memory.rs` `ensure_capacity` (třída podle stavu, ne `gate_locked`) | ověřeno nezávisle (čtení), bez testu | — | nízké (potřeba ~45 000 nových klíčů) | otevřené; návrh: v režimu brány třída 3 pro `gate_locked` |
| K21-N10 (2026-11-19) | pozitivní důkaz žebříku se pozná podle textu kroku (`schvalil `, `seznam povolenych`, `vlastnik `) | `closure_gate.rs` `positive`, `after` | ověřeno nezávisle (čtení) | — | střední při změně formátu textu (tiché vypnutí nebo zapnutí důkazu) | otevřené; návrh: strukturované pole `owner` v `StepNote`, pořadí 5 |
| K21-N11 (2026-11-19) | `CloseTicket` a `Entry` mají `Deserialize`; lístek lze vyrobit mimo bránu deserializací | `closure_gate.rs:30`, `finding_memory.rs:300` | ověřeno nezávisle (čtení); v kódu se nikde nedeserializuje (grep) | — | nízké | otevřené (spolu s N4) |
| K21-N12 (2026-11-19) | kontext jako pozitivní důkaz se v žebříku ověřuje v cyklu kontroly, ne v cyklu rozhodnutí; po expiraci záznamu může lístek nést prošlý kontext | `verify_ladder.rs:1628` (krok Context), `admit_ladder` nekontroluje čas kroku | **neověřeno** (z čtení, bez testu) | — | nízké až střední | otevřené |

## 6. Doporučené pořadí dalších kroků

1. Jedna sdílená funkce cyklu pro soak i produkci a soak s restartem v každém cyklu (4.2); teprve pak rozhodnout o uložení lístku s podpisem.
2. Pravidlo epizody i pro otevřený klíč (4.1), měřeno na nových držených seedech.
3. Zámek běhu a kontrola verze řádku v paměti (N5); monotónní čas (N8); třída vyřazení podle zámku (N9).
4. Registr chráněných prostředků (4.3) a role v simulaci.
5. Strukturovaný vlastník důkazu a klíč v lístku (N7, N10, N11); seznam povolených jen z nezávislého zdroje (N6).
6. Odpojit rozsah skeneru v simulaci od `strict_close` (M4) natrvalo podle výsledku H21-FP; pak znovu změřit RG a rozhodnout o presetu.
