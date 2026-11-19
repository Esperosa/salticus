# Krok 20: forenzní audit jádra (tok rozhodnutí o zavření nálezu)

Datum 2026-11-19. Stav kódu: commit `b0ddf5c` (zdroj rozhodování shodný s `17bbd7e`, krok 19). Zadání: `F:\work-tmp\briefs\krok20-forenzni-audit-jadra.txt`. Závazná pravidla: `docs/diplomka/rozsah-autonomie.md` (R1 zavřít jen na pozitivní důkaz, R2 chráněné a vysoký dopad nikdy automaticky, R3 cíl 0 omylem zavřených, R4 porucha se nezavírá jen proto, že není útok, R5 chybějící telemetrie je slepé místo).

Metoda: čtení kódu (grep přechodů stavů, pak čtení míst), cílené sondy jako testy (`verify_ladder::tests::audit_k20_*`) a forenzní stopy `K15_TRACE` na sítích, kde krok 19 hlásil omylem zavřené útoky (přehrání je bajtově shodné s během kroku 19, ověřeno `F:\work-tmp\k20\cmp.py` na všech přehraných sítích).

## 1. Mapa toku dat a rozhodnutí

### Vstup → nález

`pipeline/v3.rs` (produkce) a `soak/episode.rs` (simulace) mají každý **vlastní kopii orchestrace** (detektory → nálezy → paměť → kontext → žebřík → výstup). Kopie se liší (viz matice, body M10 až M13); měření kroků 9 až 19 tedy měří soakovou kopii, ne produkční.

```
toky, alerty, L7, koncová a provozní telemetrie
  → detektory (passive, behavior/*, l7, ops_evidence::distributed_findings)
  → Finding (typ, host_key, service_key, závažnost)
  → klíč paměti key_for_finding (entita|typ|služba; scan_attempts = src:<zdroj>)
  → ochrana protection::protection (typ P1–P3, degradace P4, nejednoznačnost P5)
  → kontextová brána context_gate::explain_decision → Option<Explanation>
  → paměť finding_memory::observe(obs, explanation) → Disposition
  → žebřík verify_ladder (open / observe / step) → Decision
  → zápis rozhodnutí do paměti (refute / confirm / note)
  → výstup: zobrazení (alert), případová složka (case_folder), korelace a incidenty (correlation_layer, retro), enforcement jen na pokyn člověka
```

### Kdo vlastní který stav

| stav | vlastník | kde se mění |
|---|---|---|
| `FindingState` (new, open, auto_resolved, confirmed, closed, reopened, refuted) | `FindingMemory` | `observe` (automaticky), `refute`, `confirm`, `close`, `reopen` (člověk), `sweep` (TTL), `reset_protected`, `ensure_capacity` (vyřazení) |
| případ žebříku (`Status`: open, confirmed, refuted, escalated) | `Ladder` | `run_check`, `finish`, `step` (rozpočet) |
| držení nepotvrzeného podezření (`held`, 48 cyklů) | `Ladder` | `finish` (krok 18) |
| „potvrzený klíč se nevyvrací“ | `FindingMemory` (stav `Confirmed`) | `refute` vrací `false` |
| zobrazení v cyklu | soak: `Shown.displayed` (přepisuje se žebříkem: „verifying“, „ladder_escalated“, `ladder_refuted`); produkce: `LifecycleRecord.displayed` z dispozice paměti **před** žebříkem | |
| fronta provoz | `Shown.ops` (soak), `ops_class` | jen soak |
| apriorní P | soak: `learned_prior` z paměti případů (0,01 až 0,99); produkce: pevně `DEFAULT_PRIOR` 0,15 | |

Stav „zavřeno“ tedy nemá jednoho vlastníka: o tomtéž klíči rozhoduje kontextová brána (přes `observe`), žebřík (přes `refute`), paměť sama (pohlcení, TTL) a v soaku ještě přepis `Shown`.

### Všechny cesty, kterými nález skončí zavřený, vyvrácený nebo skrytý

| # | cesta (kód) | co se stane | jaký důkaz vyžaduje | R1 pozitivní důkaz | R2 chráněné / vysoký dopad | lhoucí agent | kdo ji přebíjí |
|---|---|---|---|---|---|---|---|
| C1 | kontext → `observe(.., Some(reason))` → `AutoResolved` (`context_gate::explain_decision`, `finding_memory::observe`) | nový i existující klíč se automaticky vyřeší | aktivní záznam kontextu (kalendář, skener, záloha…), shoda hostu a zdroje; bez `strict_close` stačí **jeden** zdroj nálezu v záznamu a skener **bez rozsahu cílů** vysvětlí každý nález svého zdroje | částečně: záznam má schvalovatele a expiraci, ale bez `strict_close` dokládá zdroj, ne činnost | chráněné typy a P4/P5 ano (`protect`); vysoká závažnost jen s výslovným pokrytím a hosty, nebo dvěma druhy kontextu | n/a | `protect` (štít), `strict_close` (důkaz zdroje), `context_guard`, `sensor_strict`; audit uzavření jen v produkci |
| C2 | žebřík `run_check` → `Status::Refuted` → `memory.refute` | klíč `Refuted`, nález se nezobrazí | bez `strict_refute`: P ≤ 0,03 (vysoký dopad 0,01) a **jakýkoli** výsledek s LR < 1, i historie, profil hostu, srovnání s peery, přetrvání „zmizelo“, profil zařízení; se `strict_refute`: ≥ 2 skupiny, aspoň jedna z {kontext, živost, koncová telemetrie} | **ne** bez `strict_refute` (sonda `audit_k20_dependent_or_groupless_evidence_alone_refutes_without_strict`: samotná historie i samotní peeři vyvrátí); živost „výpadek“ je skupina 2 (silná) v rozporu s R4 | chráněné ano; **vysoký dopad se vyvrací** (jen přísnější práh 0,01) | „vše v pořádku“ od agenta je silná skupina 4, dokud není `endpoint_weak` **a zároveň** `strict_refute` | `protect`, `strict_close` (→ `strict_refute`), `endpoint_weak`, `confirm_evidence` (`held`), `Confirmed` v paměti |
| C3 | režim konkurenčních hypotéz (`hypotheses`): `best_action = CloseBenign` → `Refuted` | jako C2 | jen P ≤ 0,005 (cena omylu); **bez požadavku na neškodný výsledek** a bez rozlišení vysokého dopadu; `proven` jen se `strict_refute` | **ne** (sonda `audit_k20_competing_without_strict_closes_on_prior_alone`: zavře z apriorní P bez jediného neškodného výsledku) | chráněné ano, vysoký dopad ne | jako C2 | `strict_close` |
| C4 | pohlcení pod vyvráceným klíčem: `observe` při stavu `Refuted` bez eskalace → `Suppressed` | každý další výskyt téhož klíče (i jiná epizoda, jiný útok) se tiše skryje | žádný: dědí důkaz starého vyvrácení | **ne** (nový výskyt nemá vlastní důkaz) | chráněné typy ano (`protect_reset`) | — | eskalace závažnosti, nového zdroje (jen má-li klíč zdroje, nebo `escalate_first_source`), objemu ×4; `refute_episode` (odmlka ≥ 1 h), `reopen_stale` (odmlka ≥ 24 h, jen se `strict_close`) |
| C5 | pohlcení pod automaticky vyřešeným klíčem: `(_, Some(reason), None)` → znovu `AutoResolved` | výskyt během platného kontextu zůstává vyřešený | platný kontext v tomto cyklu | jako C1 | jako C1 | — | konec kontextu → `Reopened` (zobrazí se) |
| C6 | „verifying“: nový stav nevysokého, nechráněného nálezu se v soaku skryje do rozhodnutí žebříku | nález se zobrazí až po rozhodnutí; při vyvrácení nikdy | — | dočasné skrytí; **trvalé**, když případ nevznikl (strop `max_open_cases` = 5 000, `open` vrací `false`, ale nález je skryt dál) | chráněné a vysoký dopad se zobrazí hned | — | jen soak; produkce zobrazuje hned |
| C7 | dedup otevřeného klíče: `(Open/New/Reopened/Confirmed, None, None)` → `Suppressed` | opakování otevřeného nálezu se nezobrazí | — | nález zůstává otevřený a viditelný ve frontě (není to zavření), ale nový útok pod starým klíčem se nezobrazí bez eskalace | — | — | `redisplay`, `redisplay_age` |
| C8 | `sweep`: aktivní klíč 24 h bez výskytu → `Closed`; retence 7 dní → smazání | klíč zavřen (i `Confirmed`, `Refuted`) | čas | nejde o skrytí: další výskyt = `Reopened`, zobrazí se | — | — | — |
| C9 | `ensure_capacity`: strop 50 000 klíčů → vyřazení 10 % | klíč smazán | — | další výskyt = `First`, zobrazí se | potvrzené až naposled | — | — |
| C10 | `reset_protected` / `protect_reset` | zakázaný stav chráněného klíče → `Closed` | — | bezpečný směr (otevře se) | — | — | — |
| C11 | fronta provoz (`ops_class`): zobrazený nález s provozním důkazem → `show.ops` | odkloněn z fronty podezření | provozní důkaz v okně | nezavírá, ale odklání (v `final` místo něj `ops_annotate`) | chráněné ne | — | `ops_annotate` (při obou zapnutých vyhrává odklon) |
| C12 | držení `held` (krok 18) | vyvrácení klíče s nedávným `prior_hold` → eskalace | — | bezpečný směr, ale jen 48 cyklů | — | — | — |
| C13 | audit uzavření (`closure_audit`, jen produkce) | vypne druh kontextu nebo vyvracení žebříkem při překročené chybě | — | bezpečný směr | — | — | v soaku neexistuje |
| C14 | člověk: `close`, `reopen`, `confirm` | | rozhodnutí člověka | mimo automatiku | | | |

Retro (`retro.rs`), přehodnocení (`reassess.rs`), spisy (`case_file.rs`) a případová složka stav nemění (jen čtou); enforcement (`enforcement.rs`, `ops.rs`) se stavem nálezu nesouvisí a vyžaduje pokyn člověka. `bulk_clear` (ze zadání) není cesta zavření, ale detektor velkého přenosu po nešifrovaném portu; název je zavádějící.

**Shrnutí mapy:** o zavření rozhodují tři nezávislé moduly (kontext, žebřík, paměť) a čtvrtý (soakový přepis zobrazení) rozhoduje o skrytí; pravidla R1 a R2 jsou vynucena jen v některých kombinacích přepínačů, nikde jako invariant stavu. V presetu `recommended()` (bez `strict_close`) cesty C1 až C4 porušují R1 a C2 porušuje R2 (vysoký dopad).

## 2. Matice interakcí přepínačů

Ověřeno čtením a sondami (`cargo test --lib audit_k20`), ne domněnkou. „Mrtvý“ = v dané kombinaci bez účinku.

| # | kombinace | problém | druh | ověřeno |
|---|---|---|---|---|
| M1 | `endpoint_weak` bez `strict_close` a bez `hypotheses` | skupina 6 se čte jen v `proven` (`strict_refute` nebo konkurenční režim); jinak přepínač nic nemění. V kroku 19 tedy `endpoint_weak` nad `recommended()` neměl žádný účinek | mrtvý přepínač | sonda `audit_k20_endpoint_weak_is_inert_without_strict_refute` |
| M2 | `refute_episode` bez `strict_close` | nová epizoda vyvráceného klíče jde znovu do žebříku, který bez `strict_refute` vyvrací na samotnou historii; každá epizoda útoku pod takovým klíčem je nové (počítané) omylem vyvrácení místo dřívějšího tichého pohlcení (C4) | dvě cesty o témže stavu, jedna přepisuje druhou | stopy (sekce 3) |
| M3 | `confirm_evidence` bez `strict_close` | potvrzení se mění na eskalaci (`prior_hold`), takže klíč v paměti není `Confirmed` a ztrácí trvalou ochranu proti vyvrácení; náhradní ochrana `held` platí 48 cyklů. Dva zdroje pravdy o „klíč je podezřelý“ (`FindingMemory` stav vs. `Ladder::held`) s různou životností | duplicitní zdroj pravdy | čtení `finish`, `refute`; sekce 3 |
| M4 | `strict_close` | jedním přepínačem mění **čtyři** věci: důkaz zdroje v kontextu, `strict_refute` žebříku, `escalate_first_source`, `reopen_stale` v paměti, **a vstup simulace** (záznam skeneru dostane rozsah cílů jen se `strict_close`, `SimContext::for_cycle(.., scanner_scope)`). Srovnání `final` vs. `recommended()` je tak zmatené změnou vstupních dat | přepínač mění simulovaný svět | čtení `soak/v3.rs`, `engine.rs` |
| M5 | `context_guard` + `strict_close` | `strict_close` odmítne prázdné zdroje vždy, výjimka `context_guard` pro objem je mrtvá | redundance | čtení `GatePolicy::admits`, `source_proven` |
| M6 | `sensor_strict` + `protect` | obojí zakazuje výpadek senzoru jako kontext (dvě podmínky v `admits`) | redundance | čtení |
| M7 | `reopen_stale` (24 h, ze `strict_close`) + `refute_episode` (1 h) | dvě pravidla pro tutéž věc (stará uzávěrka nesmí pohltit nový výskyt) s různým prahem a různou příčinou eskalace (`NewSource` vs. `Episode`); kratší vyhrává | redundance, nekonzistentní značka | čtení `observe` |
| M8 | `ops_class` + `ops_annotate` | fronta provoz odkloní, anotace ponechá v podezření; při obou zapnutých se nález odkloní i anotuje | protichůdné | čtení soaku |
| M9 | `endpoint_allow` | seznam povolených z jednoho pozorování agenta se počítá jako **dvě** nezávislé skupiny {1, 4}, takže sám splní `strict_refute`; lhoucí agent hlásící povolený hash zavírá (krok 14, `emimicallow`) | dvojí započtení jednoho zdroje | čtení `run_check` |
| M10 | produkce vs. soak: apriorní P | soak `learned_prior` (0,01 až 0,99, z verdiktů simulovaného analytika), produkce pevná 0,15. Při apriorní P ≤ 0,03 stačí k vyvrácení jakýkoli výsledek s LR < 1 (C2); zrcadlo nálezu kroku 18 (potvrzení z apriorní P) | měří se jiný engine, než běží | čtení `learned_prior`, `pipeline/v3.rs` |
| M11 | produkce: uložený žebřík | `strict_refute`, `competing`, `l7` se berou jen při prvním vytvoření žebříku; u uloženého stavu se z konfigurace obnovuje jen `profile`, `protect`, `endpoint`, `ops`, `endpoint_weak`, `confirm_evidence`. Zapnutí `strict_close` v běžící instalaci žebřík nezpřísní | tichá nekonzistence konfigurace | čtení `pipeline/v3.rs` ř. 544–585 |
| M12 | produkce: zobrazení | `LifecycleRecord` (stav a `displayed`) se zapisuje před žebříkem; vyvrácený nález je v témže běhu v životním cyklu „zobrazen, open“ a v `verification_decisions` „refuted“ | dva výstupy si odporují | čtení |
| M13 | soak: výsledek `memory.refute` se ignoruje | rozhodnutí `Refuted` se počítá a nález skryje i tehdy, když paměť vyvrácení odmítla (`Confirmed`, štít); v produkci se návratová hodnota kontroluje jen kvůli auditu, `DecisionRecord` zůstane `Refuted` | metrika může počítat zavření, které nenastalo | čtení; ve stopách kroku 19 se nevyskytlo (0 případů s `Confirmed` klíčem) |
| M14 | produkce: tichá hodnota 0,15 | `case_folders` dává otevřenému případu bez rozhodnutí P(útok) = `DEFAULT_PRIOR` a klíč postavený jinak než `key_for_finding` (host_key, plný service_key); `correlation_layer::run` a `reassess` zapisují prior 0,15 bez ohledu na skutečnou apriorní P | tichý fallback, duplicitní konstrukce klíče | čtení `pipeline/v3.rs` ř. 1029, 1094–1106 |
| M15 | `protection::PROTECTED_TYPES` a `type_protection` | týž seznam typů dvakrát (konstanta a `match`); musí se držet ručně v souladu | duplicitní zdroj pravdy | čtení |
| M16 | „chráněné prostředky“ (R2) | v kódu neexistuje pojem chráněného prostředku (hostu); R2 je implementováno jen jako chráněné *typy* a signály. Vysoký dopad se vyvrací (C2) | chybějící pravidlo | čtení, stopy (8 omylem vyvrácených s `high_impact`) |
| M17 | metrika K19 | `auto_closures_wrong` počítá nález zmiňující **jakoukoli** pravdu typu `Kind::Attack` v okně (včetně `hn_*`, provozních poruch a neškodných změn, které simulace vede jako varianty), `ladder_refuted_wrong_cf` kontrafaktuálně; součet míchá dvě definice a počítá **rozhodnutí**, ne útoky. Útoky skryté pohlcením pod vyvráceným klíčem (C4) se nepočítají vůbec | měření | sekce 3 |
| M18 | `hypotheses` bez `strict_close` | zavírá na apriorní P bez neškodného výsledku (C3) | porušení R1 | sonda |
| M19 | `case_folder` bez `case_files` | `case_folder()` vyžaduje `case_files`, soak ale složky staví nezávisle na přepínači (dump `K16_CASE_DUMP`) | nekonzistence | čtení |

Mrtvý nebo nedosažitelný kód: pole `Shown.memory_contradicted` se nastavuje jen z `shown_for` (bez pozdějšího přepisu), větev `(None, Some(reason))` pozdního zobrazení nikdy nenese vyvrácení; `Status::Open` z `finish` nevzniká (žádný volající ho nepředá). Ani jedno nemění rozhodnutí.

<!-- sekce 3 doplněna po dokončení stop -->
