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

## 3. Forenzní rozbor omylem zavřených útoků kroku 19

Data: držené běhy kroku 19 (`F:\work-tmp\k19\held-a`, binárka `salticus-k18-17bbd7e.exe`). Všech 17 sítí, kde se v některém rameni objevilo omylem zavřené rozhodnutí, bylo přehráno jednotlivě se stopou `K15_TRACE` ve všech šesti ramenech (98 běhů, `F:\work-tmp\k20\rca`, seznam `rca-jobs.txt`). Přehrání je bajtově shodné s původním během (98 z 98 sítí, `cmp.py`) a stopy obsahují **všech** 39 až 59 omylem zavřených rozhodnutí z kroku 19 (počty sedí na rameno). Rozbor: `F:\work-tmp\k20\rca.py`, `refev.py`; řádky po případech `rca\rca-rows.json`.

### 3.1 Tabulka příčin (počet omylem zavřených rozhodnutí podle metriky kroku 19)

| příčina | cesta v kódu | `off` základ / kandidát | `ops` | `elying` | rodiny (součet přes ramena) |
|---|---|---|---|---|---|
| **A. kontext: záznam autorizovaného skeneru bez rozsahu cílů zavře `scan_attempts` svého zdroje** | C1: `context_gate::explain_decision` bez `strict_close` (`source_proven` = true, `host_match` přes `entry.sources`) → `FindingMemory::observe` → `AutoResolved` | 12 / 12 | 12 / 12 | 12 / 12 | v každém rameni stejných 12: zmíněná pravda `c2_beacon` 5, `lateral_cautious_one_target` 1, `cryptomining` 1, a 5 ne-bezpečnostních (`hn_*` 2, `kerberos_dc_failure` 2, `planned_patch_reboot_wave` 1); kontrafaktuálně způsobené útokem jen 3 z 12 |
| **B1. žebřík vyvrátil jen na historii nebo profil hostu** (skupina 3, týž tok dat jako detektor) | C2: `Ladder::run_check`, větev `posterior ≤ refute_at && benign_evidence && !shielded` bez `strict_refute` → `memory.refute` | 17 / 17 | 14 / 23 | 17 / 22 | `c2_beacon` 37, `dns_tunnel` 14, `update_channel_compromise_fleet` 13, `share_encryption_wave_slow` 11, `slow_scan` 6, … |
| **B2. žebřík vyvrátil jen na srovnání s peery, přetrvání nebo profil zařízení** (žádná skupina neškodného důkazu) | totéž; `benign_evidence` nastaví každý výsledek s LR < 1 | 10 / 15 | 16 / 23 | 10 / 15 | `rogue_device_in_network` 75, `c2_beacon` 8, … |
| B3. historie + peeři | totéž | 0 / 0 | 0 / 1 | 0 / 0 | |
| B4. agent „vše v pořádku“ + závislý důkaz | totéž (`endpoint_weak` bez `strict_refute` mrtvý, M1) | 0 / 0 | 0 / 0 | 0 / 1 | `dns_tunnel` |
| **celkem** | | **39 / 44** | **42 / 59** | **39 / 50** | |

Průřezové vlastnosti omylem vyvrácených (základ / kandidát): **žádné nemá silnou skupinu** (kontext, živost, koncová telemetrie) ve všech 6 ramenech (27/32, 30/47, 27/37 z 27/32, 30/47, 27/38); s vysokým dopadem (R2) 8/3, 8/6, 8/7; opakované vyvrácení klíče, který už byl vyvrácen, 6/18, 4/22, 8/19. Apriorní P odvozená z posteriory a LR kroků má medián 0,077 (rozsah 0,02 až 0,16): naučená apriorní P z paměti případů (M10) je pod výchozí 0,15, takže na vyvrácení (P ≤ 0,03) stačí jediný výsledek s LR 0,25.

Mezi **všemi** vyvráceními ve stopách (i neškodnými) je obraz stejný: v základu 794 z 820 vyvrácení (97 %) nemá silnou skupinu (z toho 425 s vysokým dopadem); se silnou skupinou a dvěma skupinami (pravidlo `strict_refute`) jen 26, z toho 12 jen díky živosti „výpadek“ (R4) a 14 díky agentovi „vše v pořádku“ u vysokého dopadu. Všech 84 omylem vyvrácených (všechny konfigurace) je ve třídě bez silné skupiny.

### 3.2 Proč kandidát kroku 19 „zhoršil“

Kandidát = `recommended()` + `endpoint_weak`, `refute_episode`, `confirm_evidence`. Rozdíl po případech (`off`, klíč a cyklus): 20 omylem vyvrácených je v obou ramenech, 7 jen v základu, 12 jen v kandidátovi. **Všech 12 přírůstků je opakované vyvrácení klíče, který byl vyvrácen už v základu** (5× `asset:*|unexpected_traffic|host-only` u `rogue_device_in_network` jen na peery, 6× `src:*|scan_attempts` u `c2_beacon` a 1× `source_volume_outlier` u `dns_tunnel` jen na historii). Mechanismus:

1. `refute_episode` po odmlce ≥ 1 h označí výskyt vyvráceného klíče jako novou epizodu (`Escalation::Episode`) a pošle ho znovu do žebříku (M2).
2. Žebřík bez `strict_refute` epizodu znovu vyvrátí na tutéž historii nebo peery (B1, B2); každé takové rozhodnutí metrika kroku 19 počítá znovu.
3. V základu tytéž výskyty zmizely **tiše**: pohltil je vyvrácený klíč (C4, `Suppressed`), což metrika rozhodnutí nepočítá vůbec (M17).

Kvantifikace na týchž stopách (výskyty útoku v okně, skryté pod vyvráceným klíčem bez nového rozhodnutí):

| | `off` | `ops` | `elying` |
|---|---|---|---|
| výskyty pohlcené pod vyvráceným klíčem, základ → kandidát | 100 → 19 | 78 → 47 | 131 → 31 |
| klíče s takovým pohlcením | 33 → 10 | 33 → 13 | 34 → 15 |

A na úrovni útoků v celých držených bězích kroku 19 (pole `attacks[]` v `networks.jsonl`, 3 451 útoků na konfiguraci):

| | `off` | `ops` | `elying` |
|---|---|---|---|
| útoky s omylem zavřeným nálezem (`k7.wrong_closed > 0`) | 51 → 36 | 51 → 53 | 52 → 43 |
| útoky s výskytem pohlceným pod vyvráceným klíčem (`diag.hidden.state_refuted > 0`) | 101 → 65 | 115 → 96 | 98 → 71 |

**Závěr 3.2:** „zhoršení“ kandidáta v kroku 19 je z velké části artefakt metriky (počítá rozhodnutí, ne útoky, a nevidí tiché pohlcení). Na úrovni útoků kandidát skrývá méně (`off` −15, `elying` −9 útoků s omylem zavřeným nálezem; pohlcení −36 až −27 útoků), v `ops` je přibližně beze změny (+2). Kořen obou čísel je ale týž: žebřík v `recommended()` vyvrací na závislý důkaz (B1, B2) a kandidát mu jen dává víc příležitostí. Ani jedna z obou konfigurací nesplňuje R1.

`confirm_evidence` (M3): v základu ani v kandidátovi nebyl ve stopách žádný omylem vyvrácený klíč dříve potvrzený (`ever_confirmed` 0 ve všech ramenech) a držení `held` neodmítlo ani jedno vyvrácení (krok 19); příspěvek M3 k přírůstku je tedy nulový. Hypotéza kroku 19 („po 48 cyklech se dá vyvrátit dřív potvrzený klíč“) se nepotvrdila; skutečná příčina je M2.

`endpoint_weak` (M1): bez `strict_refute` nic nemění; jediné rozhodnutí „agent + závislý“ v `elying` kandidátovi je toho důsledek.

### 3.3 Co z toho plyne pro opravu

- Všechna omylem zavřená rozhodnutí (A, B1–B4) by zastavila pravidla R1 a R2 vynucená **na jednom místě**: kontext jen s důkazem zdroje a rozsahem skeneru (A), žebřík jen s pozitivním důkazem s vlastníkem a druhou skupinou, nikdy vysoký dopad (B).
- Metrika musí počítat i tiché pohlcení (C4), jinak oprava, která pohlcení odstraní, vypadá jako zhoršení. Předregistrace kroku 20 proto hlásí tři metriky: rozhodnutí (kontinuita s krokem 19), útoky s omylem zavřeným nálezem a útoky s pohlceným výskytem.
- Cena: v `recommended()` je 97 % všech vyvrácení ve stopách na závislém důkazu (i neškodných), jejich odstranění zvýší zobrazené FP. To je cena R1, ne vada opravy; předpověď je v předregistraci.
