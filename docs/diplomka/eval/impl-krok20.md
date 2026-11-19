# Krok 20: jediná brána zavření

Datum zahájení 2026-11-19. Výchozí stav: konec kroku 19 (commit `b0ddf5c`, rozhodování shodné s `17bbd7e`). Zadání: `F:\work-tmp\briefs\krok20-forenzni-audit-jadra.txt`. Závazný rozsah: `docs/diplomka/rozsah-autonomie.md`. Forenzní audit, mapa cest zavření, matice přepínačů a rozbor omylem zavřených útoků kroku 19: `audit-jadra.md`.

## 1. Kořenové příčiny (z auditu, před kódem)

1. **Zavření nemá jednoho vlastníka.** O stavu klíče rozhoduje kontextová brána (přes `FindingMemory::observe`), žebřík (`FindingMemory::refute`), paměť sama (pohlcení pod vyvráceným klíčem, TTL) a v soaku přepis zobrazení. Pravidla R1 a R2 platí jen v některých kombinacích přepínačů (audit, cesty C1 až C7).
2. **V `recommended()` žebřík vyvrací na závislý nebo žádný neškodný důkaz.** Bez `strict_refute` stačí P ≤ 0,03 a jakýkoli výsledek s LR < 1 (historie, profil hostu, peeři, přetrvání). Ve stopách kroku 19 mají všechna omylem vyvrácená rozhodnutí jen takový důkaz; 8 z nich je s vysokým dopadem (R2).
3. **Pohlcení pod zavřeným klíčem (C4) je skryté zavření bez důkazu** a metrika kroku 19 ho nepočítá. `refute_episode` ho převádí na nová (počítaná) vyvrácení, protože žebřík bez `strict_refute` epizodu znovu vyvrátí na historii; proto kandidát kroku 19 na počtu rozhodnutí „zhoršil“, ačkoli na úrovni útoků zlepšil (audit, sekce 3).
4. **Dva zdroje pravdy o podezřelém klíči** (`Confirmed` v paměti trvale, `Ladder::held` 48 cyklů) a přepínače, které mají účinek jen v kombinaci (`endpoint_weak` bez `strict_refute` mrtvý, `strict_close` mění čtyři věci a vstup simulace).
5. **Kontextová uzávěra podle zdroje, ne podle činnosti:** bez `strict_close` záznam skeneru bez rozsahu cílů zavře každý nález `scan_attempts` svého zdroje (12 automatických zavření kroku 19).

## 2. Návrh (předregistrováno před kódem)

Nový přepínač `V3Features::close_gate` (výchozí vypnuto, mimo `recommended()`, vyžaduje `memory`). Bez něj se chování nemění (bajtově, viz K20-6).

**Jediná brána** `closure_gate::admit(&CloseRequest) -> Result<CloseTicket, Refusal>`. `CloseTicket` (druh, vlastník, skupiny důkazu, důvod, zdroje, platnost) vzniká jen v ní. `FindingMemory` v režimu brány vstoupí do `AutoResolved` nebo `Refuted` jen s lístkem a uloží ho k položce (invariant je kontrolovatelný na stavu). Starší vstupy (`observe` s textovým vysvětlením, `refute` s textem) v režimu brány nikdy nezavřou a počítají se jako `gate_bypass`. Soak i produkce zapisují rozhodnutí žebříku jednou funkcí `closure_gate::settle`, která vrací skutečný výsledek (vyvrácení odmítnuté bránou nebo pamětí se stává eskalací s důvodem); zobrazení a čítače se řídí tímto výsledkem.

Podmínky lístku (všechny):

- **R2:** nález není chráněný (typ P1 až P3, signál P4/P5) a nemá vysoký dopad (závažnost High nebo typ z `most_severe`). Bez výjimky.
- **Vlastník:** neprázdný schvalovatel (záznam kontextu: `approved_by` a expirace; seznam povolených: vlastník položky).
- **Kontext (C1):** druh není výpadek senzoru (R5), zdroje nálezu jsou neprázdné a všechny patří záznamu, skener má rozsah cílů (sémantika `strict_close`).
- **Žebřík (C2, C3):** P ≤ práh vyvrácení a neškodné výsledky aspoň ze dvou nezávislých skupin, z nichž jedna je **pozitivní důkaz s vlastníkem**: schválený kontext (skupina 1) nebo seznam povolených (skupina 4, počítá se jednou). „Vše v pořádku“ od agenta, výpadek služby (živost, R4: porucha jde člověku viditelně), historie, profil hostu, peeři, přetrvání a profil zařízení jsou jen podpůrné (smí být druhou skupinou). Režim konkurenčních hypotéz zavírá jen přes tutéž bránu.
- **Zámek podezření:** klíč, který byl potvrzen nebo předán jako nepotvrzené podezření (`prior_hold`), se nezavře, dokud je aktivní (jeden zdroj pravdy: položka paměti, ne `Ladder::held`).
- **Rozsah epizody (C4):** zavřený klíč pohltí jen souvislé pokračování (odmlka < 1 h) se zdroji obsaženými v lístku; jinak eskalace `Episode` a nové ověření.

Co tím odpadá (v režimu brány se ignoruje nebo je zahrnuto): `strict_close` pro žebřík a kontext, `endpoint_weak`, `refute_episode`, `reopen_stale`, `held` z `confirm_evidence`, `context_guard`, `sensor_strict` (pro zavírání). Simulovaný vstup se nemění: rozsah cílů skeneru dostává simulace jen se `strict_close` jako dosud (bez něj brána takový záznam odmítne, nic nezavře).

## 3. Předregistrace měření

Ramena (párově, stejný seed a síť): **R** = `recommended()`, **RG** = R + `close_gate`, **F** = `final` (R + `breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate`), **FG** = F + `close_gate`. Konfigurace sítí jako v kroku 19: `off`, `ops` (`--ops-telemetry on`), `elying` (`endpoint_ext`, `--endpoint on --endpoint-agent ok`). Společné volby: `soak run --max-networks 4 --threads 1 --block-size 2 --no-legs --engine v3 --no-feedback --counterfactual --l7 cal --coverage k10`. Srovnání RG proti R a FG proti F.

- **Ladicí seedy:** 20269701 až 20269710 (držené seedy kroku 19, po něm diagnostické; na nich proběhl forenzní rozbor). Rameno R se nepouští znovu, pokud K20-6 potvrdí shodu nové binárky s `17bbd7e`.
- **Nové držené seedy (zapsáno dopředu, použít jednou): 20270101, 20270102, 20270103, 20270104, 20270105, 20270106, 20270107, 20270108, 20270109, 20270110.** Všechna čtyři ramena. Seed se sítí, jejíž běh přesáhne 2 h, se vynechá ve všech ramenech a zapíše.
- Žádné ladění prahů (`p_refute`, LR, apriorní P, detektory). Změna kódu po prvním běhu na ladicích seedech se zapíše jako odchylka; po drženém běhu se kód nemění.

| práh | metrika | splněno, když |
|---|---|---|
| K20-1 | omylem zavřené (definice kroku 19: `auto_closures_wrong` + `ladder_refuted_wrong_cf`) | RG a FG 0 v každé konfiguraci; hlásí se horní mez Wilson 95 % (jmenovatel = útoky) |
| K20-1b | útoky s omylem zavřeným nálezem (`attacks[].k7.wrong_closed > 0`, úroveň útoku) | RG a FG 0; Wilson |
| K20-1c | útoky s výskytem pohlceným pod zavřeným klíčem (`diag.hidden` `state_refuted` nebo `state_auto_resolved`) | RG ≤ R a FG ≤ F; cíl 0 |
| K20-2 | detekce po rodinách (zobrazeno, kontrafakt) | žádná rodina s ≥ 20 útoky nepoklesne o víc než 1 p. b.; 95% interval rozdílu souhrnné detekce (párový bootstrap po sítích, stratifikovaný podle seedu, B = 2000, semínko 20) nesmí ležet celý pod −1 p. b. |
| K20-3 | zobrazené FP | poměr ≤ 1,02 |
| K20-4 | případy pro člověka (potvrzeno + eskalováno) | nárůst ≤ 2 % |
| K20-5 | invariant | property/fuzz test (≥ 20 000 náhodných posloupností operací paměti a rozhodnutí žebříku v režimu brány): zavřený stav ⇒ lístek s pozitivním důkazem a vlastníkem; chráněný nebo vysoký dopad nikdy zavřen; žádný přechod do zavřeného stavu mimo bránu (obchvat starými vstupy nic nezavře); 0 porušení, 0 paniků |
| K20-6 | regrese bez přepínače | `networks.jsonl` nové binárky bez `close_gate` shodný s `17bbd7e` ve všech polích kromě časů (ladicí seedy 20269701 a 20269703, 4 sítě, 3 konfigurace) |

**Předpověď z auditu (zapsáno před měřením):** v `recommended()` stojí většina vyvrácení na závislém důkazu (ve stopách kroku 19 asi 90 % i u neškodných případů, z toho většina s vysokým dopadem). Brána je odstraní, takže u RG očekávám **nárůst zobrazených FP o několik procent (K20-3 pravděpodobně nesplněno)** a nárůst případů pro člověka pod 1 %. To je cena pravidel R1 a R2, ne chyba návrhu; neladí se. U FG (už se `strict_close`) očekávám malé změny.

Rozhodnutí: `close_gate` se navrhne do presetu jen tehdy, když rameno (RG nebo FG) splní K20-1 až K20-4 ve všech třech konfiguracích na držených seedech. `recommended()` se v tomto kroku nemění; návrh co ve `V3Features` smazat a sloučit je v závěru.

Omezení předem: council, sol-loop a delegování se podle zadání nespouštějí (odchylka od `CLAUDE.md` daná zadáním); review dělá autor. Simulace je jediný zdroj pravdy o tom, co je útok; definice „vlastníka“ pozitivního důkazu je volba autora (schvalovatel záznamu kontextu nebo položky seznamu povolených).

## 4. Implementace (commit `fb1546c`)

- `closure_gate.rs` (nový modul): `CloseTicket` (soukromá pole, vzniká jen v `admit_context`, `admit_explanation`, `admit_ladder`), `Refusal` s čitelným důvodem, `settle` (jediný zápis rozhodnutí žebříku do paměti v režimu brány; vrací skutečný výsledek, odmítnuté vyvrácení je eskalace „brana zavreni: …“). Pozitivní důkaz žebříku se pozná z kroku: schválený kontext („schvalil X“, ne výpadek senzoru) nebo seznam povolených („vlastnik X“, jedna skupina 4, ne {1, 4}).
- `finding_memory.rs`: `MemoryConfig::gate`; `Entry::ticket` a `Entry::suspected`; `observe_gated`, `refute_gated`, `mark_suspected`, `gate_violations` (kontrola invariantu na stavu), `reset_unticketed` (lístek se do SQLite neukládá, po načtení se zavřená položka bez lístku převede na `Closed`, tedy bezpečným směrem). V režimu brány `observe` s textem a `refute` nic nezavřou (`gate_bypass`); zavřený klíč pohltí jen výskyt se zdroji z lístku (jinak eskalace `NewSource`) a jen souvislou epizodu (odmlka < 1 h, jinak `Episode`).
- `context_gate.rs`: `Explanation` nese schvalovatele, expiraci a `sources_proven` (přísný důkaz zdroje počítaný vždy, `strictly_proven`); `GatePolicy::for_engine` zapne přísné zavírání i s branou.
- `engine.rs`: přepínač `close_gate` (vyžaduje `memory`), `strict_refute()` = `strict_close || close_gate`, `endpoint_weak_effective()`, paměť s branou má `escalate_first_source` a `refute_episode_s = 3600`.
- `soak/episode.rs` a `pipeline/v3.rs`: v režimu brány kontext → `admit_explanation` → `observe_gated`, žebřík → `settle`; zobrazení, `verification_decisions` a čítače se řídí vráceným rozhodnutím. V produkci se s branou obnovuje `strict_refute` i u uloženého žebříku (audit M11). Soak hlásí `k7.gate_bypass`, `gate_refused`, `gate_violations`.
- Testy: `closure_gate::tests` (7 testů, mezi nimi property/fuzz `gate_invariant_holds_under_random_operations_fuzz`: 20 000 náhodných posloupností operací paměti a rozhodnutí žebříku včetně obchvatů starými vstupy, kontrola `gate_violations` po každé operaci, vysoký dopad a chráněný typ nikdy v zavřeném stavu; generátor musí vytvořit > 500 zavření), `engine::tests::close_gate_is_opt_in_needs_memory_and_subsumes_combinations`, sondy auditu `verify_ladder::tests::audit_k20_*`. `cargo test --lib`: 673 prošlo, 6 selhalo (5 `broker::*` bez Redis jako dřív; `engine::tests::parse_mode_and_disable_list` kvůli novému jménu v popisku, opraveno a znovu prošlo). Clippy bez nových varování ve změněných řádcích.

## 5. Výsledky

### K20-6 regrese bez přepínače

Binárka `salticus-k20-fb1546c.exe` bez `close_gate`, rameno R, seedy 20269701 a 20269703, 3 konfigurace, 4 sítě: `networks.jsonl` shodný s během kroku 19 (`salticus-k18-17bbd7e.exe`) ve **24 z 24 sítí** ve všech polích kromě časů. **Splněno.** Rameno R ladicí sady se proto nepouštělo znovu; použity běhy kroku 19 (`F:\work-tmp\k19\held-a`, `--alias base=R`).

### Ladicí seedy 20269701 až 20269710 (40 párů sítí na konfiguraci, 3 443 útoků)

Výstupy `F:\work-tmp\k20\tune`, souhrn `F:\work-tmp\k20\report-tune.txt` (`tools/k20_gate.py`). Všech 96 běhů doběhlo (kód 0), 0 nespárovaných sítí.

| srovnání | konfigurace | omylem zavřeno (rozhodnutí) | útoky s omylem zavřeným | útoky s pohlceným výskytem | detekce | rodiny s poklesem > 1 p. b. | zobrazené FP | případy pro člověka |
|---|---|---|---|---|---|---|---|---|
| RG / R | `off` | 39 → **0** | 51 → **0** | 110 → **0** | 81,88 → 81,88 % [−0,15; +0,13] | `c2_beacon` −1,0 (1 útok), `hn_mail_newsletter_burst` −2,9 (1) | ×1,0178 [+0,68; +3,27] % | +0,43 % |
| RG / R | `ops` | 42 → **0** | 51 → **0** | 124 → **0** | 82,05 → 81,99 % [−0,19; +0,07] | `c2_beacon` (1), `credential_stuffing` −1,2 (1), `hn_mail_newsletter_burst` (1) | ×1,0182 [+0,72; +3,32] % | +0,67 % |
| RG / R | `elying` | 39 → **0** | 52 → **0** | 107 → **0** | 82,02 → 81,96 % [−0,18; +0,06] | `c2_beacon` (1), `hn_mail_newsletter_burst` (1) | ×1,0179 [+0,78; +3,13] % | +0,77 % |
| FG / F | `off` | 0 → 0 | 0 → 0 | 1 → **0** | 84,17 → 84,20 % | žádná | ×1,0000 | +0,00 % |
| FG / F | `ops` | 0 → 0 | 0 → 0 | 1 → **0** | 84,26 → 84,26 % | žádná | ×1,0000 | +0,02 % |
| FG / F | `elying` | 0 → 0 | 0 → 0 | 8 → **0** | 84,26 → 84,29 % | žádná | ×0,9998 | +0,05 % |

Wilson 95 % horní mez pro 0 z 3 443 je 0,111 %. Obchvat brány 0, porušení invariantu 0, paniky 0 ve všech ramenech s branou. Brána odstranila 286 až 367 vyvrácení a 13 automatických zavření v R a 5 až 24 vyvrácení v F.

Rozbor poklesů po útocích (`F:\work-tmp\k20\diffatt.py`; v každé konfiguraci se změní 7 až 10 útoků oběma směry):

- `c2_beacon` (seed 20269707, síť 0, útok 59, ve všech třech konfiguracích): v R „detekován“ jen přes nález skenu autorizovaného skeneru, který kontext automaticky zavřel a po konci okna kontextu znovu otevřel (zobrazil); kontrafaktuálně útokem způsobeno **ne** v R ani v RG. Jde o artefakt připsání (sdílená adresa), ne o ztrátu detekce.
- `hn_mail_newsletter_burst` je neškodný vzor (hard negative): pokles jeho „detekce“ je pokles FP, ne ztráta.
- `credential_stuffing` (20269705, síť 2, útok 25, `ops`): vlastní nálezy útoku jsou v obou ramenech pohlceny otevřeným klíčem z cyklu 0 (dedup C7, „suppressed“, stopa `F:\work-tmp\k20\rca2`); v R se útok zobrazil jen přes pozdní eskalaci jiného nálezu se sdílenou adresou, která v RG vyšla jinak (běhy se po prvních rozdílných rozhodnutích rozcházejí, viz i jiná čísla `asset:N`). 
- Ostatní ztráty (`clicks_to_rare_destination`, `uplink_saturation`) a zisky (`disk_full_backup_failure`, `dns_ttl_misconfig`, `data_destruction_smb_wave`, `c2_dns_txt_beacon`, `ssh_bruteforce`) mají týž mechanismus: když se klíč nevyvrátí, zůstane otevřený a dedup (C7) pohltí pozdější výskyt bez eskalace; opačně zmizí pohlcení pod vyvráceným klíčem.

Podle předregistrace se po ladicím běhu kód **nemění**: K20-2 neprošlo jen kvůli jednotlivým útokům s výše uvedeným mechanismem (dedup otevřeného klíče, cesta C7, kterou krok 20 neřeší) a kvůli neškodné rodině `hn_*`, kterou kritérium kroku 19 počítá mezi „rodiny“. Definice kritéria se nemění; na držených seedech se hlásí tak, jak byla předregistrována, a pokles `hn_*` se uvede zvlášť. Předpověď z auditu (FP u RG o několik procent) se nepotvrdila: zobrazené FP rostou o 1,8 %, protože většina vyvrácených nálezů s vysokým dopadem se zobrazovala už při otevření případu a eskalace přidá zobrazení jen u zbytku.
