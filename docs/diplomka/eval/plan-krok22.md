# Krok 22: plán (fáze PLAN cyklu Plan-Do-Check-Act)

Datum: 2026-11-19. Výchozí stav: `3f8ae95` (konec kroku 21). Zadání: `F:\work-tmp\briefs\krok22-plan.txt`. Závazný rozsah: `docs/diplomka/rozsah-autonomie.md`. Registr nálezů: `rozhodnuti-jadra.md` (dále „registr“). Tento dokument je jen plán; kód se v této fázi nemění.

**Cíl kroku podle rozhodnutí vedoucího:** jádro je primární; cílem je jistota o tom, co brána zavření umí a neumí, ne další ladění. Krok 21 ukázal, že „0 omylem zavřených“ s bránou vzniká tím, že se nezavře nic (`impl-krok21.md` 5 a 6 a). Krok 22 má (a) odstranit dvě ověřené vady kontextové brány, (b) dát měřicí nástroj pro hranici automatizace (stínové lístky) a (c) poprvé vytvořit prostředí, ve kterém lze správně zavírat, bez kruhovosti.

## 0. Ověřená fakta, na kterých plán stojí

| fakt | zdroj | ověřeno v této fázi |
|---|---|---|
| s bránou 0 vyvrácení a 0 automatických zavření na 120 držených sítích; `gate_refused` = 0 | `impl-krok21.md` 5, 6 a | převzato (měření kroku 21) |
| historie vrací `Insufficient`, dokud nemá ≥ 3 dny (`New`) nebo ≥ 2 dny výskytu (`Seen`); profil hostu je zralý po 5 dnech | `src/flow_history.rs:207-218`, `src/behavior/profile.rs:68` (`mature_s: 5 * 86_400`) | **ano, čtením** |
| soak má 2 virtuální dny na síť | `networks.jsonl` (`virtual_days` 2,0), např. `F:\work-tmp\k21\held\off-F-20270201` | ano |
| simulované záznamy kontextu vznikají **z pravdy o neškodném jevu** (`truth.victim_devices`, `truth.attacker_device`), `sources` jsou prázdné kromě skeneru; skener má rozsah jen při `scanner_scope` a ten je opět `victim_devices` | `src/soak/v3.rs:393-457` | ano, čtením |
| N14: v `explain_decision` se `source_proven` kontroluje (a nastaví `ambiguous`) před shodou hostu | `src/context_gate.rs:540-553` | ano, čtením |
| N13: `hosts` záznamu skeneru se porovnává s hostem nálezu, ne s cíli | `src/context_gate.rs:547-553`, test `known_gap_scanner_scope_does_not_match_finding_host_of_egress_scan` | převzato (test kroku 21) |
| cena soaku: 480 sítí držených běhů kroku 21 = 10,1 h CPU, tj. ≈ 76 s CPU na síť (2 dny); 132 úloh (528 sítí) při 8 paralelních úlohách ≈ 1 h 26 min reálného času | `F:\work-tmp\k21\held/*/networks.jsonl` (`elapsed_wall_s`), `jobs.txt.log` | ano |
| laboratoř kroku 17 existuje (Docker, role A: provozní služby, B: DNS tunel/DoH), štítky dává skript | `labs/k17`, `impl-krok17.md` | ano (výpis) |

### 0.1 Oprava kritéria hranice (zjištěno při plánování)

Kandidátní kritérium „Wilsonova horní mez < 1 % a ≥ 300 správných zavření“ je při n = 300 **nesplnitelné**: s 0 omyly je horní mez Wilson 95 % = z²/(n + z²) = 1,26 %. Minimální počet zavření v buňce, aby horní mez klesla pod 1 %:

| omylem zavřených v buňce | minimální počet zavření v buňce (Wilson 95 %, oboustranný z = 1,96) |
|---|---|
| 0 | 381 |
| 1 | 563 |
| 2 | 726 |
| 3 | 878 |

Plán proto používá kritérium **„horní mez Wilson 95 % podílu omylů mezi zavřeními < 1 %“** (z něj plyne n ≥ 381); podmínka „≥ 300 správných“ zůstává jako dolní hranice pro hlášení, ne pro zapnutí. Jmenovatel = všechna zavření v buňce (správná + omylem), omyl = omylem zavřené ve smyslu cf **nebo** příčinně (sjednocení, přísnější z obou definic kroku 19).

## 1. PLAN

### 1.1 Měřitelné cíle kroku

| ID | cíl | měřitelné kritérium (zapsáno před měřením) |
|---|---|---|
| G1 | kontextová brána bez vad N14 a N13 | sondy `known_gap_strict_close_flags_ambiguous_from_other_host_record` a `known_gap_scanner_scope_does_not_match_finding_host_of_egress_scan` převrácené na pozitivní testy projdou; bez přepínače bitově shodné výstupy s krokem 21 (K22-6) |
| G2 | odstranit artefakt +5,6 % zobrazených FP u brány | na držených seedech K22-3 (sekce 1.5) |
| G3 | změřitelná hranice automatizace v simulaci | tabulka buněk (druh pozitivního důkazu × typ nálezu) se správnými a omylem zavřenými (stínové lístky), Wilsonovou horní mezí a n; ve světě v2 aspoň jedna buňka s n ≥ 381 **nebo** zdůvodněný údaj, kolik dní/sítí by k tomu bylo třeba |
| G4 | brána umí správně zavřít na reálných datech | v laboratoři C (1.2 bod E4) aspoň jeden lístek pro každý druh pozitivního důkazu, který laboratoř vytváří, a 0 lístků na útocích uvnitř okna kontextu |
| G5 | zachovat bezpečnost | 0 omylem zavřených ve všech gated ramenech všech běhů; detekce po rodinách nesnížená (K20-2) |

Mimo cíle kroku: zapnout automatické zavírání v produkci (pravidlo 6 `rozsah-autonomie.md`: autonomie jen podle stínového provozu na reálných datech; simulace autonomii nepřiděluje, jen určuje kandidáty).

### 1.2 Body práce seřazené podle přínosu k jistotě na jednotku nákladu

Odhad nákladů: tokeny = práce agenta (čtení, kód, testy, dokumentace), stroj = CPU/reálný čas běhů. „Stojí za to“ = poměr jistoty a ceny.

#### B1. Rozbor dvou nerozebraných omylem vyvrácených ze seedu 20270207 (síť 0, rameno R)

- **Příčina / fakta:** `impl-krok21.md` 6 b: 2 příčinně omylem vyvrácené nejsou ve stopách; tvrzení „všechny rozebrané případy brána zablokuje“ má tak výjimku bez důkazu.
- **Co se změní:** nic v kódu; deterministické opakování běhu R 20270207 s `K15_TRACE` (jako v kroku 21: stopa jen čte, seed se neladí) a rozbor skriptem `rca21.py`.
- **Riziko:** že případy mají jiný vzor (např. silná skupina + omyl), který by brána pustila; to je přesně důvod to udělat.
- **Měření a kritérium (předem):** přijato, pokud oba případy mají příčinu zapsanou v tabulce 6 b (jedna slabá skupina, bez pozitivního důkazu s vlastníkem) a test brány na rekonstruovaném rozhodnutí vrátí `Refusal`. Zamítnutí (= nový nález K22-N1, vysoká priorita), pokud některý případ obsahuje pozitivní důkaz s vlastníkem nebo dvě nezávislé skupiny.
- **Náklad:** ≈ 30 tis. tokenů, ≈ 10 min stroje. **Stojí za to:** ano, nejlevnější uzavření mezery v tvrzení o R1.

#### B2. Oprava N14 (shoda hostu a zdroje před přísnou kontrolou) za přepínačem

- **Příčina / fakta:** registr K21-N14; `context_gate.rs:540` (`source_proven` → `ambiguous = true`) běží před `:547` (`host_match`). Záznam o cizím hostu tak označí nález jako nejednoznačný, s `protect` vznikne P5 a nález se zobrazí hned (`episode.rs:1850`, `:1975`). V 20270208/0: 162 ze 164 navíc zobrazených FP.
- **Co se změní:** v `explain_decision` se pořadí změní na: aktivní a pokrývá typ → `admits` → shoda hostu → shoda zdroje (u zdrojového záznamu) → `source_proven`. `ambiguous` nastaví jen záznam, který se nálezu týká (shoda hostu). Za novým přepínačem `ctx_host_first` (V3Features), zapnutým v rameni brány `close_gate` kroku 22; `final` bez přepínače beze změny (K21-6 zůstává platné).
- **Riziko:** (i) skrytý FN: záznam, který se týká hostu, ale ne zdroje, dnes nález „ochrání“ (zobrazí); po změně zůstane stejně (kontrola zdroje se jen posune), ověřit testem; (ii) změna `final` později → měřit na nových držených seedech.
- **Měření a kritérium (předem):** jednotkové testy: (a) záznam jiného hostu → `ambiguous = false`, rozhodnutí jako bez záznamu; (b) záznam téhož hostu bez doloženého zdroje → `ambiguous = true` (beze změny); (c) dnešní `known_gap_*` test převrácen na pozitivní. Stopa 20270208/0 (diagnostika, ne rozhodnutí): z 162 nálezů `connection_timeout_burst` s `protected` jen v RG zmizí ≥ 95 %. Na držených seedech K22-3.
- **Náklad:** ≈ 80 tis. tokenů, ≈ 20 min stroje (testy, stopa). **Stojí za to:** ano; ověřená příčina, malá změna, odstraní největší známý artefakt FP.

#### B3. Oprava N13 (rozsah skeneru se porovnává s cíli nálezu)

- **Příčina / fakta:** registr K21-N13; `GateInput` nemá cíle nálezu; `hosts` záznamu se porovnává s `input.host_ids` (u skenu ven přes bránu je hostem brána). Měřicí přepínač kroku 21 byl proto nefunkční (6 c).
- **Co se změní:** `GateInput` dostane `targets` (cíle nálezu, z flow/nálezu); u záznamu druhu `AuthorizedScanner` platí: zdroj nálezu ∈ `sources` **a** všechny cíle nálezu ∈ rozsah (`hosts`, podporuje CIDR jako dnes adresy); prázdný rozsah = nedoloženo (beze změny, `strictly_proven`). Ostatní druhy záznamů beze změny. Za stejným přepínačem jako B2 (jedna sada „kontext v2“, aby ramen nebylo víc). Měřicí přepínač `K21_SCANNER_SCOPE` se odstraní (nahradí ho svět v2, B5).
- **Riziko:** sken mimo rozsah, ale se zdrojem skeneru, se dnes v přísném režimu nezavře a nadále nezavře (správně); riziko je jen v nesprávném plnění `targets` (cíle z agregovaného nálezu `breadth`/`fanout2` jsou množina; neúplná množina by mohla zavřít sken, který rozsah překročil) → kontrola „všechny cíle v rozsahu“ a test s jedním cílem mimo rozsah.
- **Měření a kritérium (předem):** test „sken ven přes bránu, rozsah = vnější cíl, zdroj = skener → vysvětleno“; test „jeden cíl mimo rozsah → nevysvětleno“; test „zdroj skeneru + útok ze stejného zařízení na cíl v rozsahu v tomtéž okně“ → hlášeno jako `ambiguous`/nezavřeno, pokud nález nese jiný typ než sken (rozhodnutí podle `explicitly_covers`). Účinek v soaku se měří až ve světě v2 (dnes simulace rozsah negeneruje).
- **Náklad:** ≈ 100 tis. tokenů, ≈ 20 min stroje. **Stojí za to:** ano, ale samostatně v soaku neměřitelné; hodnota se ukáže až s B5 a v laboratoři (B6).

#### B4. Stínové lístky a měřená tabulka hranice

- **Příčina / fakta:** registr 6 bod 3; krok 21: k bráně se nic nedostane, protože `strict_refute` vyvrácení zastaví dřív (`verify_ladder.rs:1392`), a kontext je s přísným doložením vždy `undetermined`. Hranici nelze měřit z toho, co se skutečně zavře.
- **Co se změní:** režim `shadow` brány: (a) pro každé rozhodnutí žebříku s P ≤ `p_refute` a pro každý kontext, který nález vysvětlí, se zavolá `admit_ladder`/`admit_context` nad **týmiž vstupy**; (b) výsledek (lístek nebo `Refusal` s důvodem) se zapíše do `shadow_tickets.jsonl` s klíčem, typem nálezu, druhem pozitivního důkazu (skupina 4: `context:<druh>`, `allowlist`, `owner_record`), skupinami, P, časem; (c) **nic se nezavře** a zobrazení se nemění. V soaku se k záznamu doplní pravda (útok v okně cf, příčinně) až při vyhodnocení (`tools/k22_shadow.py`), ne v enginu. Buňka = (druh pozitivního důkazu × typ nálezu). Vyhodnocení: n, správná, omylem (sjednocení cf a příčinně), Wilson 95 % horní mez, odmítnutí podle důvodu.
- **Riziko:** (i) stínový lístek se liší od skutečného, pokud by skutečné zavření změnilo další průběh (pohlcení dalších výskytů) — stín měří jen rozhodnutí, ne následky; proto se v buňce hlásí i počet následných výskytů téhož klíče do 24 h (co by pohltilo zavření) a jejich pravda; (ii) sdílený kód: stínové volání nesmí měnit stav (`&self`, bez zápisu do paměti) → test a K22-6.
- **Měření a kritérium (předem):** K22-6: se stínovým režimem i bez něj bitově shodné `networks.jsonl` (kromě časů) s krokem 21 na ladicích seedech 20269701 a 20269703. Kontrola smyslu: na rameni R (bez brány) musí stínový záznam obsahovat všech 14 automatických zavření a 1 529 vyvrácení ze `scan` běhu jako „bez pozitivního důkazu“ odmítnutá (shoda počtu ± 0).
- **Náklad:** ≈ 150 tis. tokenů, ≈ 1 h stroje. **Stojí za to:** ano; bez něj nelze hranici měřit vůbec a je to čistě měřicí změna.

#### B5. Svět simulace v2: záznamy kontextu se zdroji, skener s rozsahem, delší horizont (předregistrovaná změna světa)

- **Příčina / fakta:** registr K21-N15, K21-N16, K21-N13; `soak/v3.rs:393-457` tvoří záznam **z pravdy** neškodného jevu, takže záznam je dnes orákulum (když existuje, je přesný; nikdy nepokrývá útok v okně kromě shody zařízení). To je samo o sobě nerealistické a zároveň kruhové v opačném směru.
- **Princip proti kruhovosti:** kalendář je **příčina**, ne popis pravdy. Generátor nejdřív podle rolí sítě vytvoří plán provozu (zálohy, dávky, patch okna, autorizované skeny, servisní okna) nezávisle na útocích; neškodné jevy pak vznikají z plánu; útoky se generují nezávisle (jako dnes) a smí se s oknem překrývat v čase, hostu i zdroji. Parametry světa se odvodí z veřejně doložitelné praxe, ne z výsledku brány, a zapíší se před prvním během:
  - záloha: denně v noci, zdroj = zálohovací server (role), cíle = chráněné servery a klienti z inventáře; záznam `Backup` má `sources = [zálohovací server]`, `hosts = cíle`;
  - patch okno: měsíčně (druhé úterý) + mimořádné; zdroj = server aktualizací (WSUS/repo), `hosts` = skupina;
  - autorizovaný sken zranitelností: týdně, zdroj = skener, rozsah = **vnitřní podsítě i vnější cíle** podle konfigurace skeneru (ne podle obětí);
  - dávka: denně, hostitel dávky = zdroj, cíle = databázový/souborový server;
  - nedokonalost kalendáře (předem, ne laděno): 10 % jevů bez záznamu, 5 % záznamů bez jevu (zrušené okno), 5 % záznamů s posunutým oknem ± 1 h; útoky **v okně** kontextu se nechají vznikat přirozeně z nezávislého generátoru a navíc jako předem stanovený podíl scénářů „útok ze zálohovacího serveru/skeneru“ (kompromitace infrastruktury, 2 % útoků), aby svět obsahoval i nejtěžší případy pro R1.
  - horizont: 7 virtuálních dní na síť (profil zralý po 5 dnech, historie po 3; kódové konstanty, ne výsledek). Měří se jen dny 6 a 7, dny 1 až 5 jsou zahřátí (zobrazení a detekce se v nich hlásí zvlášť).
- **Co se změní:** `SimContext::for_cycle` a generátor plánu provozu v `soak` (nový modul `soak/calendar.rs`), parametr horizontu; `scanner_scope` z `for_cycle` zmizí. Engine se nemění.
- **Riziko:** (i) svět v2 je stále simulace a jeho čísla neplatí pro reálnou síť (rozsah-autonomie „co nelze slíbit“); (ii) parametry kalendáře určují počty v buňkách → hlásí se citlivost (viz 3); (iii) cena: 3,5× delší běh.
- **Měření a kritérium (předem):** validita světa nezávisle na bráně (kontroluje se před prvním gated během, na ladicích seedech, ramena F a R): podíl neškodných jevů se záznamem 90 % ± 2 %; podíl útoků, jejichž zdroj nebo cíl leží v aktivním okně kontextu, se hlásí (není cíl); rameno R (bez brány) ve světě v2 musí mít **víc** kontextových zavření než ve světě v1 (jinak svět nedodává pozitivní důkaz). Pokud validita neprojde, opraví se generátor na ladicích seedech a zapíše se změna; held se nespouští.
- **Náklad:** ≈ 250 tis. tokenů, ladicí běhy ≈ 1,5 h reálného času (viz 5). **Stojí za to:** ano, je to jediná cesta, jak v simulaci vůbec dostat správné zavření; bez B4 však nelze nic odečíst.

#### B6. Laboratoř C: nezávislý zdroj pozitivního důkazu na reálném provozu

- **Příčina / fakta:** registr 6 bod 2; svět v2 je stále autorovo dílo. Laboratoř kroku 17 dodává reálný provoz se štítky ze skriptu.
- **Co se změní:** nová sada `labs/k22` (rozšíření rolí z `labs/k17`): skutečná záloha (`rsync` ze zálohovacího kontejneru na 2 servery, noční okno zrychlené), skutečný autorizovaný sken (`nmap -sV` na vnitřní podsíť z kontejneru skeneru), skutečná dávka (`pg_dump`). Kalendář (`context-calendar.json` ve formátu `admit_context`, s vlastníkem a expirací) píše operátor laboratoře **před** během podle plánu úloh, ne z výsledků. Útoky: (A) sken z jiného kontejneru v okně skenu, (B) exfiltrace ze zálohovacího kontejneru v okně zálohy (kompromitace infrastruktury), (C) sken cíle mimo rozsah z kontejneru skeneru. Zachycení Zeek, přehrání jako v kroku 17 s `SALTICUS_REPLAY_NOW`.
- **Riziko:** malé n (jednotky až desítky relací) → ověřuje sémantiku, ne míru; laboratoř staví autor brány (hrozba validity jako v kroku 17).
- **Měření a kritérium (předem):** lístek (ve stínu) vydán pro každou neškodnou relaci s úplným záznamem (≥ 90 % relací); **0 lístků** pro útoky A, B, C (každý aspoň 3 relace); relace bez záznamu → „nelze určit“, nezavřeno. Zamítnutí: jakýkoli lístek na útoku = nový nález, oprava před dalším krokem.
- **Náklad:** ≈ 150 tis. tokenů, ≈ 3 h stroje (Docker, 2 sady: ladicí seed 22001, držená 22101). **Stojí za to:** ano, jediný nesimulovaný důkaz, že brána umí zavřít správně a odmítnout útok v okně; levnější než velké soaky.

#### B7. Sdílená funkce cyklu soak/produkce a soak s restartem každý cyklus (registr 4.2)

- **Příčina / fakta:** dvě kopie orchestrace (`soak/episode.rs`, `pipeline/v3.rs`), ověřené rozdíly 1 až 5 v registru 4.2; FG21P ukázal +0,5 % FP z pevné apriorní P, zavírání neotestováno.
- **Co se změní:** jedna funkce `cycle::step(memory, context, ladder, gate, obs) -> CycleOutput` volaná z obou míst; soak dostane režim `restart_each_cycle` (flush + načtení z SQLite).
- **Riziko:** velká změna (stovky řádků) v logice zavírání; regrese.
- **Měření a kritérium (předem):** shoda výstupu sdílené funkce se současným soakem bitově (K20-6 obdoba) na ladicích seedech; s `restart_each_cycle` hlásit rozdíl zavření a FP (diagnostika produkčního chování).
- **Náklad:** ≈ 500 tis. tokenů, ≈ 2 h stroje. **Stojí za to:** **až po B4 a B5.** Dokud se nic nezavírá, rozdíl soak/produkce v zavírání nelze změřit; bez zavíratelných případů by refaktor přinesl jen jistotu o zobrazení (již změřeno FG21P).

#### B8. Pravidlo epizody i pro otevřený klíč (registr 4.1, C7)

- **Fakta:** sonda `known_gap_open_key_absorbs_new_episode_silently`.
- **Změna:** jedno pravidlo epizody (`episode_s` = 1 h) pro všechny stavy; nahradí `redisplay`, `redisplay_age`, `reopen_stale` (M7).
- **Riziko:** nárůst FP u periodických neškodných jevů (zálohy s mezerou > 1 h) — ve světě v2 měřitelné.
- **Kritérium (předem):** detekce po rodinách útoků s opakovanými epizodami ≥ F; FP ≤ 1,02 × F; případy pro člověka ≤ +2 %.
- **Náklad:** ≈ 120 tis. tokenů + držený běh. **Stojí za to:** střední; týká se detekce, ne hranice zavírání. Odloženo do kroku 23 (viz 1.4).

#### B9. Registr chráněných prostředků (registr 4.3, M16)

- **Změna:** `protected-assets.json` (asset, adresy, vlastník, důvod, expirace), `Subject.protected |= host ∈ registr`, štít v paměti.
- **Riziko:** falešný pocit ochrany při neúplném registru.
- **Kritérium:** v simulaci v2 0 lístků (ani stínových) na hostech v registru; cena v případech pro člověka se hlásí.
- **Náklad:** ≈ 150 tis. tokenů. **Stojí za to:** nutné **před** jakýmkoli zapnutím autonomie (R2), ale pro měření hranice ve stínu nepotřebné: ve stínu se buňky dají filtrovat podle role hostu dodatečně. Odloženo do kroku 23.

### 1.3 Etapy, pořadí a body zastavení

| etapa | body | Check (co se změří) | Act |
|---|---|---|---|
| **E0** předregistrace a levné uzavření mezer | B1; zápis předregistrace K22 (sekce 1.5, 2) do `impl-krok22.md` a commit **před** kódem | B1 kritérium | B1 přijato → E1; zamítnuto → nový nález, opravit dřív než cokoli dalšího |
| **E1** kontext v2 + stín | B2, B3, B4 (testy, stopa 20270208/0, K22-6 na ladicích seedech) | testy, K22-6, kontrola smyslu stínu na rameni R (14 a 1 529) | vše projde → E2; K22-6 neprojde → oprava (nesmí se měnit nic bez přepínače); stín nesouhlasí s R → stín je chybný, opravit, ne pokračovat |
| **E2** svět v2 (ladicí) a laboratoř C | B5 na ladicích seedech; B6 (ladicí sada 22001, pak držená 22101 jednou) | validita světa (B5), kritéria B6 | validita a B6 projdou → zmrazit kód a svět (commit) → E3; laboratoř dá lístek na útoku → oprava brány, E3 se nespouští; svět neprojde validitou → upravit generátor (zapsat), znovu ladicí |
| **E3** držený běh (jednou) | ramena na 20270301 až 20270310 (sekce 2) | K22-1 až K22-5, tabulka hranice | výsledek se hlásí, ať je jakýkoli; kód se po něm nemění. Buňky s horní mezí < 1 % → kandidáti pro stínový provoz (sekce 4), ne pro zapnutí |
| **E4** (podmíněně) | B7 | bitová shoda, `restart_each_cycle` | jen když E3 dá aspoň jednu buňku s n ≥ 100 (jinak není co porovnávat) |

### 1.4 Co se vědomě NEDĚLÁ a proč

- **Ladění prahů žebříku (`p_refute`, LR, apriorní P) a brány** — zakázáno zadáním; 99 % případů nedosáhne P ≤ 0,03 kvůli horizontu, ne kvůli prahu (registr 6, odmítnutá alternativa ii).
- **Zmírnění brány** (živost nebo historie bez vlastníka jako pozitivní důkaz) — přesně tento vzor dává 40 omylem vyvrácených v R (odmítnutá alternativa i).
- **Zapnutí automatického zavírání** kdekoli — ani při splnění kritéria v simulaci (pravidlo 6).
- **B8, B9** v tomto kroku — nemění měřitelnost hranice; B9 je podmínka před autonomií, ne před stínem.
- **N5, N8, N9** (souběh, skok hodin, vyřazení) — produkční robustnost, v soaku neměřitelné, nízké až střední riziko; krok 23.
- **N6, N7, N10, N11, N12** — návrhy z registru; N6 (lhoucí agent) se ve světě v2 projeví jen v `elying`, hlásí se buňka `allowlist` zvlášť a do kandidátů nepřechází, dokud N6 není opraveno.
- **Uložení lístku do SQLite** (N4) — nebezpečný směr; až po B7.
- **Úprava simulace kvůli bráně** mimo pravidla B5 (např. přidat zdroje jen tam, kde by zavření bylo správné) — kruhovost (sekce 3).
- **Veřejné datasety DoH/tunelu** s formulářem osobních údajů (D17-1).

### 1.5 Prahy kroku 22 (předregistrace, platí pro E3)

| práh | metrika | splněno, když |
|---|---|---|
| K22-1 | omylem zavřená (skutečná, ne stínová) zavření ve FG22 | 0 ve všech konfiguracích; hlásí se i n zavření a Wilson |
| K22-2 | detekce po rodinách a souhrnná, FG22 vs F22 | jako K20-2 (žádná rodina nižší o víc než 1 útok, souhrn ≥) |
| K22-3 | zobrazené FP | FG22/F22 ≤ 1,01 **a** F22c/F22 ≤ 1,00 (oprava N14 nemá FP zvýšit) |
| K22-4 | případy pro člověka FG22 vs F22 | nárůst ≤ 2 % |
| K22-5 | tabulka hranice (stín) | hlásí se pro každou buňku n, správná, omylem, horní mez; **buňka je kandidát**, když horní mez < 1 % (tj. n ≥ 381 s 0 omyly) |
| K22-6 | regrese bez přepínačů | bitová shoda s krokem 21 na ladicích seedech (kromě časů) |
| K22-7 | svět v1 vs v2 (diagnostika) | hlásí se změna FP, detekce a počtu stínových lístků; bez prahu |

Předpověď zapsaná předem: protože `final` má `strict_close` také (FG = F ve FP, `impl-krok21.md` 6 d), artefakt N14 je i ve `final`; čekám F22c/F22 ≈ 0,95 (pokles zobrazených FP o 3 až 6 %). FG22 bude mít skutečná zavření jen tehdy, když `strict_refute` dovolí vyvrácení se dvěma skupinami včetně pozitivního důkazu; ve světě v2 čekám desítky až nízké stovky stínových lístků na kontext (zálohy, skeny) za 40 sítí a konfiguraci, tedy **žádnou buňku s n ≥ 381 po rozdělení podle typu nálezu**. Pokud se to potvrdí, výsledkem E3 je odhad potřebného objemu (sítě × dny) pro každou buňku, ne kandidát.

## 2. Plán měření

**Rozdělení seedů (zapsáno dopředu):**

| sada | seedy | použití |
|---|---|---|
| ladicí (stávající) | 20269701, 20269703 | K22-6 regrese, kontrola stínu |
| ladicí svět v2 | 20269801 až 20269805 | vývoj a validita světa v2; smí se použít opakovaně |
| **držená** | **20270301, 20270302, 20270303, 20270304, 20270305, 20270306, 20270307, 20270308, 20270309, 20270310** | jen E3, **jednou**, po zmrazení kódu a světa commitem |
| stopy | 20270207 (R), 20270208 (R, RG) | jen B1 a diagnostika B2; tyto seedy už byly použity jako držené v kroku 21, rozhodnutí se o ně neopírá |
| laboratoř C | 22001 (ladicí), 22101 (držená, jednou) | B6 |

**Ramena E3** (svět v2, horizont 7 dní, 4 sítě na seed, `--threads 1`, společné volby jako krok 21): **F22** (`final`), **F22c** (`final` + kontext v2, ukáže účinek N14 bez brány), **FG22** (`final` + `close_gate` + kontext v2 + stín). Rameno R (bez brány, se stínem) jen v konfiguraci `off` jako referenční „co by zavřel systém bez brány“. Konfigurace `off`, `ops`, `elying`.

**Protokol 10 seedů × 3 konfigurace jen tam, kde je potřeba:** ano pro F22, F22c, FG22 (rozhodovací čísla K22-1 až K22-5). Rameno R jen `off` (diagnostika). Ladicí běhy jen `off` a 2 až 5 seedů.

**Co lze ověřit bez dalšího soaku:**

- B1: stopa deterministického opakování;
- B2, B3: jednotkové testy, převrácené `known_gap_*`, stopa 20270208/0;
- B4: K22-6 (bitová shoda) a kontrola smyslu na existujících bězích ramena R ze `scan`;
- invarianty: fuzz pravdivého invariantu kroku 21 (5 000 posloupností s restarty) se stínovým režimem, 0 porušení a 0 zápisů stínu do paměti;
- B6: laboratoř C (reálný provoz).

**Vyhodnocení:** `tools/k22_shadow.py` (tabulka buněk, Wilson), `tools/k22_gate.py` (K22-1 až K22-4, vzor `k21_gate.py`). Skripty se napíšou a otestují na ladicích bězích **před** E3.

## 3. Registr rizik a předpokladů

| ID | předpoklad / riziko | co když neplatí | zmírnění |
|---|---|---|---|
| A1 | **kruhovost:** svět v2 je navržen tak, aby brána vypadala dobře | čísla hranice jsou artefaktem autora | parametry B5 zapsány předem z praxe, ne z výsledku; svět obsahuje i nejtěžší případy (útok z infrastruktury v okně); validita světa se kontroluje na rameni F a R, ne na bráně; laboratoř C jako nezávislá kontrola; výsledek E3 se hlásí, ať je jakýkoli |
| A2 | kalendář jako příčina neškodných jevů odpovídá realitě | v reálné síti jsou záznamy horší (chybí, nepřesné) | parametry nedokonalosti (10/5/5 %) se hlásí; citlivostní běh na ladicích seedech s dvojnásobnou nedokonalostí (diagnostika, ne rozhodnutí) |
| A3 | **závislost na simulaci:** buňky z E3 nic neříkají o reálné síti | přenos závěrů je neoprávněný | pravidlo 6: simulace dává jen kandidáty; autonomie jen ze stínového provozu na reálných datech (sekce 4) |
| A4 | stínový lístek = skutečný lístek | stín podhodnotí následky zavření (pohlcení dalších výskytů) | hlásí se následné výskyty klíče do 24 h a jejich pravda; po B7 porovnat se skutečným zavíráním |
| A5 | 7 dní stačí k dozrání historie a profilu | i po 7 dnech eskalace `nezjisteno` | hlásí se rozklad důvodů eskalace po dnech (`ladder_block.py`); když podíl P ≤ 0,03 zůstane < 5 %, závěr: hranici omezuje žebřík, ne svět |
| A6 | definice omylu (cf ∪ příčinně) zachytí všechny špatné zavření | omyl, který není ani cf, ani příčinný (např. zavření, které skryje pozdější fázi útoku) | následné výskyty (A4); ruční kontrola 30 případů (sekce 4) |
| A7 | buňky dosáhnou n ≥ 381 | nedosáhnou (pravděpodobné, 1.5) | výstupem je potřebný objem; žádné slučování buněk kvůli dosažení n (slučování jen jako předem zapsaná diagnostika po druhu důkazu) |
| A8 | N14 oprava nezpůsobí skrytý FN | nález, který dnes zobrazí P5, by po opravě šel do ověření a byl skryt `verifying` | K22-2; párování nálezů F22 vs F22c na seedu s největším rozdílem |
| A9 | laboratoř C reprezentuje skutečné zálohy a skeny | provoz skutečných nástrojů v síti s jiným hardwarem vypadá jinak | uvádí se jako hrozba validity; stínový provoz v reálné síti (sekce 4) |
| A10 | autor plánu a implementace je tentýž model | slepá místa se nezachytí | ruční posouzení člověkem (sekce 4); nezávislé review plánu v hlavní konverzaci před E1 (tato fáze ho podle zadání nespouští) |
| A11 | O1 až O3 kroku 21 se ve světě v2 poprvé uplatní | nečekané interakce se stínem | fuzz invariantu se stínem; K22-1 |

## 4. Nezávislé posouzení a stínový provoz

### 4.1 30 případů k ručnímu posouzení člověkem

**Výběr (skript `tools/k22_pick30.py`, seed výběru 2203, zapsáno předem, z držených běhů E3 rameno FG22):** stratifikovaný náhodný výběr:

| vrstva | počet | proč |
|---|---|---|
| stínový lístek na kontext, pravda neškodné | 8 | správnost hranice |
| stínový lístek na žebřík, pravda neškodné | 4 | |
| stínový lístek, pravda útok (všechny, pokud ≤ 4; jinak náhodně) | 4 | nejcennější; když jich je 0, doplní se z ramena R (zavření bez brány na útoku) |
| odmítnuto bránou, pravda neškodné | 6 | cena přísnosti |
| eskalováno člověku s případovou složkou, pravda útok | 4 | kvalita složky |
| eskalováno člověku, pravda neškodné | 4 | zátěž |

Plus 5 až 10 relací z laboratoře C (reálný provoz) jako samostatná vrstva, pokud posuzovatel stihne.

**Formát:** složka `k22-review/case-NN/` s `slozka.md` (případová složka: časová osa, aktéři, hypotézy, důkazy pro a proti, co chybí; bez pravdy, bez rozhodnutí brány a bez názvu ramena), `dukazy.json` (strojová podoba), pořadí náhodné. Klíč (pravda, rozhodnutí brány, vrstva) v odděleném souboru `klic.json` mimo předávanou složku. Formulář `odpovedi.csv`: `case | rozhodnutí (zavřít / eskalovat / nelze určit) | jistota 1–5 | co chybí | čas v minutách | poznámka`. Vyhodnocení: shoda člověka s pravdou, s bránou (Cohenovo κ), a hlavně případy, kde by člověk zavřel a brána ne a naopak. Posuzovatel: ideálně analytik s praxí (vedoucí určí); předem se domluví, že posuzuje věrohodnost rozhodnutí z dostupných důkazů, ne simulátor.

### 4.2 Návrh stínového provozu (jen návrh)

- **Laboratoř (bez souhlasu třetích stran):** laboratoř C běží nepřetržitě 7 dní s plánem úloh a náhodným rozvrhem útoků od pomocného skriptu (rozvrh skrytý, odhalí se až při vyhodnocení); Salticus ve stínovém režimu, nic neřídí. Odhad: desítky lístků týdně; ověří sémantiku, ne míru.
- **Domácí síť (jen se souhlasem uživatele, nic se nedotýká bez něj):** pasivně Zeek na zrcadleném portu nebo na routeru, žádné aktivní sondy, žádné vynucení; kalendář kontextu vede člověk (zálohy NAS, aktualizace); týdně ruční označení vzorku stínových lístků. Odhad: v domácí síti stovky lístků za měsíc jen pro málo buněk (zálohy, aktualizace); n ≥ 381 na buňku je realistické jen pro 1 až 2 buňky za 1 až 3 měsíce. Údaje zůstávají lokálně, mimo repozitář.
- **Laboratoř UHK** (pokud bude dostupná): stejný postup, větší rozmanitost; vyžaduje souhlas správce.

## 5. Rozpočet

Cena soaku: ≈ 76 s CPU na síť a 2 dny; 7 dní ≈ 270 s CPU na síť. Při 8 paralelních úlohách se reálný čas ≈ CPU / 8.

| etapa | tokeny (odhad) | CPU | reálný čas stroje | poznámka |
|---|---|---|---|---|
| E0 (B1 + předregistrace) | 50 tis. | 0,2 h | 0,2 h | |
| E1 (B2, B3, B4, testy, K22-6) | 330 tis. | 2 h | 0,5 h | regrese 12 úloh × 2 dny + `cargo test` |
| E2 (B5 ladicí, B6 laboratoř C) | 400 tis. | 8 h + Docker 3 h | 1,5 h + 3 h | ladicí svět v2: 5 seedů × 3 ramena × `off` × 4 sítě × 270 s ≈ 4,5 h CPU, plus opakování |
| E3 (držený běh, vyhodnocení, výběr 30 případů) | 200 tis. | 10 × 3 × 3 × 4 = 360 sítí × 270 s ≈ 27 h, R `off` 40 sítí ≈ 3 h; celkem ≈ 30 h | ≈ 3,8 h | |
| E4 (B7, podmíněně) | 500 tis. | 4 h | 1 h | |
| **celkem E0 až E3** | **≈ 1,0 mil.** | **≈ 40 h** | **≈ 9 h** (z toho 3 h Docker) | |
| celkem s E4 | ≈ 1,5 mil. | ≈ 44 h | ≈ 10 h | |

**Minimální etapa s největší jistotou za nejmenší cenu: E0 + E1** (≈ 380 tis. tokenů, < 1 h reálného času stroje). Dává: uzavření mezery 20270207 (R1), opravu dvou ověřených vad kontextové brány s testy, odstranění artefaktu FP (diagnosticky na stopě) a měřicí nástroj (stín), který bez změny chování ukáže, co by brána zavřela. Hned za ní poměrem jistoty a ceny **laboratoř C (B6)**: jediný nesimulovaný důkaz správného zavření a odmítnutí útoku v okně, bez potřeby velkého soaku. Svět v2 a držený běh (E2 část B5, E3) jsou nejdražší a dávají hlavně číslo pro simulaci; spouštět až po E0, E1 a B6.

## Review

Fáze PLAN v tomto zadání nezávislé review nespouští (zadání vylučuje council, sol-loop i delegaci). Podle metodiky repozitáře (`CLAUDE.md`) má plán s prahy před měřením projít nezávislým posouzením v hlavní konverzaci před E1; dokud neproběhne, je plán neposouzený.
