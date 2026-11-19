# Krok 24: rozdělení `sev_calib`, pojistka souběžné aktivity a rozbor FP

Podklad: `impl-krok23.md` (sekce 2.4, 3 a 4) a `impl-krok22.md` (sekce 11 až 14). Vedoucí schválil Act kroku 23: R2 a P6 beze změny, brána se nezmírňuje, E3 (20270301 až 20270310) se nepoužije. Pracovní data: `F:\work-tmp\k24`. Sekce 1 je zapsána a komitnuta **před** jakoukoli změnou kódu kroku 24.

## 1. Předregistrace (zapsáno před kódem)

### 1.1 Seedy (zapsáno dopředu)

| sada | seedy | použití |
|---|---|---|
| regrese | 20269701, 20269703 | K24-6 (bez přepínačů shoda s krokem 21, i se stínem) |
| **ladicí** | **20270461 až 20270465** | měření 1.5, smí se opakovat |
| **držená** | **20270501 až 20270510** | jednou, jen pro kombinaci, která splní všechna svá ladicí kritéria, a jen po zmrazení kódu commitem |
| nepoužít | 20270301 až 20270310 (E3), 20270401 až 20270410 (držené kroku 23), 20270451 až 20270455 (ladicí kroku 23, jen rozbor 1.4) | ne |

### 1.2 Úkol 1: rozdělení `sev_calib`

- **Změna:** dva nové přepínače `V3Features`, výchozí vypnuto: `attr_calib` = O2 (zdroj objemové anomálie podle bajtů a paketů) + O3 (zdroj nespárovaných událostí), `sev_calib_o1` = O1 (závažnost objemových nálezů podle události, nejméně Medium). Stávající `sev_calib` zůstává jako souhrn obou (`attr_calib` + `sev_calib_o1`), aby šly zopakovat běhy kroku 23. `recommended()` se nemění; nové přepínače jsou v něm vypnuté.
- **Zdůvodnění nezávislé na bráně:** O2 a O3 mění jen zdroj nálezu, ne závažnost; R2 (vysoký dopad nezavírá) tedy zůstává pro každý High nález v platnosti a kontext zálohy, který v kroku 23 zavíral, potřeboval obojí (Medium z O1 **a** správný zdroj z O2).
- **Předpověď (zapsáno předem):** `attr_calib` samo nepřidá žádné automatické zavření (0 → 0) ani omylem zavřené; atribuce A1 až A3 jako v kroku 23 (cizí zdroj objemu klesne zhruba z 36 % na 4 %, nespárované bez zdroje ze 100 % na ≈ 12 %); detekce B2 beze změny; zobrazené FP ≤ základ (O2 jen mění zdroj, viz rozbor 1.4: redisplay „nový zdroj“ ubude).

### 1.3 Úkol 2: pojistka souběžné aktivity pro všechny druhy kontextu

- **Změna:** nový přepínač `ctx_activity_guard` (`V3Features`, výchozí vypnuto) → `GatePolicy::activity_guard`. Registrace nálezů cyklu (`ContextGate::note_activity`, 48 h) běží, když je zapnuté `scanner_guard` **nebo** `activity_guard`. S `activity_guard` záznam kontextu `E` **jakéhokoli druhu** nález `N` nevysvětlí ani nepodpoří, když v okně `E` (`E.start ≤ A.at ≤ E.end`) existuje zaznamenaná aktivita `A`, které se **host nálezu** účastní (některý identifikátor hostu `N` je v hostu, zdrojích nebo cílech `A`) a kterou by `E` sám nepokryl. `A` je pokrytá, jen když platí všechno: (a) typ `A` pokrývá `E` (`GatePolicy::covers`, u skeneru jen tvar skenu); (b) zdroje `A` jsou neprázdné a všechny patří záznamu (zdroj nebo host `E`; u skeneru jen zdroje skeneru); (c) host a cíle `A` leží v hostech nebo rozsahu `E` (`targets_in_scope`). Aktivita bez zdroje se tedy nepočítá jako pokrytá (stejně jako přísné doložení zdroje).
- Rozhodnutí je pak nejednoznačné (P5, případ jde člověku) s důvodem `kontext: soubezna aktivita hostu mimo pokryti zaznamu`; důvod jde do paměti (produkční cesta), do stínu se počítá čítačem `k24_activity_foreign` (soak). K22-N3 (souběžná aktivita **zdroje skeneru**) platí beze změny vedle toho.
- **Omezení (předem):** pojistka vidí jen nálezy zaregistrované do okamžiku rozhodnutí (aktivita, která v okně záznamu začne až po zavření, zavření nezastaví) a jen aktivitu, která vytvořila nález (útok bez nálezu na hostu je mez detekce, ne chyba pojistky). Produkční cesta zná jen aktivitu aktuálního běhu (jako K22-N3).
- **Předpověď (zapsáno předem):** pojistka zastaví zavření záloh na hostech se souběžným útokem, který na hostu vytvořil nález; zároveň zastaví i část správných zavření, protože zálohy samy vytvářejí `multi_target_pattern` (typ mimo pokrytí, 13.2 kroku 22) a objemové nálezy bez zdroje. Čekám, že FG2AOG zavře méně než FG2AO (krok 23: 17 na konfiguraci), a nevím, zda B3 projde: záleží na tom, zda souběžné útoky na hostech záloh mají vlastní nález na hostu před zavřením.

### 1.4 Úkol 3: rozbor +1 % zobrazených FP kroku 23 (C1), ze stopy, bez ladění

Proveden před kódem na stopách `F:\work-tmp\k23\lad` (FG2 proti FG2S, ladicí seedy kroku 23), skripty `F:\work-tmp\k24\fp_type.py`, `fp_pair.py`, `fp_reason.py`. FP ve stopě = zobrazený nález bez pravdy v okně (shoda se soak agregací na ±3 %; agregace navíc připisuje okenní neškodné události bez IP).

- **Typ:** celý nárůst je `packet_rate_spike` (+36 až +37 na konfiguraci, agregace `displayed_fp_by_type`); `inductive_volume_anomaly` −7, `novel_fanout` −4, `unmapped_passive_event` +1, ostatní ±3.
- **Důvod zobrazení (objemové typy, na konfiguraci):** FG2 877 → FG2S 895 (+18). `escalated_severity` **3 → 33 (+30)**, `escalated_source` 37 → 24 (−13), první zobrazení + eskalace žebříku + znovuotevření 836 → 838 (+2).
- **Mechanismus:** O1 dá prvnímu výskytu klíče Medium (událost < 10× nad baseline). Medium nález nejde rovnou na obrazovku, ale do žebříku, a ten ho eskaluje (stejný počet zobrazení, jen později: `first` 496 → 201, `ladder_escalated` 167 → 575). Klíč v paměti si ale uloží maximální závažnost Medium; když později na témže klíči přijde událost ≥ 10× (High), paměť to vyhodnotí jako zvýšení závažnosti a nález znovu zobrazí (`escalated_severity`). Bez O1 je klíč High od prvního výskytu a zvýšení nenastane. Jde tedy o **O1**, ne o O2: O2 počet redisplayů „nový zdroj“ snižuje (−13).
- **Zdroj:** z 33 `escalated_severity` FP (off) je 32 `packet_rate_spike`, 15 bez zdroje a 17 se zdrojem; služby na pozadí (8080: 17, 22: 10, 80: 4, 25: 2, 443 a 993: 1); žádná pravda v okně (jedna mimo okno `qos_drops`).
- **Důsledek pro předpověď:** `attr_calib` samo C1 nezhorší; kombinace s O1 ponese +≈ 1,3 % FP z redisplayů závažnosti. Práh C1 se nemění; oprava paměti (například redisplay jen při skoku z Medium na High s novým zdrojem) by byla nová změna s vlastní předregistrací, v tomto kroku se nedělá.

### 1.5 Měření

Svět v2 (`--world-v2`), 168 h, 4 sítě na seed, `--threads 1`, Idle, maska 0x3FFFFC, nejvýš 6 souběžných úloh (≤ 8 vláken), odpojeně, všechny ladicí běhy se stopou (`K15_TRACE`). Tři konfigurace sítí `off`, `ops`, `elying` jako v kroku 23. Ramena navíc k F (`breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate`) a `close_gate,ctx_host_first`:

| rameno | přepínače navíc | role |
|---|---|---|
| FG2 | — | základ |
| FG2A | `attr_calib` | kandidát 1 (úkol 1) |
| FG2AO | `attr_calib,sev_calib_o1` | diagnostika: O1 bez pojistky na nových seedech (jen hlášení) |
| FG2AOG | `attr_calib,sev_calib_o1,ctx_activity_guard` | kandidát 2 (O1 s pojistkou) |
| FG2G | `ctx_activity_guard` | diagnostika: cena pojistky bez kalibrace (jen hlášení) |

Ladicí: 5 seedů × 3 konfigurace × 5 ramen = 75 běhů. Regrese: `reg6` a `regsh6` (24 běhů, bez přepínačů, `regsh6` se stínem `K22_SHADOW`). Vyhodnocení: `tools/k20_gate.py` (páry FG2/FG2A, FG2/FG2AO, FG2/FG2AOG, FG2/FG2G) a `tools/k23_attr.py` (atribuce a závažnost).

### 1.6 Kritéria přijetí (ladicí; stejná pro držené)

Prahy a definice jsou převzaté z kroku 23 beze změny. Každé kritérium se hodnotí v každé ze tří konfigurací.

**Kandidát 1 (FG2A proti FG2):**

| kritérium | splněno, když |
|---|---|
| K24-A1 | objem s pravdou: podíl správných > základ **a** podíl cizích ≤ 0,5 × základ |
| K24-A2 | objem na cílech útoků: podíl správných ≥ základ − 1 p. b. |
| K24-A3 | nespárované: bez zdroje < základ; se zdrojem správně ≥ 90 % (při n ≥ 20) |
| K24-B2 | žádná rodina (n ≥ 20) s poklesem detekce > 1 p. b.; horní mez 95% CI rozdílu > −1 p. b. |
| K24-Z | automatická zavření FG2A ≤ FG2; K20-1 = 0, K20-1b = 0, K20-1c ≤ základ |
| K24-C1 | zobrazené FP FG2A/FG2 ≤ 1,01 |

**Kandidát 2 (FG2AOG proti FG2):** K24-A1 až A3, B2 a C1 jako u kandidáta 1, navíc:

| kritérium | splněno, když |
|---|---|
| K24-B1 | 0 nálezů útoků objemových typů s Low |
| K24-B3 | omyl = definice K20-1 beze změny: automaticky zavřený nález, který zmiňuje (host nebo zdroj) útok aktivní v okně nálezu (± latence atribuce), **i když útok se zavřeným jevem příčinně nesouvisí** (zmínka útoku na hostu v okně stačí). Splněno: K20-1 = 0 (auto i žebřík), K20-1b = 0, K20-1c (útoky pohlcené pod zavřeným klíčem) ≤ základ |

FG2AO a FG2G se jen hlásí (zavření, omyly, FP, blokace pojistky).

**Regrese a kód:** K24-6: `reg6` 48/48 a `regsh6` 48/48 shodných sítí s `F:\work-tmp\k21\reg` (kromě časů). K24-T: jednotkové testy rozdělení (attr bez O1 nemění závažnost; O1 bez attr nemění zdroj; `sev_calib` = `attr_calib` + `sev_calib_o1`) a pojistky (cizí typ, zdroj mimo záznam, cíl mimo host, aktivita bez zdroje → nevysvětleno, nejednoznačné, důvod; pokrytá aktivita, aktivita mimo okno a aktivita jiného hostu → beze změny; pořadí registrace nemění výsledek); property test pojistky (≥ 5 000 kalendářů: s pojistkou nikdy vysvětlení ani podpora při cizí aktivitě hostu v okně; bez zaznamenané aktivity rozhodnutí s pojistkou = bez ní; bez přepínače aktivita nic nemění); `cargo test --lib` bez nových selhání (známá: 5 `broker`, 1 `identity_lab`); `fmt` čisté, `clippy` bez varování ve změněném kódu.

**Rozhodovací pravidlo:** držené seedy 20270501 až 20270510 se spustí (jednou, ramena FG2 a každý kandidát, který prošel) jen pro kandidáta, který na ladicích seedech splní **všechna** svá kritéria, a jen když projdou K24-6 a K24-T a kód je zmrazený commitem (binárka podle hashe). Jinak se držené nespustí a zapíše se proč. Prahy a definice omylu se po výsledku nemění; držený běh se hlásí celý.

## 2. Výsledek (DO)

Commit `493db02` (přepínače `attr_calib`, `sev_calib_o1`, `ctx_activity_guard`; `ContextGate::note_activity` pro všechny druhy kontextu, čítač `k24_activity_foreign`). Binárka `F:\work-tmp\k24\bin\salticus-k24-493db02.exe`. 99 běhů (75 ladicích `F:\work-tmp\k24\lad`, 24 regresních `reg6` a `regsh6`), všechny s kódem 0, 22:35 až 00:22 (≈ 1 h 47 min). Vyhodnocení: `F:\work-tmp\k24\gate_lad.out` (K20 metriky, `gate.py` = `tools/k20_gate.py` s páry kroku 24), `F:\work-tmp\k24\attr_lad.out` (`tools/k23_attr.py`), `extra.py` (zavření podle důvodu, citace pojistek), `fp_reason.py` (FP podle důvodu zobrazení).

### 2.1 Testy a regrese

| kritérium | výsledek | stav |
|---|---|---|
| K24-T rozdělení | `engine::tests::k24_split_switches` (zapojení: `sev_calib` = obě poloviny, každá polovina zvlášť jen svou část, `recommended()` a Legacy bez nich). Chování odděleně stojí na testech kroku 23 (O1, O2 property) a potvrzuje ho měření: FG2A má stejný počet High u `packet_rate_spike` jako FG2 (3 931 = 3 931, `off`), FG2AO má stejnou atribuci jako FG2A (správný zdroj 3 879 = 3 879) | splněno |
| K24-T pojistka | `context_gate::tests::k24_activity_guard_blocks_context_on_host_with_foreign_activity` (cizí typ, zdroj mimo záznam, aktivita bez zdroje, host jako zdroj, cíl mimo host → nevysvětleno, nejednoznačné, důvod `HOST_FOREIGN`, bez podpory, v obou pořadích registrace; bez přepínače a se samotným `scanner_guard` záloha dál zavře; bez aktivity, pokrytá aktivita, aktivita mimo okno a aktivita jiného hostu → beze změny) | splněno |
| K24-T property | `k24_activity_guard_property` (náhodné kalendáře všech druhů; nezávislý výpočet pokrytí; pojistka jen ubírá; bez aktivity totožné; bez přepínačů aktivita nic nemění) | splněno |
| `cargo test --lib` | 711 prošlo, 6 známých selhání (5 `broker`, 1 `identity_lab`), 31 ignorováno; testy `k24` znovu ověřeny na HEAD (3/3) | splněno |
| `fmt`, `clippy` | `fmt` čisté; 124 varování `clippy`, žádné ve změněných řádcích (varování v `anomaly_v3.rs` 276, 287 a `soak/episode.rs` mimo hunky commitu) | splněno |
| K24-6 | `reg6` 48/48, `regsh6` 48/48 shodných sítí s `F:\work-tmp\k21\reg` (kromě časů) | splněno |

Mezivýsledek: první běh property testu (22:22) selhal; po opravě před commitem prošel. Do měření šel jen kód z commitu.

### 2.2 Kandidát 1: FG2A (`attr_calib`) proti FG2

Ladicí seedy 20270461 až 20270465, svět v2, 3 konfigurace × 20 sítí. Atribuce je ve všech konfiguracích stejná, uvádí se jednou.

| kritérium | FG2 | FG2A | stav |
|---|---|---|---|
| K24-A1 objem s pravdou (n 2 966 → 2 968 na konfiguraci) | správný 14,5 %, cizí 29,3 % | správný **43,6 %**, cizí **4,1 %** | splněno |
| K24-A2 objem na cílech útoků | správný 19,5 %, cizí 12,9 % | správný 30,1 %, cizí 6,1 % | splněno |
| K24-A3 nespárované (n 603) | bez zdroje 100 % | bez zdroje 20,1 %; se zdrojem 482, správně **96,3 %** | splněno |
| K24-B2 detekce | off 85,02 → 85,12 % (95% [−0,11; +0,28]), ops 85,17 → 85,17 %, elying 85,23 → 85,33 % | elying: `exploit_attempt` 45,6 → 43,9 % (n 57) | **nesplněno** (elying) |
| K24-Z zavření | 0 | **1 506 / 1 506 / 1 507** (vše `backup`) | **nesplněno** |
| K24-Z K20-1 omylem zavřeno | 0 | **1 055 / 1 055 / 1 056** (cf 821; příčinně 244) | **nesplněno** |
| K24-Z K20-1b útoky s omylem zavřeným nálezem | 0 | **66** v každé konfiguraci | **nesplněno** |
| K24-Z K20-1c pohlcené útoky | 0 | **82** v každé konfiguraci | **nesplněno** |
| K24-C1 zobrazené FP | 3 160 / 3 164 / 3 448 | ×0,9927 / ×0,9902 / ×0,9910 (off/ops/elying) | splněno |

Další: vyvráceno žebříkem 0 → 29 (elying 26), případy pro člověka +2,1 až +2,6 %, obchvat brány 0, porušení invariantu 0, paniky 0.

### 2.3 Kandidát 2: FG2AOG (`attr_calib,sev_calib_o1,ctx_activity_guard`) proti FG2

| kritérium | výsledek | stav |
|---|---|---|
| K24-A1 až A3 | jako FG2A (správný 43,0 %, cizí 4,1 %; útoky 29,5 / 6,0 %; nespárované bez zdroje 20,1 %, se zdrojem správně 96,3 %) | splněno |
| K24-B1 | 0 nálezů útoků objemových typů s Low | splněno |
| K24-B2 | off 85,02 → 85,17 % (95% [+0,00; +0,31]); ops a elying: `exploit_attempt` 45,6 → 43,9 % (n 57) | **nesplněno** (ops, elying) |
| K24-B3 | K20-1 = 0, K20-1b = 0, K20-1c = 0 ve všech konfiguracích | splněno |
| K24-C1 | ×0,9975 / ×0,9940 / ×0,9962 (off/ops/elying) | splněno |
| zavření | **0** ve všech konfiguracích (pojistka citována 6 157× na konfiguraci) | hlášeno |
| případy pro člověka | +3,4 / +3,6 / +2,1 % | hlášeno |

### 2.4 Diagnostická ramena (jen hlášení)

| rameno | zavření | K20-1 (cf; příčinně) | K20-1b | K20-1c | FP | citace pojistky |
|---|---|---|---|---|---|---|
| FG2AO (A + O1, bez pojistky) | 73 na konfiguraci (vše `backup`) | 55 (0; 1) | 0 | 21 | ×0,994 až ×0,997 | 0 |
| FG2G (jen pojistka) | 0 | 0 | 0 | 0 | ×1,0000 | 130 (bez vlivu na výstup; FG2 nic nezavírá) |

FG2AOG proti FG2AO: pojistka zastavila všech 73 zavření, z nich 55 omylem podle K20-1 a 18 bez omylu (předpověď 1.3: zastaví i část správných zavření, potvrzeno; „méně než FG2AO“ potvrzeno až na nulu).

### 2.5 Rozbor neúspěchu K24-Z (stopa, ne ladění)

Předpověď 1.2 („`attr_calib` samo nepřidá žádné zavření“) je **vyvrácená**. Všech 1 506 zavření FG2A (`off`) jsou kontext zálohy nad `packet_rate_spike` se závažností **Medium**. Tytéž klíče (stejný seed, síť, cyklus a klíč) jsou ve FG2 také Medium, ale bez zdroje, takže přísné doložení zdroje záznam zálohy odmítne. `attr_calib` jim dá zdroj (hostitel zálohy) a záloha je pak vysvětlí. S O1 je 1 460 z 1 506 týchž nálezů **High** (R2 je zamkne) a 46 zůstává Medium. Rozložení závažnosti `packet_rate_spike` (`off`, 5 seedů): FG2 High 3 931 / Medium 5 516, FG2A 3 931 / 5 488, FG2AO **6 453 / 2 555**.

Důsledek: zdůvodnění 1.2 i výklad 2.4 kroku 23 („O1 dá nálezu zálohy Medium, O2 správný zdroj, je potřeba obojí“) byly obráceně. Nálezy zálohy jsou Medium už bez O1; O1 objemové nálezy na hostech záloh převážně **zvyšuje** na High a tím zavírání brzdí. Zavírání odemyká samotná správná atribuce, R2 chrání jen High. Zavřené klíče leží na hostech, kde v okně běžely útoky (`slow_scan` 360, `port_scan_horizontal` 238, `lateral_cautious_one_target` 74, `c2_internal_proxy_chain` 72, `lateral_winrm` 71, `lateral_movement` 61, `hn_db_replication_bulk` 60 …). Z 1 055 omylů podle K20-1 je 244 příčinných (útok se na zavřeném jevu podílel), takže nejde jen o artefakt definice zmínkou.

### 2.6 Rozbor neúspěchu K24-B2

Celý pokles `exploit_attempt` dělá **jeden útok**: seed 20270463, síť 1, útok 39, 2 cykly. Ve FG2 (`elying`) se mu připíše jediný nález, `packet_rate_spike` Medium bez zdroje na 192.168.27.42 v cyklu 286, kde v témže okně běží Backup a CloudMigration. Ve FG2A (`elying`) tento nález nevznikne. V `off` je to obráceně (FG2 bez nálezu, FG2A s ním, +1 útok). Detekce útoku tedy visí na náhodném objemovém nálezu, který exploit nevyvolal, a jeho vznik závisí na drobné změně příznaků. Kritérium je předregistrované a po výsledku se nemění: B2 je v `elying` (oba kandidáti) a v `ops` (kandidát 2) nesplněno.

### 2.7 Rozbor FP (navazuje na 1.4)

Zobrazené FP objemových typů ze stopy (bez pravdy v okně), na konfiguraci:

| rameno | celkem | `escalated_severity` | `escalated_source` | `first` | `ladder_escalated` | `reopened` |
|---|---|---|---|---|---|---|
| FG2 | 1 242 až 1 247 | 22 | 20 | 640 | 362 až 367 | 195 |
| FG2A | 1 244 až 1 246 | 21 | **68** | 636 | 317 až 319 | 198 |
| FG2AO | 1 228 až 1 230 | **28** | 58 | 356 | 662 až 664 | 122 |
| FG2AOG | 1 227 až 1 231 | 27 | 58 | 356 | 661 až 665 | 123 |

- Mechanismus z 1.4 (O1: první výskyt Medium jde do žebříku, pozdější High na témže klíči se znovu zobrazí) na nových seedech **je**: `first` 640 → 356, `ladder_escalated` +300, `escalated_severity` 22 → 28. Je ale malý (+6 místo +30 v kroku 23) a vyrovná ho méně znovuotevření (195 → 122). Celkem O1 ramena FP o ≈ 1 % **snižují**.
- Předpověď 1.4, že s `attr_calib` ubude redisplayů „nový zdroj“, se na těchto seedech **nepotvrdila**: `escalated_source` 20 → 68. Vyrovná se to úbytkem `ladder_escalated` (−45); C1 drží (×0,99).
- +1 % FP kroku 23 tedy na nových seedech nevzniklo. Mechanismus je skutečný, jeho velikost závisí na seedech. Práh C1 je dál v pořádku.

### 2.8 Držené seedy

**Nespuštěny.** Kandidát 1 nesplnil K24-Z (všechny konfigurace) a B2 (`elying`); kandidát 2 nesplnil B2 (`ops`, `elying`). Rozhodovací pravidlo (1.6) držený běh nedovoluje. Držené seedy 20270501 až 20270510 zůstávají nepoužité; E3 a držené kroku 23 také.

## 3. Check

| otázka | odpověď |
|---|---|
| Prošla regrese a kód? | ano: K24-6 48/48 a 48/48, K24-T, `cargo test --lib` bez nových selhání, `fmt` a `clippy` ve změněném kódu čisté |
| Splnil kandidát 1 (`attr_calib`) všechna kritéria? | ne: K24-Z (1 506 zavření, 1 055 omylem podle K20-1, z toho 244 příčinně; 66 útoků s omylem zavřeným nálezem, 82 pohlcených) a K24-B2 v `elying` (jeden útok) |
| Splnil kandidát 2 (FG2AOG) všechna kritéria? | ne: K24-B2 v `ops` a `elying` (tentýž jeden útok); B3 splněno, ale kandidát nezavře **nic** (0 zavření, pojistka citována 6 157×) |
| Platily předpovědi? | 1.2 (`attr_calib` 0 → 0 zavření) **vyvrácena**; atribuce A1 až A3 potvrzena (cizí 29 → 4 %, nespárované bez zdroje 100 → 20 %); 1.3 (pojistka zastaví zálohy se souběžným útokem i část správných) potvrzena, a to do nuly; 1.4 (O1 redisplay závažnosti) potvrzena kvalitativně, velikost malá; „O2 ubere redisplay zdroje“ vyvrácena |
| Je atribuce sama o sobě bezpečná? | ne. Správný zdroj odemyká kontextové zavření Medium objemových nálezů, které R2 nechrání. Atribuce mění vstup brány zavírání, takže ji nelze posuzovat jen jako „mění zdroj, ne závažnost“ |
| Držené seedy | nespuštěny (pravidlo 1.6) |
| Omezení | B2 hodnotí útok podle nálezů zmiňujících jeho cíl v okně; detekce `exploit_attempt` je na těchto seedech náhodná (útok 39 zachytil objemový nález jiného jevu). Pojistka vidí jen aktivitu, která vytvořila nález. Svět je simulovaný (v2) |

## 4. Act (doporučení vedoucímu)

1. **Nepřijmout ani jednoho kandidáta.** `recommended()` beze změny. `attr_calib` a `sev_calib_o1` zůstávají vypnuté; `ctx_activity_guard` také.
2. **`attr_calib` nikdy bez pojistky.** Správná atribuce sama vyrábí omylem zavřené zálohy na hostech s útokem. Do dokumentace přepínače (`V3Features`) zapsat, že samotná atribuce nesmí do produkční konfigurace.
3. **Opravit výklad kroku 23** (2.4 a 4 kroku 23): zavření záloh neodemklo O1, ale O2. O1 objemové nálezy záloh převážně zvyšuje na High. Provedeno: poznámka v `impl-krok23.md` 2.4 s odkazem sem; čísla kroku 23 se nemění.
4. **Pojistka je bezpečná, ale nepoužitelná.** S kalibrací zablokuje všechna zavření (73 → 0, z toho 18 bez omylu); proti FG2AO přidá +0,2 až +0,3 % případů pro člověka (celé FG2AOG proti FG2 +2,1 až +3,6 %, většinou kvůli O1 a žebříku). Další krok (25) má nejdřív ze stopy, bez ladění, rozebrat, kterou aktivitu pojistka cituje: vlastní nálezy zálohy (`multi_target_pattern`, objem bez zdroje) proti nálezům útoků. Teprve potom s předregistrací navrhnout zúžení (například aktivitu, kterou sám záznam vytvořil, za pokrytou považovat jen se shodným zdrojem a typem z pokrytí). Měřit i rameno FG2AG (`attr_calib` + pojistka bez O1), které v kroku 24 chybělo.
5. **B2 neměnit zpětně.** Pro další krok zvážit předregistraci doplňku B2 (detekce rodiny počítaná jen z nálezů, které útok příčinně vyvolal, nebo pokles aspoň o 2 útoky). Zapsat **před** měřením, ne kvůli tomuto výsledku.
6. **Držené 20270501 až 20270510** zůstávají nepoužité, krok 25 je může převzít jako svou drženou sadu.
7. **Review:** změna sahá na logiku zavírání (kontextová brána), proto podle pravidel repa patří před uzavřením kroku `sol-loop` nad commitem `493db02` a předregistrace kroku 25 do `council`. Spouští je hlavní konverzace; v tomto zápisu review **neproběhlo**.
