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
