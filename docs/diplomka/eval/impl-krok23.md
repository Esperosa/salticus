# Krok 23: oprava kalibrace závažnosti a atribuce zdroje (O1 až O3)

Podklad: `impl-krok22.md`, sekce 13 (analýza K22-N4) a 14 (Act, bod 3). Vedoucí schválil O1 až O3; R2 a P6 beze změny, brána se nezmírňuje, E3 a držené seedy 20270301 až 20270310 se nepoužijí. Pracovní data: `F:\work-tmp\k23`. Sekce 1 je zapsána a komitnuta **před** jakoukoli změnou kódu kroku 23.

## 1. Předregistrace (zapsáno před kódem)

### 1.1 Cíl a zdůvodnění nezávislé na bráně

Cílem je, aby nález nesl závažnost a zdroj, které odpovídají události, ze které vznikl. Dnes (13.1 a 13.2) pravidla nálezů zahazují kalibrovanou závažnost detektoru a dominantní zdroj objemové anomálie se počítá podle počtu toků i tehdy, když anomálii vyhlásily bajty. To je chyba bez ohledu na to, co s nálezem udělá brána: analytik dostane jako High i odchylku 3× nad baseline a jako zdroj klienta, který s anomálií nesouvisí. Úspěch se proto měří **proti pravdě simulátoru** (je zdroj ten, kdo provoz vytvořil?) a **posunem závažnosti útoků** (neschová se útok?). Počet zavření brány je jen sekundární a není cílem; změna, která by zlepšila zavírání a zhoršila atribuci, se nepřijme.

### 1.2 Změny (vše za novým přepínačem `sev_calib`, `V3Features`, výchozí vypnuto)

- **O1 (závažnost objemu podle velikosti události):** pravidla `inductive_volume_anomaly` a `packet_rate_spike` dostanou závažnost nejsilnější události téhož typu na službě (detektor v3: High jen při poměru ≥ 10× nad baseline, jinak Medium), **nejméně Medium** (nález z objemové anomálie nikdy neklesne na Low). Dnes: `inductive_volume_anomaly` pevně High, `packet_rate_spike` High při počtu toků služby ≥ 5. `connection_timeout_burst`, `scan_attempts`, R2 a P6 beze změny.
- **O2 (zdroj podle rysu, který anomálii vyhlásil):** když `inductive_volume_anomaly` vyhlásily bajty (ne toky), dominantní zdroj = zdroj s **≥ 50 % bajtů služby v cyklu** (nejvýš jeden, při přesné shodě 50/50 dva). Analogicky `packet_rate_spike` vyhlášený počtem paketů za okno: zdroj s ≥ 50 % paketů. Anomálie vyhlášená toky a rychlost podle p95 kvalifikovaných toků: beze změny (dominance podle počtu toků). Když žádný zdroj podíl nesplní, nález je bez zdroje (rozptýlený objem; poctivější než cizí klient). Zdroj v události (`src_ip`) a text zdroje ve zprávě odpovídají nové atribuci.
- **O3 (zdroj u nespárovaných událostí):** `unmapped_passive_event` dostane zdroje z nespárovaných událostí téhož cíle (IP, protokol, port) a typu: `src_ip` události a dominantní zdroje detektoru pro tentýž klíč a typ (stejná mapa, kterou používají spárované nálezy). Počet (`count`) beze změny.
- **Bez přepínače** se nemění žádná cesta (K22-6 musí zůstat 48/48 a 48/48).

### 1.3 Seedy (zapsáno dopředu)

| sada | seedy | použití |
|---|---|---|
| regrese | 20269701, 20269703 | K23-6 (bez přepínače shoda s krokem 21) |
| **ladicí** | **20270451 až 20270455** | měření 1.4, smí se opakovat |
| **držená** | **20270401 až 20270410** | jednou, jen po zmrazení kódu commitem a jen když všechna ladicí kritéria projdou |
| nepoužít | 20270301 až 20270310 (E3) | ne |

### 1.4 Měření

Svět v2 (`--world-v2`), 168 h, 4 sítě na seed, `--threads 1`, Idle, maska 0x3FFFFC, nejvýš 6 souběžných úloh (≤ 8 vláken), odpojeně. Tři konfigurace sítí jako v regresi kroku 22: `off`, `ops` (`--ops-telemetry on`), `elying` (`endpoint_ext`, `--endpoint on --endpoint-agent ok`). Ramena (párově podle seedu a sítě):

| rameno | přepínače v3 navíc k F (`breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate`) |
|---|---|
| F2 | — |
| F2S | `sev_calib` |
| FG2 | `close_gate,ctx_host_first` |
| FG2S | `close_gate,ctx_host_first,sev_calib` |

Ladicí: 5 seedů × 3 konfigurace × 4 ramena = 60 běhů, všechny se stopou (`K15_TRACE`). Držené: 10 seedů × 3 konfigurace × ramena FG2 a FG2S = 60 běhů se stopou.

**Atribuce proti pravdě (nástroj `tools/k23_attr.py`):** nález typu `inductive_volume_anomaly`, `packet_rate_spike` nebo `unmapped_passive_event` v cyklu c se přiřadí pravdám aktivním v c, jejichž cíle (`truth_cycle.targets`, IP:port) obsahují službu nálezu. Pravdivé zdroje = sjednocení `truth_cycle.sources` těchto pravd. Třídy: **správný** (zdroje neprázdné a všechny v pravdivých), **cizí** (aspoň jeden zdroj mimo pravdivé), **žádný** (bez zdroje). Nálezy bez pravdy (pozadí) se jen počítají.

### 1.5 Kritéria přijetí (ladicí seedy; stejná pro držené)

Primární (na bráně nezávislá), pro každou dvojici F2S/F2 a FG2S/FG2 a souhrnně přes konfigurace:

| kritérium | metrika | splněno, když |
|---|---|---|
| K23-A1 | atribuce objemových nálezů (`inductive_volume_anomaly`, `packet_rate_spike`) s pravdou, všechny druhy pravd | podíl správných S > základ **a** podíl cizích S ≤ 0,5 × základ |
| K23-A2 | totéž jen u nálezů útoků | podíl správných S ≥ základ − 1 p. b. |
| K23-A3 | `unmapped_passive_event` s pravdou | podíl bez zdroje S < základ; mezi nálezy se zdrojem podíl správných S ≥ 90 % (když jich je ≥ 20; jinak se jen hlásí) |
| K23-B1 | závažnost nálezů útoků O1 typů | 0 nálezů útoků s Low; posun High → Medium po rodinách se hlásí |
| K23-B2 | detekce a zobrazení útoků po rodinách (K20-2) | žádná rodina (n ≥ 20) s poklesem > 1 p. b.; souhrn: horní mez 95% CI rozdílu > −1 p. b. |
| K23-B3 | omylem zavřené (K20-1, K20-1b) | 0 v S ramenech; pohlcené útoky (K20-1c) S ≤ základ |

Sekundární (hlásí se; K23-C1 je kritérium, ostatní bez prahu):

| kritérium | metrika | splněno, když |
|---|---|---|
| K23-C1 | zobrazené FP | S/základ ≤ 1,01 |
| K23-C2 | případy pro člověka, počet zavření (auto, vyvráceno), stín | jen hlášení; nárůst zavření **není** argument pro přijetí |

Regrese a kód:

| kritérium | metrika | splněno, když |
|---|---|---|
| K23-6 | bez přepínače | `reg5` 48/48 a `regsh5` 48/48 shodných sítí s `F:\work-tmp\k21\reg` (kromě časů) |
| K23-T | testy | jednotkové testy O1 až O3; property test O1 a O2 (≥ 5 000 náhodných cyklů: závažnost nálezu = max(Medium, událost); bez přepínače totožné s dnešním chováním; O2 vybraný zdroj má ≥ 50 % bajtů nebo paketů); `cargo test --lib` bez nových selhání (známá: 5 `broker`, 1 `identity_lab`); `fmt` čisté, `clippy` bez varování ve změněném kódu |

**Rozhodovací pravidlo:** držené seedy se spustí jen když na ladicích seedech projdou K23-A1 až A3 (A3 v části, která má n), B1 až B3, C1, K23-6 a K23-T, a kód je zmrazený commitem (binárka podle hashe commitu). Když některé ladicí kritérium neprojde, držené se nespustí a výsledek se zapíše jako neúspěch s příčinou; prahy se po výsledku nemění. Držený běh se hlásí celý, včetně zhoršení.

**Předpověď (zapsáno předem):** O2 převede objemové nálezy dávek z cizího zdroje na správného hostitele dávky (13.2: 42 cizích); zálohy (jeden tok na cíl) dostanou zdroj podle bajtů. O1 sníží část nálezů útoků z High na Medium (útoky s odchylkou < 10×), detekce se nezmění (závažnost nerozhoduje o zobrazení nového nálezu). O3 dá zdroj skoro všem `unmapped_passive_event`.
