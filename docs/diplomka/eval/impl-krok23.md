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

## 2. Výsledek (DO)

Commit `c1db6e9` (přepínač `sev_calib`: `findings::calibrate_volume_severity` (O1), `volume_dominant` v detektoru v3 (O2), `findings::finding_signal_with_unmapped` (O3); nástroj `tools/k23_attr.py`). Binárka `F:\work-tmp\k23\bin\salticus-k23-c1db6e9.exe`. Ladicí běhy `F:\work-tmp\k23\lad` (60 běhů, všechny s kódem 0, ≈ 33 min), regrese `F:\work-tmp\k23\{reg5,regsh5}` (24 běhů). Vyhodnocení `F:\work-tmp\k23\lad-gate.txt` (K20 metriky) a `F:\work-tmp\k23\lad-attr.txt` (atribuce a závažnost).

### 2.1 Testy a regrese

| kritérium | výsledek | stav |
|---|---|---|
| K23-T jednotkové | O1: `k23_o1_volume_severity_follows_event`; O2: `k23_o2_batch_volume_is_attributed_by_bytes` (dávka: podle toků pravidelný klient, podle bajtů hostitel dávky), `k23_o2_backup_gets_source_and_split_volume_gets_none`, `k23_volume_dominant_half_rule`; O3: `k23_o3_unmapped_event_carries_its_source` | splněno |
| K23-T property | `k23_o1_property_calibrated_severity` (5 000 služeb: závažnost = max(Medium, událost), ostatní nálezy totožné); `k23_o2_property_only_volume_sources_change_and_hold_half` (5 120 cyklů: události s přepínačem a bez totožné, mění se jen zdroj objemu vyhlášeného bajty nebo pakety a ten má vždy ≥ 50 %) | splněno |
| `cargo test --lib` | 708 prošlo, 6 známých selhání (5 `broker` bez Redis, 1 `identity_lab` bez Dockeru) | splněno |
| `fmt`, `clippy` | `fmt` čisté; `clippy` bez varování ve změněném kódu | splněno |
| K23-6 | `reg5` 48/48, `regsh5` 48/48 shodných sítí s `F:\work-tmp\k21\reg` | splněno |

### 2.2 Primární metriky (ladicí seedy 20270451 až 20270455, svět v2, 3 konfigurace × 20 sítí)

Atribuce je ve všech třech konfiguracích prakticky stejná; uvádí se souhrn (FG2S/FG2, F2S/F2 se liší o jednotky nálezů).

| kritérium | základ (FG2) | S (FG2S) | stav |
|---|---|---|---|
| K23-A1 objem s pravdou (n 6 099 → 6 221) | správný 11,3 %, cizí 36,1 %, žádný 52,6 % | správný **46,7 %**, cizí **4,1 %**, žádný 49,2 % | splněno |
| z toho zálohy (n 300) | správný 2,0 %, cizí 74,0 %, žádný 24,0 % | správný 95,0 %, cizí 3,0 %, žádný 2,0 % | |
| z toho dávky (n 1 503 → 1 506) | správný 2,8 %, cizí 95,0 % | správný 99,6 %, cizí 0,0 % | |
| K23-A2 objem na cílech útoků (n 2 913 → 3 023) | správný 21,5 %, cizí 19,6 % | správný 38,4 %, cizí 6,7 % | splněno |
| K23-A3 nespárované (n 1 110) | bez zdroje 100 % | bez zdroje 12,2 %; se zdrojem 975, z nich správně **99,4 %** | splněno |
| K23-B1 závažnost útoků (objemové typy) | High 16 443, Medium 2 875, Low 0 | High 13 830, Medium 7 886, **Low 0** | splněno |
| K23-B2 detekce (FG2S/FG2) | off 82,49 → 82,49 %, ops 82,69 → 82,62 % (95% [−0,35; +0,22]), elying 82,62 → 82,75 % | žádná rodina níž o > 1 p. b. | splněno |
| K23-B3 omylem zavřené (K20-1) | 0 | **8** v každé konfiguraci (F2S: 9) | **nesplněno** |
| K23-B3 útoky s omylem zavřeným nálezem (K20-1b) | 0 | 0 | splněno |
| K23-B3 pohlcené útoky (K20-1c) | 0 | **9** v každé konfiguraci (F2S: 10, 10, 16) | **nesplněno** |

Posun závažnosti: největší pokles High u `slow_scan` (−1 569 nálezů), `credential_stuffing` (−174), `hn_db_replication_bulk` (−156), `share_encryption_wave_slow` (−147); 20 rodin má všechny objemové nálezy Medium (např. `exfil_icmp_payload`, `ftp_bruteforce`, `mysql_login_failures`; ostatní typy nálezů těchto rodin beze změny). Detekce ani zobrazení útoků po rodinách neklesly.

### 2.3 Sekundární metriky

| kritérium | F2S/F2 | FG2S/FG2 | stav |
|---|---|---|---|
| K23-C1 zobrazené FP | off ×1,0098, ops ×1,0092, elying ×1,0098 | off **×1,0127**, ops **×1,0126**, elying **×1,0113** | **nesplněno** ve FG2S |
| K23-C2 případy pro člověka | +0,87 až +1,11 % | +0,89 až +1,15 % | hlášeno |
| K23-C2 automatická zavření | 0 → 18 v každé konfiguraci | 0 → 17 v každé konfiguraci | hlášeno |

### 2.4 Rozbor neúspěchu B3 (stopa, ne ladění)

Všech 51 automatických zavření ve FG2S (3 konfigurace × 17) je **kontext zálohy** (`auto_reason` „backup … schválil sim-správce“) nad `inductive_volume_anomaly` (12) a `packet_rate_spike` (39). Mechanismus: O1 dá nálezu zálohy Medium (R2 už klíč nezamkne) a O2 mu dá správný zdroj (hostitel zálohy), takže přísné doložení zdroje záznamu zálohy projde. Před krokem 23 tyto nálezy zavřít nešlo (High a cizí nebo žádný zdroj, 13.2).

Proti pravdě simulátoru (`truth_cycle`: cíl nálezu v cílech pravdy nebo zdroj nálezu v jejích zdrojích) je 48 z 51 zavření jen záloha a 3 bez pravdy; **žádné zavření nemá příčinný vztah k útoku**. Metrika K20-1 je ale definovaná zmínkou (útok v okně zmiňuje IP hostu nálezu), a na hostech zálohy v témže okně běžely útoky (`slow_scan`, `apt_chain`, `hn_db_replication_bulk`, `service_reclassification`, `vlan_hop_or_misconfig`, `onion_style_circuit_egress`, `port_scan_horizontal`, `c2_internal_proxy_chain`). Proto 8 „omylem“ a 9 „pohlcených“ útoků; všechny pohlcené útoky jsou dál **detekované a zobrazené** (jeden jejich klíč ve stavu `auto_resolved`, ostatní otevřené). Kritérium bylo zapsáno předem a po výsledku se nemění: B3 je nesplněno. Že zavření je příčinně správné, je diagnóza, ne důvod k přijetí: zavřený klíč zálohy na hostu, kde zároveň běží útok, je přesně riziko „schovat útok pod kontext“, které K20-1c hlídá.

FP: S ramena zobrazí o 19 až 26 FP víc (+0,9 až +1,3 %); FG2S nad prahem 1,01. Příčina nerozebrána (kandidát: O2 rozdělí dřívější klíč s cizím zdrojem na klíče podle skutečného hostitele, `packet_rate_spike` bez zdroje se zobrazí jako nový stav).

### 2.5 Držené seedy

**Nespuštěny.** Ladicí kritéria B3 a C1 neprošla (1.5, rozhodovací pravidlo). Držené seedy 20270401 až 20270410 zůstávají nepoužité; E3 (20270301 až 20270310) nepoužito.

## 3. Check

| bod | stav |
|---|---|
| O2 atribuce podle bajtů a paketů (A1, A2) | splněno, velký účinek: cizí zdroj objemu 36 % → 4 %, dávky 95 % → 0 %, zálohy 74 % → 3 % |
| O3 zdroj nespárovaných (A3) | splněno: bez zdroje 100 % → 12 %, správně 99,4 % |
| O1 kalibrace závažnosti (B1, B2) | splněno: žádný útok na Low, detekce beze změny; High → Medium u 16 % nálezů útoků |
| B3 zavírání | **nesplněno**: O1 + O2 společně odemknou kontext zálohy (0 → 17 zavření), 8 omylem podle zmínky, 9 pohlcených útoků (příčinně 0) |
| C1 FP | **nesplněno** ve FG2S (×1,011 až ×1,013) |
| K23-6, testy | splněno |

## 4. Act (doporučení vedoucímu)

1. **`sev_calib` nezapínat jako celek** a držené seedy nespouštět. Prahy se po výsledku nemění.
2. **Rozdělit přepínač** (nová předregistrace): O2 a O3 jsou opravy atribuce s jednoznačně lepší shodou s pravdou a samy o sobě R2 neodemykají (High zůstává High). Předpověď k ověření: `attr_calib` (O2 + O3) bez O1 nezavře nic navíc (zálohy zůstanou High) a FP se nezmění; O1 zvlášť změří, kolik zavření a FP přidá samotná kalibrace.
3. **Před jakýmkoli zapnutím O1 s bránou** doplnit pojistku obdobnou K22-N3: kontext zálohy (a obecně jakýkoli kontext) nezavře klíč hostu, na kterém je v okně záznamu zaznamenaná aktivita jiného typu nebo zdroje mimo záznam. Jinak zavřený klíč zálohy může pohltit souběžný útok na témže hostu (K20-1c).
4. Rozebrat +1 % FP (2.4) na stopě dřív, než se O2 zapne pro zobrazení.
5. R2 a P6 beze změny; brána se nezmírňuje.

**Neúspěchy a omezení:** B3 a C1 nesplněny; držené seedy nepoužity, takže žádný výsledek kroku 23 není potvrzen na nezávislých datech. Pravdivé zdroje a cíle ve stopě jsou omezené na 12 na pravdu a cyklus (u distribuovaných útoků se správný zdroj může jevit jako cizí). Měřeno jen ve světě v2; svět v1 jen regresí bez přepínače. Simulátor dává zálohám jeden tok na cíl, takže účinek O2 na zálohy závisí na tomto modelu. Nezávislé review diffu (`sol-loop`) zadání vylučuje; diff sahá na atribuci zdroje, která vstupuje do brány, review patří do hlavní konverzace.
