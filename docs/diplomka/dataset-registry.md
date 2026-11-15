# Dataset registry

Registr datových zdrojů pro `src/eval/` (replay a baseline měření korelačního enginu). Formát polí podle `docs/diplomka/SALTICUS_kompletni_technicky_navrh_diplomova_prace.md`, sekce 7.1. Zdroje se nabalují po vlnách (sekce "Dataset" v plánu diplomky) — vlna 0 je ověření frameworku na jednom zdroji, další vlny přidávají další `ScenarioSource` implementace bez zásahu do `dataset_replay.rs`.

## Vlna 0 — IoT-23

| Pole | Hodnota |
|---|---|
| `dataset_id` | `iot23` |
| `source` | Stratosphere IPS / CTU (ČVUT) |
| `url` | https://www.stratosphereips.org/datasets-iot23 |
| `license` | CC BY-NC-SA 4.0, pro výzkum |
| `modalities` | Zeek `conn.log.labeled` (per-flow metadata, ne raw PCAP) |
| `label_schema` | `label` ∈ {Benign, Malicious} (case se liší scénář od scénáře), `detailed-label` ∈ {C&C, C&C-FileDownload, DDoS, PartOfAHorizontalPortScan, ...} |
| `known_leakage_risks` | Žádný per-flow label se nesmí dostat do `correlate_events`/`rank_finding`/`score_services` — zajištěno strukturně (parallel `Vec<ConnectionObservation>`/`Vec<GroundTruthLabel>` v `LabeledDataset`, viz `src/eval/ground_truth.rs`). Malé stažené scénáře nemusí reprezentovat celou škálu provozu v plném IoT-23 korpusu. |
| `wave` | 0 |

### Stažené scénáře (committed, malé labelované výřezy)

| Scénář | Cesta v repu | Velikost | SHA-256 | Flows | Malicious | Benign |
|---|---|---|---|---|---|---|
| CTU-IoT-Malware-Capture-44-1 | `labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled` | 31 179 B | `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f` | 237 | 26 (C&C, C&C-FileDownload, DDoS) | 211 |
| CTU-Honeypot-Capture-7-1 / Somfy-01 | `labs/datasets/iot23/CTU-Honeypot-Capture-7-1-Somfy-01/conn.log.labeled` | 18 024 B | `fb37fb38393c48b064d3afd373b075ffe31063d4924a2df1c5d13fc490b830cc` | 130 | 0 | 130 |

**Zdroj souborů:** staženo přímo z mirroru `mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/` (odkaz z homepage datasetu výše), konkrétně `.../CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled` a `.../CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled`, dne 29. 10. 2026.

**Proč committed, ne `.gitignore`:** jde o malé (desítky KB) labelované výřezy, ne o celý korpus — licence CC BY-NC-SA 4.0 pro výzkum to umožňuje a reprodukovatelnost testu na čistém klonu to vyžaduje (`src/eval/sources/iot23.rs` i `src/eval/dataset_replay.rs` mají `#[cfg(test)]` testy, které tyto soubory čtou). Pokud se v další vlně přidají větší scénáře/datasety, ty už patří mimo git (stahovací skript + hash v registru, ne commit).

### Rozšíření 30.10.2026 — 7 dalších scénářů (committed) + 1 velký (gitignored)

**Důvod rozšíření**: stejný jako u CTU-13 výše — N=2 (jen 1 malware rodina) je jako vzorek nedostatečné. IoT-23 má 20 individuálních scénářů na mirroru; doplněno 7 malých (pod 3 MB, committed) + zaznamenán 1 větší (24 MB, gitignored, zatím nezapojený do testu).

**Reálný bug nalezený při rozšíření**: `CTU-IoT-Malware-Capture-34-1` má `tunnel_parents`/`label`/`det_label` jako **3 řádně oddělené tab-pole** (novější verze CTU labelovacího skriptu), ne smáčknutý kombinovaný formát jako 44-1/Somfy-01. Bez opravy `extract_label` (`src/eval/sources/iot23.rs`) by se každý řádek tiše vyhodnotil jako "Unknown" (fail-safe z dřívější N9 opravy) — celý scénář by tiše změřil 0 known klíčů, ne viditelně selhal. Opraveno: `extract_label` teď nejdřív zkusí přesný klíč `"label"` (nový formát), až pak fallback na kombinované pole (starý formát). Ověřeno rozbij→spadne→vrať→projde (2 nové testy, oba spadly se `0 malicious`/`"Unknown" != "Benign"` před oprava).

| Scénář | Velikost | SHA-256 | Flows | Malicious | Rodina/technika |
|---|---|---|---|---|---|
| CTU-Honeypot-Capture-4-1 | 61 653 B | `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e` | 452 | 0 | benigní honeypot |
| CTU-Honeypot-Capture-5-1 | 182 147 B | `f36db06e7d6ba7364e932a5b003f75835e004b320d70019e8a2f0ba8685d9262` | 1374 | 0 | benigní honeypot |
| CTU-IoT-Malware-Capture-8-1 | 1 431 000 B | `4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a` | 10403 | 8222 | C&C |
| CTU-IoT-Malware-Capture-20-1 | 419 604 B | `ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711` | 3209 | 16 | C&C-Torii |
| CTU-IoT-Malware-Capture-21-1 | 428 943 B | `b63db259aead078f50fc150aa97ace4d1f69576e1245334962759d978ce437eb` | 3286 | 14 | C&C-Torii |
| CTU-IoT-Malware-Capture-34-1 | 2 926 718 B | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` | 23145 | 21222 | C&C, DDoS, PartOfAHorizontalPortScan |
| CTU-IoT-Malware-Capture-42-1 | 585 829 B | `269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa` | 4426 | 6 | C&C-FileDownload, FileDownload |

**Pozn. k přesnosti počtu flows:** počty výše = `grep -v "^#" conn.log.labeled | wc -l` (ověřeno bez prázdných řádků), tedy přesně to, co spočítá i produkční parser `src/passive/zeek.rs::parse_zeek_log` (přeskakuje jen řádky začínající `#` nebo prázdné). Dřívější odhad v této tabulce byl o 1 nižší na všech 7 scénářích (chyba v ručním odhadu, ne v datech) — opraveno na přesné počty.

**Gitignored (zaznamenáno, zatím nezapojeno do testu — viz `.gitignore`):**

| Scénář | Velikost | SHA-256 | Poznámka |
|---|---|---|---|
| CTU-IoT-Malware-Capture-3-1 | 24 383 537 B | `9851009bbca03e15089fa1a356dd4b5eee4a98161a51703626058a0b507f50d0` | 151 567 malicious / 156 103 flows (Attack, C&C, PartOfAHorizontalPortScan) — stejná velikostní kategorie jako CTU-13 výřezy, vědomě odloženo mimo tento krok |

**Vědomě vynechaný scénář (zjištěno/zdokumentováno 31.10.2026):** `CTU-IoT-Malware-Capture-43-1` (Mirai) vrací 404 na standardní cestě `bro/conn.log.labeled`, protože tenhle konkrétní scénář má `conn.log.labeled` ve VLASTNÍM adresáři `labeled/`, ne v `bro/` jako všechny ostatní dosud použité scénáře (`bro/` obsahuje jen `conn.log`/`dns.log`/`http.log`/... bez labelu). Ověřeno přímo (`curl` directory listing). Samotný soubor `labeled/conn.log.labeled` má navíc **9,36 GB** (`Content-Length` ověřen přímo HTTP HEAD požadavkem) — o 2 řády víc než ostatní committed IoT-23 scénáře, vyžadovalo by stejnou offset-based výřezovou techniku jako u CTU-13 velkých souborů. Vědomě nezapojeno do téhle vlny rozšíření (klesající návratnost — N=9/4 rodiny už poskytuje statisticky testovatelný vzorek, viz `baseline-iot23.md` dodatek s Wilcoxon testem) — zaznamenáno jako known gap, ne jako ztracený/zapomenutý scénář.

**Reprodukce stažení:**
```
base="https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios"
curl -s "$base/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-Honeypot-Capture-4-1/conn.log.labeled
curl -s "$base/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-Honeypot-Capture-5-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-8-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-20-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-21-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-21-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-34-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-42-1/conn.log.labeled
# gitignored, vetsi:
curl -s "$base/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-3-1/conn.log.labeled
```

**Souhrn po rozšíření: 9 scénářů committed (2 benigní + 44-1 + Somfy-01... pozn. Somfy-01 je taky benigní, takže 3 benigní + 6 malware), 4 rodiny/techniky** (C&C, C&C-Torii, DDoS, FileDownload, PartOfAHorizontalPortScan), **+ 1 scénář zaznamenaný mimo git**. Nová sdílená `IOT23_COMMITTED_SCENARIOS` konstanta v `src/eval/dataset_replay.rs`, nový `iot23_nine_scenarios_four_families_dataset_sufficiency_check` test — BEZ `#[ignore]`, běží normálně v CI (všechny soubory committed).

## Vlna 1 — CTU-13

| Pole | Hodnota |
|---|---|
| `dataset_id` | `ctu13` |
| `source` | Stratosphere IPS / CTU (ČVUT) |
| `url` | https://www.stratosphereips.org/datasets-ctu13 |
| `license` | CC BY-NC-SA 4.0, pro výzkum |
| `modalities` | NetFlow-style bidirekční flow CSV (`binetflow`) — **jiná modalita než IoT-23's Zeek conn.log**, vlastní parser (`src/eval/sources/ctu13.rs`), žádné sdílení s `passive::zeek` |
| `label_schema` | `Label` pole `flow=From-Botnet-...`/`flow=Background`/`flow=Normal-...` — 3 kategorie, normalizováno na `Malicious`/`Benign`/**`Unknown`** (ne binárně — oprava 29.10.2026, `Background` = neověřený provoz, `is_unknown()` v `ground_truth.rs`, vyřazeno z confusion matrix, ne počítáno jako Benign) |
| `known_leakage_risks` | Stejná strukturní záruka jako IoT-23 (paralelní `Vec`). Navíc: `State` pole je NetFlow notace ("FPA_FPA", "CON"), ne Zeek `conn_state` slovník ("S0", "REJ") — heuristiky v `passive::anomaly`/`correlation_v2` laděné na Zeek vokabulář na CTU-13 nefungují stejně (změřeno, viz níže) |
| `wave` | 1 |

**Stažený výřez (NE committed — 30 MB/scénář, nad limit pro git, viz `.gitignore`):**

| Scénář | Rodina (ověřeno přímo na `mcfp.felk.cvut.cz`) | Cesta (lokální, gitignored) | Velikost | SHA-256 | Flows (ve výřezu) | Malicious |
|---|---|---|---|---|---|---|
| CTU-Malware-Capture-Botnet-54, scénář 13, prvních 30 MB | Virut | `labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv` | 31 457 281 B | `e53331ede25cb047e65ed814b7e34dd49f3926e8585d4ea6294aba4cccf336b6` | 229 653 | 6 185 |
| CTU-Malware-Capture-Botnet-51, scénář 10, prvních 30 MB | Rbot | `labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv` | 31 457 281 B | `c27b7443884c68c4b4ae49ce1404bf897a5dd7a430122a21121e4d135bfbca32` | 228 760 | 81 |
| CTU-Malware-Capture-Botnet-42, scénář 1, 30 MB od offsetu 150 000 000 B | Neris | `labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv` | 31 457 312 B | `2b78111d5eefae6ea24d58bb7cf54f6958a6c2cbb9b843e8693d5075f8bb8710` | 229 501 | 2 614 |

**Deliverable 18 (29.10.2026) — rozšíření ze 1 na 3 scénáře, 2 další malware rodiny.** Důvod offsetu u Botnet-42: první 30 MB (chronologický začátek 6,15h capture) obsahovalo 0 Botnet-labelovaných flows — malware aktivita v téhle capture začíná později. Ověřeno přímo (`curl` sondy na 150MB/250MB offsetu), ne odhadnuto. Výřez proto sestaven jako: hlavičkový řádek z bytu 0 (CSV header, nutný pro `src/eval/sources/ctu13.rs::column()` lookup podle jména) + 30 MB dat od bytu 150 000 000, první (potenciálně useknutý) řádek dat zahozen. **Honestní poznámka k Botnet-51**: tahle scénář má v adresáři i druhý soubor (`capture20110818.binetflow.labeled`, jiné jméno sloupců `Label(Normal:CC:Background)` + extra `CCDetector` sloupec) — NEpoužitý, protože nemá stejné schéma jako ostatní 2 scénáře; ověřeno přímo (`curl -r 0-500`), ne předpokládáno ze jména souboru.

**Oprava 29.10.2026:** všechny tři SHA-256 hashe v této tabulce byly dřív useknuté o 1 hex znak (63 místo 64) — chyba při přepisu z `sha256sum` výstupu, odhalená nezávislou kontrolou. Opraveno zde na skutečné hashe.

**Reprodukce stažení** (HTTP Range request — "reprezentativní výřez", ne bezhlavé stažení celého souboru, per návrh sekce 7):
```
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow" -o labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow" -o labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv
# Botnet-42: header z bytu 0 + data od offsetu 150 000 000 (viz vysvetleni vyse)
curl -s -r 0-200 "$URL42" | head -1 > header.tmp
curl -s -r 150000000-181457280 "$URL42" | tail -n +2 > body.tmp
cat header.tmp body.tmp > labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv
```

### Rozšíření 30.10.2026 — zbývajících 10 scénářů, plná sada 13/13

**Důvod rozšíření**: N=3 není statisticky ani datově průkazné. CTU-13 (akademický paper "An empirical comparison of botnet detection methods", mcfp.weebly.com) má přesně 13 scénářů — bylo doplněno zbývajících 10, čímž je **poprvé pokryta celá, standardní, publikovaná CTU-13 sada, ne jen výběr 3**.

**Rodina u každého scénáře ověřena PŘÍMO na `mcfp.felk.cvut.cz`** (jméno exe vzorku a/nebo capture název v adresáři scénáře), **ne odhadnuta ze zapamatované mapovací tabulky** — stejná disciplína, co tento projekt už jednou vynutila opravu (Virut/RBot mix-up, viz historie výše v tomto dokumentu). Dva scénáře se od často citované "scénář 6 = Menti, scénář 8 = Murlo" tabulky skutečně liší: přímo zjištěno **Donbot** (Botnet-47) a **Qvod** (Botnet-49), ne Menti/Murlo. Dva scénáře (Botnet-46, Botnet-53) nemají u zdroje jednoznačné jméno rodiny (jen capture technika "fast-flux" / generické "bot") — zapsáno honestně jako neoznačené, ne domyšlené.

Tři scénáře (Botnet-46/48/52) mají celý soubor pod 30 MB — stažen celý (ne výřez). U tří scénářů (Botnet-43/44/45) byla raná část capture (prvních 30 MB) málo nebo vůbec zastoupená malware provozem — ověřeno přímo sondami na více offsetech (stejná disciplína jako u Botnet-42 výše), výřez sestaven z hustší oblasti. Zbývající čtyři (Botnet-47/49/50/53) mají dost malware provozu už v prvních 30 MB.

| Scénář | Rodina (ověřeno přímo) | Cesta (lokální, gitignored) | Velikost | SHA-256 | Flows | Malicious |
|---|---|---|---|---|---|---|
| CTU-Malware-Capture-Botnet-43, scénář 2, 30 MB od offsetu 60 000 000 B | Neris | `labs/datasets/ctu13/Botnet-43/capture20110811.binetflow.excerpt.csv` | 31 457 330 B | `72aff359dfdd7e4534fe6033771324f1094a7d44a98ca81ad91f14b4529a0d80` | 229 265 | 10 263 |
| CTU-Malware-Capture-Botnet-44, scénář 3, 30 MB od offsetu 475 000 000 B | Rbot | `labs/datasets/ctu13/Botnet-44/capture20110812.binetflow.excerpt.csv` | 31 457 370 B | `23c323a23484fef6e8fce57c2c578e6d7ef6ce6ec4aa67ba89ae67f75cfd01e0` | 231 592 | 4 757 |
| CTU-Malware-Capture-Botnet-45, scénář 4, 30 MB od offsetu 58 000 000 B | Rbot (DoS varianta) | `labs/datasets/ctu13/Botnet-45/capture20110815.binetflow.excerpt.csv` | 31 457 365 B | `726a30ca60915cd304949dbc43a54b496f328db7de1c42a716979acdd1cceca2` | 229 288 | 469 |
| CTU-Malware-Capture-Botnet-46, scénář 5, celý soubor | "fast-flux" (rodina neoznačena u zdroje) | `labs/datasets/ctu13/Botnet-46/capture20110815-2.binetflow.full.csv` | 17 766 203 B | `ef5c9ed6895d4ca5aec723449dae30054ccd1f6b091713a52ffcb681ff78a02c` | 129 832 | 901 |
| CTU-Malware-Capture-Botnet-47, scénář 6, prvních 30 MB | Donbot (NE "Menti" — ověřeno přímo, mapovací tabulka se mýlí) | `labs/datasets/ctu13/Botnet-47/capture20110816.binetflow.excerpt.csv` | 31 457 281 B | `107a93bc1923a50a2a8c15e1b9ad785011dcf028f470df99691d157914521482` | 228 608 | 1 552 |
| CTU-Malware-Capture-Botnet-48, scénář 7, celý soubor | Sogou | `labs/datasets/ctu13/Botnet-48/capture20110816-2.binetflow.full.csv` | 15 630 512 B | `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680` | 114 077 | 63 |
| CTU-Malware-Capture-Botnet-49, scénář 8, prvních 30 MB | Qvod (NE "Murlo" — ověřeno přímo, mapovací tabulka se mýlí) | `labs/datasets/ctu13/Botnet-49/capture20110816-3.binetflow.excerpt.csv` | 31 457 281 B | `72935df0e450755278550c0289b363f93b2e8d6175d96339462f1da376bc050f` | 228 413 | 381 |
| CTU-Malware-Capture-Botnet-50, scénář 9, prvních 30 MB | Neris | `labs/datasets/ctu13/Botnet-50/capture20110817.binetflow.excerpt.csv` | 31 457 281 B | `dc49523e0f11c6bb418784d4cc0703c6bbdbfe340fbf7d98583b963d44255e43` | 229 364 | 50 |
| CTU-Malware-Capture-Botnet-52, scénář 11, celý soubor | Rbot | `labs/datasets/ctu13/Botnet-52/capture20110818-2.binetflow.full.csv` | 14 596 615 B | `cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c` | 107 251 | 8 164 |
| CTU-Malware-Capture-Botnet-53, scénář 12, prvních 30 MB | rodina neoznačena u zdroje ("bot") | `labs/datasets/ctu13/Botnet-53/capture20110819.binetflow.excerpt.csv` | 31 457 281 B | `8a7d096e2aa40c8da267cf50987a6775dccfdeb8d3b0dd9f9d551c0ad8bd745e` | 228 811 | 1 720 |

**Souhrn po rozšíření: 13/13 standardních CTU-13 scénářů, ~2,64 milionu flows celkem, ~27 000 malicious flows, 7 odlišných rodin/technik** (Neris×3, Rbot×4, Virut×1, "fast-flux"×1, Donbot×1, Sogou×1, Qvod×1, neoznačeno×1) — proti dřívějšímu N=3 (3 rodiny, ~688 000 flows). Použito v `src/eval/dataset_replay.rs`'s sdílené `CTU13_ALL_SCENARIOS` konstantě, nahrazující 6 dříve nezávisle hardcoded N=3 seznamů.

**Reprodukce stažení zbývajících 10** (stejný vzor jako výše; offsety u Botnet-43/44/45 zjištěny sondováním více bodů v souboru, ne odhadem):
```
# Cele soubory (<30MB)
curl -s "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/detailed-bidirectional-flow-labels/capture20110815-2.binetflow" -o labs/datasets/ctu13/Botnet-46/capture20110815-2.binetflow.full.csv
curl -s "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow" -o labs/datasets/ctu13/Botnet-48/capture20110816-2.binetflow.full.csv
curl -s "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow" -o labs/datasets/ctu13/Botnet-52/capture20110818-2.binetflow.full.csv

# Prvnich 30MB (dost malware provozu uz na zacatku)
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/detailed-bidirectional-flow-labels/capture20110816.binetflow" -o labs/datasets/ctu13/Botnet-47/capture20110816.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow" -o labs/datasets/ctu13/Botnet-49/capture20110816-3.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow" -o labs/datasets/ctu13/Botnet-50/capture20110817.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-53/detailed-bidirectional-flow-labels/capture20110819.binetflow" -o labs/datasets/ctu13/Botnet-53/capture20110819.binetflow.excerpt.csv

# Offset-based (rana cast capture ma malo/zadny malware provoz, ověřeno sondou)
curl -s -r 0-200 "$URL43" | head -1 > h.tmp; curl -s -r 60000000-91457279 "$URL43" | tail -n +2 > b.tmp; cat h.tmp b.tmp > labs/datasets/ctu13/Botnet-43/capture20110811.binetflow.excerpt.csv
curl -s -r 0-200 "$URL44" | head -1 > h.tmp; curl -s -r 475000000-506457279 "$URL44" | tail -n +2 > b.tmp; cat h.tmp b.tmp > labs/datasets/ctu13/Botnet-44/capture20110812.binetflow.excerpt.csv
curl -s -r 0-200 "$URL45" | head -1 > h.tmp; curl -s -r 58000000-89457279 "$URL45" | tail -n +2 > b.tmp; cat h.tmp b.tmp > labs/datasets/ctu13/Botnet-45/capture20110815.binetflow.excerpt.csv
```

## Vlna 1 (krok 5, 2026-11-04): CIC-IDS2017 a UNSW-NB15

Obě sady jsou mimo git v `F:\Projekty\bakula-datasets\` (proměnná `SALTICUS_EXTERNAL_DATASETS`). Do repa jde jen kód zdroje, skripty výřezu (`tools/datasets/`) a hashe níže. Rozdělení na vývojovou a zamčenou testovací část je v `docs/diplomka/eval/anchor-split.txt` (`[dev-k5]`, `[test-k5]`, SHA-256 testovací části `b1dbb1ca…`), pravidla jsou v `impl-krok5.md`, A9.

### CIC-IDS2017 (přegenerovaná verze Engelen a kol.)

| Pole | Hodnota |
|---|---|
| `dataset_id` | `cicids2017` |
| `source` | Canadian Institute for Cybersecurity (UNB), záznam 3. až 7. 7. 2017; toky a štítky přegenerovali Engelen, Rimmer, Joosen (KU Leuven, WTMC 2021) opraveným CICFlowMeterem |
| `url` | https://www.unb.ca/cic/datasets/ids-2017.html (originál), https://intrusion-detection.distrinet-research.be/WTMC2021/ (použitá verze, `Dataset/dataset.zip`, 333 841 436 B, ověřeno HTTP Range 2026-11-04) |
| `license` | Ani originál, ani přegenerovaná verze nemají výslovnou licenci. Obě stránky žádají citaci: Sharafaldin, Lashkari, Ghorbani, ICISSP 2018, a Engelen a kol., IEEE SPW/WTMC 2021. Ověřeno na oficiálních stránkách 2026-11-04. |
| proč ne originál | Stažení z UNB vyžaduje formulář se jménem, e-mailem a organizací. Pravidla práce zakazují posílat osobní údaje externím službám, proto je použita veřejně stažitelná přegenerovaná verze téhož záznamu. Opravuje i známé chyby originálu: konstrukci toků, ignorované RST, chybné příznaky a přes 20 % přeznačených toků. |
| `modalities` | Toky CICFlowMeteru. Výřez má jen sloupce Src/Dst IP a port, Protocol, Timestamp, Flow Duration (µs), počty paketů a délky payloadu v obou směrech, FIN/SYN/RST a Label. |
| `label_schema` | `BENIGN` nebo název útoku, u pokusů bez payloadu přípona `- Attempted`. Obojí se počítá jako Malicious. |
| osobní údaje | Testbed, provoz 25 simulovaných uživatelů (B-Profile). Žádní skuteční uživatelé. |
| `known_leakage_risks` | Toky nemají Zeek `conn_state`: zdroj ho odvozuje přibližně (bez paketů zpět = S0, RST = RSTO, jinak SF). Časy jsou o +5 h posunuté proti místnímu času testbedu (přegenerovaná verze), relativní pořadí sedí. Útočník je za NAT jako 172.16.0.1, mimo rozsah 192.168.10.0/24. |
| `wave` | 1 |

Staženo po dnech přes HTTP Range ze `dataset.zip` (komprimovaně: pondělí 64,8 MB, úterý 54,9 MB, středa 87,0 MB, čtvrtek 53,1 MB, pátek 74,0 MB). Plná data se neukládala. Výřezy podle A9 jsou okno [první tok skupiny štítků − 30 min, poslední + 30 min], nejvýš 3 h. Neškodné pondělní výřezy jsou hodina 1 až 2 a 5 až 6 od začátku dne.

| Výřez | Část | Okno (čas souboru) | Toků | Škodlivých | Velikost | SHA-256 |
|---|---|---|---:|---:|---:|---|
| `tue-ftp-patator` | dev | 04.07. 13:47:52 až 15:50:13 | 102 995 | 3 984 | 10 137 032 B | `5b95badc02325b80166d4f904421c447727fee9b5abe8dda7aea7fd7b7c5a628` |
| `wed-dos-slow` | dev | 05.07. 13:31:00 až 15:40:36 | 95 251 | 10 843 | 9 470 140 B | `df91914427c2be10f5d6d2cace59819faf2377154fa2d69283b091f890e25212` |
| `fri-botnet` | dev | 07.07. 14:04:13 až 17:04:13 | 135 702 | 1 509 | 13 309 039 B | `31e515f92154af22a9cb3db1b2b98be5c2e98a3580bd1e46eece4e08c4d88b22` |
| `mon-benign-am` | dev | 03.07. 14:55:58 až 15:55:58 | 59 849 | 0 | 5 905 339 B | `b3d1993cc6cc4489cc986d4dcc7c7c772b667e67b19660b5c9d75a2bc42d9dab` |
| `tue-ssh-patator` | test | 04.07. 18:39:01 až 21:34:15 | 122 372 | 2 988 | 12 053 674 B | `36db1cdcd235e7383c2d714d27f13ae6d536668b707d2043c7a859240a1976d3` |
| `wed-dos-hulk-goldeneye` | test | 05.07. 15:40:36 až 16:49:49 | 211 284 | 166 709 | 21 103 295 B | `e1631a242d09aaed6ad8e7ebd49d93c1063a75687c87b35270450ec9b92d2ad6` |
| `thu-web` | test | 06.07. 13:45:54 až 16:12:50 | 86 752 | 2 056 | 8 564 709 B | `5e822969eb69ab17c30fa0e255a66c9bdb5a5743cc25811d62ab98913b16efa6` |
| `thu-infiltration` | test | 06.07. 18:49:02 až 21:14:24 | 174 824 | 48 | 16 691 017 B | `7f83aeceeed6569c75bc93f636b9abe36705cc411133dd7e953e26b49b833cde` |
| `fri-portscan` | test | 07.07. 17:07:57 až 20:07:57 | 225 719 | 139 741 | 21 286 911 B | `e091f5127881d036807bce0ab17eb4c83be637308ad9b72e0b548f70fe7d5e03` |
| `fri-ddos` | test | 07.07. 20:26:31 až 21:46:10 | 143 780 | 95 123 | 13 919 184 B | `9740f79b940e5a329f8053160bfa8cb41dc16e8e10ba39e5eefcddc5ff6ef993` |
| `mon-benign-pm` | test | 03.07. 18:55:58 až 19:55:58 | 35 878 | 0 | 3 517 788 B | `046f23600c4900f4ecf268954b6dcd1fc54427f9db9df4a63b4e35cb089119a3` |

Odchylka od A9, zjištěná před během jakéhokoli detektoru: okna `wed-dos-slow` a `wed-dos-hulk-goldeneye` se podle pravidla překrývala (15:13 až 16:07), takže vývojová a testovací část by sdílely toky. Hranice je proto v polovině mezery mezi posledním tokem pomalé skupiny (15:37:49) a prvním tokem Hulk (15:43:23), tedy 15:40:36 (`tools/datasets/cic_recut_wed.py`). Heartbleed (11 toků, večer) není v žádném výřezu. Ve výřezu `fri-portscan` jsou i pozdní pokusy botnetu (`Bot - Attempted` do 17:59).

### UNSW-NB15

| Pole | Hodnota |
|---|---|
| `dataset_id` | `unsw-nb15` |
| `source` | UNSW Canberra, Cyber Range Lab, nástroj IXIA PerfectStorm (Moustafa a Slay, MilCIS 2015) |
| `url` | https://research.unsw.edu.au/projects/unsw-nb15-dataset (oficiální sdílená složka UNSW; anonymní odkaz z oficiální stránky, bez přihlášení) |
| `license` | „Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.“ Citovat pět článků z oficiální stránky. Ověřeno 2026-11-04. |
| `modalities` | Argus a Bro toky, `UNSW-NB15_4.csv` (97 588 754 B, 440 044 řádků, 49 sloupců podle `NUSW-NB15_features.csv`). Výřez má `stime, srcip, sport, dstip, dsport, proto, state, dur, sbytes, dbytes, spkts, dpkts, attack_cat, label`. |
| `label_schema` | `label` 0/1, `attack_cat` ∈ {Fuzzers, Analysis, Backdoor, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms} |
| osobní údaje | Syntetický provoz testbedu, žádní skuteční uživatelé |
| `known_leakage_risks` | Argus stavy jsou převedené přibližně (INT/REQ = S0, RST = RSTO, FIN/CON/CLO/ACC = SF). Útočníci 175.45.176.0/24 jsou mimo rozsah 59.166.0.0/24 + 149.171.126.0/24. „Generic“ tvoří dvě třetiny škodlivých toků. |
| `wave` | 1 |

| Výřez | Část | Okno (Unix čas) | Toků | Škodlivých | Velikost | SHA-256 |
|---|---|---|---:|---:|---:|---|
| `unsw-h0` | dev | 1424249984 až +3600 s | 138 993 | 30 525 | 11 469 722 B | `58489ca79c3c32e0958678d7c5e35d7a1366972e399d4c05404ca2d3f1ed2123` |
| `unsw-h2` | test | 1424257184 až +3600 s | 132 138 | 29 411 | 10 921 712 B | `335d8b55900afb4393056f251ea57661a61ecf834226270aee6feb46218c2f42` |

Odchylka od A9: kategorie útoků se v UNSW-NB15 v čase prolínají, takže rozdělení „Reconnaissance a Exploits do vývojové části“ by šlo provést jen vyřazením toků z provozu. Místo něj se dělí po čase: první hodina souboru je vývojová, třetí hodina testovací a mezi nimi je hodina odstupu. Rozhodnuto před během jakéhokoli detektoru. Obě části mají všech 9 kategorií.

## Budoucí vlny (naplánováno, ne implementováno)

- **Vlna 1 (zbytek):** CSE-CIC-IDS2018, CICIoT2023 — každý jako nová `ScenarioSource` implementace v `src/eval/sources/`. CIC sady vyžadují registrační formulář s osobními údaji, takže jen přes veřejné přegenerované verze (Engelen a kol., CNS 2022), nebo po rozhodnutí autora.
- **Vlna 2:** threat intel enrichment (NVD/KEV/EPSS, URLhaus, ThreatFox, OTX).
- **Vlna 3:** Mininet/Containerlab generátor syntetických scénářů — zdroj prakticky neomezeného objemu kontrolovaných scénářů (DHCP/NAT churn, vlastní firewall/DNS/IPS politiky), včetně identity-churn scénářů, které IoT-23 ani CTU-13 nepokrývají.

## Vlna 2 (krok 8, 2026-11-11): koncová telemetrie (jen záznam licencí, nic se nestahuje)

| dataset | url | licence podle oficiální stránky | použití v kroku 8 |
|---|---|---|---|
| OTRF Security-Datasets | https://github.com/OTRF/Security-Datasets | stránka uvádí zároveň GPL-3.0 a MIT, nerozhodnuto | nepoužit; před použitím ověřit LICENSE |
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | GPL-3.0 | nepoužit, parser se testuje vlastními syntetickými záznamy |
| DARPA OpTC | https://github.com/FiveDirections/OpTC-data | public domain, Distribution A, bez záruk | nepoužit (formát eCAR, velikost) |
| LANL Unified Host and Network | https://csr.lanl.gov/data/cyber1/ | CC0 1.0, žádá citaci DOI 10.17021/1179829, stažení po zadání e-mailu | nepoužit (stažení vyžaduje e-mail, to se neodesílá) |

## Vlna 3 (2026-11-14): rozšíření registru o další veřejné datasety

Soubory leží mimo git v `F:\Projekty\bakula-datasets\<dataset>\`, každá složka má `manifest.json` (cesta, velikost, SHA-256, URL, datum). Staženo jen přes veřejné HTTP(S) bez přihlášení, bez odeslání formulářů a bez zadání osobních údajů; velké soubory jen jako výřezy (prefix souboru). Do žádného výřezu nepatří malwarové binárky ani PCAP s obsahem malwaru. Licence jsou citovány z oficiálních stránek ověřených 2026-11-14. Každý dataset má vlastní labelovací schéma; štítky se nesjednocují do jednoho plochého schématu (mapování mezi schématy se dělá až v adaptérech zdrojů). Datum stažení všech výřezů: 2026-11-14.

### Přehled stavu

| dataset | stav | poznámka |
|---|---|---|
| CSE-CIC-IDS2018 | staženo (výřezy) | 4 prefixy, 240,0 MB |
| LUFlow | staženo (4 denní soubory) | 76,6 MB |
| HAI (ICS) | staženo (3 soubory) | 28,7 MB |
| OTRF Security-Datasets | staženo (3 archivy JSON logů) | 1,1 MB |
| EVTX-ATTACK-SAMPLES | staženo (5 souborů EVTX + metadata) | 4,6 MB |
| MAWI/WIDE (samplepoint-F) | staženo (prefix 60 MB) | bez labelů |
| UNSW-NB15 | záznam už existuje výše (vlna 1, krok 5) | beze změny |
| CIC-IDS2017 | záznam už existuje výše (vlna 1, krok 5) | beze změny |
| CICIoT2023 | vyžaduje žádost, neodesláno | stažení jen přes formulář |
| TON_IoT | nestaženo | jen sdílená složka SharePoint |
| Bot-IoT | nestaženo | jen sdílená složka SharePoint |
| Kitsune | nestaženo | server nepodporuje HTTP Range, labely až za 2 GB dat |
| ICS-Flow | nestaženo | Kaggle, vyžaduje přihlášení |
| DARPA OpTC | nestaženo | Google Drive, přibližně 1 TB |
| LANL Unified Host and Network | vyžaduje žádost, neodesláno | formulář s e-mailem |

### CSE-CIC-IDS2018

| Pole | Hodnota |
|---|---|
| `dataset_id` | `cse-cic-ids2018` |
| `source` | Communications Security Establishment (CSE) a Canadian Institute for Cybersecurity (UNB); Sharafaldin, Lashkari, Ghorbani, ICISSP 2018 |
| `url` | https://registry.opendata.aws/cse-cic-ids2018 (AWS Open Data, anonymní S3, bucket `arn:aws:s3:::cse-cic-ids2018`, region `ca-central-1`, „No AWS account required“); dataset: https://www.unb.ca/cic/datasets/ids-2018.html |
| `license` | Stránka AWS Open Data uvádí licenci jen jako odkaz na http://www.unb.ca/cic/datasets/ids-2018.html. Stránka UNB uvádí: „You may redistribute, republish, and mirror the CSE-CIC-IDS2018 dataset in any form.“ a žádá, aby každé použití nebo šíření obsahovalo citaci datasetu a odkaz na stránku v AWS. Citace: Sharafaldin, Lashkari, Ghorbani, „Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization“, ICISSP, leden 2018. Pojmenovaná licence (CC, ODC) uvedena není. |
| `modalities` | Toky CICFlowMeteru (80 sloupců): `Processed Traffic Data for ML Algorithms/*_TrafficForML_CICFlowMeter.csv`. Verze v S3 nemá sloupce zdrojové a cílové IP ani zdrojového portu (jen `Dst Port`), takže spojování s hostovými daty podle adres není možné. |
| `label_schema` | Poslední sloupec `Label`. Hodnoty ve výřezech: `Benign`, `FTP-BruteForce`, `SSH-Bruteforce`, `DoS attacks-GoldenEye`, `DoS attacks-Slowloris`, `Bot`, `Infilteration` (tak v datech, s překlepem). Stránka UNB uvádí názvy útoků v jiném zápisu (např. „DoS-GoldenEye“, „Infiltration“) a neuvádí samostatný benigní štítek; platí zápis v souboru. |
| osobní údaje | Testbed, provoz generovaný simulací; skuteční uživatelé nejsou. |
| `known_leakage_risks` | Soubory nejsou řazené podle času (časové značky `dd/mm/yyyy hh:mm:ss` se uvnitř souboru střídají a hodina je bez AM/PM), prefix souboru proto nemusí být souvislé časové okno. Uprostřed některých souborů jsou vložené opakované hlavičky (v prefixu `thu-01-03` 12 řádků `Dst Port,...`), při načítání je nutné je vyřadit. Prefix `wed-14-02` obsahuje téměř jen útočné toky (701 benigních). Pro tuto verzi toků platí známé výhrady k chybám štítků a konstrukce toků CICFlowMeteru popsané v literatuře o CIC sadách. Protože chybí adresy, nelze oddělit útočníka od oběti podle adresního plánu testbedu a naopak roli „útočník“ lze odvodit jen z portů a z charakteru toku. |
| `wave` | 3 |

Výřezy (prefix souboru od bajtu 0, useknuto na poslední kompletní řádek; počty bez opakovaných hlaviček):

| Výřez (`cse-cic-ids2018\`) | Zdrojový soubor v S3 (velikost) | Velikost | SHA-256 | Toků | Štítky |
|---|---|---:|---|---:|---|
| `wed-14-02-ftp-ssh.prefix.csv` | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` (358 223 333 B) | 79 999 917 B | `d1178f0b1b5b90e673a967ec831f43b786c5bb79fda0ba49290ae206c3197ec7` | 281 111 | Benign 701, FTP-BruteForce 179 244, SSH-Bruteforce 101 166 |
| `thu-15-02-dos.prefix.csv` | `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` (375 945 899 B) | 34 999 838 B | `968bbdbd65f5f2c152dea4d276f8b60354b6dff9e14a1fd36330ce280fb09753` | 90 143 | Benign 37 645, DoS attacks-GoldenEye 41 508, DoS attacks-Slowloris 10 990 |
| `fri-02-03-bot.prefix.csv` | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` (352 368 373 B) | 69 999 753 B | `623db79e3be7d7681049098fe17c1ccd808f356b29cf1fac262da8669a51f245` | 220 340 | Benign 38 787, Bot 181 553 |
| `thu-01-03-infiltration.prefix.csv` | `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` (107 842 858 B) | 54 999 859 B | `aae619ebcc4ddc5b618e1fb9415c2d32a978a43088e93960de1265942347dd5c` | 170 163 | Benign 117 644, Infilteration 52 519 |

Celkem 239 999 367 B. Základ URL souborů: `https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/<soubor>` (HTTP Range `0-N`).

### LUFlow

| Pole | Hodnota |
|---|---|
| `dataset_id` | `luflow` |
| `source` | Lancaster University, telemetrie z honeypotů v adresním prostoru univerzity, nástroj Cisco Joy, anotace rámcem Citrus/Tangerine (podle README repozitáře) |
| `url` | https://github.com/ruzzzzz/LUFlow (veřejný repozitář; soubory `<rok>/<měsíc>/<rok>.<mm>.<dd>.zip`) |
| `license` | Neověřeno. V repozitáři není soubor LICENSE, README licenci ani pravidla použití neuvádí a GitHub API vrací `license: null`. Citace datasetu README neuvádí. Použito jen pro výzkum v rámci práce; před jakýmkoli dalším šířením nutné ověřit u autorů. |
| `modalities` | Jednosměrné toky Joy (CSV v zipu), 16 sloupců: `avg_ipt,bytes_in,bytes_out,dest_ip,dest_port,entropy,num_pkts_out,num_pkts_in,proto,src_ip,src_port,time_end,time_start,total_entropy,label,duration`. IP adresy jsou podle README anonymizované na číslo autonomního systému. |
| `label_schema` | Sloupec `label` (15. z 16, ne poslední) ∈ {`benign`, `malicious`, `outlier`}. `outlier` = tok, který se nepodařilo označit za škodlivý, ale nepatří do běžného profilu; nepočítat ani jako Malicious, ani jako Benign (obdoba `Unknown` u CTU-13). Útoky nejsou rozlišeny podle typu. |
| osobní údaje | Provoz honeypotů a produkčních služeb univerzity; adresy anonymizované na AS. Před zveřejněním výstupů ověřit. |
| `known_leakage_risks` | Štítek vzniká automaticky z korelace s threat intelligence, takže závisí na indikátorech (IP, porty), které by mohl používat i detektor. Škodlivé toky pocházejí převážně z honeypotů, benigní z produkčních služeb: rozdíl v cílových adresách a portech je silný, ale nereprezentativní signál. Hodnoty `avg_ipt` se v CSV místy zapisují exponenciálně (`5.07E-4`). |
| `wave` | 3 |

| Soubor (`luflow\`) | Zdroj | Velikost (zip) | SHA-256 (zip) | Toků | benign | malicious | outlier |
|---|---|---:|---|---:|---:|---:|---:|
| `2020.06.19.zip` | `2020/06/2020.06.19.zip` | 18 960 782 B | `c54441124cba8fef46559d05a535712a92df8c1490f2ac4c044fb3aaef6e4ea4` | 765 360 | 377 672 | 263 950 | 123 738 |
| `2020.09.01.zip` | `2020/09/2020.09.01.zip` | 21 003 030 B | `c113d8b0985a1e25d551825019d9ce3de957be02c63a95de2174533251d8e988` | 929 443 | 439 966 | 429 801 | 59 676 |
| `2021.02.01.zip` | `2021/02/2021.02.01.zip` | 25 921 333 B | `dc3e3954ee304773b90287289d941f5f75ebaca58d8e64e17002da0051135b71` | 1 156 141 | 526 880 | 343 239 | 286 022 |
| `2022.06.13.zip` | `2022/06/2022.06.13.zip` | 10 714 666 B | `f629c95b283a60dc4b66fd302e6efe78a8eba2ae90c973dd668c9af05c585e27` | 452 123 | 219 917 | 107 240 | 124 966 |

Základ URL: `https://raw.githubusercontent.com/ruzzzzz/LUFlow/master/`. Počty toků spočítány proudově z obsahu zipu (bez rozbalení na disk).

### HAI (ICS, HIL testbed)

| Pole | Hodnota |
|---|---|
| `dataset_id` | `hai` |
| `source` | ETRI, HIL-based Augmented ICS testbed (Shin, Lee, Yun, Min a spol.) |
| `url` | https://github.com/icsdataset/hai |
| `license` | README uvádí: „This work is licensed under a Creative Commons Attribution-ShareAlike License (CC BY-SA 4.0)“; metadata na téže stránce uvádějí „CC BY 4.0“. Stránka je sama v rozporu, proto se předpokládá přísnější CC BY-SA 4.0 (uvedení autora a stejné podmínky při šíření odvozenin). Citace podle verze: HAI 20.07 = Shin, Lee, Yun, Kim, „HAI 1.0: HIL-Based Augmented ICS Security Dataset“ (USENIX CSET 2020); HAI 21.03 = Shin, Lee, Yun, Min, „Two ICS Security Datasets and Anomaly Detection Contest on the HIL-Based Augmented ICS Testbed“ (CSET 2021). |
| `modalities` | Časové řady procesních proměnných (senzory a akční členy, 1 s), ne síťový provoz. Sloupec `time` a procesní sloupce (HAI 20.07: 64 sloupců celkem, HAI 21.03: 84). |
| `label_schema` | Poslední čtyři sloupce: `attack` (celý systém, 0/1), `attack_P1`, `attack_P2`, `attack_P3` (podle procesů). U HAI 20.07 je oddělovačem `;`, u HAI 21.03 čárka. Od HAI 22.04 se štítky podle procesů nevedou (zde nestaženo). |
| osobní údaje | Fyzický testbed (simulace kotle, turbíny, čerpání), žádní uživatelé. |
| `known_leakage_risks` | Útoky jsou málo početné a souvislé v čase, náhodné dělení řádků na trén a test proto vede k úniku; dělit je nutné po časových blocích a po celých útocích. Tréninkové soubory jsou čistě normální, útoky jsou jen v `test*`. |
| `wave` | 3 |

| Soubor (`hai\`) | Zdroj | Velikost | SHA-256 | Řádků | Štítek `attack` |
|---|---|---:|---|---:|---|
| `hai-20.07_test2.csv.gz` | `hai-20.07/test2.csv.gz` | 16 907 509 B | `427841d8240d5fa557fb28ed58da21bb93d0a3c2b30e43b82ab2d816330185e2` | 153 000 | 0: 147 011, 1: 5 989 |
| `hai-21.03_test1.csv.gz` | `hai-21.03/test1.csv.gz` | 6 149 549 B | `532de41bed372206941609d05b763958f59abecfd63c8c123649f823452e445e` | 43 201 | 0: 42 572, 1: 629 |
| `hai-21.03_test4.csv.gz` | `hai-21.03/test4.csv.gz` | 5 602 841 B | `51380fd28fd985b94a10cae3d8b80926becb3af9f233f2d3a38ab8be9482a482` | 39 601 | 0: 38 444, 1: 1 157 |

Základ URL: `https://raw.githubusercontent.com/icsdataset/hai/master/`.

### OTRF Security-Datasets (hostová telemetrie, JSON)

| Pole | Hodnota |
|---|---|
| `dataset_id` | `otrf-security-datasets` |
| `source` | Open Threat Research Forge (OTRF), laboratoř „Mordor shire“ |
| `url` | https://github.com/OTRF/Security-Datasets |
| `license` | Soubor LICENSE v repozitáři: „MIT License, Copyright (c) 2021 Open Threat Research Forge“ (GitHub API: `MIT`). README zároveň v sekci „License: GPL-3.0“ odkazuje na GNU General Public License a má odznak MIT; rozpor v repozitáři trvá. Závazný je soubor LICENSE (MIT), README se zaznamenává jako nejednoznačnost. |
| `modalities` | JSON záznamy událostí Windows (Sysmon, Security, PowerShell a další), jeden objekt na řádek, v zipu. Staženy jen složky `host`, ne síťové PCAP. |
| `label_schema` | Žádný štítek na úrovni události. Pravda je na úrovni scénáře: soubor `_metadata/<id>.yaml` (klíče `title`, `id`, `attack_mappings` s `technique`, `sub-technique`, `tactics`, `description`, `simulation.tools`). Záznamy mají klíč `tags` (u části souborů `["mordorDataset"]`), ten není štítek útoku. |
| osobní údaje | Laboratorní prostředí, účty jsou testovací. |
| `known_leakage_risks` | Útok tvoří jen část záznamů každého scénáře a čas začátku útoku není ve štítcích, jen v popisu. Pozadí pochází z jednoho prostředí (jména hostů `MORDORDC`, `WORKSTATION5`), model se může naučit jména hostů. Příkazové řádky obsahují zakódované PowerShell příkazy (text logu, ne spustitelné soubory). |
| `wave` | 3 |

| Soubor (`otrf-security-datasets\`) | Zdroj v repozitáři (`datasets/atomic/`) | Velikost | SHA-256 | Technika (metadata) |
|---|---|---:|---|---|
| `covenant_psremoting_command.zip` (JSON 9 592 189 B, 4 284 řádků) | `windows/lateral_movement/host/` | 359 550 B | `4a2e0f9688c87a90b17b608ff38fb2230ceb7305ea0368703dcfe53269e3f096` | T1021.006 (SDWIN-200806115603) |
| `empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip` (JSON 38 828 677 B, 8 465 řádků) | `windows/credential_access/host/` | 655 112 B | `fe1fcc96c0ff0cbae8fd4ffaadf85f51e28475441774f6fda3d963d4e2962800` | metadata YAML neověřeno (ID nenalezeno), podle názvu DCSync |
| `cmd_psexec_lsa_secrets_dump.zip` (JSON 408 881 B, 286 řádků) | `windows/credential_access/host/` | 38 086 B | `c52e6145fefe37373a5274e2976ccf6d62e4d33e13c55dc1a2ce17f00506d1a6` | T1003.004 (SDWIN-201019033054) |
| `SDWIN-200806115603.yaml`, `SDWIN-201019033054.yaml` | `_metadata/` | viz `manifest.json` | viz `manifest.json` | metadata scénářů |

Základ URL: `https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/`.

### EVTX-ATTACK-SAMPLES (hostová telemetrie, EVTX)

| Pole | Hodnota |
|---|---|
| `dataset_id` | `evtx-attack-samples` |
| `source` | sbousseaden (jednotlivec), vzorky EVTX seřazené podle taktik MITRE ATT&CK |
| `url` | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| `license` | GPL-3.0 (soubor `LICENSE.GPL`, GitHub API: `GPL-3.0`). Copyleft: při šíření odvozených děl platí stejné podmínky; soubory se v repozitáři práce nešíří (zůstávají na disku mimo git). |
| `modalities` | Binární Windows Event Log (`.evtx`, malé soubory, 69 632 B). Pomocný soubor `evtx_data.csv` (4 262 506 B) je výpis událostí ze všech vzorků do CSV. |
| `label_schema` | Žádný štítek na úrovni události. Pravda je na úrovni souboru: název souboru (předpona `CA_` Credential Access, `LM_` Lateral Movement) a v `evtx_data.csv` sloupce `EVTX_FileName` a `EVTX_Tactic` (první sloupec je bezejmenný index; dále např. `Channel`, `Computer`, `EventID`, `EventRecordID`, `SystemTime`). |
| osobní údaje | Laboratorní prostředí (`example.corp`, `insecurebank.local`). |
| `known_leakage_risks` | Soubory obsahují jen útočné události bez benigního pozadí, takže detektor učený ze samotných vzorků se naučí rozlišovat podle ID událostí. Použít jen jako sbírku pozitivních příkladů a ke kontrole parseru; benigní pozadí je nutné doplnit jinde. Jména hostů se opakují mezi vzorky. |
| `wave` | 3 |

| Soubor (`evtx-attack-samples\`) | Velikost | SHA-256 | Taktika |
|---|---:|---|---|
| `CA_DCSync_4662.evtx` | 69 632 B | `679b2ff27af6c932c07bf3e81391e455fae98e69bf3aff0f524e31aadc418131` | Credential Access |
| `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` | 69 632 B | `c890d2b67dc2902b2fa5a094e517674920911a15b273f43c674fbfaa69540658` | Lateral Movement |
| `LM_REMCOM_5145_TargetHost.evtx` | 69 632 B | `9f6fd1e395454108e2176448f31cc8354378075f51474756a1ed2418e9bbdae2` | Lateral Movement |
| `LM_Remote_Service02_7045.evtx` | 69 632 B | `af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458` | Lateral Movement |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | 69 632 B | `53999570b8edb7f909cb07165fecda1f29bf04e3462d13dc404e31f31a9ab932` | Lateral Movement |
| `evtx_data.csv` | 4 262 506 B | `9220b0725221244a6b61dff8dabbf382831c0fcc2ad9d261ae60cb1f2b082fff` | metadata, všechny taktiky |

Základ URL: `https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/`.

### MAWI / WIDE (neškodný provoz páteřní linky)

| Pole | Hodnota |
|---|---|
| `dataset_id` | `mawi` |
| `source` | WIDE Project, MAWI Working Group, samplepoint-F |
| `url` | https://mawi.wide.ad.jp/mawi/ (soubor https://mawi.wide.ad.jp/mawi/samplepoint-F/2024/202401011400.pcap.gz, 3 590 906 931 B, `Accept-Ranges: bytes`; popis záznamu https://mawi.wide.ad.jp/mawi/samplepoint-F/2024/202401011400.html) |
| `license` | Formální licence není. Stránka MAWI uvádí: „You may use WIDE traffic data for only research purposes.“ a „Actions that trespass upon users' privacy are prohibited.“ Pokyny https://mawi.wide.ad.jp/mawi/guideline.txt: „Traffic data can be used only for research purposes. It is prohibited to use traffic data for other than research. Care should be taken not to trespass upon users' privacy.“ a „Traffic data conforming to this guideline can be used for research without permission from the WIDE Project.“ Anonymizace: IP adresy jsou zamíchány upravenou verzí tcpdpriv (stránka MAWI), payload je odstraněn (pokyny; stránka záznamu uvádí `CapLen: 96 bytes`). |
| `modalities` | PCAP (little-endian, snaplen 96 B), pouze hlavičky. Staženo prvních 60 000 000 B komprimovaného gz souboru; gzip proud je záměrně useknutý a čte se od začátku do konce dostupných dat (na konci se očekává chyba „unexpected end of file“). Hlavička pcap ověřena (`d4c3b2a1`, snaplen `0x60`). |
| `label_schema` | Žádný štítek v souboru. Anomálie značkuje samostatný projekt MAWILab; jeho štítky nejsou součástí výřezu a jejich dostupnost a licence pro tento den neověřeny. Provoz je neoznačený, ne benigní: obsahuje reálné skeny a útoky z internetu. |
| osobní údaje | Adresy anonymizované podle výše; do výstupů práce nepřebírat konkrétní adresy a nepokoušet se je deanonymizovat. |
| `known_leakage_risks` | Jedna linka, jeden den; prefix 60 MB komprimovaného souboru pokrývá jen začátek patnáctiminutového záznamu. Vazba na jiné datasety není možná kvůli zamíchaným adresám. |
| `wave` | 3 |

| Soubor (`mawi\`) | Velikost | SHA-256 |
|---|---:|---|
| `samplepoint-F_202401011400.pcap.gz.prefix60MB` | 60 000 000 B | `01599d8a34724799f1b188b90fcb9b9c90e715d591fe682d0a19ffd68e717554` |

### UNSW-NB15 a CIC-IDS2017

Záznamy obou datasetů už jsou v sekci „Vlna 1 (krok 5, 2026-11-04)“ výše (licence, schéma štítků, výřezy a SHA-256), proto se tu nedublují ani nepřepisují.

### Nestaženo, s důvodem

| dataset | url | licence / podmínky podle oficiální stránky | důvod |
|---|---|---|---|
| CICIoT2023 | https://www.unb.ca/cic/datasets/iotdataset-2023.html (odkaz „Download the dataset“ na http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/) | Stránka UNB licenci ani podmínky neuvádí (jen „© University of New Brunswick“), licence neověřena. Citace: Neto, Dadkhah, Ferreira, Zohourian, Lu, Ghorbani, „CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment“, Sensors 2023. Kategorie útoků podle stránky: DDoS, DoS, Recon, Web-based, Brute Force, Spoofing, Mirai. | Vyžaduje žádost, neodesláno. Odkaz vede na formulář (jméno, příjmení, e-mail, organizace, funkce, země). |
| TON_IoT | https://research.unsw.edu.au/projects/toniot-datasets | „Free use of the TON_IoT datasets for academic research purposes is hereby granted in perpetuity.“ Komerční použití po dotazu u autora (Dr Nour Moustafa). Nutná citace osmi článků uvedených na stránce. | Data jsou na oficiální stránce jen jako sdílená složka SharePoint. Stránka neuvádí názvy souborů ani sloupců štítků (složky Raw, Processed, Train_Test, Description_stats, SecurityEvents_GroundTruth). Přímé stažení z prostého HTTP(S) URL se neověřilo a nebylo zkoušeno; schéma štítků neověřeno. |
| Bot-IoT | https://research.unsw.edu.au/projects/bot-iot-dataset | „Free use of the Bot-IoT dataset for academic research purposes is hereby granted in perpetuity.“ Komerční použití „should be agreed by the authors“. Citace: Koroniotis, Moustafa, Sitnikova, Turnbull, Future Generation Computer Systems 2019 a další články z oficiální stránky. | Stejný důvod jako TON_IoT (sdílená složka SharePoint). Stránka uvádí 5% podmnožinu (4 soubory, asi 1,07 GB), která je nad limitem 300 MB na dataset. Názvy souborů a sloupců stránka neuvádí; schéma štítků neověřeno. |
| Kitsune Network Attack Dataset | https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset | CC BY 4.0 („allows for the sharing and adaptation of the datasets for any purpose, provided that the appropriate credit is given“). Citace: Kitsune Network Attack [Dataset], UCI Machine Learning Repository, 2019, https://doi.org/10.24432/C5D90Q. | Jediný ZIP o velikosti 17,7 GB; server na požadavek s hlavičkou Range odpověděl celým obsahem (HTTP 200), výřez tedy nejde získat bez přenosu celého začátku. V ZIPu je u prvního útoku (`active_wiretap`) soubor `…_pcap.pcapng.gz` (147 053 948 B) a za ním `…_dataset.csv.gz` (2 090 996 164 B); `_labels.csv` by byl až za těmito daty. Výřez s labely by vyžadoval přenos nad 2 GB, nad limitem. Zkušební přenos se po zhruba 236 MB přerušil a data se smazala. Labely podle stránky: soubory `_labels.csv`, hodnoty 0/1 (1 = škodlivý paket). |
| ICS-Flow | https://www.kaggle.com/datasets/alirezadehlaghi/icssim (podle článku arXiv 2305.09678) | Neověřeno (článek licenci dat neuvádí, stránku Kaggle bez přihlášení nelze ověřit). | Kaggle vyžaduje přihlášení, nestaženo. |
| DARPA OpTC | https://github.com/FiveDirections/OpTC-data | README: „DARPA is releasing these files in the public domain to stimulate further research.“ a „The data is released as-is. DARPA makes no warranties…“; „Distribution A: Approved for public release: distribution unlimited“. GitHub API licenci nevrací. | Data (přibližně 1 TB komprimovaného JSON, složky `ecar-bro`, `ecar`, `bro`) jsou na Google Drive (https://drive.google.com/drive/u/0/folders/1n3kkS3KR31KUegn42yk3-e6JkZvf0Caa), ne přes přímé HTTP(S) URL; nestaženo. Ground truth je v `OpTCRedTeamGroundTruth.pdf` v repozitáři. |
| LANL Unified Host and Network | https://csr.lanl.gov/data/cyber1/ | CC0 1.0 („Los Alamos National Laboratory has waived all copyright and related or neighboring rights“). Citace: A. D. Kent, „Comprehensive, Multi-Source Cybersecurity Events“, LANL, 2015, DOI 10.17021/1179829. | Vyžaduje žádost, neodesláno. Stažení vyžaduje formulář s e-mailem a popisem použití. Soubory: auth 7,2 GB, proc 2,2 GB, flows 1,1 GB, dns 177 MB, redteam 4,8 kB. |

## Krok 13: CTU-13 pcap a CTU-Normal-20 (2026-11-15)

| pole | hodnota |
|---|---|
| source | Stratosphere IPS / CTU (ČVUT), `mcfp.felk.cvut.cz/publicDatasets` |
| licence | CTU-13: Creative Commons CC-BY (stránka stratosphereips.org/datasets-overview, ověřeno 2026-11-15); citovat Garcia, Grill, Stiborek, Zunino 2014. CTU-Normal-20: licence v README neuvedena, použito jen lokálně |
| soubory | `ctu-normal-20/2017-04-30_win-normal.pcap` (282 415 864 B); `ctu13-pcap/botnet-{42,43,46,54}.pcap` |
| zpracování | Zeek (docker zeek/zeek:latest), logy v `out/` vedle pcapů; data mimo repozitář (`F:\Projekty\bakula-datasets`) |
| nezpracováno | CIRA-CIC-DoHBrw-2020 a CIC-Bell-DNS2021 (stažení přes formulář UNB, vyloučeno zadáním), MAWI (licence neověřena) |
