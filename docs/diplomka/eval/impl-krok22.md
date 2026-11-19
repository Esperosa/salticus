# Krok 22: provedení (fáze DO a CHECK)

Plán: `plan-krok22.md` (schválen vedoucím). Pracovní data: `F:\work-tmp\k22`. Tento dokument se doplňuje po etapách; sekce 1 je zapsána a komitnuta **před** jakoukoli změnou kódu kroku 22.

## 1. Předregistrace (E0, zapsáno před kódem)

### 1.1 Prahy pro držený běh E3 (beze změny z plánu 1.5)

| práh | metrika | splněno, když |
|---|---|---|
| K22-1 | omylem zavřená (skutečná, ne stínová) zavření ve FG22 | 0 ve všech konfiguracích; hlásí se i n zavření a Wilson 95 % |
| K22-2 | detekce po rodinách a souhrnná, FG22 vs F22 | jako K20-2 (žádná rodina nižší o víc než 1 útok, souhrn ≥) |
| K22-3 | zobrazené FP | FG22/F22 ≤ 1,01 **a** F22c/F22 ≤ 1,00 |
| K22-4 | případy pro člověka FG22 vs F22 | nárůst ≤ 2 % |
| K22-5 | tabulka hranice (stín) | pro každou buňku (druh pozitivního důkazu × typ nálezu) n, správná, omylem (sjednocení cf a příčinně), horní mez Wilson 95 %; kandidát, když horní mez < 1 % (n ≥ 381 s 0 omyly) |
| K22-6 | regrese bez přepínačů | bitová shoda `networks.jsonl` s krokem 21 na ladicích seedech 20269701 a 20269703 (kromě časů) |
| K22-7 | svět v1 vs v2 (diagnostika) | hlásí se změna FP, detekce a počtu stínových lístků; bez prahu |

Předpověď (z plánu 1.5): F22c/F22 ≈ 0,95; ve světě v2 žádná buňka s n ≥ 381.

### 1.2 Seedy (zapsáno dopředu)

| sada | seedy | použití |
|---|---|---|
| ladicí | 20269701, 20269703 | K22-6, kontrola stínu |
| ladicí svět v2 | 20269801 až 20269805 | E2 |
| **držená** | **20270301 až 20270310** | jen E3, jednou, po zmrazení kódu a světa commitem |
| stopy | 20270207 (R), 20270208 (R, RG) | jen B1 a diagnostika B2 |
| laboratoř C | 22001 (ladicí), 22101 (držená) | B6 |

V E0 a E1 se držené seedy nepoužijí.

### 1.3 Kritéria etap E0 a E1 (zapsáno před kódem)

- **B1 (E0):** deterministické opakování R 20270207 (binárka `salticus-k21-224ed3e.exe`, `K15_TRACE`, jen síť 0, `--max-networks 1`; nejdřív se ověří shoda souhrnu sítě 0 s během `F:\work-tmp\k21\scan\off-R-20270207`). Přijato, když oba příčinně omylem vyvrácené případy mají příčinu z tabulky `impl-krok21.md` 6 b (slabé skupiny, bez pozitivního důkazu s vlastníkem) a brána na rekonstruovaném rozhodnutí vrátí `Refusal`. Zamítnuto (nový nález K22-N1, vysoká priorita), když některý obsahuje pozitivní důkaz s vlastníkem nebo dvě nezávislé skupiny.
- **B2 (N14):** přepínač `ctx_host_first` (V3Features, výchozí vypnuto). Jednotkové testy: (a) záznam jiného hostu → `ambiguous = false`, rozhodnutí jako bez záznamu; (b) záznam téhož hostu bez doloženého zdroje → `ambiguous = true`; (c) sonda `known_gap_strict_close_flags_ambiguous_from_other_host_record` převrácena na pozitivní test s přepínačem (bez přepínače zůstává chování kroku 21). Stopa 20270208/0, rameno RG s přepínačem: z nálezů `connection_timeout_burst`, které jsou `protected` jen v RG (162), jich zmizí ≥ 95 %.
- **B3 (N13):** za týmž přepínačem. `GateInput.targets`; u `AuthorizedScanner`: zdroj ∈ `sources` a **všechny** cíle ∈ rozsah (`hosts`, CIDR); prázdný rozsah = nedoloženo. Testy: sken ven přes bránu s rozsahem = vnější cíl a zdrojem = skener → vysvětleno; jeden cíl mimo rozsah → nevysvětleno; zdroj skeneru + nález jiného typu než sken → nevysvětleno/nezavřeno. Sonda `known_gap_scanner_scope_does_not_match_finding_host_of_egress_scan` převrácena. Měřicí přepínač `K21_SCANNER_SCOPE` zůstává do B5 (odstranění patří ke světu v2, E2; v E1 se simulace nemění).
- **B4 (stín):** přepínač `shadow` (výchozí vypnuto). Stín volá `admit_ladder`/`admit_context` nad týmiž vstupy, zapisuje `shadow_tickets.jsonl`, nic nezavírá, nemění zobrazení ani stav. Kritéria: K22-6 se stínem i bez něj (bitová shoda `networks.jsonl` kromě časů s krokem 21); kontrola smyslu: rameno R se stínem na seedech běhu `scan` kroku 21 musí ve stínu obsahovat všech 14 automatických zavření a 1 529 vyvrácení jako odmítnutá „bez pozitivního důkazu“ (shoda počtu ± 0), viz 1.4.
- **Testy:** `cargo test --lib` bez nových selhání (známá: 5 `broker::tests` bez Redis, 1 `identity_lab` bez Dockeru); `cargo fmt --check`, `cargo clippy` čisté.

### 1.4 Upřesnění kontroly smyslu stínu (zapsáno před kódem)

Plán (B4) žádá shodu stínu se 14 automatickými zavřeními a 1 529 vyvráceními z běhu `scan` ramene R (seedy 20270201 až 20270210, 40 sítí). Tyto seedy byly drženými seedy kroku 21; v kroku 22 se použijí jen jako diagnostika správnosti stínu (stejně jako stopy 20270207/08), ne pro rozhodnutí o prazích K22. Odhad ceny: 40 sítí × ≈ 76 s CPU ≈ 50 min CPU, 8 vláken. Pokud by cena výrazně překročila rozpočet E1, kontrola se zúží na seedy se stopou (20270203, 20270206, 20270209) a zapíše se to.
