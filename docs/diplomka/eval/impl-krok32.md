# Krok 32: nezávislý test `outbound_scan` a nové pravidlo `unanswered_retry`

Podle `predreg-krok32.md`. Přehrání po 30minutových oknech celou produkční cestou v3 (`tools/k30_ctu13.py`), vyhodnocení `tools/k32_eval.py`. Nové scénáře IoT-23 (`dataset23`, `dataset7`, `dataset10`) z Zenodo (CC BY 4.0), vytažené jednotlivě přes HTTP Range (`tools/k32_csv2zeek.py`); data zůstávají lokálně, mimo git.

## 1. Část A: nezávislý test `outbound_scan` (krok 31)

| scénář | infikováno | A zachyceno | C zachyceno | zobrazeno A | zobrazeno C | z toho `outbound_scan` |
|---|---|---|---|---|---|---|
| 23 (horizontální sken infikovaného hosta, 112 h) | 1 | 1 | 1 | 3 | 672 | 669 |
| 7 (DDoS, 24 h) | 2 | 1 | 1 | 2 | 2 | 0 |
| 10 (horizontální sken, 10 h) | 1 | 1 | 1 | 2 | 22 | 20 |

- **H-A1 (žádná ztráta): splněna** (0 scénářů s C < A).
- **H-A2 (C zachytí o ≥ 1 host víc): NESPLNĚNA** (0). Ve všech třech scénářích výchozí nastavení infikovaný host uvnitř rozsahu už zachytilo jinak; jediný nezachycený je externí adresa 162.248.88.215 ve scénáři 7 (útočník vně rozsahu, na který pravidlo odchozího skenování nemůže sedět).
- **H-A3 (šum ≤ 1,5×): NESPLNĚNA** (poměr 99,4).

Podle předregistrace: **`outbound_scan` zůstává „potvrzeno jen na datech, ze kterých vzniklo“**, nezávisle se přínos neprokázal.

### Forenzní příčina šumu a oprava

Vada nebyla v detekci, ale v metadatech nálezu: do `sources` jsem dával vzorek tří cílů, který se mění v každém okně, a paměť nálezů to bere jako „nový zdroj“ a nález zobrazí znovu. 669 zobrazení za 224 oken u jednoho hostu. Oprava: `sources` prázdné (`src/behavior/outscan.rs`, test hlídá stabilitu). Práh ani podmínky detekce se nezměnily.

Kontrola opravy (ne nový předregistrovaný test, jen ověření opravené vady na dvou scénářích, kde se vada projevila):

| scénář | zobrazeno C před | zobrazeno C po | zachyceno před/po |
|---|---|---|---|
| IoT-23 3-1 | 57 (54 `outbound_scan`) | 4 (1) | 1 / 1 |
| nový 10 | 22 (20) | 3 (1) | 1 / 1 |

## 2. Část B: `unanswered_retry`

Pravidlo: ≥ 20 neúspěšných TCP pokusů vnitřního hosta na stejný vnější (cíl, port) za 600 s a žádné úspěšné spojení v úseku (`src/behavior/retry.rs`, přepínač `retry`, výchozí vypnuto, chráněný typ).

Výsledek přes 23 scénářů (3 nové, 10 IoT-23, 10 CTU-13), rameno D proti výchozímu A:

- **H-B1 (žádná ztráta): splněna** (0 scénářů s D < A).
- **H-B2 (šum): splněna**, zobrazeno D/A = 1,014 a na skutečné domácí síti (3 dny) **0** nálezů `unanswered_retry`.
- **H-B3 (přínos, průzkumná):** **+3 infikovaní hosté**: IoT-23 8-1 (0 → 1; motivující scénář), CTU-13 43 a 46 (0 → 1). **Na nezávislých scénářích 0 hostů navíc** (výchozí nastavení tam hosty zachytilo jinak).

Čtení: pravidlo nic nekazí a na neškodné domácí síti mlčí, a zachytí infikované hosty, které výchozí v3 nevidí, ale **nezávislý důkaz přínosu chybí**, protože nové scénáře tento vzor neobsahují.

## 3. Celkový stav po krocích 30 až 32

| nastavení | skutečné scénáře | stav |
|---|---|---|
| výchozí v3 | CTU-13 test: 10 z 23 infikovaných hostů uvnitř rozsahu (43 %) | výchozí |
| + `outscan` | CTU-13 test 13 z 23 (+3, potvrzovací), nezávislé scénáře +0; po opravě zobrazení šum únosný | volitelné, nezávisle neověřeno |
| + `retry` | +3 hosty na datech, ze kterých vzniklo (8-1, CTU-13 43, 46), nezávisle +0; domácí síť 0 zásahů | volitelné, bez ztráty |
| + `attempts`, `attr_calib`, `upload_horizon` | skutečné botnety +0; nic nezhorší | volitelné |

Zbývající nezachycení jsou hosty s 63 a 5 spojeními (neodlišitelné toky) a externí adresy označené „From-Botnet“.

## 4. Meze

- Nové scénáře jsou velké a „snadné“ (DDoS a horizontální skeny s miliony toků); výchozí nastavení v nich infikované hosty zachytí samo. Tento test proto neměří jemnější případy.
- Dvě pravidla (`outscan`, `retry`) vznikla z forenzního rozboru jiných scénářů, kde výchozí nastavení selhalo; nezávislý přínos by vyžadoval další scénáře se stejným vzorem, které teď nemám (zrcadlo CTU je nedostupné, Zenodo má jen část).
- Kontrola opravy vady `sources` je jen ověření na dvou scénářích, ne předregistrovaný test.
- Regresi soaku 48/48 jsem nespouštěl; přepínače jsou ve všech presetech vypnuté.
