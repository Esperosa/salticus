# Krok 30: výsledek předregistrovaného testu na skutečných botnetech CTU-13

Podle `predreg-krok30.md`. Přehrání po 30minutových oknech celou produkční cestou v3 (`tools/k30_ctu13.py`, převod binetflow v1), 10 testovacích scénářů (43 až 53 bez vývojových), rozsah 147.32.84.0/24, každý scénář jednou v obou ramenech. Vyhodnocení `tools/k30_eval.py`.

## 1. Výsledek

| scénář | infikováno | A zachyceno | B zachyceno | A zobrazeno | B zobrazeno |
|---|---|---|---|---|---|
| 43 | 1 | 0 | 0 | 344 | 344 |
| 44 | 2 | 1 | 1 | 312 | 400 |
| 45 | 1 | 1 | 1 | 243 | 267 |
| 46 | 1 | 0 | 0 | 326 | 329 |
| 47 | 1 | 1 | 1 | 325 | 344 |
| 48 | 1 | 0 | 0 | 363 | 364 |
| 49 | 1 | 0 | 0 | 439 | 461 |
| 50 | 10 | 1 | 1 | 385 | 413 |
| 52 | 3 | 3 | 3 | 386 | 386 |
| 53 | 9 | 3 | 3 | 406 | 444 |
| **celkem** | **30** | **10 (33 %, [19 %; 51 %])** | **10** | **3 529** | **3 752** |

- **H1 (žádná ztráta): splněna**, 0 z 10 scénářů s B < A.
- **H2 (šum ≤ 1,5×): splněna**, poměr 1,063.
- **H3 (přínos): žádný**, B = A ve všech scénářích. Přepínače `attempts`, `attr_calib` a `upload_horizon` na těchto datech nic nepřidávají (netýká se to jejich smyslu: botnety CTU-13 hrubou sílu ani druhého útočníka na stejné službě neobsahují).
- Rozhodnutí z předregistrace: přepínače nezhoršují, ale **přínos na skutečných botnetech se neprokázal**.

## 2. Hlavní zjištění: zachycení skutečných botnetů je nízké

V obou ramenech jen **10 z 30** označených infikovaných hostů. Všech 20 nezachycených nemá v produktu **žádný nález**. Forenzní rozbor (ruční rozbor toků, `docs` viz predreg-krok30 a 31):

| skupina | hostů | co dělají |
|---|---|---|
| vnitřní hosty s tisíci spojeními (scénáře 43, 46, 49) | 3 | 10 263, 901 a 381 spojení na 419, 183 a 215 různých cílů, většinou SYN bez odpovědi (port 80, 135) a pokusy o SMTP spam |
| vnitřní hosty s 63 a 5 spojeními (scénáře 48, 50) | 10 | DNS, HTTP a NTP v jednotkách spojení; žádný detektor toků to od neškodného provozu neodliší |
| vnější adresy označené „From-Botnet“ (scénáře 44, 53) | 7 | volají infikovaný host (C&C, peer); **moje předem zapsaná definice je zahrnula**, i když nejsou infikované |

Příčina první skupiny v kódu: pokusy bez odpovědi se jako `scan_attempts` počítají jen u toků s cílem v rozsahu; odchozí toky jdou jen do behaviorální vrstvy, jejíž detektory vyžadují zralý profil hosta (12 až 48 h). Host, který skenuje hned po infekci, je neviditelný. Tohle vedlo ke kroku 31.

## 3. Meze

- Sedm rodin botnetů, jedna síť, 10 scénářů; interval široký.
- Převod binetflow ztrátový (počty paketů úměrně bajtům, stav z jednosměrnosti, v kroku 31 zpřesněn).
- Soubory jsou 30MB výřezy (1 až 6 oken), takže stavové vrstvy se téměř neuplatní.
- Pětice scénářů při první dávce spadla na vadě převodníku (usečený poslední řádek), ještě před měřením; po opravě převodníku proběhly znovu. Detektory ani prahy se neměnily.
- Dvě externí adresy (scénáře 44 a 53) počítají jako „nezachycené“ podle předem zapsané definice; bez nich je podíl na hostech uvnitř rozsahu 10 z 23 (43 %).
