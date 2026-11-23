# Předregistrace kroku 31: pravidlo odchozího skenování (`outbound_scan`)

Zapsáno **před** prvním měřením pravidla na produkční cestě. Navazuje na krok 30.

## 1. Motivace a forenzní zjištění (krok 30)

Na skutečných botnetech CTU-13 zachytila produkční cesta v3 jen 10 z 30 označených infikovaných hostů (33 %, interval 19 až 51 %), shodně v obou ramenech. Rozbor nezachycených hostů (`tools/k30_eval.py`, ruční rozbor toků):

- Scénáře 43, 46, 49 (host 147.32.84.165): **10 263, 901 a 381 spojení** na 419, 183 a 215 různých cílů, většinou SYN bez odpovědi (7 580 na port 80; 159 na port 135) a pokusy o SMTP spam. Produkt k nim **neměl žádný nález**.
- Scénáře 48 a 50: hosty mají jen 63 a 5 spojení (DNS, HTTP, NTP); žádný detektor toků to od neškodného provozu neodliší.
- Scénáře 44 a 53: „infikovaní“ jsou vnější adresy volající infikovaný host (C&C); předem zapsaná definice kroku 30 je zahrnula.

Příčina v kódu: pokusy bez odpovědi se jako `scan_attempts` počítají jen u toků s cílem v rozsahu; odchozí toky (cíl venku) jdou jen do behaviorální vrstvy, jejíž detektory vyžadují zralý profil hosta (`host_mature_s` 12 h, `mature_s` 48 h). Infikovaný host, který skenuje hned po infekci, je tedy neviditelný.

## 2. Pravidlo (zmrazeno před měřením)

`src/behavior/outscan.rs`, typ `outbound_scan`, přepínač `outscan` (výchozí vypnuto, `recommended()` se nemění, typ je chráněný). Podmínky: aspoň **25** různých vnějších cílů s neúspěšným TCP spojením (`S0`, `REJ`, `RSTOS0`) na stejný port během **300 s** a podíl neúspěšných spojení na (host, port) v úseku aspoň **0,5**. High od 100 cílů.

Původ prahů: 25 cílů a 5 minut jsou výchozí hodnoty skriptu `scan.zeek` v Zeeku (`addr_scan_threshold`, `scan_interval`), nikoli hodnoty z mých dat. Podmínku podílu 0,5 („většina pokusů selhala“) jsem přidal po kontrole falešných poplachů na skutečné domácí síti: bez ní vyšel jeden neškodný zásah (PC, port 443, 181 neúspěšných cílů za 5 minut, ale podíl neúspěšných 0,43). Na vývojových scénářích CTU-13 (42, 51, 54) pravidlo s přesnější definicí neúspěchu označilo infikované hosty a nejvýš jednoho neinfikovaného (`tools/k31_outscan_probe.py`). Hodnoty se po tomto zápisu nemění.

## 3. Data

- **Nezávislý test (primární):** IoT-23, 7 malwarových scénářů v `labs/datasets/iot23` (skutečné Zeek stavy spojení). Pravidlo vzniklo z rozboru CTU-13, na IoT-23 jsem skenování neprohlížel. Infikovaný host = zdroj toku se štítkem `Malicious`; rozsah podle převažující privátní /24 z dat. Poznámka: tři honeypotové scénáře bez škodlivých toků slouží jako kontrola šumu.
- **Potvrzovací (není nezávislý):** CTU-13 testovací scénáře 43 až 53 (10). Rozbor kroku 30 je viděl, takže tento výsledek je potvrzení, ne nezávislý test. Převod binetflow v2: stav spojení se bere z pole `State` (`S_` → `S0`; `SR_`, `S_R`, `S_RA`, `SA_R` → `REJ`; jinak `SF`), ne z jednosměrnosti.
- **Šum na neškodných datech:** skutečná domácí síť, 3 dny, bez vložených útoků (`F:\work-tmp\shadow\zeek\logs`), 125 oken.

## 4. Ramena a měřítka

- **A2:** jádro v3, výchozí preset. **C:** A2 + `outscan`. Přehrání po 30minutových oknech celou produkční cestou, převod a vyhodnocení stejné jako v kroku 30 (`tools/k30_ctu13.py`, rozšířený o formát Zeek).
- Zachycení infikovaného hosta: zmíněn v zobrazeném nálezu jiného typu než „neočekávaný provoz“.
- Šum: počet zobrazených nálezů; pro domácí síť počet zobrazených nálezů `outbound_scan`.

## 5. Hypotézy a rozhodovací pravidla

- **H1 (žádná ztráta):** C zachytí v žádném z 17 scénářů (7 IoT-23 + 10 CTU-13) méně infikovaných hostů než A2. Splněno při 0 scénářích s C < A2.
- **H2 (šum):** součet zobrazených nálezů C přes všech 17 scénářů ≤ 1,25× součtu A2; a na domácí síti ≤ **3** zobrazených nálezů `outbound_scan` za 3 dny.
- **H3 (přínos):** C zachytí o aspoň **3** infikované hosty víc než A2 (souhrnně přes 17 scénářů). Vyhodnotit zvlášť pro IoT-23 (nezávislé) a CTU-13 (potvrzovací).
- **Rozhodnutí:** H1 a H2 splněny a H3 splněna na IoT-23 → přepínač se označí za ověřený veřejnými daty se skutečnou pravdou; H3 splněna jen na CTU-13 → označí se jako „potvrzeno jen na datech, ze kterých vzniklo“; H1 nebo H2 nesplněna → forenzní rozbor a odebrání z profilu.
- Žádný kód ani práh se po vidění testu nemění; případná změna je nový krok s novým rozdělením.

## 6. Hrozby platnosti

- Jedna rodina sítě (testbed) pro CTU-13; IoT-23 jsou IoT zařízení (jiný profil provozu).
- Převod binetflow je ztrátový i ve verzi 2 (počty paketů se dělí úměrně bajtům).
- Skenovací chování se v IoT-23 liší podle rodiny malwaru; malé scénáře mohou skenování neobsahovat vůbec (pak H3 nemá důkaz, ne výsledek).
- Označení „infikovaný host“ se opírá o štítky datasetu, ne o mou kontrolu.
