# Krok 28: benchmark vložených útoků po oknech celou produkční cestou v3

Podklad: `impl-krok26.md` (jeden běh nad celým záznamem) a `impl-krok27.md` (pravidlo `bruteforce_attempts`). Jednorázové přehrání nemůže měřit stavové vrstvy (historie hostu, hystereze beaconingu, paměť nálezů, potlačení opakovaných nálezů), a hlásí všechny události, ne to, co produkt skutečně zobrazí. Tady se záznam přehraje po 30minutových oknech tak, že stav přežívá v jednom pracovním prostoru (`tools/k27_cycles.py`, postaveno nad `tools/replay_public.py`), a počítá se jen to, co produkt **zobrazí** (`findingLifecycle[].displayed`).

## 1. Metoda

- Pozadí: skutečný `conn.log` domácí sítě (3 dny, 125 oken), útoky vložené `tools/k25_inject.py` (10 epizod × 10 rodin, každý útočník vlastní IP, pravda v `truth.json`).
- **Zahřátí hostů:** protože detektor záměrně nehlásí periodicitu ani objem hosta, který se v provozu právě objevil (komentář v `beacon.rs`: „implantát aktivní od prvního výskytu hostu se nehlásí“), mají útočníci rodin `exfil_volume`, `exfil_large` a `beaconing` 4 hodiny předchozího ustáleného provozu na tři pevné cíle; útok míří na nový cíl. Ostatní rodiny jsou nové hosty.
- **Detekce epizody** = některý zobrazený nález (jiný než „neočekávaný provoz“) zmiňuje útočníkovu IP (u `scanner_spoof` cíl) a byl poprvé zobrazen v okně, které začíná nejdřív 30 min před začátkem útoku. Interval je Wilsonův 95 %.
- Čtyři nastavení: `base` (jádro v3, výchozí), `att` (+ pravidlo `attempts`), `mod` (+ `known_activity`, vlastní sken deklarován), `mod_att` (obojí).

## 2. Výsledek (10 epizod na rodinu, zobrazené nálezy)

| rodina | base | + attempts | + modul | + modul + attempts |
|---|---|---|---|---|
| vertical_scan | 10/10 | 10/10 | 10/10 | 10/10 |
| horizontal_scan | 1/10 | 1/10 | 1/10 | 1/10 |
| ssh_bruteforce | 0/10 | **10/10** | 0/10 | **10/10** |
| exfil_volume (300 MB, zahřátý host) | 10/10 | 10/10 | 10/10 | 10/10 |
| exfil_large (1,5 GB, zahřátý host) | 8/10 | 8/10 | 8/10 | 8/10 |
| beaconing (zahřátý host) | 10/10 | 10/10 | 10/10 | 10/10 |
| syn_flood | 10/10 | 10/10 | 10/10 | 10/10 |
| ssdp_masquerade (schování) | 10/10 | 10/10 | 10/10 | 10/10 |
| broadcast_masquerade (schování) | 1/10 | 1/10 | 7/10 | 7/10 |
| scanner_spoof (schování) | 0/10 | 0/10 | 0/10 | 0/10 |
| **zobrazeno celkem za 3 dny** | 9 067 | 8 770 | 982 | **684** |

Intervaly: 10/10 [0,72; 1,00], 8/10 [0,49; 0,94], 7/10 [0,40; 0,89], 1/10 [0,02; 0,40], 0/10 [0,00; 0,28]. Rozdíly o jednu až dvě epizody nejsou statisticky rozlišitelné.

Totéž s hosty **bez zahřátí** (starší verze benchmarku, nastavení `mod` a `mod_att`): `exfil_volume` 0/10, `beaconing` 0/10, `exfil_large` 8/10, ostatní rodiny shodně. Rozdíl mezi 0/10 a 10/10 u prvních dvou ukazuje, že stavové vrstvy fungují jen pro hosta, o kterém produkt už něco ví; to je dokumentovaná vlastnost, ne chyba.

## 3. Co z toho plyne

1. **Stavové vrstvy se v okenním přehrání prokázaly:** beaconing a objemová exfiltrace zahřátého hosta 10/10 (v jednorázovém přehrání to bylo 0/10).
2. **Modul `known_activity` snižuje zobrazené nálezy 13× (9 067 → 684 s `attempts`) bez ztráty zachycení u skenu, SYN záplavy, SSH, exfiltrace a beaconingu.** Spolu s pravidlem `attempts` je to nejlepší nastavení na tomto pozadí.
3. **Pravidlo `attempts` je jediná změna, která zvedá zachycení** (SSH 0/10 → 10/10) a modul to u v3 nezhoršil (jeho deklarace skenu už vrstevníky nepotřebuje).
4. **Zjištění o produktu: nový útočník na již zobrazených službách se nezobrazí.** `horizontal_scan` je jen 1/10, protože epizody sdílejí sadu 40 cílů. Ověřeno přímo dvěma po sobě jdoucími okny: první útočník vyrobí 41 zobrazených nálezů, druhý útočník na týchž službách vyrobí 41 nálezů se svou IP, ale všechny mají stav `open` / `suppressed` / nezobrazeno, protože nespárované události mají identifikátor podle cíle a pozdější zdroj se do už zobrazeného nálezu jen přidá. To je záměrné potlačení opakování, ale znamená, že **druhý útočník na stejnou službu zůstane skrytý**. Doporučení (neprovedeno): opakované zobrazení u chráněných a útokových typů, když se objeví nový různý zdroj. Je to návrh pro další krok, měl by se řešit A/B s regresí.
5. **Schovávání:** modul schová jen část toků a zobrazí souhrn „vysvětleno“ (u `ssdp_masquerade` a `broadcast_masquerade` vypadá detekce zobrazená právě jako tento souhrn, ne jako původní nález). Bez modulu je u `broadcast_masquerade` jen 1/10 (ostatní toky na broadcast :137 produkt nezobrazil), s modulem 7/10 díky souhrnu. `scanner_spoof` (podvržená IP deklarovaného skeneru) zůstává 0/10 ve všech nastaveních, i bez modulu.

## 4. Meze (bez zastírání)

- **Útoky jsou moje syntetické epizody** a intenzity jsem zvolil já. Měří se hranice detekce na tomto pozadí, ne pravdivost vůči skutečným útočníkům. Deset epizod na rodinu dává široké intervaly.
- `exfil_large` 8/10: dvě chybějící epizody jsem nediagnostikoval (nepodložená hypotéza: stejné potlačení jako u skenu).
- Detekce se přiřazuje podle zmínky IP v zobrazeném nálezu. Souhrn „vysvětleno“ útočníkovu IP také zmiňuje a počítá se, i když je to jen informace o vysvětleném provozu (viz bod 5).
- Cíle útoků jsou neznámá zařízení; útoky na hosty z aktivního inventáře se neměřily.
- Šum je počet zobrazených nálezů na pozadí bez ověření (pravda z domácí sítě není), ne počet falešných poplachů; nezachycené útoky jsou součástí 9 067 i 684 jen v té míře, v jaké je produkt zobrazil.
- Zahřátí hostů je moje volba (4 h, 3 pevné cíle); jiný způsob zahřátí může dát jiné výsledky.
- Nic se nelaďilo; prahy detektorů jsou beze změny.

## 5. Reprodukce

```
python tools/k25_inject.py gen --conn <conn.log> --out <zeek_dir> --truth truth.json
python tools/k27_cycles.py --conn <zeek_dir>/conn.log --truth truth.json --bin <salticus-program> \
    --work <dir> [--v3-on attempts] [--env SALTICUS_KNOWN_ACTIVITY=cesta.json]
```

Pracovní data jsou jen lokálně (`F:\work-tmp\shadow\cycles`).

## 6. Další krok

1. Opakované zobrazení nálezu u nového různého zdroje (bod 4), měřené stejným benchmarkem a regresí 48/48.
2. Diagnostika dvou chybějících epizod `exfil_large`.
3. Brána uzavírání na přehrání po oknech (nyní má stav a zobrazené nálezy; `findingLifecycle` už nese `disposition` a `auto_resolved`).
