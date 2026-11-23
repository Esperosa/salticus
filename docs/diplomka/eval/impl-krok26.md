# Krok 26: hranice detekce na reálném pozadí (vložené útoky)

Podklad: `impl-krok25.md` (znalost vlastní činnosti sítě). Otázka: co Salticus z útoků skutečně zachytí, když je pozadí skutečná domácí síť, a kolik skutečně skryje modul `known_activity`. Nic se nelaďilo, žádný práh se nezměnil.

## 1. Metoda

Nástroj `tools/k25_inject.py` (`gen`, `eval`): do skutečného `conn.log` z domácí sítě (3 dny, 283 tisíc toků) vloží 10 epizod od každé z 10 rodin. Každý útočník má vlastní IP, takže detekce se přiřazuje jednoznačně. Pravda je v `truth.json` (ne v záznamu). Spustí se tři nastavení nad stejným záznamem: legacy bez modulu, legacy s modulem `known_activity` (konfigurace z kroku 25) a jádro v3 (`[engine] mode = "v3"`, modul se s v3 nepoužívá).

Definice měřítek v `eval`:

- **upozornění**: epizoda má aspoň jednu událost nebo nález s útočníkovou IP (zdroj, u podvržené IP skeneru cíl), který není jen „neočekávaný provoz“ a není souhrn „vysvětleno“. Interval je Wilsonův 95 %.
- **cokoli**: i neočekávaný provoz (nízká závažnost), který vzniká i u neškodného provozu.
- **skryto toků**: počet toků epizody, které modul vyňal z detekce (součet souhrnných událostí).

## 2. Výsledek (10 epizod na rodinu)

| rodina | co to je | legacy | legacy + modul | v3 |
|---|---|---|---|---|
| vertical_scan | 1 000 portů na jedno neznámé zařízení, 10 portů/s | 0/10 | 0/10 | **10/10** |
| horizontal_scan | port 445 na 40 adres | 1/10 | 1/10 | **10/10** |
| ssh_bruteforce | 300 spojení za 10 min na :22 | 0/10 (jen „neočekávaný provoz“ 10/10) | 0/10 (stejně) | **10/10** |
| exfil_volume | 300 MB ven za 10 min | 0/10 | 0/10 | 0/10 |
| exfil_large | 1,5 GB ven za 10 min | 0/10 | 0/10 | **10/10** |
| beaconing | 180 spojení po 60 s ven | 0/10 | 0/10 | 0/10 |
| syn_flood | 20 000 SYN za minutu | **10/10** | **10/10** | **10/10** |
| ssdp_masquerade (schování) | podvržený dotaz oběti + 600 „odpovědí“ | 10/10, skryto 0 | 10/10, **skryto 3 000 z 6 000** | 10/10 |
| broadcast_masquerade (schování) | 5 000 toků na broadcast :137 | 10/10, skryto 0 | 10/10, **skryto 1 356 z 50 000** | 10/10 |
| scanner_spoof (schování) | podvržená IP deklarovaného skeneru v jeho okně | 0/10 | 0/10 | 0/10 |

Interval u 10/10 je [0,72; 1,00], u 0/10 [0,00; 0,28], u 1/10 [0,02; 0,40]. S deseti epizodami je rozlišení hrubé; rozdíl 10/10 proti 0/10 je jasný, drobnější rozdíly ne.

Šum téhož pozadí bez vložených útoků (tentýž záznam, nálezy za 3 dny): legacy bez modulu **20 832**, legacy s modulem **267**, v3 **5 527**.

## 3. Co z toho plyne

1. **Legacy cesta je slepá téměř ke všemu kromě záplavy.** Skeny, hrubá síla na SSH a odchozí provoz nezachytí (0/10). Modul `known_activity` šum snižuje 78×, ale zachycení nemění (stejné řádky). To je poctivý obraz: modul odstraňuje šum, detekci nezlepšuje.
2. **Jádro v3 zachytí skeny, hrubou sílu, velkou exfiltraci i záplavu (10/10), ale má 5 527 nálezů šumu na tomto pozadí.** To je 20× víc než legacy s modulem. Praktická cesta k použitelnému nástroji je tedy dostat znalost vlastní činnosti do v3, ne spoléhat na legacy. Dnes se modul s v3 nepoužívá (v3 dostává dotazy SSDP/mDNS jako odchozí toky); to je další krok.
3. **Hranice objemové exfiltrace:** 300 MB za okno = 0/10, 1,5 GB = 10/10. Odpovídá absolutní mezi bez historie 1 GB v `egress_volume.rs` (`cold_bytes`). Práh je volba autora (viz komentář v modulu); meze jsem neměnil.
4. **Schovávání pod známou činnost:** modul skryje jen část toků a každá epizoda zůstává aspoň z části viditelná (10/10 v obou případech), ale objem skrytého je měřitelný: 50 % toků u podvržených odpovědí (strop 10× na odpovídajícího × 30 financovaných dotazů), 2,7 % u broadcastu. Podvržená IP deklarovaného skeneru se schová celá, ale žádné nastavení ji u této rodiny nezachytilo ani bez modulu (0/10), takže modul tu nic neztrácí; příčinu u v3 jsem nezjišťoval.

## 4. Meze (bez zastírání)

- **Útoky jsou moje syntetické epizody** (řádky `conn.log`, bez obsahu), intenzity jsem zvolil já. Nereprezentují skutečné útočníky; měří hranici na tomto pozadí a těchto intenzitách. Deset epizod na rodinu dává široké intervaly.
- **Cílem jsou neznámá zařízení** (adresy, které v záznamu nikdy nebyly). Útoky na hosty z aktivního inventáře se touto metodou nepřiřadí (události se spojí s hostem a ztratí zdrojovou IP), proto se neměří.
- **Jednorázové přehrání.** Stavové vrstvy (hystereze beaconingu, historie objemu) se jedním během nenaučí. `beaconing 0/10` proto neříká, že živý provoz beaconing nezachytí; říká jen, že ho jednorázové přehrání nezachytí. Pro stavovou detekci je nutný soak se cykly.
- Pozadí obsahuje skutečné neškodné i neznámé události; „šum“ je počet nálezů bez ověření, ne počet falešných poplachů (pravda z domácí sítě není).
- Přiřazení k epizodě podle IP: pro rodiny s náhodným veřejným cílem se přiřazuje jen podle zdroje (cíle se mohou opakovat); původní vyhodnocení podle zdroje i cíle dalo falešné zásahy u exfil_volume a beaconingu, proto bylo zúženo.
- Žádný práh ani pravidlo se pro tento test neupravovalo; nejde o ladění na pravdě.
- Konfigurace v3 byla výchozí z `salticus.toml` (všechny přepínače zapnuté, `peers = false`).

## 5. Reprodukce

```
python tools/k25_inject.py gen --conn <conn.log> --out <zeek_dir> --truth truth.json
salticus-program beh spust --workspace <ws> --nazev x --scope 192.168.1.0/24 \
  --nmap-xml <full.xml> --zeek-dir <zeek_dir>      # s SALTICUS_REPLAY_NOW na začátek záznamu
python tools/k25_inject.py eval --report <ws>/runs/<run>/report.json --truth truth.json
```

Pracovní data jsou jen lokálně (`F:\work-tmp\shadow\bench2`).

## 6. Znalost vlastní činnosti v jádře v3 (provedeno)

Kód: `passive::load_and_normalize_with_behavior` uplatní `known_activity::split` hned po importu Zeeku (před rozdělením na odchozí, vnitřní a příchozí toky a před detekcí). Vysvětlené toky nejdou do detekce ani do behaviorální vrstvy, zbude jeden souhrn. Bez `SALTICUS_KNOWN_ACTIVITY` se chování nemění. `cargo test --lib passive` 81/81.

| nastavení | nálezy na reálném pozadí (bez útoků) | skeny | SSH | exfil 1,5 GB | záplava |
|---|---|---|---|---|---|
| v3 bez modulu | 5 527 | 10/10, 10/10 | 10/10 | 10/10 | 10/10 |
| v3 + modul, vlastní sken **deklarován** | **357** | 10/10, 10/10 | **0/10** | 10/10 | 10/10 |
| v3 + modul, vlastní sken **nedeklarován** | **396** | 10/10, 10/10 | **10/10** | 10/10 | 10/10 |

Šum klesl o 93 % (5 527 → 357), vloženým útokům to nic nevzalo, kromě SSH při deklarovaném skenu. Kontrolní běh to vysvětlil: v3 počítá u nového klíče bez historie baseline z ostatních klíčů na stejném portu („skupina_sluzeb“, `anomaly_v3.rs`) a bez dostatečné skupiny jen sbírá. Na portu 22 byli jediní vrstevníci toky mého vlastního nmap skenu; deklarace skenu je vyjmula a hrubá síla zůstala jen jako nízká „neočekávaná spojení“. **Zachycení SSH u v3 tedy v tomto měření závisí na přítomnosti vrstevníků, ne na vlastní vlastnosti útoku.** V klidné síti, kde na portu 22 nikdo jiný není, by v3 stejnou hrubou sílu zřejmě také nehlásil jako vysokou; to je mezera v detekci (chybí pravidlo „mnoho krátkých opakovaných spojení z jednoho zdroje na jeden cíl a port“), ne chyba modulu. Neověřoval jsem to na síti bez vrstevníků.

Pro provoz z toho plyne: **vlastní sken se do `own_scanners` deklaruje jen tehdy, když je to potřeba pro snížení šumu, a výsledek je nutné číst s vědomím, že vyjmutý sken už nedělá vrstevníky.** Pro tento domácí běh je výchozí konfigurace bez deklarace skenu (396 nálezů, žádná ztráta v benchmarku).

## 7. Další krok

1. Pravidlo pro opakovaná krátká spojení (hrubá síla) nezávislé na vrstevnících, měřené stejným benchmarkem s vrstevníky i bez nich.
2. Stavové vrstvy (beaconing, historie objemu) měřit přes soak se cykly, ne jedním přehráním.
3. Teprve potom brána uzavírání na reálných datech.
