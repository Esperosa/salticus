# Krok 25: znalost vlastní činnosti sítě na domácích datech (shadow režim)

Podklad: `impl-krok24.md` (doporučení: žádná změna `recommended()`, hlavní směr jsou reálná data) a běh shadow režimu na domácí síti 20. až 23. 11. 2026. Pracovní data jsou jen lokálně v `F:\work-tmp\shadow` (nejde do gitu).

## 1. Co se naměřilo (shadow režim, bez zásahů)

Sběr: pasivní záznam hlaviček na jednom počítači (12,3 GB, 3 dny), NetFlow, kontroly přítomnosti zařízení (369 kontrol), plný TCP sken 18 zařízení. Záznam prošel Zeekem a pak `beh spust` Salticu.

Pozor na provedení: `beh spust` bere okno pro pasivní data z času běhu. Pro přehrání starého záznamu je nutné nastavit `SALTICUS_REPLAY_NOW` na začátek záznamu, jinak se nenačte nic (první běh: 0 událostí).

Výchozí chování (beze změny kódu): **20 832 nálezů, 29 889 událostí**. Z toho 20 738 „událost bez vazby na inventář". Žádný nález se nepotvrdil jako útok.

## 2. Ruční rozbor (78 případů, dělal Claude, ne nezávislý reviewer)

Soubor `F:\work-tmp\shadow\labeling\pripady_oznaceno.csv`. Výsledek: 0 útoků, 60 benigních nebo nejspíš benigních, 6 „nevím". Co za nálezy stálo:

| zdroj nálezů | jak ověřeno |
|---|---|
| vlastní nmap sken z tohoto PC (všech 93 nálezů na zařízeních) | čas a počet toků (~6 000 toků na ~5 800 portů každého zařízení) sedí na sken |
| odpovědi SSDP/UPnP na dotazy tohoto PC (~47 500 toků, 99,7 % neuvedených událostí na PC) | záznam s obsahem: `HTTP/1.1 200 OK … HOST: 239.255.255.250:1900`; dotazů z PC na multicast je 110 812, odpověď přijde na zdrojový port dotazu do 10 minut |
| NetFlow export UniFi → PC :2055 | nastavil jsem sám |
| „ztráty paketů" | artefakt záznamu jen hlaviček (snaplen 128, Zeek hlásí chybějící bajty) |
| broadcast/mDNS (Spotify, Steam, Windows aktualizace, smart zařízení) | porty a cíle |

**Oprava vlastního omylu:** nejdřív jsem odvodil, že SSDP odpovědi poznám podle zdrojového portu 1900. To platí jen u části zařízení (Hue); TV a další odpovídají z náhodných portů (3 % toků má port 1900). Správný znak je vazba na dotaz, který příjemce sám poslal.

## 3. Návrh: modul `passive::known_activity` (výchozí vypnuto)

Zapíná se jen souborem z `SALTICUS_KNOWN_ACTIVITY` (JSON, načte se jednou za proces; neplatný soubor nebo neplatná politika = funkce vypnutá). Bez něj se chování neliší od dosavadního, `recommended()` a R2/P6 se nemění. Nic se nezavírá. Vysvětlené toky se vyjmou z detekce a každá skupina nechá **jednu souhrnnou událost** `explained_activity` (Low, „vysvětleno, ne uzavřeno", s nejčastějšími cíli). Obálka se používá jen s legacy detektorem (detektor v3 dostává dotazy jako odchozí tok; tam se funkce zatím nepoužívá a pipeline to zaloguje).

Pravidla (po dvou kolech nezávislého review, viz sekce 6):

1. **Vlastní sken:** jen deklarovaná IP, deklarované okno **a deklarované cíle** (prázdné cíle = žádná výjimka).
2. **Odpověď na vlastní dotaz:** UDP z privátní adresy na privátního příjemce, který ostře před tím (do 600 s, přesný čas) poslal dotaz na multicast 239.255.255.250:1900 nebo 224.0.0.251:5353 ze stejného portu. Rozpočet v klouzavém okně 600 s: odpovědí od jednoho odpovídajícího nejvýš 10× počet dotazů z okna a od všech nejvýš 30×; budoucí a vypršené dotazy nefinancují nic.
3. **Discovery multicast (3 známé skupiny) a broadcast** na skutečné broadcast adresy deklarovaných podsítí (`/31` a `/32` ne); strop 1 000 toků za UTC hodinu na zdroj.
4. **Záznam jen hlaviček:** `missed_bytes` se ignoruje v celém záznamu (platí pro celý záznam, ne jen vysvětlené toky).
5. Každý vysvětlený tok (mimo vlastní sken) musí být malý: nejvýš 64 paketů a 16 KB (součty obou směrů) a tempo pod stejnými prahy jako legacy detektor (2 500 pps, 35 Mb/s). Rychlý nebo velký tok zůstane v detekci.

Zamítnuto po vlastní kontrole a review: „UDP ze zdrojového portu 1900 je SSDP", „libovolný multicast nebo adresa končící `.255`", „unicast mDNS na portu 5353".

Zeek parser v režimu `DstOnly` zahazoval toky mimo rozsah, tedy i multicast dotazy. Při aktivní obálce se proto ponechají jen přesné UDP dotazy na ty dvě skupiny ze zdroje v rozsahu. `egress::keep()` a import Suricaty se nezměnily.

## 4. Výsledky

| měření | výsledek |
|---|---|
| jednotkové testy modulu | 27/27 (včetně záporných kontrol: nedeklarovaný sken, cíl mimo deklaraci, sken mimo okno, odpověď bez dotazu / před dotazem / ve stejný čas / po 600 s + 1 ms, nad rozpočtem, budoucí a vypršený dotaz, `/31` a `/32`, vysoké tempo, součty obou směrů, neplatná politika) |
| celá knihovna `cargo test --lib` | 723 prošlo / 7 selhalo před posledními úpravami: 6 známých (5× `broker::*` bez Redis, `identity_lab`) + `case_memory::update_helper_serialises_concurrent_writers` (nestabilní při zátěži, samostatně 3/3 prošel, i na kódu bez této změny) |
| domácí data, výchozí chování | 20 832 nálezů (vysoká 10 388 / střední 5 178 / nízká 5 266) |
| domácí data, finální pravidla | **583 nálezů** (vysoká 314 / střední 80 / nízká 189), 43 souhrnů „vysvětleno" (discovery multicast 21, broadcast 12, odpovědi na vlastní dotaz 9, vlastní sken 1) |
| pozitivní kontrola na reálných datech | do kopie `conn.log` vloženy 4 útoky po 250 tocích na jednu službu: nedeklarovaný sken, sken z deklarované IP mimo okno, UDP ze zdroje 1900 bez dotazu, totéž z veřejné adresy. Všechny 4 zůstaly hlášené (události u portu 2222: 5, portu 3333: 5, UDP bez dotazu 3, veřejná adresa 3) |

Vývoj počtu nálezů podle verze pravidel (pro úplnost, ne jako ladění): první verze 258 (volnější pravidla), po review 256, po zpřísnění tempa a velikosti **583**. Rozdíl 256 → 583 způsobilo pravidlo 5: 938 odpovědí (2 %) jsou drobné toky do 64 paketů, které legacy detektor označuje za „skok tempa" jen proto, že trvají milisekundy. Přísnější varianta je konzervativnější a podle review správná; legacy odhad tempa na ultrakrátkých tocích je samostatná slabina k pozdějšímu řešení.

## 5. Meze (bez zastírání)

- **Žádný útok v domácích datech není.** Měřilo se, kolik šumu zmizí a že vložené útoky zůstanou. Přesnost odhalení útoků z toho nejde odhadnout.
- **Označení dělal Claude, ne nezávislá osoba** (78 případů, šest „nevím": adresa 10.68.166.252 mimo LAN a mobil s náhodnou MAC). Označení vznikla před finálními pravidly.
- Legacy detektor sken s jedním tokem na port nevidí ani bez změn; kladná kontrola proto používá 250 toků na jednu službu.
- **Residuální riziko (sporné, S1):** z hlaviček paketů nejde dokázat, že tok je skutečná odpověď. Místní útočník, který zná dočasný port příjemce i načasování a drží se pod rozpočtem a limitem velikosti, by byl vidět jen jako souhrn Low s počtem a cíli, ne jako původní nález. Odpůrce (review) chce takové toky nechat v detekci a odpovědi jen anotovat; to by odstranilo většinu přínosu (snížení šumu o ~97 %). Rozhodnutí je na provozovateli; modul je ve výchozím stavu vypnutý a pro shadow režim je dostatečný.
- Zbývá 583 nálezů, z toho 314 s vysokou závažností: jde o další činnost, kterou pravidla neznají (TCP a UDP mezi PC a TV/Cast na dočasných portech, například PC → TV :5555, 452 toků, vypadá jako ADB aplikace na PC).
- Bez pravdivých označení z domácí sítě nejsou chybové meze. Bran uzavírání (`K22_SHADOW`) `beh spust` nepoužívá, takže o uzavírání nemáme z domácí sítě žádná čísla.
- Použit je release z kódu kroku 24 plus tento modul; regrese 48/48 se této cesty netýká (modul je mimo soak a bez proměnné se nespustí).

## 6. Review (sol-loop, GPT-6.2 Sol, effort high)

| kolo | výsledek |
|---|---|
| 1 | CHANGES: 3 blokery (S1, S3, S5; S2 jako blocker v původním značení) a 6 „should" |
| 2 | CHANGES: S1 sporné; S2, S3, S5, S6, S8, S14 otevřené; S4, S7, S9 až S13 vyřešené |
| úpravy po kole 2 | S2 (tempo a součty obou směrů), S3 (`/31`, `/32`), S5 (klouzavé okno, jen dřívější dotazy), S6 (aktivace jen s běžící obálkou), S8 (ostře dřív), S14 (validace politiky) opraveny a pokryty testy |
| kolo 3 | **neproběhlo**: vedoucí přerušil používání agentů OpenAI. Opravy po kole 2 nejsou Solem znovu ověřeny. |

**Kontrola kola 3 levným modelem (Claude Haiku, jen čtení, bez Sola).** Nálezy jsem ověřil v kódu sám:

| nález | posouzení |
|---|---|
| B2: multicast a broadcast bez kontroly portu (UDP na `224.0.0.251:4444` by se vysvětlil) | **potvrzeno, opraveno**: multicast jen přesné dvojice skupina:port (1900, 5353, 5355), broadcast jen známé porty (67, 68, 137, 138, 1900, 5353, 5355, 27036, 57621); nový test; 28/28 |
| B1: vlastní sken nemá limit velikosti a tempa, podvržená IP skeneru na LAN | záměr návrhu (deklarované IP, okno a cíle); residuální riziko, rozhoduje provozovatel; do dokumentu zapsáno |
| S1: rozpočet odpovědí se škáluje aktivitou oběti | známé residuální riziko (viz S1 výše), omezeno 10×/30× |
| S2: strop za pevnou UTC hodinu dovolí 2× strop kolem hranice | potvrzeno, přijato (strop je jen pojistka proti záplavě, ne detekce); test to dokumentuje |
| S3: tok bez doby trvání nemá kontrolu tempa | zamítnuto: velikost je omezena 64 pakety a 16 KiB nezávisle na tempu |
| S4: chybí test celkového stropu 30× a `orig_pkts = None` | přijato jako dluh testů |
| N1 až N4 | nity, nechávám |

**Kolo 3 hlubší kontrolou (Claude Opus, jen čtení, nahrazuje Sola; vedoucí zakázal OpenAI agenty).** Verdikt ZMĚNY, nálezy ověřeny v kódu:

| nález | posouzení |
|---|---|
| B-A: útočník si podvrhne multicast dotaz sám sobě a zaplatí si odpovědi na libovolný port | **potvrzeno, zúženo**: dotaz financuje jen ze zdrojového dočasného portu (≥ 32768) a nejvýš 30 dotazů z okna na příjemce (strop skrytých odpovědí 300 za 600 s a příjemce); zbytek riziko S1 |
| B-B: rutinní mDNS dotaz oběti ze zdrojového portu 5353 „zaplatí“ unicast na 5353 | **potvrzeno, opraveno**: dotaz ze servisního portu nic nefinancuje; nový test |
| S-A: příznak `ACTIVE` přežije do dalšího běhu v témže procesu | **potvrzeno, opraveno**: pipeline ho na začátku každého běhu vynuluje (`deactivate`) |
| S-C: dotazy přidané parserem mohly protéct do vnitřního detektoru | **potvrzeno, opraveno**: po párování se vždy vyřadí |
| S-D: dva testy po změně portů netestovaly broadcast adresu (port 80) | **opraveno**: testy používají známý port 57621 |
| S-B: viditelnost souhrnu závisí na inventáři; souhrn visí na zdroji, ne na oběti | **přijato jako omezení**, ne měněno |
| N-A až N-C | nity, nechávám (N-B: souhrn se mezi běhy nehlásí jako nový při růstu počtu) |

Testy modulu: 30/30. **Přeměřeno po kole 3** (release z commitu `1a78045`, stejná data i příkaz): reálná data **583 nálezů, 599 událostí**, tedy beze změny proti sekci 4 (znamená, že na domácích datech žádný provoz nespadl pod nové zúžení portů ani stropu dotazů). Data s vloženými útoky: 615 událostí, tj. o 16 víc než reálná data, přesně 5 + 5 + 3 + 3 vložených událostí; všechny 4 útoky jsou nadále hlášené (zdroj 192.168.1.250, sken z deklarované IP mimo okno, UDP bez dotazu a veřejná adresa 203.0.113.9 jsou v reportu). Zúžení tedy zlepšilo odolnost proti obejití bez ztráty přínosu na těchto datech.

Stav: S1 zůstává sporné (viz výše, rozhoduje provozovatel). Ostatní nálezy jsou opraveny, ale bez nezávislého potvrzení. Před zapnutím mimo shadow režim doporučuji kolo 3.

## 6a. Rozbor zbylých nálezů a oprava kontroly tempa (po kole 3)

Rozbor 583 zbylých nálezů (`unmappedEvents`, seskupeno podle zdroje, cíle a portu) ukázal hlavní příčinu: **odpovědi TV a Cast zařízení na SSDP dotaz PC měly platný dotaz, ale nebyly vysvětleny kvůli kontrole tempa.** Jedno paketové UDP trvající 0,27 ms vychází jako 3 700 pps, tedy nad prahem 2 500 pps. To je artefakt měření, ne rychlost zdroje. Ověřeno na konkrétních případech (port 53554: dotaz z PC v 12:27:27, odpovědi 12:27:28 až 12:27:30, všechny S0 s dobou trvání v mikrosekundách).

Úprava: kontrola tempa u vysvětlených toků **zrušena**. Zdůvodnění: tok do 64 paketů a 16 KiB nemůže být záplava; objem celku omezují rozpočty odpovědí (10× na odpovídajícího, 30× celkem) a stropy za hodinu. Test, který dřív vyžadoval, aby rychlý tok zůstal v detekci, je nahrazen testem, že milisekundový tok v mezích velikosti se vysvětlí a že záplava 100 takových toků se vysvětlí jen do rozpočtu (90 zbude v detekci).

Nové: konfigurační pole `broadcast_ports` (provozovatel deklaruje další známé broadcast porty). V domácí konfiguraci je deklarován jen 1947 (6 160 toků; na PC běží `hasplms`/`hasplmv`, licenční manager Sentinel HASP, který tento port používá); ostatní neznámé broadcast porty (6537, 2000, 2015, 9998, 9999) zůstávají v detekci.

| měření | reálná data | data s vloženými útoky |
|---|---|---|
| před kolem 3 (sekce 4) | 583 nálezů | 599 + 16 událostí, 4/4 útoky |
| po kole 3 (zúžení portů) | 583 nálezů | 4/4 útoky |
| po zrušení kontroly tempa | **263 nálezů** (vysoká 117 / střední 13 / nízká 133) | 296 událostí, o 16 víc než reálná data, 4/4 útoky |
| po deklaraci broadcast portu 1947 | **259 nálezů** | 292 událostí, o 16 víc, 4/4 útoky |

Zbývající nálezy podle rozboru (nezávislé označení chybí, jde o můj rozbor):

- **PC → TV TCP 5555, 8008, 8009, 34617** (např. 452 neúspěšných spojení na :5555): shodné s procesy běžícími na tomto PC (kontrola 23. 11.): `adb` (ADB server zkouší TV :5555), Chrome a NVIDIA Overlay (otevřená spojení na Cast :8008/:8009 u .195 a .232), `sunshine` (streaming pro Moonlight na TV, odtud TV → PC :47989). Je to hypotéza podle běžících procesů, časovou shodu jednotlivých spojení jsem neověřoval. Zůstává v detekci.
- **Broadcast na neznámých portech** od zařízení 192.168.1.149, .45, .195, .73: mohou být benigní discovery (herní zařízení, chytré zásuvky), ale protokol neznám; zůstává v detekci záměrně (jinak by šlo skrýt libovolný kanál).
- **NetFlow export UniFi → PC :2055** (64 toků): vlastní nastavení; není deklarace pro vlastní exportér, zůstává.
- **ICMP unreachable** od brány a od internetové adresy na PC: odezvy na provoz PC.
- **Zbytek SSDP odpovědí** (~23 toků od jednoho zařízení): pravděpodobně nad rozpočtem odpovědí nebo bez dotazu v okně; neanalyzoval jsem.

Kromě toho jsem po tomto kroku nezměnil `recommended()`, R2 ani P6.

## 7. Stav doporučení

`recommended()` beze změny, modul zůstává vypnutý ve výchozím stavu. Další krok: kolo 3 review po obnovení agentů, nezávislé označení zbylých případů (30 dle `plan-krok22.md` §4) a rozhodnutí o S1.
