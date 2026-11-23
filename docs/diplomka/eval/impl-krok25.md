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

Zapíná se jen souborem z `SALTICUS_KNOWN_ACTIVITY` (JSON). Bez něj se chování neliší od dosavadního, `recommended()` a R2/P6 se nemění. Nic se nezavírá. Vysvětlené toky se vyjmou z detekce a každá skupina nechá **jednu souhrnnou událost** `explained_activity` (Low, „vysvětleno, ne uzavřeno").

Pravidla:

1. **Vlastní sken:** jen deklarovaná IP a deklarované časové okno.
2. **Odpověď na vlastní dotaz:** UDP z privátní adresy na privátní příjemce, jehož (IP, zdrojový port) poslal v posledních 600 s dotaz na multicast 239.255.255.250:1900 nebo 224.0.0.251:5353. Strop: odpovědí za hodinu nejvýš 10× počet dotazů téhož příjemce za tu hodinu (stanoveno předem z logiky protokolu: odpověď nemůže být početnější než dotazy, které ji vyvolaly).
3. **mDNS a broadcast/multicast v LAN:** UDP mezi privátními adresami, strop 1 000 toků za hodinu na zdroj (strop jsem nastavil bez měření; viz 5).
4. **Záznam jen hlaviček:** `missed_bytes` se ignoruje (je to artefakt záznamu).

Zamítnuto po vlastní kontrole: pravidlo „UDP ze zdrojového portu 1900 je SSDP" (bez dotazu to může být útok; po zavedení pravidla 2 nic neztratilo).

Technická poznámka: Zeek parser v režimu `DstOnly` zahazoval toky mimo rozsah, tedy i multicast dotazy. Při zapnuté znalosti činnosti se proto ponechají toky ze zdroje v rozsahu na dvě multicast skupiny (SSDP, mDNS). Bez zapnutí beze změny.

## 4. Výsledky

| měření | výsledek |
|---|---|
| celá knihovna `cargo test --lib` | 723 prošlo / 7 selhalo: 6 známých (5× `broker::*` bez Redis, `identity_lab`) + `case_memory::update_helper_serialises_concurrent_writers` (nestabilní při zátěži: samostatně 3/3 prošel, i na kódu bez této změny) |
| jednotkové testy modulu | 13/13 (včetně kladných kontrol: nedeklarovaný sken, sken mimo okno, UDP:1900 bez dotazu, veřejný zdroj, záplava odpovědí, odpověď po 600 s) |
| domácí data, výchozí chování | 20 832 nálezů |
| domácí data, znalost činnosti zapnutá | **258 nálezů** (závažnost vysoká 101 / střední 9 / nízká 148, před: 10 388 / 5 178 / 5 266) |
| souhrny „vysvětleno" | 58 (mDNS 28, broadcast 18, odpovědi na vlastní dotaz 12) |
| pozitivní kontrola na reálných datech | do kopie `conn.log` vloženy 4 útoky po 250 tocích na jednu službu: nedeklarovaný sken, sken z deklarované IP mimo okno, UDP ze zdroje 1900 bez dotazu, totéž z veřejné adresy. Všechny 4 zůstaly beze změny; počet zmínek v reportu bez / se znalostí činnosti: port 2222 13 : 13, port 3333 13 : 13, port 4444 31 : 31, adresa 203.0.113.9 9 : 9, adresa 192.168.1.250 12 : 12 (u portu 5555 je rozdíl 73 : 62 jen kvůli skutečným tokům PC → TV, ne vloženým) |

## 5. Meze (bez zastírání)

- **Žádný útok v domácích datech není.** Měřilo se, kolik šumu zmizí a že vložené útoky zůstanou. Přesnost odhalení útoků se z toho nedá odhadnout.
- **Označení dělal Claude, ne nezávislá osoba.** Šest případů je „nevím" (adresa 10.68.166.252 mimo LAN a mobil s náhodnou MAC).
- Legacy detektor sken s jedním tokem na port nevidí (ani bez změn): kladná kontrola proto používá 250 toků na jednu službu. To je vlastnost dosavadního detektoru, ne tohoto kroku.
- Strop 1 000 toků/hod u mDNS a broadcastu jsem nastavil před měřením, ale po prohlédnutí dat. Útočník, který se drží pod stropem v mDNS/broadcastu, bude vidět jen jako souhrn Low, ne jako nález. To je cena za 98% pokles šumu a je to vidět v souhrnné události, ne mlčky.
- Zbývá 258 nálezů, z toho 101 s vysokou závažností: nejde o útoky, jde o další činnost, kterou pravidla nezná (např. PC → TV :5555, 452 toků, vypadá jako ADB aplikace na PC; zdroje 10.68.166.252, .57, .94).
- Bez pravdivých označení z domácí sítě nejsou chybové meze. Bran uzavírání (`K22_SHADOW`) `beh spust` nepoužívá, takže o uzavírání nemáme z domácí sítě žádná čísla.
- Použit je release z kódu kroku 24 plus tento modul; regrese 48/48 se této cesty netýká (modul je mimo soak a bez proměnné se nespustí).
- Council a sol-loop (CLAUDE.md) se pro tento krok nespouštěly. Změna nesahá na zavírání nálezů, ale přidává logiku, která nálezy skrývá, takže doporučuji sol-loop před zapnutím mimo shadow režim.

## 6. Stav doporučení

`recommended()` beze změny, modul zůstává vypnutý ve výchozím stavu. Zapnout ho smí jen provozovatel souborem z `SALTICUS_KNOWN_ACTIVITY`. Další krok: nezávislé označení zbylých případů (30 případů dle `plan-krok22.md` §4) a sol-loop.
