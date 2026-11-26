# Krok 49: pozitivní a negativní kontroly k příčinám z kroku 47/48 (opraven i vlastní chyb v testu)

Podklad: `impl-krok47.md` (reálná laboratoř téměř neviditelná pro Salticus). Cíl: proměnit silné hypotézy o příčině na ověřené mechanismy pomocí skutečných pozitivních/negativních kontrol ve stejné laboratoři, ne jen citací kódu.

## Oprava vlastní chyby: scope zahrnoval útočníka

`--scope 10.60.0.0/16` v krocích 47–48 zahrnoval i útočníkovu podsíť (10.60.1.0/29). `FlowDirection::Outbound` (`src/passive/egress.rs:52`) vyžaduje zdroj v rozsahu A cíl MIMO rozsah — útočník uvnitř rozsahu znamenal, že žádný tok k němu nebyl nikdy klasifikován jako odchozí, takže `egress_volume_anomaly` nemohl nikdy nastat, bez ohledu na objem. To je chyba mého testu, ne Salticusu. Opraveno (`tools/k47_lab.py`): scope jen skutečně vnitřní podsítě (web/app/db/jump/stanice), útočníkovy podsítě vynechány. Všechny tři předchozí běhy (cold, warm, warm2) jsem s opraveným scope zopakoval.

## Pozitivní kontrola 1: exfiltrace nad 1 GB

Skutečný přenos 1 258 291 200 B (`dd` + `curl -X POST`) ze stejné kompromitované cesty (app → útočník). **Výsledek: `egress_volume_anomaly`, závažnost high, správně na hostiteli 10.60.3.3 s cílem 10.60.1.3.** Detektor funguje; reálná exfiltrace 188 893 B z kroku 47 je 5 300× pod prahem 1 GB (`cold_bytes`, `src/behavior/egress_volume.rs:54`) — to teď není jen citace konstanty, je to prokázaný mechanismus s pozitivní kontrolou.

## Pozitivní/negativní kontrola 2: rychlost skenu

Hypotéza z kroku 47: rychlý sken (1000 portů za 0,12 s) je mimo tempo, na které je generátor/detekce laděná (10 portů/s). Zkouška: stejný sken, ale tempem 10 portů/s (`nmap --scan-delay 100ms -T sneaky`, 200 portů za 20,1 s, přesně tempo syntetického generátoru z `k25_inject.py`). **Výsledek: žádný nález specifický pro sken, stejně jako při rychlém skenu.** Hypotéza o rychlosti je tímto vyvrácena.

## Skutečná příčina: žádná skupina vrstevníků pro vertikální sken

Místo toho potvrzeno přímo v kódu: `src/passive/anomaly_v3.rs:18`, doslovně — "Bez historie rozhoduje skupina podobných služeb; bez ní se jen sbírá." Sken na mnoho různých portů jednoho hostitele vytvoří tolik samostatných klíčů (cíl, port), kolik portů sken zasáhl, každý viděný poprvé, žádný se žádnou skupinou vrstevníků na stejném portu u jiných hostitelů. Podle vlastního návrhu modulu se bez skupiny "jen sbírá" — nikdy nevznikne nález, nezávisle na rychlosti. Stejný mechanismus byl popsán už v `impl-krok26.md` u SSH hrubé síly bez vrstevníků; tady je potvrzen podruhé, nezávisle, na jiném typu útoku (vertikální sken) a hlavně se dvěma reálnými kontrolami, ne jen odvozením.

## Shrnutí: dvě různé příčiny, obě ověřené kontrolou

| nález | proč chyběl | ověřeno kontrolou |
|---|---|---|
| `egress_volume_anomaly` | absolutní práh 1 GB, realistická exfiltrace 188 KB je 5 300× pod ním | ano — >1 GB stejnou cestou nález vyvolal |
| sken (jakýkoli typ) | žádná skupina vrstevníků pro klíč (cíl, port) viděný poprvé; nezávisí na rychlosti | ano — pomalý sken (10 portů/s) dopadl stejně jako rychlý |

## Co z toho plyne

1. **Dvě různé, nezávisle ověřené mezery**, ne jedna: objemový práh je příliš vysoký pro realistickou exfiltraci; architektura "skupina vrstevníků" nepokrývá vertikální sken na mnoho portů vůbec, bez ohledu na práh nebo rychlost.
2. **Metodická lekce pro mě:** moje první chyba (scope zahrnující útočníka) by bez kontrolního běhu s >1 GB zůstala skrytá a vedla by k nesprávnému závěru "detektor objemu nefunguje ani nad 1 GB". Pozitivní kontrola to odhalila. Negativní/pozitivní kontroly jsou teď standardní součást tohoto druhu diagnostiky, ne jen citace prahů z kódu.
3. **Pro produkci:** objemový práh by měl mít i mnohem nižší úroveň s vyšší jistotou po delší historii (ne jen jeden absolutní práh 1 GB), a vertikální sken potřebuje samostatné pravidlo nezávislé na skupině vrstevníků (počet různých portů jednoho zdroje k jednomu cíli v okně, podobně jako `outscan` počítá různé cíle). Obojí je mimo rozsah korelace — je to detekce samotná.

## Omezení

Jedna laboratoř, malý počet kontrol (2 hypotézy, po jedné kontrole každá). Nebylo testováno: horizontální sken (mnoho cílů, stejný port — jiná struktura klíče, možná má skupinu vrstevníků), nižší objemy exfiltrace mezi 188 KB a 1 GB (kde přesně leží reálná hranice citlivosti), ani vliv zralosti profilu na tyto dva mechanismy odděleně (testováno jen v kombinaci se zahřátím).
