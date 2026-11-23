# Předregistrace kroku 32: nezávislý test `outbound_scan` a nové pravidlo `unanswered_retry`

Zapsáno **před** spuštěním na nových datech. Navazuje na `predreg-krok31.md` a `impl-krok31.md`.

## 1. Nová, dosud neviděná data

Po kroku 31 jsem získal další scénáře IoT-23 z veřejného zrcadla na Zenodo (record 19367312, soubor `IoT_23 2.zip`, CC BY 4.0, vytažené jednotlivé soubory přes HTTP Range, převod `tools/k32_csv2zeek.py`): `dataset23`, `dataset7`, `dataset10`. Porovnáním počtu toků a časů s lokálními scénáři jsem ověřil, že jsou to **jiné** scénáře než deset, které už mám (`dataset5`, `11`, `13`, `17`, `19` jsou tytéž lokální scénáře 8-1, 44-1, 42-1, 34-1 a 3-1 a nepoužívám je jako nové). Jejich obsah jsem před zápisem této předregistrace prohlédl jen v rozsahu štítků (počty toků, škodlivé zdroje, typy štítků), nikoli z hlediska toho, co zachytí produkt:

| soubor | toků | doba | škodlivé zdroje | štítky škodlivých toků |
|---|---|---|---|---|
| dataset23 | 1 008 748 | 112 h | 192.168.100.103 | PartOfAHorizontalPortScan 539 465, C&C 8 |
| dataset7 | 3 581 028 | 24 h | 162.248.88.215, 192.168.1.195 | DDoS 3 578 457, C&C-HeartBeat 95 |
| dataset10 | 3 394 338 | 10 h | 192.168.1.200 | PartOfAHorizontalPortScan 3 386 119, Attack 2 752, C&C-PartOfAHorizontalPortScan 888 |

## 2. Část A: nezávislý test pravidla `outbound_scan` (krok 31)

Pravidlo je zmrazené (25 cílů, 300 s, podíl ≥ 0,5). Ramena **A** (výchozí v3) a **C** (A + `outscan`), přehrání po 30minutových oknech jako v kroku 31 (`tools/k30_ctu13.py --zeek`). Rozsah: převažující privátní /24 z dat.

- **H-A1 (žádná ztráta):** C nezachytí v žádném ze tří scénářů méně infikovaných hostů než A.
- **H-A2 (přínos, hlavní):** C zachytí o aspoň **1** infikovaný host víc než A (součet přes tři scénáře). Očekávám přínos u scénářů 23 a 10 (horizontální sken infikovaného hosta).
- **H-A3 (šum):** zobrazeno C ≤ 1,5× zobrazeno A přes tři scénáře.

## 3. Část B: nové pravidlo `unanswered_retry` (krok 32)

`src/behavior/retry.rs`, typ `unanswered_retry`, přepínač `retry` (výchozí vypnuto, chráněný typ, `recommended()` beze změny). Podmínky: aspoň **20** neúspěšných TCP pokusů (`S0`, `REJ`, `RSTOS0`) z vnitřního hosta na stejný vnější (cíl, port) během **600 s** a **žádné úspěšné spojení** na tento (cíl, port) v úseku. Původ: forenzní nález IoT-23 scénáře 8-1 (8 222 SYN bez odpovědi na dva cíle a port 50), který skenovací pravidlo ani beaconing nezachytí. Prahy stanoveny předem, na skutečné domácí síti (3 dny) 0 zásahů (`tools/k32_retry_probe.py`); neladěno na pravdě testovacích dat.

Ramena **A** a **D** (A + `retry`). Měření:

- Nezávislé: `dataset23`, `dataset7`, `dataset10`.
- Šum na skutečné domácí síti (3 dny) a na deseti scénářích IoT-23 a deseti CTU-13 z kroku 31 (nezávislé nejsou, protože 8-1 pravidlo motivoval; slouží ke kontrole regrese a šumu).
- **H-B1 (žádná ztráta):** D nezachytí v žádném scénáři méně infikovaných hostů než A (všech 23 scénářů).
- **H-B2 (šum):** zobrazeno D ≤ 1,25× zobrazeno A (přes všechny scénáře) a na domácí síti ≤ **3** zobrazené nálezy `unanswered_retry` za 3 dny.
- **H-B3 (přínos):** průzkumná; počet infikovaných hostů navíc u D (hlavně IoT-23 8-1 a nové scénáře), bez rozhodovací hranice.

## 4. Rozhodnutí

- H-A1 a H-A3 splněny a H-A2 splněna → `outscan` označeno za **ověřené nezávisle** na veřejných datech se skutečnou pravdou (3 scénáře).
- H-A2 nesplněna → `outscan` zůstane „potvrzeno jen na datech, ze kterých vzniklo“ a zapíšu proč (forenzně).
- H-B1 a H-B2 splněny → `retry` je „bez ztráty a bez nadměrného šumu“; přínos se uvede podle H-B3, ne jako ověřený, dokud není nezávislý scénář s tímto vzorem.
- Žádný kód ani práh se po vidění výsledku nemění.

## 5. Hrozby platnosti

- Velké scénáře (milióny toků) jsou DDoS a horizontální skeny: mohou být pro skenovací pravidlo extrémně snadné; přínos v nich neříká nic o jemnějších případech.
- U dataset7 je jeden ze škodlivých zdrojů vnější adresa; moje definice „infikovaný = zdroj škodlivého toku“ ho zahrnuje a může tam dát nezachycení.
- Jediný škodlivý host na scénář u 23 a 10; interval je široký, výsledek je počet scénářů, ne statistika.
