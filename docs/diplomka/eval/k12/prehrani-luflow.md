# Krok 12: přehrání LUFlow celou produkční cestou a příčina „1 z 259“

Datum 2026-11-15. Vstup: LUFlow 2020.06.19, prvních 200 000 toků (zdroj: `F:\Projekty\bakula-datasets\luflow`, licence a SHA-256 v `dataset-registry.md`), 28 oken po 1800 s, produkční cesta `salticus-program beh spust` v režimu v3 s `protect`, binárka kroku 12. Run `luflow-k12`, výstup `F:\Projekty\bakula-soak\k11\replay\luflow-k12.md`.

## Co se změnilo proti kroku 9

1. **Rozsah.** Dřív `10.0.0.0/8` (vše uvnitř). Teď automaticky `10.3.36.0/24`, tedy jen síť jediného cíle, na který míří útočníci. Hranice uvnitř a venku je tím blíž skutečnému umístění senzoru.
2. **Vyhodnocení.** Dřív se útočník započítal jen tehdy, když byl `host_key` zobrazeného nálezu. Nález ale nese jako `host_key` **cíl**, ne zdroj. Teď se zdroj započítá, i když je zmíněn v titulku, zdůvodnění nebo důkazech zobrazeného nálezu.

## Příčina „1 z 259“ (měřeno)

- **Příčina 1, metrika.** Z 259 škodlivých zdrojů míří 258 na **jedinou cílovou adresu** (honeypot). Nález je vždy veden na cíl, takže metrika „host_key je škodlivý zdroj“ nemohla vyjít jinak než ~0. Po opravě metriky: **64 z 259** škodlivých zdrojů je zmíněno v zobrazených nálezech (25 %).
- **Příčina 2, chybí inventář.** Ze 522 zobrazených nálezů je 518 typu `unmapped_passive_event` (provoz na adresu, kterou inventář nezná) a 4 `beacon_periodic`. Replay nemá inventář (prázdné nmap XML), proto nefungují cesty `unexpected_traffic` a `scan_attempts` nad známými službami. Engine bez inventáře vidí „provoz na neznámou adresu“, ne skeny.
- **Příčina 3, málo toků na zdroj.** Zmíněno podle počtu škodlivých toků zdroje: 1 tok: **0 z 51**, 2 až 5 toků: 5 z 56, 6 až 50 toků: 29 z 86, více než 50: 30 z 66. Zdroj s jedním tokem nemá statistický důkaz ani teoreticky (jeden tok je podle tokových rysů nerozlišitelný od jednoho neškodného), takže **51 zdrojů (20 %) je z tokové telemetrie principiálně nedetekovatelných** bez dalších vstupů (IDS podpis, reputace zdroje).
- **Příčina 4, strop zdrojů v nálezu.** Nález uvádí nejvýš 4 dominantní zdroje (`max_dominant`), takže u cíle s 258 útočníky nelze v jednom nálezu zmínit víc; to je důvod, proč i zdroje s více než 50 toky jsou zmíněny jen z poloviny (30 z 66).

## Co zbývá a co jsem neudělal

- Reálné přehrání **s TLS a DNS metadaty** jsem neudělal: LUFlow má jen toky, MAWI jen hlavičky bez obsahu, a na stroji není Zeek ani Suricata ani tshark. K tomu je potřeba PCAP s obsahem (CTU-13 a Stratosphere pcapy, CIC pcapy) a Zeek (např. kontejner z Docker Hub; Docker na stroji je, stažení obrazu a pcapů jsem nespustil kvůli rozsahu). **Část C (kalibrace simulátoru L7 na veřejných datech) tedy zůstává nehotová** a výsledky nad `--l7` světem platí jen pro autorova rozdělení.
- Dvě další opravy se nabízejí a jsou levné, ale neprovedl jsem je: zvýšit strop zdrojů v `unmapped_passive_event` a (pro replay) dodat inventář z prvního okna. Obě zlepší připsání, ne detekci per se.
