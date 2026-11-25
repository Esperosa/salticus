# Krok 44: vážený graf nálezů s komunitami (`corr_graph`) a prototyp potvrzení druhým zdrojem

## Vážený graf (negativní, popisně)

Hrana mezi nálezy se sdílenou adresou v okně 30 min, váha = 0,4 adresa + 0,2 typ a taktika + 0,2 služba + 0,2 čas, práh 0,6, komunity šířením štítků; váhy a práh stanoveny před měřením a po něm neladěny. Spuštěno jen na datech použitých dříve (žádná čerstvá data se nespotřebovala; Week6_Day2 a Week5_Day5-6 zůstávají stažené a nepoužité).

| data | incidenty | úplnost | kontaminace | největší incident | duplicity |
|---|---|---|---|---|---|
| DAPT Week6_Day4 | 38 | 0,03 | 0,77 | 13 | 0 |
| DAPT Week6_Day3 | 42 | 0,06 | 0,56 | 20 | – |

Perkolace zmizela, ale kampaň se rozpadla na jednotlivé nálezy: úplnost 0,03 až 0,06 (horší než `corr_core` 0,28 až 0,55). Nálezy kampaně jsou převážně nespárované pasivní události bez typu s taktikou a bez služby, takže dostanou málo rysových bodů a nepřekročí práh. Čerstvá data se na tuto variantu neplýtvají. Zapsáno jako negativní výsledek; syntetická regrese nebyla dokončena a nerozhoduje.

## Prototyp: potvrzení slabé vazby druhým zdrojem (PicoDomain, offline)

`tools/k45_corroborate.py`: hrana ze sdílené adresy se uzná jen při potvrzení druhým zdrojem (úspěšná NTLM autentizace mezi hosty, společný vzácný vnější cíl) nebo silné vazbě. Na PicoDomain se **všech 74 hran ukázalo jako „silné“** (nálezy sdílejí vnitřního hostitele), druhý zdroj nepřidal nic a výsledek je shodný s B1b (úplnost 0,46, kontaminace 0,49). Prototyp je **neprůkazný**: v šestihostitelské doméně je téměř každá vazba mezi stejnými hosty a pravda podle zmínky adresy nerozliší, zda by potvrzení pomohlo.

## Co z toho plyne

Ověřit, zda druhý nezávislý zdroj zvyšuje čistotu, vyžaduje data, kde (1) je nezávislý zdroj zarovnaný s toky (hostové logy, IDS, identita) a (2) pravda rozlišuje nálezy kampaně od nálezů téhož hostu mimo kampaň. Takovou kombinaci v dostupných sadách máme jen částečně (DAPT2021: hostové logy auth/syslog/audit a Snort NIDS po dnech; PicoDomain: NTLM, DNS, SSL, ale s ruční pravdou na úrovni hostitele). Další krok: zjistit, zda DAPT2021 nabízí zarovnání Snort a hostových logů s toky pro dny, kde už máme sítové nálezy.
