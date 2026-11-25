# Předregistrace kroku 48: studený start v laboratoři z kroku 47 (diagnostika)

Zapsáno před spuštěním, po krok 47 (jehož výsledek je znám: 3 zobrazené nálezy za celou kampaň, `coverageStatus.immature_hosts = 5 z 5`, žádný nález specifický pro útok). Cílem je zjistit, zda je příčinou studený start (profil mladší 48 h, `PROFILE_MATURE_S` v `src/protection.rs`), ne obecně příliš slabý signál útoku.

## Metoda (diagnostika, ne nový nezávislý test)

`tools/k48_warmup.py`: skutečně zachycené pozadí (toky, které se nedotýkají útočníka, 219 z 1233) se zopakuje s posunutými časovými razítky přes 50 h před prvním tokem útoku; obsah toků se nemění, jen jejich čas. Skutečný záznam (pozadí i útok) se připojí beze změny se svým skutečným časem. To dá hostitelům zralý profil bez vymýšlení nové kampaně nebo nového obsahu. Okno replaye 1800 s (50 h zahřívání + ~7 min incidentu).

Tohle NENÍ nezávislé ověření korelace (je to tatáž laboratoř, tatáž kampaň) — je to diagnostika jednoho konkrétního mechanismu (nezralost profilu), ne měření přínosu `corr_v3`.

## Hypotézy

- **H1:** `coverageStatus.immature_hosts` klesne na 0 (nebo blízko) v okně bezprostředně před útokem.
- **H2:** aspoň jeden nález specifický pro útok (typ jiný než `unmapped_passive_event`/`unexpected_traffic`, např. `scan_attempts`, `bruteforce_attempts`, `egress_volume_anomaly`) se zobrazí a dotýká se adresy útočníka (10.60.1.3) nebo kampaně (10.60.2.3, 10.60.3.3, 10.60.4.3).
- **H3:** počet zobrazených nálezů dotýkajících se kampaně vzroste nad 1 (hodnota z chladného běhu kroku 47).

## Co z výsledku plyne

- H1 platí a H2/H3 neplatí: příčina chybějící detekce v kroku 47 NENÍ (jen) studený start; signál útoku je obecně slabý vůči prahům, nezávisle na zralosti profilu. To by byl závažnější nález než studený start samotný.
- H1, H2, H3 všechny platí: studený start je potvrzená, dominantní příčina; doporučení pro produkci: nová síť by měla mít výrazně nižší důvěru ve ticho, dokud neprojde zahřívacím oknem, nebo by prahy pro nové hostitele měly být jiné (populační apriorní pravděpodobnost podle třídy zařízení, jak navrhl nezávislý posuzovatel).
- H1 neplatí: 50 h zahřívání nestačí nebo tiled pozadí nevytváří dost rozmanitosti pro "zralost" tak, jak ji kód počítá; zapsat jako limit metody, ne jako závěr o studeném startu.

## Omezení

Syntetické posunutí časových razítek skutečného pozadí, ne nová nezávislá data. Pozadí je jen 219 toků opakovaných ~185×, takže "zralost" tu neznamená skutečnou rozmanitost provozu 50 hodin, jen jeho formální stáří. Pokud se detekce zlepší, je to důkaz, že VĚK profilu (ne jeho rozmanitost) je rozhodující proměnná v kódu — což je samo o sobě informace.
