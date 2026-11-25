# Krok 41: DAPT2021, den s vyšším objemem (Week6_Day3_06302021)

Podklad: `predreg-krok41.md`, kód zmrazen commitem `16a73ad`. 363 413 toků po odstranění duplicit, 61 oken po 30 min, 0 selhání. Zobrazeno 347 nálezů, z toho 31 se týká adres kampaně APT (informativní test podle předregistrovaného pravidla, ≥ 10).

## Výsledek (úroveň normal; strict a loose shodné)

| rameno | incidenty (celkem) | s kampaní | úplnost | hostů kampaně v nejlepším | kontaminace | největší incident | duplicitní položky |
|---|---|---|---|---|---|---|---|
| v1 (A) | 3 | 2 | (1,68, artefakt duplicit) | 1 | 0,92 | 681 | 524 |
| C (`corr_v3`+`corr_ext`+`corr_related`) | 9 | 2 | 0,74 | 1 | 0,91 | 264 | 0 |
| C uzávěr | 5 | 2 | 0,74 | 1 | 0,92 | 298 | – |
| B1b | 7 | 2 | 0,77 | 1 | 0,90 | 258 | – |
| `corr_union` (U) | 15 | 2 | 0,42 | 1 | 0,89 | 135 | – |
| B1 | 2 | 2 | 0,94 | 2 | 0,90 | 341 | – |

## Předregistrovaná pravidla

- **H1 platí:** zobrazené nálezy beze změny (347 shodných).
- **H2 platí:** C 0 duplicitních položek, v1 524 (největší incident 681 položek ze 347 nálezů).
- **H3 neplatí:** nejlepší incident C obsahuje 1 adresu kampaně (potřeba ≥ 2).
- **H4 neplatí:** kontaminace 0,91 a největší incident 264 z 347 nálezů (76 %).
- **H5 neplatí:** kontaminace C 0,91 proti B1b 0,90 (není nižší) a úplnost uzávěru 0,74 proti 0,77.

## Příčina (zjištěno po měření, tedy diagnostika, ne rozhodnutí)

Největší incident C má 264 nálezů ze 157 `interactive_session`, 54 `beacon_periodic`, 47 nálezů bez hosta a 6 `long_lived_tunnel`; jeho hrany jsou ze 187 z 264 pravidlo `victim_actor` (protějšek dřívějšího nálezu, který se pak sám stane aktérem), dále `actor_victim`, `actor_attack`, `ext_peer`. V podnikové síti, kde vnitřní servery jsou zároveň protějšky i aktéři mnoha relací, řetězení klient → server → další klient spojí téměř celou síť. Mez hubu 25 omezuje stupeň jednoho klíče, ale nebrání **perkolaci** přes stovky klíčů. B1b (sdílená adresa s oknem a mezí) trpí totéž (největší incident 258). Neplatí to na domácí síti (největší incident 5,7 %), PicoDomain (43 %) ani LLDOS, kde je málo vnitřních hostitelů.

## Co z toho plyne

1. **Kauzální řetězení přes vnitřní protějšky nefunguje v podnikové síti s mnoha servery**: kontaminace 0,91 je horší než jakékoli předchozí měření. Doporučení „zapnout korelaci v shadow konfiguraci“ platí jen pro malé sítě; pro větší je potřeba omezit řetězení.
2. Opraveno tím jediným, co se dosud prokázalo na všech skutečných datech: žádné duplicitní položky (v1: až 681 položek v jednom incidentu).
3. Zdokumentovaný nedodělek: řetězení omezit na nálezy s mapovanou taktikou (ATT&CK), aby běžné relace mezi vnitřními hosty (`interactive_session`, `long_lived_tunnel`) netvořily mosty; to je změna pravidla podle tohoto měření, tedy nový krok s novými daty (krok 42).
