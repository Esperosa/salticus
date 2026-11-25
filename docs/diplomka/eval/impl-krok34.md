# Kroky 33 a 34: kvalita korelace na vícefázových řetězcích

Podklad: `plan-korelace.md`, `predreg-krok33.md`, `predreg-krok34.md`. Jde o první měření korelace jako takové (kroky 26 až 32 měřily jen zachycení). Přepínače `corr_v2` a `corr_v3` jsou ve výchozím stavu vypnuté, `recommended()` se nemění.

## 1. Metoda

Do skutečného 3denního `conn.log` z domácí sítě (283 tisíc toků) se vložilo 40 vícefázových řetězců (10 simple, 10 pivot, 20 ve dvojicích se sdíleným vnějším cílem a obětním serverem). Přehrání po 30minutových oknech, trvalý workspace, 125 oken, 0 selhání. Pravda je po řetězcích; nález patří řetězci, jen když zmiňuje IP aktéra právě jednoho řetězce. Metrika: párové F1 (dvojice nálezů stejného řetězce ve stejném incidentu), čistota, slité skupiny, fragmentace, úplnost; ramena B0 každý nález zvlášť, B1 seskupení podle sdílené IP, B2 náhodné se stejnými velikostmi, produkční incidenty.

## 2. Krok 33: oprava korelace za `corr_v2`, měření v1 a v2

Seed 133 (test), zobrazených nálezů 8 421 v obou během (množina `finding_id` totožná, **H1 platí**).

| rameno | F1 | úplnost | přesnost | slité skupiny |
|---|---|---|---|---|
| B1 podle IP | 0,757 | 1,00 | 0,61 | 10 |
| produkce v1 | 0,255 | 0,16 | 0,60 | 10 |
| produkce v2 (`corr_v2`) | **0,0** | 0 | 0 | 0 |

**H3 neplatí.** v2 nespojila žádný řetěz (2 incidenty, oba pozadí). Příčiny ověřené v datech: fáze skenu vzniká jako nález bez `host_key` a korelace ho zahodila (32 zahozených), a v2 spojuje jen stejného aktéra se stejným protějškem, takže řetěz A→V, V→X nespojí nikdy. v1 spojuje přes jakýkoli sdílený host, proto má úplnost jen 0,16 a zároveň slévá.

## 3. Krok 34: kauzální seskupení `corr_v3`

Seed 233 (nový, v žádném dřívějším kroku nepoužitý). Pravidla (a) stejný aktér a protějšek, (b) protějšek dřívějšího nálezu se stane aktérem, (c) oběť z nálezu bez hosta, (d) stejný aktér u dvou útočných nálezů; společný protějšek sám nespojuje; klíč nad 25 nálezů je hub.

| rameno | F1 (95 % interval) | úplnost | přesnost | slité skupiny | fragmentace |
|---|---|---|---|---|---|
| B1 podle IP | 0,775 [0,652; 0,885] | 1,00 | 0,63 | 10 | 1,0 |
| produkce v1 | 0,258 [0,285; 0,423]† | 0,16 | 0,60 | 10 | 1,0 |
| `corr_v3` | **0,931 [0,878; 0,976]** | 0,885 | 0,98 | **5** | 1,25 |

† Bod odhadu v1 leží těsně pod vlastním intervalem: bootstrap poměrové metriky s 30 jednotkami je mírně vychýlený (slité skupiny v1 se při vzorkování násobí). Pořadí ramen to nemění (horní mez v1 0,42 je daleko pod dolní mezí B1 0,65), ale intervaly je třeba číst jako orientační.

Rozdíl `corr_v3` − B1 = +0,156, 95 % interval [0,076; 0,255].

Předregistrovaná pravidla:

- **H1 platí:** zobrazené nálezy v běhu A a C totožné (8 420).
- **H3 platí:** +0,156 ≥ 0,10, dolní mez > 0, překonává B2 (0,04).
- **H4 platí:** 5 slitých skupin proti 10 u B1. Všech 5 jsou kolizní dvojice; příčina: obě dvojice skenují stejný obětní server a nález skenu nemá zdroj, takže kauzálně nelze říct, čí sken to byl. To je limit nálezu bez hosta, ne chyba seskupení.
- **H2 neplatí:** 69 incidentů za 3 dny proti stropu 45. Z toho 45 jsou řetězce (40 řetězců, 5 sloučených dvojic) a **24 jsou skutečné domácí pozadí** (například 25 `interactive_session` a 7 `long_lived_tunnel` jednoho hostu, nespárované události dalších hostů). Největší incident má 32 nálezů (0,4 % zobrazených), takže hub se nevytvořil, a žádný incident mimo kolizní dvojice neslévá řetězce. Strop jsem stanovil tak, že pozadí do něj počítá; pozadí produkuje 8 incidentů denně, ne 15, ale s řetězci je to 23 denně.

## 4. Odchylka od předregistrace a oprava metody

Předregistrovaný bootstrap „přes řetězce“ jsem implementoval chybně: kopie řetězce se ve vzorku spojily do jedné skupiny a tvořily falešné dvojice. Příznak: bod odhadu 0,775 ležel mimo vlastní interval [0,432; 0,626]. Po zjištění jsem metodu opravil (bootstrap přes jednotky pravdy, kopie se nespojují). Rozhodnutí o H3 se tím nezměnilo: platí podle staré metody (dolní mez 0,001, konzervativně vychýlená) i podle opravené (0,076). Výsledky obou kroků jsou v tabulkách podle opravené metody; starší čísla jsou v `eval.json` pod `bootstrap_chain_copies`.

## 5. Co z toho plyne a meze

1. Korelace v produkci (v1) je na vícefázových řetězcích **horší než triviální seskupení podle IP** (F1 0,26 proti 0,78), protože spojuje jen přes sdílené hosty a nálezy bez hosta zahazuje. Dosud jsme to neměřili.
2. `corr_v3` zvyšuje F1 na 0,93 a půlí slévání souběžných řetězců, **bez ztráty zachycení** (zobrazené nálezy beze změny, korelace jen anotuje).
3. **Meze:** řetězce jsou moje syntetické epizody a pravidla `corr_v3` odpovídají jejich tvaru (aktér, oběť, pivot); seed 233 ověřuje, že to platí pro nové instance, ne že to platí pro útočníky obecně. Skutečné řetězce v CTU-13 a IoT-23 mají jinou strukturu (jeden škodlivý host, tisíce toků), ověření na nich je další krok. H2 (šum) neplatí: domácí pozadí dává 24 incidentů za 3 dny a o jejich užitečnosti nemáme pravdu.
4. Dolů nejde slít to, co nemá zdroj: nález skenu bez hosta nese jen oběť. Úplné přiřazení by vyžadovalo zdroj skenu v nálezu (rozšíření `unmapped_passive_event`), ne lepší seskupení.

## 6. Další krok

Ověřit `corr_v3` na skutečných označených datech (CTU-13: fáze botnetu na hostu), změřit pozadí (24 incidentů) a zavést důvod spojení u každé hrany; výchozí profil až po soaku na domácí síti.

Reprodukce: `tools/k33_chain.py gen`, `tools/k33_corr.py run` a `eval` (zmrazeno commitem `44e2ef2`, bootstrap opraven později). Pracovní data lokálně v `F:\work-tmp\shadow\k33test` a `k34test`.
