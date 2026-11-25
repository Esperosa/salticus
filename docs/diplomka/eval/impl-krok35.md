# Krok 35: `corr_v3` po opravách, silnější baseline, dva nové tvary řetězců

Podklad: `predreg-krok35.md`. Test seed 335 (jednou), dev seed 35 (jen kontrola). 60 řetězců v 5 tvarech (simple, pivot, fanout, samewin, collision jako 6 dvojic), 125 oken po 30 min, 0 selhání.

## Výsledek na testu (seed 335)

| rameno | F1 | přesnost | úplnost | slité skupiny | pozaďové incidenty |
|---|---|---|---|---|---|
| B1 sdílená IP | 0,918 | 0,85 | 1,00 | 8 | 1 |
| B1b IP + okno 6 h + mez hubu | 0,932 | 0,87 | 1,00 | 7 | 2 |
| `corr_v3` po opravách | **0,988** | 1,00 | 0,976 | **0** | 4 |

F1 podle tvaru (test): simple, pivot, fanout, samewin všechna ramena 1,0; kolize B1b 0,600, `corr_v3` 0,857.

## Předregistrovaná pravidla

- **H1 platí:** zobrazené nálezy v běhu bez a s korelací jsou totožné (8 548).
- **H2a platí:** 4 čistě pozaďové incidenty za 3 dny (strop 30). **H2b platí:** 60 incidentů s řetězcem (strop 66). **H2c platí:** kontaminace 0,0 (strop 0,05).
- **H4 platí:** churn 0 z 88 810 nálezů v incidentech (nic se mezi okny nepřesunulo).
- **H3 neplatí:** rozdíl `corr_v3` − B1b = +0,056 [95 % interval 0,019; 0,110], tedy kladný, ale pod předregistrovaným prahem 0,10. Podmínka „není horší v žádném tvaru“ platí.

## Co z toho plyne

1. Opravy F0 fungovaly: slévání kolizních dvojic kleslo z 5 z 10 na 0 z 6, největší incident 460 nálezů je pozaďový (5,4 % zobrazených), hub se nerozpadá.
2. **Přínos `corr_v3` nad silnou baseline je malý.** B1b (sdílená IP s oknem a mezí hubu) dosahuje 1,0 ve čtyřech z pěti tvarů; jen u kolizí je horší. Syntetická data tedy `corr_v3` od jednoduchého seskupení skoro neodliší a ani s druhým tvarem to neměníme. Slib „+0,10“ byl příliš optimistický a nesplnil se; zapisuji to jako negativní výsledek.
3. Zbytkový rozdíl (kolize): úplnost 0,976, tedy některé fáze kolizních řetězců se nespojily; příčina je v nálezu skenu bez zdroje (K12 odpadá jen částečně: slévání zmizelo, úplnost ne).
4. Syntetika je vyčerpaná: další zlepšení se musí měřit na nezávislých datech (krok 36, DARPA 2000).

Reprodukce: `tools/k35_chain.py gen`, `tools/k33_corr.py run`, `tools/k35_corr.py eval`. Data lokálně `F:\work-tmp\shadow\k35test`.
