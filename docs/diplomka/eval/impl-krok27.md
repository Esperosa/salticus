# Krok 27: pravidlo pro opakovaná krátká spojení (hádání hesel), jádro v3

Podklad: `impl-krok26.md`. Měření tam ukázalo, že jádro v3 zachytilo hrubou sílu na SSH jen díky tomu, že na portu 22 byli vrstevníci (toky mého vlastního nmap skenu): baseline „skupina_sluzeb“ v `anomaly_v3.rs` bez vrstevníků jen sbírá. Po deklaraci vlastního skenu (vyjmutí těchto toků) zachycení spadlo z 10/10 na 0/10.

## 1. Pravidlo

`src/behavior/attempts.rs`, typ nálezu `bruteforce_attempts` (Medium, nízká jistota). Podmínky: aspoň **50** TCP spojení ze zdroje na `(cíl, port)` přihlašovací služby (21, 22, 23, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 5985) během **600 s**, medián doby trvání nejvýš **10 s**. Zvyklost hostu pravidlo tlumí. Vstupem jsou toky s cílem v rozsahu (vnitřní i příchozí); odchozí se nehodnotí.

- Přepínač `attempts` v `[engine.v3]`: **výchozí vypnuto** ve všech presetech, `recommended()` se nemění.
- Typ je **chráněný** (`protection.rs`), takže se nikdy nezavře automaticky; není v seznamech typů, které smí vysvětlit porucha.
- Prahy jsem určil předem podle povahy útoku (desítky pokusů za minuty), neladil jsem je na benchmarku. Kontrola na reálných datech před implementací: úsek ≥ 50 spojení za 10 minut na tyto porty se v celém záznamu vyskytl jen u mého vlastního nmap skenu (port 110, 3 dvojice po 40 až 53).

## 2. Měření

Benchmark z `impl-krok26.md` (10 epizod na rodinu, reálné pozadí), jádro v3 s modulem `known_activity` (vlastní sken deklarován, tedy bez vrstevníků na portu 22):

| nastavení | SSH hrubá síla | ostatní rodiny | nálezy na reálném pozadí |
|---|---|---|---|
| v3 + modul | 0/10 | beze změny | 357 |
| v3 + modul + `attempts` | **10/10** [0,72; 1,00] | beze změny | 357 (pravidlo na reálném pozadí nic nepřidalo) |
| v3 bez modulu + `attempts` | 10/10 | beze změny | 5 529 (o 2 víc než 5 527: dva nálezy na můj vlastní skenu) |

Zachycení už nezávisí na vrstevnících: v běhu, kde byli vrstevníci vyjmuti, pravidlo SSH zachytí.

## 3. Review (Claude Sonnet, jen čtení)

Verdikt ZMĚNY (bez blockeru). Nálezy a rozhodnutí:

| nález | rozhodnutí |
|---|---|
| `service_key` neměl tvar `kind/peer/proto/port`, takže `profile::case_pair` obracel dvojici a bral špatný protokol | **opraveno**: tvar `attempts/<protějšek>/tcp/<port>`, aktér je u vnitřního toku zdroj, u příchozího oběť |
| posuzovalo se jen první okno 50 spojení; dlouhé relace před útokem ho mohly skrýt | **opraveno**: hledá se první dost těsné okno s krátkým mediánem; test |
| chyběly testy hranic, neseřazeného vstupu, zvyku pro jiný port, ochrany typu a výchozího vypnutí | **doplněno** (13 testů, tautologický test vyměněn) |
| komentář neuváděl konkrétní falešné poplachy | **doplněno** (monitorování, Ansible a rsync, aplikace bez fronty spojení k databázi, skenery, nmap správce) |
| `attempts` bez `egress` je tichý no-op | přijato, nit |
| `duration_s = None` se bere jako 0 | přijato, test to pokrývá |
| zvyk se z příchozích toků nikdy neučí | přijato: pravidlo pro příchozí zdroje se zvykem netlumí (bezpečný směr) |

## 4. Meze (bez zastírání)

- **Pomalá hrubá síla pod prahem uniká:** 50 spojení za 10 minut je asi 5 za minutu; skript, který zkouší jedno heslo za minutu, pravidlo nezachytí. Je to cena prahu, který odděluje pokusy od běžného provozu.
- **Bez stavu mezi okny:** dávka rozdělená hranicí okna (například dvě po 40) se nespojí.
- **Falešné poplachy** jsem na tomto pozadí neměřil (pravidlo na něm nic nenašlo mimo můj vlastní sken); jiná síť s monitorováním nebo zálohami jich může mít víc. Zátěž nese analytik, nález je chráněný.
- Epizody útoku jsou moje syntetické; měří se hranice, ne pravdivost vůči skutečným útočníkům.
- Z celé knihovny (`cargo test --lib`) selhalo před opravou snímku 8 testů: 5× `broker::*` (bez Redis), `identity_lab`, nestabilní `case_memory` a `engine::tests::parse_mode_and_disable_list`, který hlídá přesný popis presetu `all()`. Poslední opraven (nové pravidlo je v `all()` vypnuto). Po opravě jsem znovu spustil jen `engine`, `behavior::attempts`, `known_activity` a `passive`, ne celou sadu.
- 48/48 regrese soaku se pravidla netýká strukturálně (přepínač je ve všech presetech vypnutý), ale po této změně jsem ji **nespouštěl** (trvá víc než hodinu). Přímá kontrola místo ní: tentýž vstup (reálný záznam, výchozí v3 bez nových přepínačů) dal před změnou a po ní shodně **7 833 událostí a 5 527 nálezů**.

## 5. Další krok

Stavové vrstvy (beaconing, historie objemu) měřit přes soak se cykly; poté brána uzavírání na reálných datech.
