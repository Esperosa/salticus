# Předregistrace kroku 30: nová nastavení v3 na skutečných označených botnetech (CTU-13)

Zapsáno **před** prvním měřením na testovacích scénářích. Cíl: ověřit na datech se skutečnou pravdou (ne na mých syntetických epizodách z kroků 26 až 28), že přepínače `attempts`, `attr_calib` a `upload_horizon` nezhorší zachycení infikovaných hostů a udrží šum v mezích.

## 1. Data a rozdělení

- CTU-13, 13 scénářů, v `labs/datasets/ctu13/Botnet-42..54` (binetflow, štítky po tocích). Skutečné botnety (Neris, Rbot, Virut, Menti, Sogou, Murlo, NSIS.ay), 7 rodin.
- **Vývojové scénáře (smí se používat k ladění převodu a vyhodnocení, nikoli k rozhodnutí):** Botnet-42 (scénář 1), Botnet-51 (scénář 10), Botnet-54 (scénář 13). Důvod: tyto tři byly použity při návrhu dřívějších kroků.
- **Testovací scénáře (rozhodují, každý se přehraje jednou):** Botnet-43, 44, 45, 46, 47, 48, 49, 50, 52, 53 (10 scénářů). Na těchto scénářích se dosud neměřila produkční cesta v3 ani nové přepínače. Registr datasetů uvádí, že byly dříve použity pro klasické skórování tokových klíčů (`src/eval`, krok 18); to s přepínači v3 nesouvisí, ale zapisuji to.
- Pravda: infikovaný host = zdroj aspoň jednoho toku se štítkem `From-Botnet`. Ostatní hosty jsou benigní nebo neznámého stavu (Background se za benigní nepovažuje a nepočítá se jako falešný poplach).
- Rozsah sítě: `147.32.84.0/24` (testbed s infikovanými hosty ve všech scénářích), určeno předem.

## 2. Ramena (párově, stejná data, stejný převod)

- **A:** jádro v3, výchozí preset (`[engine] mode = "v3"`).
- **B:** A + `attempts`, `attr_calib`, `upload_horizon`.
- Přehrání: 30minutová okna, celá produkční cesta `beh spust` s trvalým pracovním prostorem na scénář a rameno (`tools/k27_cycles.py` logika; nový ovladač `tools/k30_ctu13.py`). Modul `known_activity` se nepoužívá (síť nemá odpovídající multicast provoz; nepředpokládá se).
- Převod binetflow → conn.log je ztrátový (pakety rozděleny úměrně bajtům, stav z `Dir`); omezení zapíšu do výsledku.

## 3. Měřítka

- **Zachycení hosta:** infikovaný host je zachycen, když jeho IP je zmíněna v nálezu zobrazeném produktem (jiný typ než „neočekávaný provoz“). Pro scénář: `zachyceno / infikováno`.
- **Šum:** počet zobrazených nálezů za scénář (neověřených, nejde o falešné poplachy).
- **Zpoždění:** čas od prvního toku infikovaného hosta v rozsahu do prvního zobrazeného nálezu s jeho IP (jen popisně).

## 4. Hypotézy a rozhodovací pravidla (stanovena předem)

- **H1 (žádná ztráta):** v žádném testovacím scénáři zachytí B méně infikovaných hostů než A. Platí, když počet scénářů, kde B < A, je **0 z 10**.
- **H2 (šum v mezích):** součet zobrazených nálezů B přes testovací scénáře je nejvýš **1,5×** součtu pro A.
- **H3 (přínos, průzkumná, bez rozhodnutí):** počet scénářů, kde B > A; páry vyhodnotit exaktním znaménkovým testem a Wilsonovým intervalem na úrovni hostů.
- **Rozhodnutí:** H1 a H2 splněny → přepínače se označí za „ověřené na veřejných datech se skutečnou pravdou na 10 scénářích“ pro shadow profil. H1 nesplněna → forenzní rozbor příčiny ztráty a přepínač, který ztrátu způsobil, se z profilu odebere nebo opraví jako samostatný krok. H2 nesplněna → zapíšu poměr a doporučení omezit.
- Žádný práh ani kód se mezi vývojovou a testovací fází nemění; změna po vidění testu by znehodnotila test (zapsala by se jako nový krok s novým rozdělením).

## 5. Forenzní rozbor (pro každého infikovaného hosta, který rameno B nezachytilo)

Příčina se určí z dat v tomto pořadí a zapíše se jedna kategorie:
1. **mimo rozsah:** host nemá ve zdroji ani cíli toku adresu v rozsahu;
2. **bez nálezu:** žádný nález (zobrazený ani ne) host nezmiňuje, detektory nic nezachytily;
3. **potlačeno:** nález host zmiňuje, ale je ve stavu `suppressed` / `open` a nezobrazil se (opakování);
4. **uzavřeno:** nález zavřen/vyvrácen;
5. **jen neočekávaný provoz:** host zmíněn jen v nálezu „neočekávaný provoz“.
Ke každému hostu se uvede počet jeho toků v rozsahu a čas prvního toku.

## 6. Hrozby platnosti (přiznané předem)

- Jen sedm rodin botnetů, jedna síť (testbed), deset testovacích scénářů; intervaly budou široké.
- Převod z netflow nemá obsah ani Zeek pole; detektory závislé na nich (L7, DNS) se tu neuplatní.
- Infikovaný host je zdroj toku „From-Botnet“; hosté, kteří jsou jen cílem botnetového provozu, se nepočítají.
- Nezachycení nemusí být chyba produktu: scénáře mají malou část škodlivých toků.
