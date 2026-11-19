# Krok 19: výchozí preset a znovuověření případové složky

Datum zahájení 2026-11-19. Výchozí stav: konec kroku 18 (commit `30b76a7`, zdrojový kód shodný s `17bbd7e`). Zadání: `F:\work-tmp\briefs\krok19-preset-a-slozka.txt`. Závazný rozsah: `docs/diplomka/rozsah-autonomie.md`.

Dvě části: **A)** rozhodnutí, zda do `recommended()` patří `endpoint_weak`, `refute_episode` a `confirm_evidence` (návrhy z kroků 15 a 18); **B)** znovuověření případové složky (K16-4 a K16-9 z kroku 16 neprošly na držených seedech) a oprava tří slabin z kroku 16.

## 1. Předregistrace (zapsáno před kódem a před měřením)

### Část A: preset

Ramena, párově (stejný seed a síť v obou), základ = **současné `recommended()`** (soak bez `--v3-on`, tedy bez přepínačů konfigurace `final`), kandidát = základ + `endpoint_weak,refute_episode,confirm_evidence`:

| konfigurace sítě | základ | kandidát |
|---|---|---|
| `off` | `recommended()` | + 3 přepínače |
| `ops` | `recommended()` + `--ops-telemetry on` | + 3 přepínače |
| `elying` | `recommended()` + `endpoint_ext`, `--endpoint on --endpoint-agent ok` (agent na hostech útoku hlásí „vše v pořádku“) | + 3 přepínače |

Společné volby jako v kroku 18: `soak run --max-networks 4 --threads 1 --block-size 2 --no-legs --engine v3 --no-feedback --counterfactual --l7 cal --coverage k10`. Binárka `salticus-k18-17bbd7e.exe` (zdroj beze změny od `17bbd7e`). `endpoint_weak` má účinek jen s koncovou telemetrií (vyžaduje `endpoint`), tedy jen v `elying`; v `off` a `ops` je beze změny chování.

**Nové držené seedy (zapsáno dopředu, použít jednou): 20269701, 20269702, 20269703, 20269704, 20269705, 20269706, 20269707, 20269708, 20269709, 20269710.** 10 seedů x 4 sítě x 3 konfigurace x 2 ramena. Ladění se nedělá (žádné prahy, žádné ladicí běhy před drženými). Seed se sítí, jejíž běh trvá přes 2 h, se vynechá v obou ramenech a zapíše.

Kritéria (každé musí platit v každé ze tří konfigurací):

| práh | metrika | splněno, když |
|---|---|---|
| K19-A1 | omylem zavřené útoky (`auto_closures_wrong` + `ladder_refuted_wrong_cf`) | kandidát 0; hlásí se horní mez Wilson 95 % (jmenovatel = útoky) |
| K19-A2 | detekce po rodinách (zobrazeno, kontrafakt) | žádná rodina s ≥ 20 útoky nepoklesne o víc než 1 p. b. |
| K19-A3 | zobrazené FP | poměr kandidát/základ ≤ 1,01 |
| K19-A4 | případy pro člověka (potvrzeno + eskalováno) | nárůst ≤ 2 % |
| K19-A5 | zhoršení nad rámec rozptylu | párový bootstrap po sítích (stratifikovaný podle seedu, B = 2000, pevné semínko 19): 95% interval rozdílu souhrnné detekce nesmí ležet celý pod 0, intervaly relativní změny zobrazených FP a případů pro člověka nesmí ležet celé nad 0 |

Rozhodnutí: projdou-li všechna kritéria ve všech konfiguracích, `recommended()` se změní (s testem). Jinak zůstane beze změny a důvod se zapíše. Měřicí skript `tools/k19_preset.py`.

### Část B: případová složka

**Slabiny z kroku 16 a kořenové příčiny (z kódu `case_folder.rs`, před měřením):**

1. *Obecný doporučený krok.* Doporučení = „nejlevnější dosud neprovedená kontrola“ ze všech druhů `CheckKind`, bez ohledu na to, zda kontrola útok od neškodného vůbec rozliší. Druhy bez změřené tabulky věrohodnosti (`DnsPivot`, `Timing`, `GeoAsn`, `TlsFingerprint` mají neutrální tabulku s poměrem 1) vycházejí jako nejlevnější a žebřík je sám neumí; složka neříká, že jde o ruční krok, ani co by výsledek znamenal.
2. *Uživatel vždy „nelze určit“.* Složka nemá vstup, který by uživatele nesl: kroky žebříku jsou text a `EndpointSignal` uživatele nepředává, ačkoli koncová telemetrie ho v událostech má (vlastník procesu, přihlášení). V soaku se složce navíc nepředává ani pokrytí koncovou telemetrií (`endpoint_covered: None`).
3. *Slepé místo jako důvod předání v 99 %.* Za slepé místo se počítá každý krok s výsledkem `Undetermined`, tedy i kontrola, která proběhla a nic nerozlišila („služba odpovídá“, „jev se neopakoval“, „zdroj bez reputace“, „běžné pro typ zařízení“). Podle pravidla 5 rozsahu je slepé místo *chybějící telemetrie*, ne kontrola bez rozlišujícího výsledku.

**Opravy (rozhodnutí žebříku se nemění, jen obsah složky):**

- B-oprava 1: zbývající kontroly se řadí podle změřené informace na cenu (`competing::information_per_cost` při P(útok) případu, tabulky kroku 12): nejdřív neprovedené kontroly, které rozlišují (informace > 0), pak neprovedené bez změřené rozlišovací schopnosti, pak provedené bez výsledku. Doporučený krok jmenuje jen kontrolu, která rozlišuje; řekne, zda ji program dělá sám, nebo jde o ruční krok (s konkrétní instrukcí pro druh kontroly), a jak by výsledek posunul P(útok) (podezřelý / neškodný). Když žádná dostupná kontrola nerozlišuje, řekne to.
- B-oprava 2: koncová telemetrie sbírá uživatele hosta v okně posouzení (vlastník procesu, uživatel přihlášení); složka je uvede jako aktéra `uzivatel` (pseudonym, je-li nastaveno), jinak „nelze určit“ s přesným důvodem (chybí koncová telemetrie hosta / telemetrie uživatele nenese). Soak předá složce pokrytí a uživatele stejně jako pipeline.
- B-oprava 3: slepé místo = jen kontrola, kterou nešlo provést (`Unavailable`: chybí pokrytí, mimo rozsah, čeká na schválení), a mezery pokrytí (host bez senzoru nebo agenta, chybějící provozní telemetrie). Kontrola bez rozlišujícího výsledku zůstává v „ověřeno“ a v nejistotě pozorování. Důvod předání „slepá místa“ jen u případů s takovou mezerou.
- Validátor (`case_folder::validate`) a skript (`tools/k16_case_folders.py`) dostanou pravidla navíc: doporučený krok nejmenuje kontrolu bez rozlišovací schopnosti ani už provedenou; slepé místo nesmí pocházet z kroku `Undetermined`; uživatel jako aktér jen z koncové telemetrie.

Ladění oprav jen na ladicích seedech kroku 16 (20261102 `off`, 20261103 `ops`, 20266101 `elying`, 20266105 `mixops`, 20266106 `opsnoise`, po 2 sítích).

**Nové držené seedy pro složky (zapsáno dopředu, použít jednou): 20269801 a 20269802 `off`, 20269803 a 20269804 `ops`, 20269805 a 20269806 `elying`, 20269807 a 20269808 `mixops`, 20269809 a 20269810 `opsnoise`** (`opsnoise` = `--ops-telemetry on --ops-noise 3`, `mixops` = `--mix on --ops-telemetry on`), každý 2 sítě, konfigurace `final` (`recommended()` binárky na konci kroku 19 + `breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate`), kontrafakt, dump `K16_CASE_DUMP`. Pokud část A změní `recommended()`, držený běh B už ho obsahuje (to je produkt, který se ověřuje).

| práh | metrika | splněno, když |
|---|---|---|
| K19-B1 (= K16-4) | složka netvrdí víc než důkazy | 0 porušení validátoru i nezávislého skriptu |
| K19-B2 (= K16-9) | senior review 30 případů (semínko 16, `k16_case_folders.py sample`) | ≥ 80 % „senior ví, co dělat“, 0 zavádějících; každá chyba zapsána |
| K19-B3 | „slepá místa“ jako důvod předání | ≤ 50 % předaných a každý takový případ má krok `Unavailable` nebo mezeru pokrytí (hlásí se i před opravou na stejném dumpu přepočtem) |
| K19-B4 | doporučený krok předaných | 0 % doporučení kontroly bez rozlišovací schopnosti nebo už provedené; hlásí se rozdělení doporučených kontrol a podíl ručních |
| K19-B5 | uživatel jako aktér | v `elying` u případů, kde host má živou koncovou telemetrii s uživatelem, 100 % vyplněno; hlásí se podíl vyplněných celkem |
| K19-B6 | regrese K16-1, -2, -3, -5, -6, -7 | beze změny splněno (p95 ≤ 8 KiB, max ≤ 16 KiB); bez dumpu `networks.jsonl` shodný s binárkou `17bbd7e` (ladicí seed, 2 sítě, 3 konfigurace) |

Omezení předem: council, sol-loop a delegování se podle zadání nespouštějí (odchylka od `CLAUDE.md` daná zadáním); review dělá autor. K19-B2 posuzuje autor kódu, ne nezávislý senior, takže jde o horní odhad použitelnosti. Tabulky věrohodnosti pro řazení kontrol jsou ze simulace (krok 12).
