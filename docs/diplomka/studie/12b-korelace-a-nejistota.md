# Studie 12b: chytřejší korelace a práce s nejistotou

Datum 2026-11-14. Zdroje staženy a čteny v tento den. Co se ověřit nepodařilo, je označeno „ověřit“. Autorský text, bez přejímání vět ze zdrojů.

## 1. Ověřené zdroje a co z nich plyne

| téma | zdroj (URL, verze) | ověřeno | použití v návrhu |
|---|---|---|---|
| Analysis of Competing Hypotheses | R. J. Heuer, Jr., *Psychology of Intelligence Analysis*, CIA CSI, 1999, kap. 8 (s. 95 až 110); https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/ (PDF z odkazu na stránce, kap. 8 čtena z textu PDF) | osm kroků ACH: hypotézy, důkazy, matice s „diagnosticitou“, zjemnění matice (smazat důkazy bez diagnostické hodnoty), závěr **vyvracením, ne potvrzováním**, citlivost na klíčové důkazy, report všech hypotéz, milníky pro další pozorování | každý nález nese sadu konkurenčních hypotéz včetně neškodných; důkaz bez rozlišovací schopnosti nemá váhu; hlásí se všechny hypotézy, ne jen nejpravděpodobnější; milníky = „co by případ rozhodlo“ |
| Sekvenční test poměrem věrohodnosti | https://en.wikipedia.org/wiki/Sequential_probability_ratio_test (sekundární; primární je A. Wald, 1945, Annals of Math. Statistics, **ověřit**) | součet log poměrů věrohodnosti, dvě hranice z α a β: přibližně a ≈ log(β/(1−α)), b ≈ log((1−β)/α); v diskrétním případě jsou hranice jen přibližné; Wald a Wolfowitz dokázali optimalitu | základ sekvenčního vážení důkazů; hranice se ale v enginu nevolí pevně, plynou z ceny omylu (oddíl 2) |
| Kalibrace | C. Guo, G. Pleiss, Y. Sun, K. Weinberger, *On Calibration of Modern Neural Networks*, ICML 2017, https://arxiv.org/abs/1706.04599 | kalibrace = shoda předpovězené pravděpodobnosti s četností; teplotní škálování je jednoparametrová varianta Platt scaling a pro většinu úloh účinné. **Definici ECE tato stránka neobsahuje, ECE definuji sám (oddíl 3)** | metrika ECE; Platt/teplotní škálování pro málo dat |
| Platt a isotonická kalibrace | scikit-learn 1.9.1, https://scikit-learn.org/stable/modules/calibration.html | sigmoid (Platt) pro malé vzorky; isotonická je obecnější, ale přeučuje na malých datech, zhruba od 1000 vzorků je stejně dobrá nebo lepší; isotonická zavádí shody; Brier a log-loss míchají kalibraci, rozlišení a neurčitost, proto samotné neměří kalibraci | volba: isotonická, když je dost případů (dnes v `calibration.rs`), jinak sigmoid; ECE a spolehlivostní diagram se hlásí vedle Brierova skóre |
| Konformální predikce | A. Angelopoulos, S. Bates, *A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification*, arXiv:2107.07511 v6 | distribuční bez předpokladů, neasymptotická záruka, že množina obsahuje pravdu s uživatelem zadanou pravděpodobností; výstup je množina; abstence je zmíněna jen okrajově. **Termín „marginální pokrytí“ stránka nepoužívá (ověřit v textu)** | záruka pokrytí pro množinu {útok, neškodné, porucha}; prázdná nebo vícečlenná množina = předat člověku |
| Subjective Logic | A. Jøsang, *Subjective Logic: A Formalism for Reasoning Under Uncertainty*, Springer 2016; https://www.mn.uio.no/ifi/english/people/aca/josang/sl/ | argumenty jsou subjektivní názory s epistemickou nejistotou; binomické na Beta, multinomické na Dirichlet; zobecňuje Bayesovo pravidlo. **Složky belief/disbelief/uncertainty/base rate a fúzní operátory stránka nedefinuje (ověřit v knize)** | model nejistoty z chybějících dat: žádné pozorování = vysoká nejistota, ne rovnoměrná pravděpodobnost |
| ATT&CK | https://attack.mitre.org/ (verze stránka neuvádí) | 15 taktik Enterprise matrix (Reconnaissance až Impact; stránka uvádí i „Stealth“ a „Defense Impairment“), techniky a podtechniky, odkaz na Detections s Data Components | řetězení nálezů do fází kill-chain podle taktiky (už je taktika v rodinách) |
| Velociraptor | https://docs.velociraptor.app/ | existují hunty, artefakty a VQL, dokumentace zmiňuje sekci Security; **schvalování a oprávnění stránka neřeší (ověřit)**; upozornění na verzi 0.77.3 kvůli CVE | forenzní sběr jako čtecí artefakt, jen se schválením a jen určené artefakty (oddíl 5) |
| Timesketch | https://timesketch.org/ | sdílené „sketches“, analyzátory (Tagger, Sigma, extrakce rysů), tagování, import časových os | spis případu jako časová osa se štítky |
| Security Onion 2.4 | https://docs.securityonion.net/en/2.4/ | Suricata, Zeek, Stenographer (PCAP), Strelka, Elastic, Sigma detekce, Cases (jen index dokumentace, funkce nepopsány) | PCAP ring buffer a případy jako vzor; ověřit popis funkcí před citací |
| Sigma | https://github.com/SigmaHQ/sigma-specification | specifikace pravidel a samostatná specifikace korelačních pravidel; **typy event_count, value_count, temporal stránka neuvádí (ověřit ve specifikaci)** | korelační pravidla v enginu jsou vlastní; Sigma jen jako formát požadavku na vyhledání v logu |

Neověřeno v tomto kole: Zeek/RITA korelace nad rámec již ověřené stránky RITA (studie 12), Wazuh, Arkime, Dempster–Shafer, EVOI (rozhodovací analýza), SIEM korelační pravidla jako rodina, provenance grafy v EDR/XDR. Tyto pojmy se v textu práce necitují, dokud se nenajde primární zdroj.

## 2. Návrh (každé za přepínačem, výchozí vypnuto)

1. **Konkurenční hypotézy** (`hypotheses`, existující `hypothesis.rs` a `verification_planner.rs`): u každého nálezu množina H = {útok, záloha, aktualizace, plánovaný skener, porucha, chybná konfigurace}, každá s předpovědí, co musí platit v telemetrii (např. záloha: stabilní cíl s historií hosta, nahrání v okně a směru, plán v kalendáři). Kontrola je zvolena podle **očekávané informace na cenu** (EVOI): největší očekávané snížení nejistoty rozdělení H dělené cenou kontroly. Řetěz nezávislých kontrol (`verification_chain.rs`) se zapojí do žebříku.
2. **Sekvenční vážení.** Poměry věrohodnosti po nezávislých skupinách důkazů (síť, TLS/DNS, endpoint, kontext, profil hosta); závislé důkazy ve skupině se nesčítají, skupina přispívá nejvýš svým nejsilnějším členem (nebo korelačně zeslabeným součtem). Prázdná data mají log poměru 0 a navíc zvyšují nejistotu. Zastavení: rozhodnout, když očekávaná ztráta rozhodnutí (cena omylu × posterior) klesne pod cenu další kontroly; jinak pokračovat nebo předat člověku. Cena omylu je asymetrická: zavřít útok ≫ eskalovat neškodné.
3. **Chybějící data jako výstup.** Rozhodnutí brzděné chybějící telemetrií vrací strukturovanou žádost: typ logu, segment, senzor (viz studie 12, oddíl 7 a pokrytí senzorů).
4. **Retrospektivní vyhledávání.** Nový indikátor (SNI, JA3/JA4, adresa, jméno) se dohledá v uložené historii nálezů a L7 záznamů; výstup: první výskyt, časová osa hostu, řetězec fází podle taktik, propojení do jednoho incidentu s příčinou (útok nebo porucha).
5. **Znovuotevření.** Nové důkazy smí přehodnotit starší rozhodnutí; nic není definitivní; každé přehodnocení se zapisuje do auditu (kdo/co, staré a nové rozhodnutí, důkaz).
6. **Kalibrace a abstence.** Posteriory se ukládají v soaku (dosud ne). Kalibrace isotonicky při ≥ 1000 případech, jinak Platt; ECE a spolehlivostní diagram. Konformální množina pro zaručené pokrytí; prázdná nebo nejednoznačná množina = „nevím, předat analytikovi“.
7. **Spis případu.** Časová osa, ověřené a neověřené kontroly, proč je případ nerozhodnutý a co by ho rozhodlo (milníky podle Heuera, krok 8). Výstup přes existující API bez zásahu do UI.
8. **Forenzní sběr.** Jen čtecí akce (vyžádání PCAP ring bufferu, triage balíčku z EDR, vyhledání v logu), každá jen po schválení člověka a s auditem. Engine sám nic nespouští.

## 3. Hranice automatizace (co se měří a hlásí)

Pro každý případ: autonomní rozhodnutí (zavřít jako neškodné, potvrdit jako útok), nebo předání člověku s důvodem (chybí telemetrie; hypotézy se nerozliší; cena omylu je vyšší než cena zjištění; chráněný typ; konflikt důkazů; pokrytí konformální množiny není jednoznačné). Hlásí se:

- podíl případů rozhodnutých autonomně a podíl předaných člověku, rozdělený podle důvodu předání;
- u autonomních rozhodnutí **horní mez 95 % Wilson** chyby zvlášť pro omylem zavřený útok a pro omylem eskalovaný neškodný případ;
- závislost na množství dat (počet případů v kalibraci) a na pokrytí telemetrií (bez L7, s L7, s endpointem);
- každé autonomní rozhodnutí nese vysvětlení, důkazy a záznam v auditu. Kde záruku nelze dát, rozhoduje člověk.

Poctivé omezení: záruka konformální predikce je marginální přes případy téhož rozdělení; na jiné síti nebo jiném typu útoku neplatí automaticky, proto se kalibruje po síti a hlásí se zvlášť pro nové rodiny (leave-one-family-out).

## 4. Metriky a prahy (předregistrace je v `impl-krok12.md`, oddíl 5)

## 5. Bezpečnost forenzního sběru

Akce jsou jen čtecí; každá má identifikátor, žadatele, schvalovatele, rozsah (hosté, čas, artefakty) a expiraci; schválení nelze odvodit z dat nálezu (prompt injection: obsah logů se nikdy nepoužije jako příkaz). Provedení mimo scope politiky se odmítne.
