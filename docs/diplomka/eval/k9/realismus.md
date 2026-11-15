# Realismus simulace: co je kalibrováno a co není

Stav k 2026-11-14, svět `--coverage k9`. Texty popisují, co simulace dělá, ne co dokazuje.

## Co simulace obsahuje

- Neškodný provoz s denním a týdenním vzorem, svátky, pravidelnými vzory (aktualizace, CDN streamování, synchronizace, zálohy, monitoring), různými archetypy sítí (SOHO, SMB, podnik, kampus, datové centrum, nemocnice, IoT, cloud, metro, průmysl) a třídami velikosti až XXXL.
- Neškodné události a poruchy: záloha, autorizovaný skener, flash crowd, aktualizace, NTP, pád služby, výpadek linky, onboarding a vyřazení zařízení, patchovací okno, dávka, zpoždění sběru, výpadek senzoru, poškozené logy, výpadek DNS, přečíslování DHCP, kolísání linky, chybná konfigurace, selhaná záloha, vypršený certifikát, výpadek napájení podsítě, hromadné připojení VPN, migrace do cloudu, nasazení SaaS (rodiny kroku 5 až 8).
- Krok 9: 100+ parametrických variant útoků a poruch (tabulka `variants::SPECS`), s ID techniky ATT&CK, kategorií a očekávanými typy nálezů; provozní poruchy zahrnují selhání DHCP, DNS, NTP, drift času, duplicitní IP, broadcast storm, zaplnění linky, degradaci latence, kaskádu, flapping, plánované okno vs. neplánovaný výpadek.

## Kalibrace na veřejných datech

Kvantitativní kalibrace simulace na veřejných datech zatím provedena není. Parametry generátoru (rozdělení objemů, trvání, tempa) jsou volba autora v řádu typických hodnot; porovnání rozdělení s CIC-IDS2017, CTU-13, IoT-23, CSE-CIC-IDS2018 a LUFlow je otevřený úkol (kategorie c). Veřejné datasety se zatím používají jako samostatné přehrání celou produkční cestou (kapitola datasety v `impl-krok9.md`), ne jako zdroj parametrů. Labely datasetů se nemíchají do jednoho schématu: každý dataset má vlastní adaptér a vlastní vyhodnocení.

## Kde simulace NENÍ realistická

1. **Bez obsahu.** Generátor nevyrábí DNS dotazy, TLS handshaky (SNI, JA3), hlavičky HTTP ani logy cloudových služeb. Proto varianty, které se od legitimního provozu liší jen obsahem (DNS tunel s pomalým tempem, `c2_dns_txt_beacon`, exfiltrace přes DNS, přístup k cloudovému úložišti, drive-by stažení, kliknutí na vzácný cíl), jsou na úrovni toků principiálně nerozlišitelné od provozu běžného klienta. Výsledek u těchto variant neříká nic o tom, jak by je zachytila detekce nad DNS a TLS záznamy.
2. **Závislost mezi hosty.** Generované toky jsou nezávislé po cyklech; skutečná síť má dlouhé korelace (jeden uživatel, jedna aplikace, sdílený cíl). Pravidelné vzory benigního provozu mají mnohem menší rozptyl než skutečné aplikace.
3. **Dlouhý ocas služeb a CDN churn.** Počet různých cílů hostů je malý proti realitě (desítky tisíc domén), takže „novost vazby“ je v simulaci silnější signál než ve skutečné síti. Odhad falešných poplachů z novosti je proto nejspíš optimistický.
4. **Sezónnost a drift.** Týdenní a svátkový vzor jsou, měsíční a roční (uzávěrky, prázdniny, akademický rok) nejsou. Drift chování zařízení (aktualizace firmware, změna aplikací) je jen nahodilý.
5. **Útočník.** Varianty jsou statické vzory; útočník nereaguje na detekci (kromě rozprostření v čase a maskování v tabulce), nemění taktiku a nepoužívá nové infrastruktury během kampaně.
6. **Telemetrie.** Výpadky senzoru, ztráty a duplicity jsou parametrické; skutečné chyby (asymetrické směrování, NAT, vzorkování SPAN, zpožděné toky) jsou zastoupeny jen částečně.
7. **Koncová telemetrie** (`endpoint`) je odvozená z týchž rodin jako provoz, takže přínos je nadhodnocený; skutečné záznamy Sysmon a Wazuh slouží jen k testům parserů.
8. **Chyby datasetů.** U veřejných datasetů jsou známé problémy štítků a nástrojů (Engelen a kol. o CIC-IDS2017); replay datasetů je proto vedlejší důkaz a neslouží k ladění.

## Krok 12: metadata TLS a DNS v simulaci (`soak/l7sim.rs`), co sedí a co ne

Stav 2026-11-15. **Žádná z hodnot níže není kalibrována na veřejných datech.** Jsou to autorovy předpoklady z dokumentace nástrojů (studie 12, oddíl 7) a z obecné zkušenosti; kvantitativní porovnání s PCAP daty (CTU-13, Stratosphere, CIC) nebylo provedeno, protože na stroji není Zeek a PCAPy se nestahovaly (viz `k12/prehrani-luflow.md`).

| prvek | předpoklad v simulaci | ověřeno na datech |
|---|---|---|
| otisk klienta (JA4) neškodného hosta | 3 stabilní otisky na host z množiny 4 | ne |
| cíle TLS pozadí | 55 % dlouhý chvost (3 000 jmen, Zipf), jinak 24 sdílených populárních jmen | ne |
| neškodné změny (záloha, aktualizace, pošta) | sdílené populární jméno, otisk hosta, starý certifikát | ne |
| útok | 30 % populární jméno, 75 % nástrojový otisk (mimo masking), 2/3 čerstvý nebo self-signed certifikát u vzácného jména | ne |
| DNS pozadí | NXDOMAIN 5 %, 4 % dlouhé hashované značky typu A (CDN), 2 % TXT na běžných jménech | ne |
| DNS útok | výčet zóny: jména po řadě, NXDOMAIN 55 %, 10 % ANY, 5 % AXFR; tunel: značka 20 až 40 znaků, TXT | ne |

Důsledek: detekce nad `--l7` světem (bucket_mass_download, cloud_api_discovery_burst, dns_zone_enum_burst a další) ukazuje, že **logika detektorů funguje nad metadaty s těmito vlastnostmi**; nic neříká o skutečné četnosti útočníků s novým nástrojovým otiskem nebo čerstvým certifikátem. Zejména „75 % nástrojový otisk“ je přímo to, co detektor využívá, a je to moje volba.

### Krok 12, první měření na reálném provozu (CTU-Normal-20, Zeek v dockeru)

Zdroj: `CTU-Normal-20/2017-04-30_win-normal.pcap` (282 MB, jeden normálně používaný Windows hostitel 10.0.2.15, 3,1 h), stažen z `mcfp.felk.cvut.cz/publicDatasets`, zpracován `zeek -C -r` (docker zeek/zeek). Jde o **jednoho hostitele a tři hodiny**, takže čísla níže jsou první kvantitativní bod, ne kalibrace rozdělení.

| veličina | reálně (CTU-Normal-20) | simulace | verdikt |
|---|---|---|---|
| DNS dotazy typu A / AAAA | 75,4 % / 24,5 % | A téměř vše, AAAA nemodelováno | rozdíl: sim nemá AAAA |
| NXDOMAIN z odpovědí | 0,013 % | 5 % pozadí | **sim ~400× víc**; jeden host s čistou konfigurací, korporátní sítě mívají víc; potřebuje další zachycení |
| TXT a NULL dotazy | 0 % | 2 % pozadí (pošta) | sim víc; reálný hostitel nemá poštu ani tunel |
| jména s první značkou ≥ 24 znaků a entropií ≥ 3 bity | 4,1 % ze 1 142 různých jmen (CDN, hashovaná jména) | 4 % řádků | **sedí řádově**; proto tunelové pravidlo vyžaduje i typ TXT/NULL |
| TLS bez SNI | 1,5 % spojení | nemodelováno u pozadí | detektor má bez SNI jako rys; na pozadí vzácné |
| nové SNI po první hodině (podíl spojení) | **13,4 %** | pozadí: 55 % dlouhý chvost, ale cíl se hostu opakuje | reálný host se k novým jménům dostává často, samotná novost cíle proto nemůže být poplach (detektor dále vyžaduje objem nebo dávku a druhý rys) |
| x509 vlastnoručně podepsané | 3,0 % | útok 1/3, pozadí 0 | pozadí v sim je čistší než realita |
| x509 mladší než 30 dní | 100 % (nespolehlivé: časy zachycení u tohoto pcapu nejspíš neodpovídají datu certifikátu) | pozadí 0 % | **neověřeno**, pole `young` z tohoto zdroje nepoužít |

**Zjištění o formátu:** aktuální Zeek (docker `latest`) v `ssl.log` neuvádí `cert_chain_fuids` jako dokumentace ověřená ve studii 12, ale `cert_chain_fps` a `x509.log` má `fingerprint` bez `id`; parser to dřív nespojil. Opraveno a pokryto testem nad skutečnými logy (`l7::tests::real_zeek_logs_parse_and_join_certificates`).

**Co z toho plyne:** simulace nadhodnocuje NXDOMAIN a TXT na pozadí, podhodnocuje podíl self-signed certifikátů a nemodeluje AAAA. Změna těchto parametrů bez dalších zachycení (jiné sítě, servery, IoT) by byla ladění na jednom hostiteli, proto jsem ji **neprovedl**; výsledky `--l7` zůstávají s výhradou z úvodu této sekce. DoH, DNS tunel a škodlivé CTU/Stratosphere pcapy jsem nestahoval ani nezpracoval.
