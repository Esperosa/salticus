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
