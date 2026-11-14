# Studie 12: telemetrie šifrovaného provozu a politika zavírání poplachů

Datum 2026-11-14. Stav: první verze psaná z paměti, **dne 2026-11-14 ověřena stažením primárních stránek (oddíl 7)**. Co se ověřit nepodařilo, je označeno „ověřit“.

## 1. Proč krok 11 selhal (kvantitativně)

Z kroku 11 (držené seedy, `k11/held-A.md`, 240 sítí): rodiny po šifrovaném portu (bucket_mass_download 6,7 %, cloud_api_discovery_burst 13,6 %, clicks_to_rare_destination 9,5 %) se z toků bez obsahu rozlišit od neškodných hn_* nedaly (tvar toků stejný, 70 % neškodných zobrazeno při zapnutí `bulk_novel` a `peer_burst`). Příčina je vstupní, ne prahová: model pozorování nese jen pět čísel toku (konce, port, bajty, doba, stav). Profesionální nástroje rozlišují právě podle polí, která model nemá.

## 2. Co používají profesionální nástroje

Zdroje (domovské dokumentace): Zeek (zeek.org, logy `conn`, `ssl`, `x509`, `dns`, `http`, `files`, `notice`, `weird`), Suricata EVE JSON (docs.suricata.io, události `flow`, `tls`, `dns`, `http`, `fileinfo`, `anomaly`, `alert`), RITA (github.com/activecm/rita, beaconing, dlouhá spojení, DNS tunelování, rarita), Arkime (arkime.com), Security Onion (securityonion.net), Corelight (corelight.com, rozšíření Zeeku), Wazuh (wazuh.com), MITRE ATT&CK Data Sources a Sigma (github.com/SigmaHQ/sigma), JA3 (github.com/salesforce/ja3) a JA4+ (github.com/FoxIO-LLC/ja4).

### 2.1 Šifrované hromadné stažení a shluk toků na nový cíl

| vlastnost | zdroj pole | co rozlišuje |
|---|---|---|
| SNI (jméno serveru) | Zeek `ssl.server_name`, EVE `tls.sni` | rarita jména v rámci sítě a v historii hosta; neškodné stažení míří na jména, která zná víc hostů (CDN, aktualizace), útok na jméno, které nezná nikdo |
| JA3/JA4 klienta | `ssl.ja3` / `tls.ja3`, JA4 | otisk klientského softwaru; nový otisk na hostu (nová aplikace) nebo otisk, který na síti vidí jediný host |
| certifikát | Zeek `x509` (stáří, vydavatel, self-signed, SAN), EVE `tls.notbefore`/`notafter`/`issuerdn` | čerstvý nebo self-signed certifikát, certifikát bez shody SNI a SAN |
| ALPN | `ssl.next_protocol` | typ aplikace (h2, http/1.1, vlastní) |
| velikost a směr | `conn.orig_bytes`/`resp_bytes`, `files.log` | stažení (resp >> orig) a nahrání (orig >> resp) v poměru ke zvyku hosta |
| rarita cíle | odvozené: počet hostů, které cíl znají; stáří prvního výskytu | „první vztah“ je jen vstup; rozhodující je, zda cíl zná flotila |
| DNS předcházející spojení | `dns.log` | spojení bez předchozího DNS dotazu (přímá IP) je silný rys; stáří a rarita domény |

Co z toho nástroje samy dělají: RITA a Corelight skórují beaconing a rarity ze statistik na dvojici a z SNI; Suricata a Zeek jen dodávají pole, o poplachu rozhodují pravidla (ET, Sigma) a analytik. Rozdíl je v tom, že rozhodnutí je vždy kombinace aspoň dvou nezávislých polí, nikdy jen port. (ověřit: konkrétní prahy RITA v aktuální verzi.)

### 2.2 DNS

| rys | pole | použití |
|---|---|---|
| typ dotazu | `dns.qtype_name` (AXFR, IXFR, ANY, TXT) | AXFR/IXFR od vnějšího zdroje na vnitřní DNS je zone transfer pokus; ANY je zesilování |
| počet unikátních jmen na zdroj a okno | agregace `qname` | výčet zóny; tunel |
| poměr NXDOMAIN | `dns.rcode_name` | výčet jmen, DGA |
| entropie a délka jména, délka subdomény | `qname` | tunel (DoH i klasický); práh se kalibruje na veřejných datech |
| objem TXT odpovědí | `qtype`, `answers`, velikost | tunel, C2 přes TXT |
| periodicita | časy dotazů na jméno | beacon přes DNS |

### 2.3 Skeny, beacon, HTTP

Skeny: poměr neúspěšných pokusů a distinktní cíle (už v enginu); doplnění: vnější zdroj, který nikdy nenavázal úspěšné spojení. HTTP (Zeek `http.log`, EVE `http`): metoda, `user_agent`, `host`, `uri` délka, velikost těla; vzácný nebo prázdný user agent a přímé IP v hlavičce Host jsou klasické rysy. Beacon: periodicita a jitter (už v enginu), doplnění: stejný JA3 a SNI v celé řadě spojení a malé, stejně velké odpovědi.

## 3. Jak SOC zavírá poplachy (zásady pro politiku zavírání)

1. Zavření stojí na **pozitivním důkazu neškodnosti**, ne na absenci důkazu o škodlivosti. Důkaz má podobu záznamu: allowlist položka (vlastník, důvod, expirace, rozsah hostů a cílů), schválený změnový požadavek s oknem, nebo ověřený tok zálohy či aktualizace podle cíle (SNI, certifikát vydavatele) a podpisu.
2. Zavření je **úzké**: platí jen pro hosty a cíle uvedené v záznamu, jen v okně a jen pro uvedený typ nálezu. Souběh se skutečným útokem na jiném hostu nebo cíli se nezavírá (příčina většiny omylů v kroku 11, viz oddíl 4).
3. Každé zavření se loguje (kdo, proč, jaký záznam, jaký důkaz), vzorek se kontroluje člověkem a záznam vyprší.
4. Co je pod hladinou důkazu, se **nezavírá, ale může být řazeno níž**; nikdy se neztratí.
5. Pokles pokrytí (výpadek senzoru, slepá podsíť) je samostatný, viditelný nález, ne ticho.

## 4. Rozbor příčin 0,7 % omylem zavřených (kontrola dat)

Zdroj: držené seedy kroku 11, rameno A, 20 870 útoků s toky, 148 s omylem zavřeným nálezem. Důvody zavření (součet `auto_closures_wrong_by_reason`): **`authorized_scanner` 84, `patch_window` 5, `backup` 1**. Tedy téměř vše (93 % z důvodů uvedených v záznamu) je jediné pravidlo: kontext „autorizovaný skener“ zavřel nález typů `scan_attempts`, `unexpected_traffic`, `connection_timeout_burst` a `unmapped_passive_event`, zatímco se ve stejném okně dělo něco, co skener nebylo (slow_scan, lateral_movement, c2_beacon, dns_tunnel, ransomware). Rozbor po rodinách útoku, jejichž nález byl zavřen: slow_scan 13, lateral_movement 11, share_encryption_wave_slow 11, dns_partial_failure 9, ransomware 7, dns_tunnel 6.

Hypotéza příčiny (z kódu `context_gate.rs`, ověřit měřením): záznam skeneru je platný pro celé okno a pro typy nálezů, a kontrola zdroje (`source_sensitive`) se u `AuthorizedScanner` uplatní jen pokud nález nese zdroj; nález bez identifikovaného zdroje nebo s více zdroji, z nichž jeden je skener, projde. Oprava (předregistrovaná, kapitola G v `impl-krok12.md`): zavřít jen když **všechny** zdroje nálezu patří záznamu a nález má identifikovaný zdroj a cíl v rozsahu záznamu; jinak nález zůstane zobrazen s poznámkou „kontext částečně odpovídá“.

Poctivé omezení: 0 omylem zavřených v měření není záruka nuly. Při 0 z N je horní mez Wilson 95 % přibližně 3,7/N (pro N = 20 000 asi 0,019 %).

## 5. Co z toho plyne pro návrh (shrnutí)

Vstupy (normalizované záznamy `tls`, `dns`, `http` a příznak směru toku), ne prahy. Detektory kombinují aspoň dva nezávislé rysy (rarita jména v síti + poměr směrů, nebo nový JA3 + čerstvý certifikát). Neškodné scénáře v simulaci musí mít realistická pole (CDN a aktualizace: široce sdílená jména, platné certifikáty velkých vydavatelů; záloha: stabilní jméno cloudu s historií hosta), aby je od útoku nerozlišoval port. Zavírání jen na pozitivní důkaz.

## 6. Otevřené (pro další kolo)

Stažení a citace primárních zdrojů; ověření prahů RITA; veřejné datasety s TLS a DNS poli (licence, velikost), kalibrace rozdělení; přehrání jednoho reálného datasetu celou cestou.

## 7. Ověření proti primárním zdrojům (staženo 2026-11-14)

| tvrzení | zdroj (URL) | výsledek |
|---|---|---|
| Zeek `ssl.log`: `server_name`, `next_protocol`, `version`, `cipher`, `resumed`, `established`, `cert_chain_fuids`, `subject`, `issuer`; `ja3`/`ja3s` jen s nainstalovanými balíčky JA3/JA3S | https://docs.zeek.org/en/master/logs/ssl.html | potvrzeno. **Oprava textu:** pole `validation_status` na této stránce není; stránka nespecifikuje verzi (odkazuje na větev master). Stáří a vydavatel certifikátu se čtou z `x509.log` přes `cert_chain_fuids` |
| Zeek `x509.log`: `certificate.not_valid_before`, `not_valid_after`, `issuer`, `subject`, `san.dns`, `basic_constraints.ca` | https://docs.zeek.org/en/master/logs/x509.html | potvrzeno. **Oprava:** příznak self-signed se nelogguje; self-signed se musí odvodit (subject = issuer), je to moje odvození, ne pole Zeeku |
| Zeek `dns.log`: `query`, `qtype_name`, `rcode_name`, `answers`, `TTLs`, `rejected`, `rtt`, `AA/TC/RD/RA` | https://docs.zeek.org/en/master/logs/dns.html | potvrzeno (verze nestanovena) |
| Suricata EVE: typy `alert`, `anomaly`, `fileinfo`, `http`, `flow`, `dns`, `tls` a další; `tls`: `sni`, `version`, `notbefore`, `notafter`, `issuerdn`, `subject`, `fingerprint`, `ja3`, `ja3s`, `ja4`, `client_alpns`, `server_alpns` (JA3/JA4 je třeba zapnout v konfiguraci); `dns`: `rrname`, `rrtype`, `rcode`, `answers` (verze 3 formátu výchozí, od Suricaty 8.0); `http`: `hostname`, `url`, `http_user_agent`, `length`; `fileinfo`: `size`, `sha256`, `magic`; `anomaly`: `type`, `event`, `layer` | https://docs.suricata.io/en/latest/output/eve/eve-json-format.html | potvrzeno; stránka odpovídá řadě Suricata 8.x. **Důsledek pro parser:** DNS v EVE má dvě podoby (starší jedna otázka na událost a novější `queries`/`answers` pole), parser musí umět obě; JA3/JA4 nemusí být v logu přítomné |
| JA3: MD5 z pěti polí ClientHello (verze, šifry, rozšíření, křivky, formáty bodů), GREASE se ignoruje; licence BSD-3-Clause; projekt Salesforce nadále neudržován, repozitář archivován 2025-05-01 | https://github.com/salesforce/ja3 | potvrzeno. **Důsledek:** JA3 je zastaralý a odolný vůči randomizaci rozšíření jen omezeně (z tohoto zdroje neplyne, ověřit); použít spolu s JA4 |
| JA4+: JA4 (TLS klient), JA4S, JA4H (HTTP), JA4X (X.509), JA4L/LS (latence), JA4SSH, JA4T/TS (TCP) | https://github.com/FoxIO-LLC/ja4 (technical_details/README) | potvrzeno rozsah; **licence JA4+ jsou jiné než BSD pro JA4 samotné a v tomto kole se nečetla repo-licence (ověřit před použitím jiných než JA4 v kódu)**. Znaky JA4 jsou ochranné známky FoxIO |
| RITA: beaconing, dlouhá spojení, DNS tunelování, threat intel nad Zeek logy (TSV, JSON) | https://github.com/activecm/rita | potvrzeno. **Oprava:** domovská stránka **žádné prahy ani váhy skóre neuvádí**; moje dřívější „ověřit prahy RITA“ zůstává otevřené a v textu práce se prahy RITA necitují |

Neověřeno (zůstává „ověřit“): konkrétní doporučení pro zavírání poplachů v SOC (oddíl 3 je moje syntéza obecných principů, ne citace; kandidáti zdrojů: NIST SP 800-61, MITRE ATT&CK Data Sources, dokumentace Security Onion); Corelight, Arkime, Wazuh a Sigma jsem v tomto kole nestahoval.
