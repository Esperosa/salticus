# Implementace, krok 11: cílené opravy detekce po rodinách

Datum 2026-11-14. Navazuje na kroky 9 a 10. Diagnostika: `k11/diagnoza.md`. Projekt: Salticus.

Poctivost o pořadí: tato předregistrace vznikla poté, co byly napsány přepínače a spuštěno první ladicí měření kandidáta (`c1`, seedy 20261102 a 20261103), ale **dříve, než jsem viděl jeho výsledky**. Prahy detektorů (níže) jsou hodnoty z návrhu, nebyly dosud upraveny. Jakákoli změna prahu po tomto zápisu se píše do sekce „Odchylky“ i s důvodem. Držené seedy se nespustily.

## A) Co se opravuje (každá oprava za vlastním přepínačem, výchozí vypnuto)

| přepínač | vlastnost (abstraktní, bez rodiny, seedu a adresy) | cílové rodiny | práh (návrh) |
|---|---|---|---|
| `bulk_novel` (`novel_bulk_transfer`) | zralý vnitřní host (≥ 12 h v profilu) má první vztah s vnějším protějškem, který profil nezná ani jako kandidáta a který nezná flotila (≤ 2 vnitřní hosté za 7 dní), a čistý přenos (stažení nebo nahrání) v prvním okně je ≥ 2 MB | drive_by_bulk_download, bucket_mass_download, exfil_alt_protocol_ftp | 2,0 MB |
| `peer_burst` (`novel_peer_burst`) | totéž první-vztah pravidlo, ale ≥ 6 toků do 300 s | cloud_api_discovery_burst, clicks_to_rare_destination | 6 toků / 300 s |
| `scan_fresh` (`scan_attempts`) | vnější zdroj (není ve vnitřním inventáři) bez jediného úspěšného spojení v okně, a 4 distinktní cíle za 24 h místo 8 | port_scan_horizontal | 4 cíle |

Nové typy nálezů `novel_bulk_transfer` a `novel_peer_burst` se řadí k novosti: nikdy se automaticky nezavírají (stejná ochrana jako `novel_persistent_peer`), kontext je nevysvětlí. Signály vycházejí z toků, které engine už má (odchozí toky vrstvy chování, profil hostu, prevalence cíle, neúspěšné pokusy zdroje). Žádný seed ani adresa v kódu (ověřuje `no_memory`).

## B) Co se neopravuje (a proč), do registru slepých míst

- `dns_zone_enum_burst`: provoz jde ven→dovnitř, vrstva chování inbound toky nedostává. Vstup (inbound toky ve vrstvě chování) chybí: kategorie b.
- `port_scan_vertical`, `credential_stuffing`, `exfiltration`, `c2_beacon`, `exploit_attempt`: většina zbylého zmeškání je slepá (výpadek senzoru, slepá podsíť) nebo typ nálezu; zapsáno jako c (potřebná nepoškozená telemetrie, u exploitu aplikační záznamy, DNS a TLS).
- Krátké beacony (< 12 spojení): RQ4-014, skóre je prázdné; kategorie c.

## C) Prahy (předregistrované, hodnoty se po prvním měření nemění)

| práh | definice | splněno, když |
|---|---|---|
| K11-1 | detekce každé opravené rodiny na držených seedech | ≥ 90 % a dolní mez Wilsona ≥ 85 % tam, kde n ≥ 50; jinak se uvede detekce a „nedostatek dat“. Nesplněné rodiny jdou do registru |
| K11-2 | zobrazené FP na síť-den, kandidát proti základu na stejných seedech (svět k10) | poměr ≤ 1,15 (celkem), a zvlášť neškodné změny hn_* nesmí zvýšit zobrazení víc než o 10 p. b. |
| K11-3 | útoky s omylem zavřeným nálezem | ≤ 2,2 % |
| K11-4 | chráněná automatická zavření | 0 |
| K11-5 | paniky a porušené invarianty | 0 |
| K11-6 | determinismus | stejný seed, stejný výsledek (test epizody) |
| K11-7 | zákaz paměti | `no_memory` zelený |
| K11-8 | generalizace (LOFO) | viz E |

Základ = stejná binárka bez nových přepínačů a bez `breadth` (preset `recommended`, ekvivalent k8ref). Kandidát = `breadth` plus nové přepínače. Dopad samotného `breadth` je znám z kroku 10 (poměr FP 1,048), a proto se u kandidáta uvádí i rameno „jen `breadth`“ (`d1`) na stejných seedech, aby bylo vidět přírůstek nových přepínačů.

## D) Seedy

- Ladění: 20261102 a 20261103 (diagnostika a první kandidát), případně 20261104, 20262301 a 20262302 pro potvrzení ladění (kroky 9 a 10 je používají).
- **Nové držené seedy** (nikdo je nepoužil, pustí se jednou na konci, základ a kandidát, svět k10, 40 sítí každý): **20263101, 20263102, 20263201, 20263202, 20263301, 20263302**.
- Kontrola, že tyto seedy nejsou v kódu ani v dřívějších řadách: `grep` v `src` a v `F:/Projekty/bakula-soak`.

## E) Leave-one-family-out pro nové detektory

Prahy se nefitují na rodinu: jsou zvoleny z úvahy o vlastnosti (2 MB čistého přenosu, 6 toků do 5 minut, 4 cíle). LOFO se proto vyhodnotí takto: (1) detekce rodin, **pro které detektor nebyl určen** (exfil_cloud_storage_upload, insider_after_hours_cloud_sync, data_staging_smb_internal, mail_forward_smtp_exfil, c2_cloud_storage_dead_drop, c2_https_legit_service a další) základ proti kandidátovi na držených seedech: kladný přírůstek ukazuje, že vlastnost se přenáší; (2) tabulka přírůstku po rodinách, aby bylo vidět, kdo se zhoršil. Přiznané omezení: prahy jsem volil po prohlédnutí tabulky diagnostiky, takže cílové rodiny nejsou nezávislé; nezávislé jsou jen rodiny mimo cíl a držené seedy.

## F) Pořadí měření

Jedno rameno najednou, Idle priorita, 6 vláken, PID 118652 se nedotýká (viz priority: Idle). Ladění: `kb` (základ) a `c1` (kandidát všechny tři přepínače) na 20261102 a 20261103; podle výsledku případné jednotlivé přepínače po jednom. Držené seedy až na konci, jednou.

## G) Odchylky a poznámky

(zapisuje se průběžně)

### G1) Odchylky po prvním ladicím měření (zapsáno před spuštěním držených seedů)

Ladění na 20261102 a 20261103 (základ `kb`, kandidát `c1` se všemi třemi přepínači), potom izolace na 20261102 (`cb`, `cp`, `cn`). Prahy detektorů (2 MB, 6 toků / 300 s, 4 cíle) se **nezměnily**. Změnil se tvar oprav:

1. **Přibyl přepínač `bulk_clear`** (`novel_bulk_transfer` jen pro přenos po nešifrovaných portech 21, 23, 25, 80, 8080). Důvod: `bulk_novel` (všechny porty) zobrazil i hard-negative hn_cdn_update_download (11,5 → 73,4 %) a hn_nightly_cloud_backup_upload (60,5 → 86,4 %), tedy poměr ≈ 2 neškodné ku 1 útoku; po šifrovaných portech je stažení z nového CDN od nového bucketu v tokách nerozlišitelné. Nešifrovaný objemový přenos na první vztah je abstraktní rys (ne rodina), ale zvolil jsem ho po pohledu na hn_* výsledky, takže hn_* nejsou u tohoto rozhodnutí nezávislé.
2. **`scan_fresh` nepomohl** na ladicích seedech (port_scan_horizontal +2,0 p. b. v kandidátu c1 se vším, v izolaci `cb` 0, a `scan_fresh` v `cb` není zapnut; v `c1` je zapnut a rozdíl +2,0 p. b. patří i ostatním přepínačům). Do držených seedů ho jako samostatnou opravu nenesu.
3. **`peer_burst` zobrazil hn_mail_newsletter_burst** (5,1 → 66,1 %) výměnou za cloud_api_discovery_burst (7,7 → 61,5 %). Rozlišit je jde jen portem (587 proti 443), což by bylo ladění na hard-negative scénář; neprovádím.

Kandidáti na držených seedech: **A = `breadth` + `bulk_clear`** (hlavní kandidát), **B = `breadth` + `bulk_novel` + `peer_burst` + `scan_fresh`** (agresivní, kvůli záznamu trade-offu). Základ = bez nových přepínačů a bez `breadth` (preset `recommended`). Pořadí běhů: základ na všech šesti seedech, potom A, potom B; vždy jedno rameno.
