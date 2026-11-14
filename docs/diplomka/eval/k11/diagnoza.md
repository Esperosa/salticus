# Krok 11: diagnostika zmeškaných útoků po rodinách

Datum 2026-11-14. Svět k10, ladicí seedy 20261102 a 20261103 (80 sítí, 2 × 40), kandidát k9 (`--v3-on breadth`, binárka s diagnostickým měřením, bez změny detekce). Seedy 20261104, 20262301 a 20262302 jsem pro diagnostiku nepoužil (čas); výsledky ostatních ladicích seedů z kroků 9 a 10 (`k9/vysledky.md`) mají stejný obraz. Nástroj: `tools/k11_diag.py` (rozdělení zmeškaných útoků do skupin), data v `F:/Projekty/bakula-soak/k11/d1-*`.

## Co se změnilo v měření (bez dopadu na detekci)

Do záznamu útoku (`networks.jsonl`, pole `diag`) přibyl souhrn toků: počet toků, zdrojů, cílů, portů, selhání, bajtů, nejvíc toků v cyklu, počet cyklů okna, kdy senzor nedodal nic, a **počet toků útoku, které přežily degradaci telemetrie** (`visible_flows`). Bez toho nešlo odlišit „engine nic nevydal“ od „engine nic nedostal“.

## Definice skupin

| skupina | význam |
|---|---|
| a slepé | žádný nález a žádný tok útoku nedorazil do telemetrie (výpadek senzoru, slepá podsíť, ztráta toků): vstup chybí, kategorie c slepých míst |
| a viditelné | žádný nález, ale toky do telemetrie dorazily: chybí signál, nebo je varianta od provozu nerozlišitelná |
| b | nález vznikl, ale nebyl zobrazen (b nezobrazeno) nebo byl zavřený či utišený (b zavřeno) |
| c nepřipsáno | nález vznikl a byl zobrazen, ale kontrafaktuál ho připisuje pozadí (existoval i bez útoku) |
| c typ | útok je zachycen (počítá se jako detekce), ale typ nálezu neodpovídá hodnocení |

Detekce = zobrazený nález, který ve světě bez útoku chybí (kontrafaktuál). Skupiny a až c nepřipsáno jsou zmeškané útoky, c typ ne.

## Tabulka rodina × skupina (80 sítí, k9 kandidát)

| rodina | n | detekce | a slepé | a viditelné | b zavřeno | b nezobrazeno | c nepřipsáno | c typ | detekce z útoků s viditelnými toky |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| c2_beacon | 183 | 166 (90,7) | 1 | 3 | 0 | 7 | 6 | 38 | 91,2 |
| port_scan_horizontal | 147 | 125 (85,0) | 2 | 5 | 0 | 5 | 10 | 10 | 86,2 |
| port_scan_vertical | 167 | 147 (88,0) | 12 | 1 | 0 | 5 | 2 | 5 | 94,8 |
| exploit_attempt | 228 | 204 (89,5) | 3 | 10 | 0 | 9 | 2 | 94 | 90,7 |
| exfiltration | 133 | 124 (93,2) | 3 | 2 | 0 | 2 | 2 | 1 | 95,4 |
| credential_stuffing | 97 | 84 (86,6) | 4 | 0 | 0 | 5 | 4 | 2 | 90,3 |
| cryptomining | 91 | 80 (87,9) | 2 | 5 | 0 | 3 | 1 | 6 | 89,9 |
| drive_by_bulk_download | 35 | 4 (11,4) | 2 | 27 | 0 | 2 | 0 | 4 | 12,1 |
| cloud_api_discovery_burst | 24 | 1 (4,2) | 1 | 12 | 0 | 9 | 1 | 1 | 4,3 |
| dns_zone_enum_burst | 21 | 2 (9,5) | 1 | 13 | 0 | 4 | 1 | 1 | 10,0 |
| bucket_mass_download | 24 | 5 (20,8) | 2 | 13 | 0 | 4 | 0 | 3 | 22,7 |
| clicks_to_rare_destination | 33 | 4 (12,1) | 2 | 15 | 0 | 11 | 1 | 3 | 12,9 |
| exfil_alt_protocol_ftp | 15 | 2 (13,3) | 1 | 9 | 0 | 3 | 0 | 0 | 14,3 |

(Zavřené nálezy: 0 u všech těchto rodin. Poznámka: rodina c2_beacon má na těchto dvou seedech 90,7 %, v agregaci pěti seedů kroků 9 a 10 přes 83,9 %; rozptyl mezi seedy je velký, viz rozptyl v `k9/vysledky.md`.)

## Příčina, navržená oprava a riziko po rodinách

| rodina | hlavní příčina zmeškání | navržená oprava | riziko FP |
|---|---|---|---|
| c2_beacon | jen 4 útoky bez nálezu. Skutečná mezera je nepřipsáno (6) a nezobrazeno (7) při krátkém okně a velkém rozptylu; 38 útoků má typ jiný než `beacon_periodic` (zachycen novostí nebo `unexpected_traffic`). Periodicita a jitter už jsou vstupem `beacon` (min. 12 spojení a rozpětí 1 h), kratší útoky mají méně spojení, než detektor smí hlásit | žádná v tomto kroku: kratší okno než 12 spojení je podle RQ4-014 prázdné skóre; zapsáno do registru jako b/c. Částečně pokrývá `peer_burst` (první vztah s rychlým shlukem) | střední |
| port_scan_horizontal | 22 zmeškaných: 7 bez nálezu (5 s viditelnými toky, medián 5 až 8 neúspěšných pokusů na 1 až 5 cílů, pod `scan_min_targets` = 8), 10 nepřipsáno (nález existoval i bez útoku) | `scan_fresh`: vnější zdroj bez jediného úspěšného spojení v okně, a to už od 4 distinktních cílů místo 8 | střední: vnější šum skenuje také (měřeno) |
| port_scan_vertical | 20 zmeškaných, z toho **12 slepých** (toky nedorazily), viditelná zmeškání 1 | žádná: signál existuje (stovky portů), vstup chybí; zapsáno jako c (potřebný vstup: nepoškozená telemetrie) | - |
| exploit_attempt | 24 zmeškaných: 3 slepé, 10 viditelných bez nálezu (medián 18 toků do jednoho cíle na jeden port, malé bajty, normální stavy SF), 9 nezobrazeno. 94 útoků je zachyceno jen jiným typem (`suricata_alert` ano, jinak `unexpected_traffic`) | žádná: výjimečně vypadající dotazy na jednu službu se z toků bez obsahu (HTTP, TLS) od provozu odlišit nedají; zapsáno jako b/c (potřebný vstup: aplikační záznamy, DNS a TLS) | - |
| exfiltration | 9 zmeškaných, 3 slepé, 2 s viditelnými toky (2 až 3 toky, mnoho GB ale pod sledovaným oknem), 2 nezobrazeno | žádná: rodina je v pásmu 93 % | - |
| credential_stuffing | 13 zmeškaných: 4 slepé, 5 nezobrazeno (nález byl, ale nebyl zobrazen), 4 nepřipsáno | žádná zde (nález existuje, rozhoduje politika zobrazení; změna zobrazování ohrožuje FP) | vysoké |
| cryptomining | 11 zmeškaných: 7 bez nálezu, z toho 5 s viditelnými toky (medián 16 toků na jednoho cíle, 4,6 MB), 3 nezobrazeno | pokryje částečně `bulk_novel` jen u větších přenosů; jinak registr (b) | střední |
| drive_by_bulk_download | 27 z 31 s viditelnými toky, 1 až 4 toky (medián 2), čistý přenos 1 až 4 MB od prvně viděného vnějšího protějšku. Existující prahy (`down_min` 10 MB, `ingest` objemový detektor je vypnutý) to nevidí | `bulk_novel`: čistý přenos ≥ 2 MB na první vztah zralého hostu s protějškem mimo flotilu | vysoké (hn_cdn_update_download, hn_nightly_cloud_backup_upload) |
| bucket_mass_download | 15 bez nálezu: 3 až 12 toků, medián 45 MB stažených od prvně viděného cíle; pod `down_cold` (300 MB) a `down_min` | `bulk_novel` (stejné pravidlo) | vysoké |
| exfil_alt_protocol_ftp | 10 bez nálezu, medián 19 MB nahraných na port 21 vnějšího protějšku (`egress` bere až 50 MB) | `bulk_novel` (směr nahrání) | střední |
| cloud_api_discovery_burst | 13 bez nálezu: 45 až 165 toků na jeden vnější cíl 443 během 4 minut jedním hostem, jeden zdroj | `peer_burst`: ≥ 6 toků do 300 s na první vztah zralého hostu | střední (nová stránka s mnoha spojeními) |
| clicks_to_rare_destination | 17 bez nálezu, 2 až 12 toků na jeden vnější cíl během 4 minut, malé bajty | `peer_burst` (jen část útoků má ≥ 6 toků v jednom okně) | střední |
| dns_zone_enum_burst | 14 bez nálezu: 21 až 159 UDP dotazů na DNS server sítě z jednoho vnějšího zdroje v 4 minutách. Toky jdou ven→dovnitř; vrstva `behavior` dostává jen odchozí a vnitřní toky | žádná v tomto kroku: nový detektor by musel nést vnější zdroj do `behavior` nebo do `anomaly_v3` (první vztah vnějšího zdroje s vnitřní službou). Zapsáno jako (b): vstup (inbound toky ve vrstvě chování) není zapojený | - |

## Závěr diagnostiky

1. Pro velké rodiny (c2_beacon, skeny, exploit, exfiltrace) zbylé zmeškání tvoří hlavně **slepé útoky** (senzor, slepá podsíť, ztráta toků) a typ nálezu, ne chybějící signál. Podíl slepých mezi zmeškanými útoky: c2_beacon 1 z 17, port_scan_horizontal 2 z 22, exploit_attempt 3 z 24, exfiltration 3 z 9, credential_stuffing 4 z 13, port_scan_vertical 12 z 20. Obecný detektor to nespraví, protože vstup chybí.
2. U stealth rodin je skutečná chybějící vlastnost jednotná a abstraktní: **první vztah zralého hostu s vnějším protějškem, který je hned nápadný** (velký čistý přenos, nebo rychlý shluk toků). Pro ni jsou přepínače `bulk_novel` a `peer_burst` (impl-krok11.md). Pro vnější sken s několika cíli je `scan_fresh`.
3. `dns_zone_enum_burst` a část `exploit_attempt` a `c2_beacon` nejde rozumně opravit v tokové vrstvě bez dalších vstupů (inbound toky ve vrstvě chování, DNS a TLS záznamy).
