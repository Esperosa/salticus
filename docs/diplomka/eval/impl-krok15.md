# Krok 15: forenzní analýza příčin selhání jádra (kroky 9 až 14) a oprava kořenových příčin

Datum zahájení 2026-11-16. Výchozí stav: konec kroku 14 (commit `02d3055`), engine `v3`, konfigurace `final` = `recommended()` + `breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate`. Zadání: `F:\claude-tmp\briefs\krok15-forenzni-analyza.txt`. Nic z kroku 15 není v `recommended()`; každá oprava je za vlastním přepínačem `V3Features`, výchozí vypnuto, s regresním testem, který bez opravy padá.

Metoda: ne ladění prahů, ale rekonstrukce jednotlivých případů. Soak dostal forenzní stopu (`K15_TRACE=soubor`): jedna JSON řádka na nález a cyklus (klíč paměti, stav položky, zdroje, dispozice, zda ho pohltil vyvrácený klíč, které pravdy zmiňuje), na rozhodnutí žebříku (kroky, důvod, pravda) a na pravdu (okno, adresy, toky a bajty po cyklech). Jedna síť se přehrává sama (`--block-size 1 --block-offset <id> --max-networks 1`); přehrání je bajtově shodné s původním během kroku 14 (ověřeno na 4 sítích: stejné počty zobrazených nálezů, FP, vyvrácení i stejné výsledky všech útoků).

## Předregistrace (zapsáno před měřením kandidátů)

Protokol kroku 13 beze změny (párově podle `run_seed` a `network_id`, bootstrap po sítích stratifikovaný seed x konfigurace, B = 2000, Wilson doplňkově). Základ = běhy kroku 14 (`off`, `elying`, `ops`, `opsnoise`, `opsdrop60`, `mixops`), které se nepouští znovu: binárka kroku 15 bez nových přepínačů dává bajtově stejný výstup jako `k14n` (ověřeno přehráním 4 sítí, viz výše).

- Ladicí seedy (smí se ladit): 20261102, 20261103, 20266101, 20266105, 20266106 (5 seedů kroku 14, 8 sítí na seed, 3 konfigurace).
- **Nové držené seedy kroku 15 (zapsáno dopředu, použít jednou, nikdy nepoužity):** 20268101, 20268102, 20268201, 20268202, 20268301, 20268302, 20268401, 20268402, 20268501, 20268502.
- Ramena kandidátů (všechna nad `final`): `k15` = `refute_episode` + `upload_horizon` (proti `off`); `k15a` = jen `refute_episode`, `k15b` = jen `upload_horizon` (LOFO); `k15e` = `elying` + `endpoint_weak` + `refute_episode` (proti `elying`); `k15ops` = `ops` + `ops_symptoms` + `ops_blast` + `refute_episode` + `upload_horizon` (proti `ops`), `k15opsA` (jen `ops_symptoms`), `k15opsB` (jen `ops_blast`); `k15noise` (proti `opsnoise`), `k15drop60` (proti `opsdrop60`), `k15mix` (proti `mixops`).
- Běhy: Idle, maska 0x3FFFFC, nejvýš 8 vláken celkem, `CARGO_TARGET_DIR=F:/claude-tmp/target-k15`, binárky `F:\claude-tmp\k15\bin`, výstupy `F:\Projekty\bakula-soak\k15\{tune,held}`.
- Po prvním měřicím běhu na ladicích seedech se změna kódu zapíše jako odchylka; na držených seedech se po měření nic nemění.

| práh | definice | splněno, když |
|---|---|---|
| K15-1 | útoky s omylem zavřeným nálezem (A4 kroku 14), všechna ramena včetně `k15e` (lhoucí agent) | 0 pozorováno; hlásí se horní mez Wilson 95 %; `k15e` ≤ `elying` − 4 (čtyři případy sítě 7 seedu 20267401 se nesmí opakovat na ladicích seedech ve stejném mechanismu) |
| K15-2 | detekce bezpečnostních útoků, `k15` − `off` | ≥ 0 p. b. (dolní mez ≥ −0,5); po rodinách hlášeno, cíl `exfil_cloud_storage_upload` ≥ +10 p. b. |
| K15-3 | zobrazené FP na síť-den, `k15` / `off` | ≤ 1,10 |
| K15-4 | C4 kroku 14 (útok maskovaný jako porucha), `k15ops` | ≤ 5 % nálezů (`ops`: 10,0 % držené, 8,3 % ladicí); `k15noise` ≤ 8 % (`opsnoise` 16,5 %) |
| K15-5 | C5 kroku 14 (porucha maskovaná jako útok), `k15ops` | ≤ 10 % (`ops`: 14,4 %) |
| K15-6 | C1 (třída poruchy) a C2 (`catalog_id`), `k15ops` | C1 ≥ 85 % (80,3), C2 ≥ 70 % (60,5; strop daný dvojicemi typů bez rozlišujícího signálu, viz tabulka příčin) |
| K15-7 | C8 čistota incidentů `k15mix` | ≥ `mixops` (82,6 %), hlásí se |
| K15-8 | determinismus a regrese | bez nových přepínačů bajtově beze změny proti `k14n`; `cargo test --lib` bez nových selhání (mimo `broker::*` bez Redis); golden snapshot zelený |

Rozhodnutí o zapnutí do `recommended()`: jen přepínač, který na držených seedech splní svůj práh a LOFO neukáže záporný příspěvek. Jinak zůstává volitelný.

## P1: omylem zavřené útoky, rekonstrukce po případech

### Případ 1: `app_layer_flood_api`, seed 20267402, síť 5 (Smb M, 30 dní), základ `off` a všech 11 ramen

Z forenzní stopy (`F:\claude-tmp\k15\trace\off-402-n5.trace.jsonl`):

| cyklus | co engine viděl | co rozhodl |
|---|---|---|
| 175 až 814 | klíč `asset:35|connection_timeout_burst|tcp/443` (host 10.0.12.93) opakovaně vzniká při neškodných událostech (FlashCrowd, ServiceCrash, SegmentPowerLoss, PatchWindow), vždy bez dominantního zdroje (`sources: []`) | zobrazeno, eskalováno žebříkem (nevyvráceno) |
| 926 | tentýž klíč při `SegmentPowerLoss` (169), závažnost Medium; žebřík: historie „stejný jev už 2 dny ve stejné hodině“ (LR 0,25, skupina 3) + živost „služba neodpovídá ani kontrole, bez dominantního zdroje: výpadek“ (LR 0,15, skupina 2, silná); posterior 0,026 ≤ 0,03 | **vyvráceno** (správně: výpadek segmentu) → položka paměti ve stavu `refuted` |
| 927 | pokračování, bez zdroje, bez změny závažnosti | potlačeno (správně) |
| 939 až 940 | **`app_layer_flood_api` (243): 6 vnějších zdrojů, 1 052 toků, 435 selhání na 10.0.12.93:443**; detektor timeoutů znovu vytvoří tentýž klíč: bez zdrojů (žádný z 6 zdrojů není dominantní), závažnost High = dosavadní maximum, počet pod 4× maxima, odstup od posledního výskytu 12 cyklů (6 h) < `quiet_close_s` (24 h) | paměť: `Refuted` + žádná eskalace = **`Suppressed`**; nález útoku zmizel pod klíčem vyvráceným před 6 h kvůli jiné události |

Útok sám byl zobrazen (`source_volume_outlier`), takže člověk ho viděl; metrika A4 ale počítá útok s jakýmkoli omylem zavřeným nálezem, a nález timeoutů oběti opravdu zmizel. Zařazení: **(a) chyba enginu**, mechanismus „vyvrácení platí pro klíč, ne pro epizodu“. Oprava kroku 12 (`reopen_stale`, `escalate_first_source`) se netýkala: zdroj nový nebyl (žádný) a odmlka byla 6 h, ne 24 h.

Oprava `refute_episode` (`MemoryConfig::refute_episode_s` = 3 600 s): vyvrácený nebo automaticky vyřešený klíč pohltí jen souvislé pokračování téže epizody; po odmlce ≥ 1 h (dva cykly) je výskyt nová epizoda (`Escalation::Episode`, stav `Reopened`) a jde znovu do žebříku; zobrazí se až po ověření (nebo hned, je-li závažnost High jako tady). V tomto případě by žebřík při znovuověření měl práh vysokého dopadu 0,01 a posterior 0,026 by nestačil na vyvrácení. Test `finding_memory::refuted_key_absorbs_only_the_continuous_episode_when_episode_scoped` (bez přepínače padá na původním chování).

Otevřený designový limit (d), který oprava neřeší: distribuovaná záplava bez dominantního zdroje vypadá pro žebřík jako výpadek (živost: „služba neodpovídá ani kontrole, bez dominantního zdroje“ je silná neškodná skupina). Síťová data a sonda to nerozliší; rozliší to provozní telemetrie serveru (CPU, limit spojení) nebo počet zdrojů v okně. Zapsáno, neladěno.

### Případ 2: čtyři „útoky“ u lhoucího agenta, seed 20267401, síť 7 (Soho S, 14 dní), ramena `elying` a `emimic`

Stopa `F:\claude-tmp\k15\trace\ely-401-n7.trace.jsonl`:

| cyklus | co engine viděl | co rozhodl |
|---|---|---|
| 641 až 647 | neškodná událost `Misconfig` (69) na routeru 192.168.11.249 | — |
| 649 | `scan_attempts` se zdrojem 192.168.11.249 (klíč `src:192.168.11.249|scan_attempts`), žebřík: historie „stejný jev už 3 dny“ (skupina 3) + **koncová telemetrie „vše v pořádku“ od agenta, který lže** (LR 0,30, skupina 4, počítá se jako silná) + typ zařízení „běžné pro router“ | **vyvráceno** |
| 650 až 664 | tentýž klíč každý cyklus | potlačeno (vyvrácený klíč) |

Nález zmiňuje adresu routeru, a tu mají v klíčových adresách i čtyři souběžné pravdy (`c2_high_jitter`, `update_channel_compromise_fleet` a dvě provozní poruchy `icmp_blocked_by_firewall`, `slow_link_loss_degradation`, které A4 počítá jako útoky). Jde tedy o **jeden omylem zavřený nález připsaný čtyřem pravdám** (z toho dvěma poruchám); A12 hlásila „4 útoky“. Zařazení: **(a) chyba enginu** v kritériu síly důkazu (odpověď agenta „nic podezřelého“ je nepřítomnost nálezu, ne pozitivní důkaz neškodnosti, a u lhoucího agenta je bezcenná) a **(b) artefakt měření** (připsání jednoho nálezu více pravdám přes sdílenou adresu brány).

Oprava `endpoint_weak` (`LadderPolicy::endpoint_weak`): `EndpointSignal::Benign` je slabá skupina (6), ne silná skupina 4; při `strict_refute` vyvrací jen spolu s kontextem (1) nebo živostí (2). Seznam povolených (`Allowed`) zůstává silný (vlastník schválil), ale je vypnutý z kroku 14. Test `verify_ladder::lying_capable_agent_benign_signal_is_not_a_strong_group_under_strict_refute` (bez přepínače: historie + agent vyvrátí; s přepínačem eskalace člověku; kontext + agent stále vyvrátí).

### Systematické hledání ve všech dumpech kroku 14 (ladicí i držené, 25 ramen, 120 + 110 sítí)

Všechny útoky s `auto_closed = true` v `networks.jsonl`:

| skupina | případů | mechanismus | zařazení |
|---|---|---|---|
| seed 20267402, síť 5, `app_layer_flood_api`, 11 ramen (všechna bez `endpoint_allow`) | 1 útok x 11 ramen | případ 1 | (a) |
| seed 20267401, síť 7, `elying` a `emimic` | 4 pravdy x 2 ramena = 1 nález | případ 2 | (a) + (b) |
| ladicí `e100allow`, `bothallow` (seznam povolených) | 1 až 3 na rameno (`hn_password_sync_periodic`, `dc_replication_from_workstation`) | seznam povolených jako silná skupina u útoku hlásícího povolený hash | známo z kroku 14, přepínač vypnut, neřeší se |
| ladicí `emimicallow` | desítky (agent hlásí povolený nástroj) | totéž | totéž |
| ostatní ramena kroku 14 | 0 | — | — |

Starší dumpy (k13h, k13m, k13mix) mají jiný základ (bez `strict_close` nebo s `authorized_scanner` kontextem) a jejich omylem zavřené byly rozebrány v krocích 12 a 13; zde se nepočítají.

## P2: rodiny pod 100 %, příčiny po případech (držené seedy kroku 14, základ `off`)

Rozklad minutých útoků z `networks.jsonl` (útok = pravda s emitovanými toky a kontrafaktuálem) a stopa pravd (`F:\claude-tmp\k15\trace\t-101-n2`, `t-101-n7`: toky a bajty po cyklech, nálezy na hostu útočníka):

| rodina | n | detekce | bez jediného nálezu | nález skrytý (otevřený klíč) | zobrazen i bez útoku | ztráta senzoru | příčina a zařazení |
|---|---:|---:|---:|---:|---:|---:|---|
| exfil_cloud_storage_upload | 23 | 52 % | 11 | 0 | 0 | 3 (vis = 0) | 7 až 29 MB za okno po 2 až 8 oken na jeden nový cíl 443: pod `min_bytes` jednoho okna (50 MB), nad průměrem pomalého úniku (`slow_max_mean` 12 MB) a kratší než 6 oken → **mezera mezi dvěma detektory, (a)**; zbytek (c) ztráta senzoru. Zásahy jen přes `tls_rare_transfer` (náhodný druhý rys) a `slow_egress` (dlouhé varianty). |
| bucket_mass_download | 29 | 38 % | 17 | 1 | 0 | 1 | stažení 16 až 103 MB za okno z nového cíle 443 bez jediného nálezu i u 410 MB: objemové detektory stažení (`ingest_volume_anomaly`, `breadth_volume`) jsou v `final` vypnuté (rozhodnutí kroku 9 kvůli FP) a `novel_bulk_transfer` běží jen pro nešifrované porty (`bulk_clear`); zbývá `tls_rare_transfer` s náhodným druhým rysem → **(d) limit konfigurace** + (b) simulace dává legitimní TLS rysy |
| cloud_api_discovery_burst | 32 | 38 % | 18 | 1 | 1 | 1 | 26 až 174 toků za 1 až 3 okna na nový cíl 443, bez nálezu: `novel_peer_burst` (`peer_burst`) vypnut od kroku 11, zbývá `tls_novel_burst` s druhým rysem → **(d)/(b)** |
| clicks_to_rare_destination | 28 | 18 % | 17 | 3 | 3 | 1 | 2 až 12 toků, 0,1 MB, na vzácný cíl: podle návrhu simulace shodné s běžným kliknutím; zásahy jen při intenzitě ≥ 0,9 přes `tls_novel_burst` → **(d) limit návrhu** (bez reputace URL nebo sandboxu nerozlišitelné) |
| drive_by_bulk_download | 29 | 62 % | 5 | 3 | 3 | 1 | 1 až 2 toky, 1 až 10 MB po portu 80: `novel_bulk_transfer` (`bulk_clear`) chytá ≥ 2 MB; miny jsou 1,1 až 1,9 MB (pod `bulk_bytes`) nebo nález existoval i ve světě bez útoku (týž host stáhl totéž jinak) → **(b) simulace** (drive-by 1 MB = běžné stažení) + (d) |
| c2_cloud_storage_dead_drop | 30 | 57 % | 11 | 1 | 1 | 5 | 3 toky za okno na nový cíl 443 po 7 až 43 oken; zásahy `novel_persistent_peer`; miny soustředěné ve velkých sítích (Industrial L, Metro XXL, Enterprise XL) bez nálezu na hostu → podezření na **(a) limit měřítka profilu** (zralost hostu nebo strop dvojic) nebo (c) ztráta senzoru (5 z 11 má vis = 0); nepotvrzeno stopou detektoru |
| telnet_iot_login | 18 | 44 % | 8 | 1 | 1 | 2 | 100 až 1 080 toků na port 23 oběti s 50 % selhání; miny v Enterprise XL (4x), 4 bez viditelných toků → **(c) ztráta telemetrie** (4) + (a) detektor pokusů na nový vnitřní cíl ve velké síti bez nálezu (nepotvrzeno) |
| smb_sweep_ext | 26 | 81 % | 1 | 2 | 2 | 0 | 2 až 20 toků: `scan_attempts` pod otevřeným klíčem `src:<zdroj>` dřívějšího sweepu téhož vnějšího zdroje (legitimní slití) nebo nález existoval i bez útoku → **(b)/(d)** |

Oprava kroku 15 pro mezeru (a): `upload_horizon` (`egress_volume::detect_horizon`): tentýž test (stejné prahy `min_bytes`, `cold_bytes`, `z`, `ratio`) nad součtem nahraného přebytku posledních 6 oken proti historii stejně dlouhých horizontů hostu; poplach nejvýš jednou na horizont, typ `egress_volume_anomaly`. Test `behavior::egress_volume::upload_spread_over_a_few_windows_is_caught_only_by_the_horizon` (3x 30 MB po 1 MB historii: bez přepínače nic, s přepínačem jeden nález). Žádný práh se neměnil.

Ověření artefaktu připsání: u 14 až 29 pravd na síť se klíčové vnitřní adresy pravdy liší od adres, ze kterých toky skutečně šly (`cycle_sources`); připsání jde i přes vnější adresu, a u minutých pravd nebyl na skutečném hostu žádný nepřipsaný nález (n7: 10 z 14, n2: 13 z 13), takže to detekci nezkresluje; zapsáno jako drobný artefakt měření.

## P3: provozní telemetrie, příčiny

Z diagnostického dumpu kroku 14 (`F:\claude-tmp\k14\diag.jsonl`, 1 464 nálezů s diagnózou) a katalogu:

| jev | pozorování | příčina | zařazení |
|---|---|---|---|
| útok maskovaný jako porucha (C4 10 %) | 46 bezpečnostních nálezů jako porucha: `snmp_walk_internal`/`unexpected_traffic` → OPS-040 (routovací černá díra, 11x), `smtp_auth_spray`/`unexpected_traffic` → OPS-011 (saturace uplinku, 4x), `novel_fanout` → OPS-002/007/060, `packet_rate_spike` → OPS-011/028/064; důkazy `sys_route_null0`, `if_util_high`, `if_out_discards`, `qos_drop` | diagnóza vysvětlí libovolný „kompatibilní“ typ nálezu jakýmkoli signálem poruchy v rozsahu /24 a okně 3 h; saturace linky ale nevyvolá nový vztah ani rozptyl cílů (novost), jen timeouty a objem | **(a)**: chybí vazba mechanismus poruchy → příznak |
| porucha maskovaná jako útok (C5 14,4 %) | 32 nálezů poruch jako útok, 31x „bez provozního důkazu“: `core_router_flapping` (12x), `ntp_unreachable` (4x), `uplink_saturation`/`beacon_periodic` (3x), `vpn_concentrator_down` | signál (if_flap, ntp_unreach) má rozsah = adresa routeru/NTP serveru, nález je o klientovi → žádný signál v rozsahu nálezu | **(a)** chybí dosah infrastrukturního zařízení na závislé hosty (simulátor dává signál na postižené zařízení, což je realistické); `iot_firmware_chatter_loop`/`novel_fanout` (9x) neobjasněno |
| `catalog_id` 60,5 % při správné třídě 80 % | typy s 0 až 2 % správného id: `app_server_crash_cascade` (375 nálezů), `port_crc_errors`, `slow_link_loss_degradation`, `load_balancer_partial_outage`, `vlan_hop_or_misconfig`; správný typ mezi kandidáty 87 % | katalog má 13 dvojic typů, kde signály jednoho jsou podmnožinou (11) nebo totožné (2: OPS-020/045, CHG-001/OPS-059) se signály druhého; skóre = podíl přítomných vlastních signálů, takže podmnožinový typ dosáhne 1,0 stejně jako nadmnožinový a výsledek je „kandidáti“ bez id | **(a)** pro podmnožiny (nadmnožinový typ vysvětlí víc téhož důkazu a má vyhrát), **(d) limit katalogu** pro 2 totožné dvojice (strop C2 ≈ 95 %) |
| „nelze určit“ jen 27 % bez doručené telemetrie (C3) | 66 % zůstalo útokem | engine pozná jen „zdroj mlčí“ (bez heartbeatu 3 h), ne „host není v pokrytí zdroje“; simulátor nedoručí signál hostu mimo pokrytí, ale zdroj jako celek žije | **(d)/(b)**: chybí registr pokrytí (které hosty který zdroj sleduje); bez něj je ticho hostu nerozlišitelné od klidu. Neopraveno v kroku 15 (vyžaduje nový vstup: inventář monitoringu), navrženo níže |
| čistota incidentů v mixech 82,6 % vs 91,5 % | `mixops` seskupuje přes `ops:<podsíť>` společnou příčinu | kořen podsítě spojuje i nálezy útoku v téže /24, které diagnóza (mylně) vysvětlila poruchou → C4 se promítá do C8 | následek C4, **(a)** |

Opravy: `ops_symptoms` (pole `explains` v katalogu v1.2.0 generované `tools/k15_catalog_explains.py` z povahy původce a tvaru provozu varianty: porucha infrastruktury vysvětlí `availability`/`volume`/`broadcast`, nikdy novost, maják ani sken; změna cest (resolver, brána, VLAN, DHCP) i novost; `ops_telemetry::symptom_groups` mapuje typ nálezu na skupiny; plus dominance: kandidát, jehož přítomné signály jsou vlastní podmnožinou nejlepšího, typ neznejasňuje) a `ops_blast` (signál s rozsahem = adresa zařízení třídy router, switch, AP, DNS, VPN platí pro všechny hosty; `DiagPolicy::infra` z klasifikace zařízení). Testy `ops_telemetry::tests::{fault_explains_only_the_symptom_groups_of_its_mechanism, superset_type_wins_over_its_dominated_subset_candidate, infrastructure_signal_reaches_dependent_hosts_only_with_blast_radius}`.

## P4: stav bez telemetrie

Stav: diagnóza hlásí „nelze určit, chybí telemetrie: X“ jen když typ nálezu je dostupnostní nebo tok vypadá jako porucha a zároveň primární zdroj (SNMP, syslog) tři hodiny mlčí; žebřík hlásí nedostupné kontroly (`neprovedeno: ...`) v důvodu eskalace. Zavření bez telemetrie: `auto_closures_wrong` 0 a `C6` 0 ve všech ramenech kroku 14 (porucha se nikdy nezavře jen proto, že není útok). Návrh pro další krok (ne kód kroku 15): registr pokrytí (zdroj → hosty/podsítě, z inventáře monitoringu), aby „host bez signálu“ šlo odlišit od „host mimo pokrytí“; simulátor by registr emitoval z `OpsSim::covered`.

## P5: realita vs. simulace

**LUFlow 2020-06-19 (200 000 toků, 28 oken po 1 800 s, rozsah 10.3.36.0/24, 259 škodlivých zdrojů podle štítků), produkční cesta `beh spust`, `tools/replay_public.py --v3-on`:** základ (`final` + `protect`) i kandidát (`final` + `refute_episode` + `upload_horizon`) dávají **totožný výsledek**: zobrazeno 522 nálezů (1 cold, 521 mature), 0 automaticky zavřených, žebřík 0 potvrzeno / 0 vyvráceno / 503 eskalováno, 64 z 259 škodlivých zdrojů zmíněno v zobrazených nálezech (jako v kroku 12). Čtení: v tomto datasetu žebřík nic nevyvrací (bez kontextu, kalendáře a sondy není žádná silná skupina), takže epizodové vyvrácení nemá co měnit, a honeypot nic nenahrává, takže horizont nahrání se neuplatní. Opravy kroku 15 tu nic nezhoršují ani nezlepšují; to je očekávané, ne důkaz přínosu.

**CTU-13 scénář 42 (Neris; 10 oken, 31 735 toků, 59 413 DNS, 63 TLS) a 54 (fast-flux; 33 oken, 88 048 toků, 15 447 DNS, 370 TLS), Zeek logy, `tools/k13_replay_zeek.py --v3`:** základ i kandidát totožně: scénář 42 zobrazeno 11 nálezů zmiňujících infikovaný host 147.32.84.165 (5 nespárovaných pasivních událostí, 3 interaktivní relace, 2 dlouhá spojení), 0 o jiných hostech; scénář 54 zobrazeno 17 (11 nespárovaných, 1 interaktivní relace, 4 pravidelná volání), 0 o jiných hostech. Žádné vyvrácení žebříkem, žádný horizont nahrání (bot nenahrává desítky MB). Závěr P5: opravy kroku 15 na třech reálných datasetech **nic nemění**; jejich účinek je zatím doložen jen na simulaci, a mechanismy, které opravují (vyvrácený klíč pohlcující pozdější epizodu, lhoucí agent, nahrání pod prahem okna), v těchto datasetech nenastávají (žádný kontext ani sonda, žádný agent, žádné nahrání). Reálné ověření P1 by vyžadovalo záznam s kalendářem údržby nebo aktivní sondou a následným útokem na tentýž cíl; takový veřejný dataset nemám.

## Měření

### Regrese a determinismus (K15-8)

Binárka kroku 15 bez nových přepínačů (`off`, seed 20261102, 2 sítě) dává `networks.jsonl` shodný s během kroku 14 (`k14n`) ve všech polích kromě časů (`wall_s`, `cycle_p99_s`). Cílené testy: `finding_memory`, `verify_ladder`, `engine::tests`, `ops_telemetry`, `behavior::egress_volume`: 60 prošlo, 0 selhalo (včetně 5 nových regresních testů). Celé `cargo test --lib` a golden snapshot viz závěr.

### Ladicí seedy (5 seedů x 8 sítí, základ = běhy kroku 14)

Odchylka od plánu: seed 20266106 má v bloku 3 dvě sítě XXL, jejichž běh trvá hodiny (rameno `elying` kroku 14 je také nemá); kandidáti se u tohoto seedu měří na 6 sítích, párování je po sítích, takže je to 38 párů místo 40. Výstupy `F:\Projekty\bakula-soak\k15\tune`, souhrn `F:\claude-tmp\k15\report15.sh tune`.

**`k15` (`refute_episode` + `upload_horizon`) proti `off`, 38 párů:**

| ukazatel | `off` | `k15` | rozdíl (95 %) | práh |
|---|---:|---:|---|---|
| detekce bezpečnostních útoků | 82,3 | 82,3 | +0,1 (+0,0 až +0,1) p. b. | K15-2 ≥ 0: splněno, ale bez přínosu |
| zobrazené FP na síť-den | 9,81 | 9,87 | poměr 1,006 (1,002 až 1,011) | K15-3 ≤ 1,10: splněno |
| útoky s omylem zavřeným | 0 z 2692 | 0 z 2692 (horní mez Wilson 0,14 %) | K15-1: splněno (na ladicích seedech nebylo co opravit) |
| hn_* zobrazeno | 65,4 | 67,3 | +1,9 (+0,4 až +3,4) p. b. | zhoršení: `hn_nightly_cloud_backup_upload` 60,0 → 74,3 % (horizont zachytí noční zálohu 15 až 35 MB za okno; nález radí ověřit zálohu, ale zobrazí se) |
| `exfil_cloud_storage_upload` | 55,6 (n = 9) | 55,6 | +0,0 | cíl ≥ +10 p. b. **nesplněn**: minuté exfiltrace ladicích seedů mají 2,8 až 13 MB za okno, tedy i součet 6 oken je pod `min_bytes` 50 MB nebo pod poměrem 10× k historii hostu; horizont pomůže jen pásmu 20 až 30 MB za okno, které je na držených seedech (3 z 11 minutých), ne na ladicích |
| autonomně vyvráceno žebříkem | 8 z 22 823 | 1 z 22 966 | | epizodové vyvrácení posílá opakované epizody zpět do žebříku; zavírá se ještě méně než dřív, omylem 0 |

Co `upload_horizon` změnil (`F:\claude-tmp\k15\horizoncheck.py`): nálezů `egress_volume_anomaly` 2 783 → 3 505; nově zachyceno 5 nočních záloh (hn) a 0 nových exfiltrací; 1 exfiltrace už zachycená získala druhý typ nálezu. Závěr: oprava mezery je správná co do mechanismu (test), ale v simulaci je v tomto pásmu objemu víc legitimních záloh než exfiltrací; **nedoporučuje se zapnout**, LOFO `k15b` níže.

**`k15e` (`elying` + `endpoint_weak` + `refute_episode`) proti `elying`, 38 párů:** detekce 82,3 = 82,3 (+0,0), FP poměr 1,000, hn_* +0,0, omylem zavřeno 0 z 2692 v obou (horní mez 0,14 %), autonomně vyvráceno 13 → 2 (lhoucí agent už nevyvrací s historií sám). Na ladicích seedech se mechanismus případu 2 nevyskytl; test K15-1 pro `k15e` rozhodnou držené seedy.

**`k15ops` (`ops` + `ops_symptoms` + `ops_blast` + `refute_episode` + `upload_horizon`) proti `ops` (součty přes 5 seedů, `k15ops` bez 2 XXL sítí seedu 20266106):**

| ukazatel | `ops` (krok 14) | `k15ops` | práh |
|---|---:|---:|---|
| C1 třída poruchy | 78,5 (n = 973) | **70,8** (n = 878) | ≥ 85: **nesplněno, horší** |
| C2 `catalog_id` s telemetrií | 60,5 | **56,6**; mezi kandidáty 88,0 → 76,0 | ≥ 70: **nesplněno, horší** |
| C4 útok maskovaný jako porucha (nálezy) | 8,3 | **21,3** | ≤ 5: **nesplněno, horší** |
| C5 porucha maskovaná jako útok | 10,8 | **20,2** | ≤ 10: **nesplněno, horší** |
| C7 správná kategorie celkem | 83,7 | 72,3 | ≥ 85: nesplněno |

Rozbor na jedné síti (seed 20261102, síť 2, dump diagnóz `F:\claude-tmp\k15\diag`): `ops_symptoms` převedl nálezy poruch na útok tam, kde simulovaná porucha vyvolá typ nálezu, který její mechanismus podle katalogu nevyvolává (první verze `explains`: `port_crc_errors` → `unexpected_traffic`; po doplnění skupin z autorského textu katalogu už ne), a `ops_blast` naopak vysvětlil útoky signálem o infrastruktuře v celé síti (`ddos_volume`/`connection_timeout_burst`, `ddos_ntp_amplification`/`packet_rate_spike`, `c2_doh_resolver`/`tls_novel_burst` → porucha): rozšířený dosah bez časové vazby mezi signálem a nálezem (okno 3 h) vysvětlí každý dostupnostní nález v síti. Obě opravy míří na skutečné příčiny C4 a C5, ale v tomto simulátoru si jdou proti sobě a bez přesnějšího modelu (kdy přesně signál platí a kterých hostů se týká) celkový výsledek zhoršují. **Ani jedna se nedoporučuje zapnout.** LOFO `k15opsA` a `k15opsB` níže; ramena `k15noise` a `k15mix` se po tomto výsledku nepouštějí (složka neprošla ladicím prahem K15-4/K15-5), což je odchylka od předregistrace zapsaná zde.

**LOFO na ladicích seedech (součty, 38 párů):** `k15a` (jen `refute_episode`) proti `off`: detekce 83,3 = 83,3, FP poměr 1,000, hn_* +0,0, omylem zavřeno 0 = 0, autonomně vyvráceno 8 = 8, latence 1,70 = 1,70: **beze změny** (na ladicích seedech se epizoda po vyvrácení nikdy neopakovala v útoku; cena nula). `k15opsB` (jen `ops_blast`) proti `ops`: C5 10,8 → 10,3 (zisk v mezích šumu), **C4 8,3 → 30,0**, C1 78,5 → 77,4, C7 83,7 → 67,1: dosah infrastrukturních signálů na celou síť vysvětlí útoky, zamítnuto. `k15opsA` (jen `ops_symptoms`) a `k15b` (jen `upload_horizon`): doplní se po doběhnutí.

Co z toho plyne pro otázku „je simulace nerealistická“: to, které typy nálezů porucha vyvolá a jaký dosah má signál o zařízení, si simulátor i katalog vymýšlejí nezávisle na sobě (katalog: text autora; simulátor: generátor varianty), a diagnóza se dá vylepšit jen tak, že se jedno přizpůsobí druhému, tedy laděním na vlastní simulátor. Ověřit to jde jen na reálném záznamu provozních incidentů (incident log NOC + toky + SNMP/syslog téže sítě); takový veřejný dataset nemám a bez něj zůstává C1 až C5 horním odhadem na uzavřeném světě.

### Držené seedy (20268101 až 20268502, jednou)

Doplní se.
