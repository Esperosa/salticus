# Předregistrace kroku 47: vlastní izolovaná laboratoř se skutečnými útočnými nástroji

Zapsáno a commitnuto před spuštěním Salticusu nad touto laboratoří. Navazuje na `plan-lab-korelace.md` a na debatu s nezávislými posuzovateli (jednička: "druhé reálné pozadí, nikdy neotevřené, s útoky skutečnými nástroji, ne generátorem").

## Data (reálná, ne syntetická)

Vlastní izolovaná laboratoř (Docker, bez publikovaných portů, izolované sítě, žádný provoz nejde ven): router (hub, zachytává veškerý mezipodsíťový provoz přes `tcpdump`), web (DMZ), app, db (skutečný Postgres), jump, dva pracovní stanice, dva nezávislí útočníci. Kampaň provedena skutečnými nástroji, ne skriptem: `nmap` (sken webu), `curl` (nalezení a stažení exponovaného zálohového klíče `/backup/web-config.bak`), `ssh` (laterální pohyb na app tímto klíčem), `psql` (dotaz na db), `curl -X POST` (exfiltrace 188 893 B na sink útočníka). Druhý, nezávislý útočník: `hydra` (neúspěšná hrubá síla SSH proti jump, účty bez heslového přihlášení). Běžící pozadí: periodické HTTP dotazy ze dvou stanic a legitimní administrativní SSH kanál (jump → app) souběžně s útokem. Záznam převeden `zeek/zeek:9.0.1`, 1234 toků, http/ssh/postgresql rozpoznáno. Pravda: `runbook.jsonl`, zapsaná v reálném čase při provádění jednotlivých kroků, ne zpětně.

Toto pozadí jsem před touto předregistrací neotevřel v Salticusu ani jsem nad ním neběžel žádné vyhodnocení; `runbook.jsonl` jsem četl jen já sám (psal jsem ho), kód se podle výsledku neladil.

## Ramena a metriky

A (v1), C (`corr_v2`+`corr_v3`+`corr_ext`+`corr_related`), offline B1, B1b, uzávěr C. Okno 120 s (laboratoř trvá ~7 minut, kratší okno než u ostatních kroků). Metriky: úplnost (podíl nálezů kampaně v nejlepším incidentu), kontaminace pozadím, **zda se nezávislý druhý útočník smíchá se skutečnou kampaní** (nová metrika, možná jen na tomto datasetu měřitelná, protože dřívější veřejná data neměla dva nezávislé, časově blízké útočníky se společnou obětí domény).

## Hypotézy a pravidla (rameno C)

- **H1 (bez ztráty):** zobrazené nálezy v A a C totožné.
- **H2 (propojení kampaně):** nejlepší incident C obsahuje nálezy aspoň 3 z 5 fází/hostitelů kampaně (útočník, web, app, db, sink).
- **H3 (oddělení útočníků):** žádný incident obsahující kampaň neobsahuje i nález druhého útočníka ().
- **H4 (čistota):** největší incident ≤ 50 % zobrazených nálezů (laboratoř je malá, 1234 toků, přísnější mez z předchozích kroků by byla nesmyslná na tak malém vzorku).
- **H5 (proti baseline):** C má aspoň tak dobrou úplnost jako B1b a nemá horší oddělení útočníků.

## Co z výsledku plyne

- H1-H5 platí: první skutečně nezávislé potvrzení přínosu opravené korelace na datech, která nikdo předtím neviděl a nepsal pro ně pravidla.
- H3 neplatí: oprávněná obava z perkolace se potvrzuje i na malém, čistém vzorku; zapsat jako další negativní důkaz.
- H2 nebo H5 neplatí: přínos nad triviální seskupení se znovu neprokazuje, konzistentně s `zaver-korelace.md`.

## Omezení

Jedna laboratoř, jeden běh, malý objem (1234 toků, ~7 minut); topologie i útok jsem navrhl já, byť nástroje a jejich chování jsou reálné a nepředvídané (čekal jsem, že SSH se připojí rovnou, ve skutečnosti jsem narazil na uzamčené účty v Alpine a musel to opravit — to je reálná, ne předstíraná neznalost výsledku). Žádná host-identita (sshd log se v laboratoři nezapsal, chybí syslog démon) — potvrzení druhým zdrojem se zde neměří, jen síťová korelace.
