# Plán laboratoře pro měření korelace s více zdroji důkazů (krok 45)

## Proč

Dosavadní měření (kroky 33 až 44) ukázala, že seskupování jen podle sdílených adres nedosáhne zároveň úplnosti a čistoty. Další zdroje (IDS, identita, proces, DNS a TLS otisky) by čistotu zvýšit mohly, ale veřejná data je neměří: chybí zarovnání zdrojů s toky a pravda po krocích na úrovni nálezů. Řešení je vlastní laboratoř, kde je každý krok útoku i neškodného provozu skriptovaný, takže pravda je přesná. Navazuje na `lab-plan.md` (část A) a využívá už existující obrazy Zeek a Suricata.

## Topologie (ověřeno: router vidí provoz mezi podsítěmi)

Tři podsítě Docker (útočník 10.50.1.0/24, DMZ 10.50.2.0/24, vnitřní 10.50.3.0/24) propojené routerem, který zachytává veškerý mezipodsíťový provoz (tcpdump do pcap) a je i DNS resolverem (hub). DMZ: webový server (slabé heslo SSH). Vnitřní: aplikační server, databáze, čtyři pracovní stanice a jump host. Útočník: nmap, hydra, curl, ncat.

## Zdroje důkazů (po fázích)

1. **Síť:** Zeek (conn, dns, ssl s JA3/JA4, ssh, http, files) a Suricata (ET Open, `community_id`) nad pcap z routeru. Základ.
2. **Identita:** autentizační logy sshd (účet, výsledek) z kontejnerů.
3. **Proces a spojení na hostu:** malý agent v kontejnerech zapisující události ve formátu osquery (procesy, otevřené sokety, uživatel); Salticus má adaptér `src/endpoint/osquery.rs`. Je to náhrada EDR v Linux kontejnerech; Windows telemetrie (Sysmon, Kerberos) tu není a výsledek se na ni nesmí zobecňovat.

## Scénáře a pravda

Kampaň (skriptovaná skutečnými nástroji): sken webu, hrubá síla SSH na web, z webu sken vnitřní sítě, SSH na aplikační server, z aplikačního serveru dotazy do databáze a výpis dat, exfiltrace HTTP POST na útočníka; varianty s více útočníky souběžně a s pivotem přes jump host. Neškodný provoz: stanice na aplikaci a web, aplikace na databázi (periodicky, hub), zálohy, administrátorské SSH přes jump host, DNS dotazy; zahrnuje záměrně vzory, které v podnikové síti způsobily perkolaci (server jako protějšek i aktér). Pravda: `runbook.jsonl` (id akce, kampaň, fáze, čas od do, zdroj, cíl, uživatel, proces) generuje samotný skript.

## Měření (předregistrované, nový seed pro každou variantu)

Ablace zdrojů: jen síť; síť + Suricata; + identita; + proces; + veto známého neškodného procesu. Pravidlo potvrzení: slabá vazba (sdílená adresa) platí, jen když ji potvrdí druhý zdroj (stejný účet nebo proces, stejná signatura, stejná doména nebo otisk). Metriky: úplnost, kontaminace, největší incident, duplicity, párové F1 po krocích, ztráta zachycení; vždy proti B1b a proti `corr_core`. Pravda po nálezech vzniká mapováním nález → akce runbooku podle času, adres a portu, ne zmínkou adresy.

## Kroky a odhad

1. Skeleton: sítě, kontejnery, router s pcap, skript kampaně a neškodného provozu, runbook (M).
2. Zeek a Suricata nad pcap, převod do vstupů Salticusu, první běh `v3` (M).
3. Identita a agent procesů, adaptér pro Salticus (M až L).
4. Pravidlo potvrzení a veto za přepínačem, předregistrace, měření na nových seedech (L).
5. Závěr a doporučení (S).

## Omezení a bezpečnost

Syntetická laboratoř s mými skripty; výsledek ukáže, zda druhé zdroje v principu zvyšují čistotu, ne že to platí na reálných útočnících. Žádný provoz neopouští izolované sítě Docker (bez portů publikovaných ven); používají se jen veřejné nástroje proti vlastním kontejnerům. Hostitel je Docker Desktop na WSL2, takže kernelová telemetrie (auditd, Falco) není k dispozici.
