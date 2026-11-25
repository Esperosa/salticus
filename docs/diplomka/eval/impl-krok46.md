# Krok 46: potvrzení druhým zdrojem na reálných host-logách DAPT2021 — mechanismus platí, data jsou příliš řídká

Diagnostická ablace (post-hoc, nad existujícími `result.json` z kroků 41–42, bez nového běhu Salticusu). Zdroj: `s3://dapt2021/raw/host-logs/` — stejný veřejný bucket jako síťové toky, dosud nepoužitý.

## Co je ve zdroji skutečně k dispozici

Z devíti hostitelů, kteří tvoří velký "znečištěný" incident na dnech Week6_Day3 a Week6_Day4 (`impl-krok41.md`), mají host-logy:

| hostitel | co má | je použitelné? |
|---|---|---|
| 10.1.1.11 | `auth-logs` (sshd) | **ano**, pokrývá 27.6.–4.7. (naše dny) |
| 10.1.3.17 | Windows `securityevents.csv` | ne: 220 neúspěšných přihlášení, všechny se zdrojem `-` (lokální); 10 úspěšných se zdrojem, všechny `127.0.0.1` (ansible provisioning). Audit politika nezaznamenává vzdálenou IP u síťových přihlášení |
| 10.1.3.8 | jen `syslog`, žádné `auth-logs` | ne: soubor pokrývá jen 9.–10. 7., mimo naše dny; bez sshd záznamů |
| 10.1.1.4, 10.1.1.6, 10.1.2.17, 10.1.2.10 | jen `syslog` | ne: syslog bez `auth-logs` nemá autentizační řádky |
| 10.1.3.10, 10.1.1.18 (zdrojová administrátorská adresa) | nic | ne |

## Zjištění na 10.1.1.11

Za celé okno (27. 6.–4. 7.) je **všech 50 přijatých SSH přihlášení** k 10.1.1.11 ze stejné adresy `10.1.1.18`, se stejným otiskem klíče (`SHA256:ggWxiKkap…`), 0 neúspěchů. To jednoznačně odpovídá administrativnímu kanálu (pravděpodobně nástroj pro správu konfigurace), ne útočníkovi — přesně hypotéza, kterou by pravidlo potvrzení/veta mělo rozlišit.

## Ablace: veto jediného potvrzeného páru

Pravidlo (ne ladění dat, odvozené přímo z pozorování): pár adres, kde celé pozorovatelné okno obsahuje jen přijaté přihlášení stejným klíčem a 0 neúspěchů, je potvrzený administrativní kanál a z indikátorů nálezu se odstraní před seskupením.

| den | rameno | před (kontaminace / největší) | po vetu | nálezů zmiňujících pár |
|---|---|---|---|---|
| Week6_Day3 | B1b | 0,900 / 258 | 0,900 / 258 | 0 |
| Week6_Day4 | B1b | 0,892 / 240 | 0,891 / 239 | 1 |

## Co z toho plyne

1. **Mechanismus je potvrzený, ne vyvrácený:** jediný pár, který šlo reálnými daty ověřit, přesně odpovídal hypotéze (administrátor, ne útočník).
2. **Efekt je na této datové sadě neměřitelný:** veto jednoho páru změní největší incident o 1 nález ze 240–258. Příčina je řídké pokrytí: ze sedmi hostitelů velkého incidentu má autentizační log jen jeden; zbylých šest má pouze `syslog` bez `auth-logs`, takže jejich kanály nejde ani potvrdit, ani vyvrátit.
3. **PicoDomain (krok 44/45) je naopak dobře instrumentovaný (NTLM na všech šesti hostitelích), ale tak malý, že tam k silné perkolaci nedochází** — potvrzení tam nemělo co opravovat (všech 74 hran bylo už „silných“).
4. **Závěr pro otázku „pomůže víc zdrojů“:** ano v principu, ale přínos je omezen pokrytím zdroje, ne logikou korelace. Na síti, kde perkolace vadí (DAPT2021), chybí dost instrumentovaných hostitelů; na síti, kde jsou zdroje bohaté (PicoDomain), perkolace nevadí. Žádná dostupná veřejná sada obojí nekombinuje v potřebném rozsahu.

## Co by to změnilo

Datová sada s hustě instrumentovanými hostiteli (auth i proces) NAD velkou síti s reálnou perkolací, nebo doplnění chybějících `auth-logs` na dalších hostitelích DAPT2021 (nejsou veřejně k dispozici). Bez toho další práce na váženém potvrzení/vetu nemá na čem se ověřit a nebyla by to měřená věda, ale spekulace.

## Dodatek: potvrzeno skutečným během enginu, ne jen Python prototypem

Mechanismus je od tohoto kroku zabudovaný v produkčním kódu (`src/corroboration.rs`, přepínač `corr_identity`, proměnná `SALTICUS_AUTH_LOG`), ne jen diagnostický skript. Test s reálným řádkem logu z `10.1.1.11` je v `src/corroboration.rs` a end-to-end test vetování konkrétního páru (bez ovlivnění jiných párů) je v `src/retro.rs::corr_v3_veto_blocks_only_the_confirmed_pair_channel`.

Skutečný běh binárky (ne Python) s `SALTICUS_AUTH_LOG` nastaveným na stažený `auth111_2` a `corr_identity` zapnutým proti Week6_Day3 a Week6_Day4 potvrzuje dřívější zjištění přesně: zobrazené nálezy beze změny (H1), `w6d3` má 0 nálezů zmiňujících oba adresy páru (0 možného efektu), `w6d4` má přesně 1 a počet i velikost incidentů se nezměnily. **Mechanismus je nyní reálnou, testovanou funkcí enginu** (default-off); jeho měřený přínos zůstává nulový na této konkrétní datové sadě ze stejného důvodu jako dřív — řídké pokrytí druhým zdrojem, ne chyba v zapojení.
