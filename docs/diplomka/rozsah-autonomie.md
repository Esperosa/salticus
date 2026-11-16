# Rozsah autonomie: co program dělá sám a co zůstává člověku

Stav: závazný cíl od 2026-11-16. Vychází z měření kroků 9 až 15 (viz `eval/impl-krok9.md` až `impl-krok15.md`).

## Cíl

Program převezme práci juniorního a mediorního analytika (třídění, dohledání kontextu, ověření, vyšetření). Člověk, nejlépe senior, dostává jen případy, které vyžadují jeho úsudek nebo pravomoc, a dostává je už vyšetřené.

Cíl není „100 % detekce“ ani „žádný člověk“. Cíl je měřitelná hranice automatizace s uvedenou chybovostí a seznam slepých míst.

## Úrovně práce

| úroveň | činnost | co dělá program | kdo rozhoduje |
|---|---|---|---|
| L1 (junior) | třídění, zjevné falešné poplachy, duplicity | zavře nález jen na pozitivní důkaz neškodnosti (podepsaný proces se známým hashem, známá záloha, autorizovaný skener s vlastníkem a expirací); seskupuje incidenty | program, s měřenou horní mezí chyby |
| L2 (medior) | kontext, ověření, vyšetření | žebřík ověřování L0 až L4, pivoting, spojení síť + endpoint + provozní telemetrie, sběr důkazů, konkurenční hypotézy, případová složka | program vyšetří, člověk potvrdí |
| L3 (senior) | nejasné případy, chráněné prostředky, zásah | předá hotový balík: co se stalo, důkazy pro a proti, co chybí, doporučení a cena ověření | člověk |

## Pravidla bezpečnosti (neměnná)

1. Nález se nikdy nezavře na základě nepřítomnosti důkazu. Bez pozitivního důkazu program hlásí „nelze určit, chybí X“ a nález zůstává viditelný.
2. Chráněné prostředky a nálezy s vysokým dopadem se nikdy nezavírají automaticky.
3. Cíl pro omylem zavřené útoky je 0. Hlásí se pozorovaný počet a horní mez Wilson 95 %. Nula pozorovaných neznamená nulu zaručenou.
4. Provozní porucha se nikdy nezavře jen proto, že není útok. Jde do fronty provozu a zůstává viditelná.
5. Chybějící telemetrie se hlásí jako slepé místo, ne jako „čisto“.
6. Autonomie se přiděluje po třídách případů a jen na základě změřené chybovosti v reálném (stínovém) provozu.

## Hlavní výstup: případová složka

Senior nedostává alert, ale vyšetřený případ: časová osa, aktéři (host, uživatel, proces, spojení), hypotézy s typovanou nejistotou, důkazy pro a proti, co zbývá ověřit a za jakou cenu, doporučený krok. Kvalita složky je měřený produkt, ne doplněk.

## Co se měří

- podíl případů rozhodnutých autonomně a horní mez jejich chyby (zatím asi 16 % autonomně, zbytek člověku);
- podíl případů předaných seniorovi s úplnou případovou složkou a čas k rozhodnutí;
- omylem zavřené útoky (cíl 0, horní mez);
- detekce po rodinách s intervaly a registr slepých míst;
- provozní poruchy: správná klasifikace jen tam, kde telemetrie existuje, jinak „nelze určit“.

## Co nelze slíbit

- Že odpadne senior. Chráněné prostředky, zásahy a skutečně nejasné případy zůstávají člověku.
- Že se zachytí vše. Slepá místa zůstávají a jsou evidována.
- Že čísla ze simulace platí v reálné síti, dokud se nepotvrdí na reálných datech a ve stínovém provozu.

## Pořadí prací

1. Dokončit krok 15 a krok 14 (držené seedy, souhrn). Provozní klasifikaci poruch dál neladit na simulaci.
2. Případová složka pro seniora jako hlavní produkt, měření její úplnosti a použitelnosti.
3. Reálná data pro poruchy (syslog, SNMP, DHCP z laboratoře nebo domácí sítě), nezávislé ověření.
4. Stínový provoz: program běží vedle člověka, jeho rozhodnutí se porovnávají se skutečnými rozhodnutími, nic neřídí.
5. Postupné přidělování autonomie po třídách případů podle změřené chybovosti ze stínového provozu.
