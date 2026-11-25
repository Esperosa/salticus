# Předregistrace kroku 36: korelace na DARPA 2000 LLDOS (nezávislá data s pravdou po fázích)

Zapsáno před měřením. Navazuje na `plan-korelace-final.md` (K9) a `predreg-krok35.md`.

## Data (nezávislá, nepoužívala se při návrhu pravidel)

DARPA 2000 LLDOS, vnitřní tcpdump, volně stažitelné (https://archive.ll.mit.edu/ideval/data/2000/). Pcap převeden `zeek/zeek:9.0.1 -C -r` na `conn.log`. Pravda: `phase-N.list` (relace pravdy pro 5 fází, čas lokální EST = UTC-5, ověřeno proti prvnímu toku záznamu).

- **Dev:** LLDOS 1.0 (125 tisíc toků). Jen k odladění skriptů a kontrole chování (struktura dat byla před zápisem prohlédnuta).
- **Test:** LLDOS 2.0.2 (79 tisíc toků), jednou, po zmrazení kódu. Obsah jsem před předregistrací neprohlížel kromě stažení a převodu. Kód `corr_v3` se po vidění dev výsledku smí měnit jen na opravu chyby doložené testem; změna prahů je zakázána (rozhodnutí o změně = nový krok bez použití testu).
- Zmrazení kódu: hash commitu se zapíše do dodatku k tomuto dokumentu před spuštěním testu.

## Jednotka a metriky (případová studie, jedna kampaň na dataset; bez statistických testů)

Kampaň = adresy ze všech pěti `phase-N.list` (bez broadcastu a podvržených jednorázových zdrojů záplavy). Nález patří kampani, jen když zmiňuje adresu kampaně. Fáze nálezu = fáze, jejíž časový interval ±30 min obsahuje čas prvního zobrazení nálezu.

Ramena: v1 (produkční incidenty bez `corr_v2`), `corr_v3` (`corr_v2` + `corr_v3`), triviální B1 a silnější B1b (sdílená IP s oknem 6 h a mezí hubu 25). Pro každé rameno: počet incidentů s nálezem kampaně (fragmentace), podíl nálezů kampaně v největším z nich (úplnost), počet pokrytých fází nejlepším incidentem, kontaminace (podíl nálezů mimo kampaň v incidentech s kampaní), počet pozaďových incidentů, největší incident.

## Hypotézy a rozhodovací pravidla (na testu LLDOS 2.0.2)

- **H1 (bez ztráty):** množina zobrazených `finding_id` v běhu v1 a `corr_v3` je totožná.
- **H2 (jeden incident kampaně):** `corr_v3` má ≤ 2 incidenty s nálezem kampaně a nejlepší z nich pokrývá ≥ 3 z fází, ve kterých má kampaň nálezy.
- **H3 (čistota):** kontaminace `corr_v3` ≤ 0,25 a největší incident ≤ 25 % zobrazených nálezů (kontrola hubu).
- **H4 (proti baseline):** `corr_v3` má nižší kontaminaci nebo menší fragmentaci než B1b a není horší v pokrytí fází.
- Dev výsledek (LLDOS 1.0) se uvede, ale nerozhoduje.

## Co plyne z výsledku

- H1 až H4 platí: `corr_v3` jde dál (K10 až K16) s doplněním „ověřeno na nezávislé kampani, N = 1 na testu a N = 1 na dev“.
- H2 nebo H4 neplatí: přínos `corr_v3` se omezuje na syntetický tvar; plán se přeřadí na opravu produkčního v1 a hledání dalších dat.
- H3 neplatí: hub nebo slévání, oprava před dalším krokem.
- H1 neplatí: oprava chyby.

## Omezení

Jedna kampaň na dataset, dva datasety: nelze mluvit o statistické významnosti. Síť z roku 2000 s jinými protokoly a jiným pozadím než domácí síť; pravda je po relacích, ne po nálezech. LLDOS 2.0.2 má v seznamech pravdy jen tři adresy.
