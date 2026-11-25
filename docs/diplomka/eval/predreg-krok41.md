# Předregistrace kroku 41: DAPT2021, den s vyšším objemem (Week6_Day3_06302021)

Zapsáno před měřením. Navazuje na `predreg-krok40.md` a `impl-krok40.md`: den Week5_Day4 měl zobrazeno 7 nálezů a 1 kampaně, a byl proto pro korelaci neinformativní. Week6_Day3 má 363 413 toků po odstranění duplicit (šest snímačů, 203 MB), vzorkování ukázalo vysoký podíl útočných toků; stejná kampaň (hostitelé 10.1.3.17, 10.1.3.8, 10.8.10.84, 192.168.0.11; fáze Establish Foothold, Data Exfiltration, Lateral Movement). Před předregistrací jsem z dne četl jen souhrn labelů nutný k pravdě.

Kód zmrazen na commitu **16a73ad** (stejný kód jako v kroku 40, mezi nimi jen dokumenty). Hypotézy, ramena, úrovně a metriky beze změny z `predreg-krok40.md` (H1 shodné zobrazené nálezy, H2 žádné duplicitní položky v incidentech ramene C, H3 nejlepší incident C obsahuje aspoň 2 adresy kampaně, H4 kontaminace ≤ 0,25 a největší incident ≤ 20 % zobrazených nálezů, H5 C lepší než B1b v kontaminaci nebo úplnosti uzávěru). Jedno měření.

Dodatečné pravidlo: pokud zobrazených nálezů kampaně bude < 10, test se označí za neinformativní a H3 až H5 se nehodnotí (stejně jako v kroku 40).

Omezení: jedna kampaň, privátní adresy (pravidlo vnějšího protějšku se neuplatní), stupně fází souvislé přes den (úrovně normal a strict splývají).
