# Krok 31: pravidlo odchozího skenování (`outbound_scan`), výsledek podle předregistrace

Podle `predreg-krok31.md`; pravidlo `src/behavior/outscan.rs`, přepínač `outscan` (výchozí vypnuto, chráněný typ, `recommended()` beze změny). Prahy: 25 různých cílů bez odpovědi na stejný port za 300 s (výchozí hodnoty `scan.zeek`) a podíl neúspěšných ≥ 0,5. 10 jednotkových testů. Vyhodnocení `tools/k31_eval.py`, jednorázově, bez zásahu do kódu mezi zápisem pravidla a testem.

## 1. Výsledek (17 scénářů se štítky + 3 honeypoty + domácí síť)

| skupina | infikováno | A (výchozí) zachyceno | C (+ `outscan`) zachyceno | zobrazeno A | zobrazeno C |
|---|---|---|---|---|---|
| IoT-23, 7 malwarových scénářů (**nezávislé**) | 8 | 6 | 6 | 22 | 76 |
| IoT-23, 3 honeypoty (kontrola šumu) | 0 | 0 | 0 | 3 | 3 |
| CTU-13, 10 testovacích scénářů (**potvrzovací**) | 30 | 10 | **13** | 2 713 | 2 733 |

- **H1 (žádná ztráta): splněna**, 0 z 20 scénářů s C < A.
- **H2 (šum): splněna**, zobrazeno C/A = 1,027 a na skutečné domácí síti za 3 dny **1** zobrazený nález `outbound_scan` (hranice 3).
- **H3 (přínos ≥ 3 hosty): splněna jen na potvrzovacích datech** (CTU-13 +3: scénáře 43, 46, 49, přesně ty, ze kterých pravidlo vzniklo), **na nezávislém IoT-23 přínos 0**. Podle předregistrace tedy: **„potvrzeno jen na datech, ze kterých vzniklo“**, ne ověřeno nezávisle.

Hosté uvnitř rozsahu CTU-13: infikováno 23, A zachytilo 10 (43 %), C zachytilo 13 (57 %). Zbývajících 10 hostů mají v záznamu 63 nebo 5 spojení, žádný detektor toků na to nestačí. Všech 13 hostů s aspoň 381 spojeními zachytilo C.

## 2. Forenzní poznámky

- **IoT-23 scénář 3-1 (Mirai):** infikovaný host 192.168.2.5 (154 886 spojení) byl zachycen už výchozím nastavením přes `interactive_session`. `outbound_scan` přidal 54 zobrazených nálezů o témže hostu (jeden za okno): z 22 na 76 zobrazených v IoT-23 je výhradně tohle opakování. Je to vada zobrazení (stejný útok se zobrazí v každém okně), ne přínos zachycení.
- **IoT-23 scénář 8-1:** infikovaný host (10 401 spojení, z toho 8 222 SYN bez odpovědi na port 50) **nemá v žádném rameni nález** a pravidlo na něj nesedí správně: je to opakování na **dva** cíle (neúspěšné spojení na mrtvé C&C), ne sken. Chybí tedy pravidlo „pravidelné opakované neúspěšné spojení na stejný vnější cíl“ (beacon bez odpovědi); beaconing existující vrstvy vyžaduje zahřátého hosta.
- **Domácí síť:** jediný zásah je PC 192.168.1.133, 22. 11. 2026 19:48 UTC: 4 476 spojení na port 443 za 5 minut, 2 247 z nich bez odpovědi (podíl 0,502) na 157 cílů. Nejde o skenování, ale o velkou dávku HTTPS spojení s polovinou neúspěšných; podíl je těsně nad hranicí 0,5. Je to jeden falešný poplach za 3 dny na jednom hostu; pravidlo je citlivé na hranici podílu.

## 3. Rozhodnutí

- `outscan` zůstává **volitelný**; do vzorové shadow konfigurace ho dávám jen jako zakomentovaný řádek, protože nezávislý přínos se neprokázal.
- Další dvě mezery nalezené forenzně: (a) opakované zobrazení téhož nálezu v každém okně u trvajícího útoku (54× u jednoho hosta), (b) beacon bez odpovědi na stejný cíl u nezahřátého hosta (IoT-23 8-1).

## 4. Meze

- Pravidlo vzniklo z rozboru testovacích scénářů CTU-13, proto je tamní výsledek jen potvrzením; nezávislý test (IoT-23) přínos neukázal, protože ve výřezech, kde se skenuje, už host nesl jiný nález.
- Převod binetflow v2 a štítky „From-Botnet“ (zahrnují i externí volající, bez nichž 10 z 23 hostů uvnitř rozsahu je v záznamu jen několika spojeními).
- Prahy jsou převzaté ze Zeeku, ne laděné; podmínka podílu 0,5 vznikla po kontrole domácí sítě (přiznáno v předregistraci).
- Regresi soaku 48/48 jsem nespouštěl; přepínač je ve všech presetech vypnutý. Celou testovací sadu `cargo test --lib` jsem po této změně nespustil (spuštěno `behavior::outscan` a `engine::tests`).
