# Krok 29: rozhodnutí o nastavení shadow režimu a brána uzavírání na přehrání po oknech

Podklad: `impl-krok25.md` až `impl-krok28.md`. Vedoucí práce předal rozhodnutí mně („je to na tobě“); zapisuji ho s důvody.

## 1. Rozhodnutí

| otázka | rozhodnutí | důvod |
|---|---|---|
| zapnout `attempts`, `attr_calib`, `upload_horizon` pro shadow režim domácí sítě | **ano, v konfiguraci pracovního prostoru** (`labs/shadow/salticus.shadow.toml`), ne v presetech | nejlepší změřené nastavení (8 z 8 skutečných rodin 10/10, 1 065 zobrazených nálezů za 3 dny proti 9 067); shadow režim nic nezavírá ani neblokuje, takže cena je jen počet zobrazených nálezů; změna je vratná; `recommended()` se nemění, protože není důkaz na držených seedech |
| spor S1 (stačí hlavičkám paketů označit tok za odpověď na vlastní dotaz?) | **modul zůstává volitelný a zapnutý jen výslovným souborem `SALTICUS_KNOWN_ACTIVITY`, s přiznaným residuálním rizikem** | odpůrce chtěl vysvětlené toky nechat v detekci a jen je anotovat, čímž by zmizelo ~13× snížení zobrazených nálezů; zbytkové riziko je měřitelné (benchmark: podvržené odpovědi skryjí 50 % toků epizody, broadcast ~3 %, každá epizoda zůstane aspoň zčásti viditelná jako souhrn „vysvětleno“) a vázané na lokálního útočníka, který zná dočasný port a čas; pro shadow režim domácí sítě je přijatelné, pro produkční nasazení je potřeba, aby provozovatel riziko výslovně přijal |
| deklarace vlastního skeneru (`own_scanners`) | **jen když je potřeba**, s vědomím, že vyjmutý sken už nevytváří vrstevníky | krok 26; po zavedení `attempts` už zachycení SSH na vrstevnících nezávisí |

## 2. Brána uzavírání na přehrání po oknech

Nastavení: modul, `attempts`, `attr_calib`, `upload_horizon`, `close_gate`, `strict_close`, `confirm_evidence`, `refute_episode`, `ctx_host_first`, `ctx_activity_guard`, `protect`; 125 oken, benchmark z kroku 28.

Výsledek: **0 uzavřených nálezů**, zachycení beze změny (8 skutečných rodin 10/10, 1 065 zobrazených).

Jak to číst: brána zavírá jen s pozitivním důkazem s vlastníkem (schválený kontext nebo seznam povolených) a žebříkem z aspoň dvou nezávislých skupin. Na domácí síti nikdo kontext neschválil, takže se zavřít nemělo nic. **Nula chybně zavřených je tu triviální, ne důkaz kvality brány**; kvalitu brány měří kroky 20 až 24 na simulaci a laboratoři, ne tento běh. Měření zavírání na skutečných datech vyžaduje schválené kontexty a nezávisle označené případy, které nemáme.

## 3. Meze

- Rozhodnutí o nastavení stojí na datech jedné domácí sítě, jednom zdroji útoků (moje syntetické epizody) a deseti epizodách na rodinu.
- Bez držených seedů, proto bez změny `recommended()`.
- Označení případů z domácí sítě (78 kusů) dělal Claude, ne nezávislá osoba.

## 4. Další krok

1. Nezávislé označení případů (30 dle `plan-krok22.md` §4), pokud bude někdo dostupný.
2. Přehrání dalšího týdne záznamu domácí sítě s tímto nastavením a porovnání počtu zobrazených nálezů (stabilita šumu).
