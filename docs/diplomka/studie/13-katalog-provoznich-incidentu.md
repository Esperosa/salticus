# Studie 13: katalog běžných síťových a provozních incidentů

Stav 2026-11-15. Doprovází krok 13, dodatek B (`impl-krok13.md`). Strojově čitelný katalog je `data/incident-catalog.json` (verze 1.0.0), načítá ho modul `src/incident_catalog.rs`.

## Co je a co není tato rešerše (poctivé omezení)

- Katalog má **75 typů**; pro **51** z nich existuje parametrický generátor s ground truth v simulátoru (`soak::variants`, z toho 13 přidáno v tomto kroku jako nové varianty tvaru toků), pro 24 generátor chybí.
- Primární zdroje byly v této relaci **skutečně načteny jen dva**: RFC 5227 IPv4 Address Conflict Detection, danluu/post-mortems (sbírka veřejných postmortemů). Ostatní odkazy (RFC čísla, dokumentace výrobců, postmortemy Cloudflare, AWS, GitHub, NANOG, Google SRE, NIST SP 800-61, ITIL) jsou uvedeny podle znalosti, mají `verified: false` a před použitím v textu práce se musí ověřit. Načtení stránky NIST SP 800-61 Rev. 3 vypršelo, údaj o definici incidentu proto z ní není převzat.
- Texty o projevech v tocích, DNS, TLS, DHCP, ARP, SNMP, syslogu a endpointu jsou autorský souhrn (`basis: assumption`, u záznamů s ověřeným zdrojem `partly-verified`). Nejsou kalibrovány na naměřených rozděleních; generátory modelují jen **tvar toků** (vzor Outage, Degrade, Flap, Flood), ne obsah L2, DNS či syslogu, takže typy rozlišené hlavně obsahem (split-horizon, TTL, zastaralý záznam) zůstávají bez generátoru.
- Kategorie `nejednoznacne` (VLAN hopping vs chyba, rogue DHCP, rogue zařízení, DDoS vs flash crowd) označuje případy, které na síťové úrovni nelze spolehlivě rozlišit od útoku; engine u nich nesmí tvrdit jistotu a musí požádat o doplnění (inventář, port, snooping, geografie).

## Definice (pro rozlišení v enginu)

Rozlišení vychází z běžné praxe ITIL (incident = nečekané přerušení nebo zhoršení služby; porucha = technická příčina; problém = kořenová příčina více incidentů) a z incidentního pojetí bezpečnosti (NIST SP 800-61). V katalogu: **porucha** = technická příčina bez nepřátelského úmyslu, **neškodná změna** = zamýšlená změna nebo plánovaný provoz, **nejednoznačné** = na úrovni sítě nerozlišitelné od útoku. Porucha je také incident, který musí člověk vidět; engine ji nikdy nezavírá jen proto, že není útok (předregistrace B4).

## Typy v katalogu

| id | typ | kategorie | závažnost | generátor v simulátoru | podobný útok |
|---|---|---|---|---|---|
| OPS-001 | Výpadek přepínače podsítě | porucha | high | switch_outage_subnet | Hromadné zmizení hostů vypadá jako izolace po kompromitaci |
| OPS-002 | Flapping páteřního směrovače | porucha | high | core_router_flapping | Periodické výpadky připomínají beaconing nebo DoS |
| OPS-003 | Vyčerpání DHCP poolu | porucha | medium | dhcp_pool_exhaustion | Vypadá jako DHCP starvation útok |
| OPS-004 | Výpadek DHCP serveru | porucha | high | dhcp_server_down | Rozpad sítě po leasu vypadá jako útok na infrastrukturu |
| OPS-005 | Částečné selhání DNS | porucha | medium | dns_partial_failure | SERVFAIL bouře vypadá jako DGA nebo tunel |
| OPS-006 | Pomalé DNS rozlišení | porucha | low | dns_slow_resolution | Retransmise vypadají jako enumerace |
| OPS-007 | Nedostupný NTP server | porucha | low | ntp_unreachable | NTP bez odpovědi vypadá jako blokovaný C2 kanál |
| OPS-008 | Drift hodin hostu | porucha | medium | ntp_clock_drift_host | Posun času může skrýt nebo napodobit anomálie |
| OPS-009 | Vypršelý interní certifikát služby | porucha | high | cert_expired_internal_service | Opakované selhání TLS vypadá jako skenování TLS |
| OPS-010 | Chybný řetěz externího certifikátu | porucha | medium | cert_chain_misconfig_external | Selhání handshaku vypadá jako MITM |
| OPS-011 | Saturace uplinku | porucha | medium | uplink_saturation | Nasycení vypadá jako DDoS nebo exfiltrace |
| OPS-012 | Přetečení okna zálohy | porucha | low | backup_window_overrun | Dlouhý odchozí přenos vypadá jako exfiltrace |
| OPS-013 | Broadcast storm / smyčka L2 | porucha | critical | broadcast_storm_loop | Záplava vypadá jako DoS na L2 |
| OPS-014 | Bouře mDNS/SSDP | porucha | low | mdns_ssdp_storm | Skenování služeb nebo SSDP amplifikace |
| OPS-015 | Duplicitní IP adresa | porucha | medium | duplicate_ip_conflict | Dvě MAC na IP vypadá jako ARP spoofing |
| OPS-016 | Kaskáda pádu aplikačního serveru | porucha | high | app_server_crash_cascade | Vlna pokusů vypadá jako DoS aplikace |
| OPS-017 | Přetížení databáze | porucha | high | db_overload_degradation | Plný pool vypadá jako credential stuffing proti DB |
| OPS-018 | Částečný výpadek load balanceru | porucha | high | load_balancer_partial_outage | Nerovnoměrný provoz vypadá jako cílený útok |
| OPS-019 | Flapping služby | porucha | medium | flapping_service | Vypadá jako skenování nebo opakovaná přihlášení |
| OPS-020 | Degradace linky se ztrátami | porucha | medium | slow_link_loss_degradation | Ztráty vypadají jako zásah do provozu |
| OPS-021 | Zaplnění disku a selhání zálohy | porucha | medium | disk_full_backup_failure | Opakované pokusy vypadají jako brute force |
| OPS-022 | Vyčerpání paměti a zamrznutí | porucha | high | memory_exhaustion_stall | Zamrznutí vypadá jako DoS |
| OPS-023 | Pád koncentrátoru VPN | porucha | high | vpn_concentrator_down | Hromadné opakování přihlášení vypadá jako spray |
| OPS-024 | Selhání řadiče AP | porucha | high | access_point_controller_failure | Hromadné re-auth vypadá jako deauth nebo rogue AP |
| OPS-025 | Fronta a opakování pošty | porucha | low | mail_relay_queue_retry | Pravidelné opakování vypadá jako beaconing |
| OPS-026 | Smyčka firmware chatter IoT | porucha | medium | iot_firmware_chatter_loop | Vypadá jako C2 beacon nebo DoS |
| OPS-027 | Chybně nastavený monitoring (polling) | porucha | low | monitoring_agent_misconfig_poll | Vypadá jako skenování |
| CHG-001 | Sezónní špička webu | neskodna_zmena | low | seasonal_peak_web | Flash crowd vs DDoS |
| CHG-002 | Plánované okno údržby | neskodna_zmena | info | planned_maintenance_window | Plánovaný výpadek vs útok |
| CHG-003 | Plánovaný patch a restart | neskodna_zmena | info | planned_patch_reboot_wave | Vlna stahování vs exfiltrace |
| CHG-004 | Noční záloha do cloudu | neskodna_zmena | low | hn_nightly_cloud_backup_upload | Velký odchozí objem vs exfiltrace |
| CHG-005 | Stahování z CDN (aktualizace) | neskodna_zmena | info | hn_cdn_update_download | Drive-by stažení vs aktualizace |
| CHG-006 | Sweep monitoringu (SNMP) | neskodna_zmena | info | hn_monitoring_snmp_sweep | Síťový sweep vs recon |
| CHG-007 | Periodická synchronizace hesel | neskodna_zmena | info | hn_password_sync_periodic | Pravidelnost vs beacon |
| CHG-008 | Hromadná administrace SSH | neskodna_zmena | low | hn_admin_bulk_ssh | Bulk SSH vs lateral movement nebo spray |
| CHG-009 | Replikace databáze | neskodna_zmena | info | hn_db_replication_bulk | Objem mezi servery vs exfiltrace |
| CHG-010 | Hromadný newsletter | neskodna_zmena | info | hn_mail_newsletter_burst | Burst SMTP vs spam bot |
| CHG-011 | Autorizovaný interní sken | neskodna_zmena | low | hn_authorized_internal_scan | Rozliší jen autorizace |
| OPS-028 | Špatný resolver v konfiguraci klienta | porucha | medium | chybí | Dotazy na cizí resolver vypadají jako DNS hijack |
| OPS-029 | Zastaralý DNS záznam | porucha | medium | chybí | Spojení na neznámou IP vypadá jako C2 |
| OPS-030 | Chyba split-horizon DNS | porucha | medium | chybí | Hairpin provoz ven vypadá jako exfiltrace |
| OPS-031 | NXDOMAIN bouře | porucha | medium | dns_nxdomain_storm | Vypadá jako DGA malware |
| OPS-032 | Chybné TTL DNS | porucha | low | chybí | Častý dotaz vypadá jako DNS beaconing |
| OPS-033 | Nesoulad native VLAN | porucha | medium | chybí | VLAN hopping vypadá stejně |
| OPS-034 | VLAN hopping vs chybná konfigurace | nejednoznacne | high | chybí | Chyba a útok jsou na síti stejné |
| OPS-035 | MTU/MSS nesoulad | porucha | medium | mtu_mss_mismatch | Visící spojení vypadá jako tarpit |
| OPS-036 | Rogue DHCP server | nejednoznacne | high | chybí | Man-in-the-middle vs omyl |
| OPS-037 | Špatné DHCP lease | porucha | medium | chybí | Podvržená brána vs překlep |
| OPS-038 | Selhání DHCP relay | porucha | medium | dhcp_relay_failure | Jako DHCP starvation |
| CHG-012 | Změna certifikační autority | neskodna_zmena | info | chybí | Mladý certifikát vs podvržení |
| OPS-040 | Routovací černá díra | porucha | high | routing_blackhole | Blackhole vypadá jako filtrování útoku |
| OPS-041 | Asymetrické směrování | porucha | medium | chybí | Jednosměrné toky vypadají jako skenování nebo spoof |
| OPS-042 | Špatná výchozí trasa | porucha | high | chybí | Přesměrování vs MITM |
| OPS-043 | Vyčerpání NAT/PAT | porucha | high | nat_pat_exhaustion | SYN flood nebo skener vyčerpá totéž |
| OPS-044 | Duplex mismatch | porucha | low | duplex_mismatch | Ztráty vypadají jako zásah do provozu |
| OPS-045 | Chyby CRC na portu | porucha | medium | chybí | Poškozené pakety vypadají jako fuzzing |
| OPS-046 | Zahazování QoS | porucha | medium | chybí | Selektivní ztráty vypadají jako cílený zásah |
| CHG-013 | Nové neznámé zařízení (onboarding) | neskodna_zmena | low | chybí | Nový host vs rogue zařízení |
| OPS-048 | Rogue zařízení v síti | nejednoznacne | high | chybí | Stejné jako onboarding, liší se chováním |
| OPS-049 | Smyčka restartů zařízení | porucha | medium | chybí | Opakování vypadá jako beacon |
| OPS-050 | Selhávající aktualizace firmwaru | porucha | low | chybí | Opakované stahování vs staging |
| CHG-014 | Aktualizace čeká na restart | neskodna_zmena | info | chybí | - |
| OPS-052 | Zpožděná replikace | porucha | medium | chybí | Dlouhé spojení vypadá jako C2 long-lived tunnel |
| OPS-053 | Vypršení licence | porucha | medium | license_expiry | Selhání vypadá jako blokace |
| OPS-054 | Selhávající zdravotní kontroly | porucha | low | health_check_failing | Opakované dotazy vypadají jako brute force |
| OPS-055 | Padání VPN tunelu | porucha | medium | chybí | Periodické spojení vypadá jako beacon |
| OPS-056 | Chyba proxy nebo WAF (falešné blokování) | porucha | medium | waf_false_block | 403 vypadá jako úspěšná obrana nebo skenování |
| OPS-057 | Výpadek cloudového regionu | porucha | high | cloud_region_outage | Výpadek vs blokace nebo DoS |
| CHG-015 | Reklasifikace služby | neskodna_zmena | info | chybí | Nový cíl a port vs lateral movement |
| OPS-059 | DDoS vs flash crowd | nejednoznacne | high | chybí | Zásadní nejednoznačnost |
| OPS-060 | Rozbitý aktualizační server | porucha | medium | update_server_broken | Opakování vypadá jako DoS na server |
| OPS-061 | Zablokované ICMP firewallem | porucha | low | chybí | Blokace ICMP vypadá jako stealth |
| OPS-062 | Topology change smyčka STP | porucha | medium | chybí | Unknown unicast vypadá jako MAC flooding |
| OPS-063 | Selhání AD/Kerberos (čas nebo DC) | porucha | high | kerberos_dc_failure | Mnoho selhání vypadá jako spray |
| OPS-064 | Limit spojení služby dosažen | porucha | medium | connection_limit_reached | Odmítání vypadá jako firewall blok |

## Co zbývá

Generátory pro typy bez varianty, napojení nálezů na `catalog_id` (vysvětlení a doporučená kontrola v UI), měření správnosti klasifikace po typech (B2, B3, B6) a ověření zdrojů proti primárním textům. Stav v tabulce dodatku v `impl-krok13.md`.
