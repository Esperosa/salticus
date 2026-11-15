# Krok 12: držené seedy (jednou) a hranice automatizace

Seedy 20264101 a 20264102 (nikým neviděné před tímto měřením; 80 sítí, 5 506 útoků a poruch s toky), svět k10 s `--l7 on`. **Odchylka od předregistrace:** předregistrováno bylo šest držených seedů, z časových důvodů se pustily dva (4101, 4102); seedy 4201 až 4302 zůstávají nepoužité pro navázání. Základ = preset `recommended` bez nových přepínačů, kandidát = `breadth`, `bulk_clear`, `strict_close`, `l7_tls`, `l7_dns`, `icmp_payload`. Režimy `hypotheses` a `redisplay` v kandidátu nejsou (viz `impl-krok12.md`, oddíl 9: nepřinesly nebo uškodily).

Rozdělení hn_*: ladicí (smí se po nich ladit) hn_cdn_update_download, hn_mail_newsletter_burst, hn_admin_bulk_ssh, hn_authorized_internal_scan; **držené** hn_nightly_cloud_backup_upload, hn_db_replication_bulk, hn_monitoring_snmp_sweep, hn_password_sync_periodic. Výhrada: změna pravidla rarity cíle (impl-krok12.md, oddíl 8) vznikla po pohledu na výsledek hn_nightly_cloud_backup_upload na ladicím seedu.

## A) Základ proti kandidátu

| ukazatel | základ | kandidát |
|---|---|---|
| sítí | 80 | 80 |
| zobrazené FP na síť-den | 9.05 | 9.55 (poměr 1.056) |
| útoky s omylem zavřeným nálezem | 34 (0,6 %) | 4 (0,1 %) |
| detekce bezpečnostních útoků (bez poruch a hn_*) | 84,1 (82,9 až 85,3) | 87,2 (86,1 až 88,3) |

### Opravené rodiny

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| drive_by_bulk_download | 30/30 | 6,7 (1,8 až 21,3) | 43,3 (27,4 až 60,8) | +36,7 |
| bucket_mass_download | 29/29 | 13,8 (5,5 až 30,6) | 34,5 (19,9 až 52,7) | +20,7 |
| exfil_alt_protocol_ftp | 24/24 | 12,5 (4,3 až 31,0) | 79,2 (59,5 až 90,8) | +66,7 |
| cloud_api_discovery_burst | 29/29 | 17,2 (7,6 až 34,5) | 41,4 (25,5 až 59,3) | +24,1 |
| clicks_to_rare_destination | 22/22 | 4,5 (0,8 až 21,8) | 4,5 (0,8 až 21,8) | +0,0 |
| port_scan_horizontal | 145/145 | 75,9 (68,3 až 82,1) | 76,6 (69,0 až 82,7) | +0,7 |

### Velké rodiny (kontrola, že se nezhoršily)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| c2_beacon | 148/148 | 85,1 (78,5 až 90,0) | 87,8 (81,6 až 92,2) | +2,7 |
| port_scan_horizontal | 145/145 | 75,9 (68,3 až 82,1) | 76,6 (69,0 až 82,7) | +0,7 |
| port_scan_vertical | 160/160 | 88,8 (82,9 až 92,8) | 88,8 (82,9 až 92,8) | +0,0 |
| exploit_attempt | 167/167 | 82,6 (76,2 až 87,6) | 82,6 (76,2 až 87,6) | +0,0 |
| exfiltration | 136/136 | 88,2 (81,7 až 92,6) | 88,2 (81,7 až 92,6) | +0,0 |
| credential_stuffing | 99/99 | 96,0 (90,1 až 98,4) | 96,0 (90,1 až 98,4) | +0,0 |
| cryptomining | 64/64 | 96,9 (89,3 až 99,1) | 96,9 (89,3 až 99,1) | +0,0 |

### Neškodné změny hn_* (podíl zobrazených = FP z pohledu útoku)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| hn_admin_bulk_ssh | 139/139 | 82,0 (74,8 až 87,5) | 82,0 (74,8 až 87,5) | +0,0 |
| hn_authorized_internal_scan | 138/138 | 97,8 (93,8 až 99,3) | 97,8 (93,8 až 99,3) | +0,0 |
| hn_cdn_update_download | 117/117 | 9,4 (5,3 až 16,1) | 10,3 (6,0 až 17,1) | +0,9 |
| hn_db_replication_bulk | 128/128 | 78,9 (71,0 až 85,1) | 80,5 (72,8 až 86,4) | +1,6 |
| hn_mail_newsletter_burst | 146/146 | 12,3 (7,9 až 18,6) | 15,1 (10,2 až 21,8) | +2,7 |
| hn_monitoring_snmp_sweep | 123/123 | 67,5 (58,8 až 75,1) | 66,7 (57,9 až 74,4) | -0,8 |
| hn_nightly_cloud_backup_upload | 120/120 | 50,0 (41,2 až 58,8) | 51,7 (42,8 až 60,4) | +1,7 |
| hn_password_sync_periodic | 132/132 | 92,4 (86,6 až 95,8) | 92,4 (86,6 až 95,8) | +0,0 |

### Přenos na ostatní bezpečnostní rodiny (největší změny, LOFO)

| rodina | n | základ | kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| dns_zone_enum_burst | 20 | 20,0 (8,1 až 41,6) | 75,0 (53,1 až 88,8) | +55,0 |
| exfil_icmp_payload | 26 | 46,2 (28,8 až 64,5) | 96,2 (81,1 až 99,3) | +50,0 |
| exfil_over_c2_trickle | 25 | 44,0 (26,7 až 62,9) | 84,0 (65,3 až 93,6) | +40,0 |
| exfil_cloud_storage_upload | 27 | 18,5 (8,2 až 36,7) | 44,4 (27,6 až 62,7) | +25,9 |
| exfil_https_burst | 25 | 36,0 (20,2 až 55,5) | 56,0 (37,1 až 73,3) | +20,0 |
| ddos_dns_amplification | 24 | 54,2 (35,1 až 72,1) | 70,8 (50,8 až 85,1) | +16,7 |
| c2_dns_txt_beacon | 28 | 60,7 (42,4 až 76,4) | 75,0 (56,6 až 87,3) | +14,3 |
| insider_after_hours_cloud_sync | 23 | 60,9 (40,8 až 77,8) | 73,9 (53,5 až 87,5) | +13,0 |
| lateral_movement | 172 | 95,9 (91,8 až 98,0) | 95,3 (91,1 až 97,6) | -0,6 |
| lateral_ssh_hop | 21 | 90,5 (71,1 až 97,3) | 85,7 (65,4 až 95,0) | -4,8 |

Všechny ostatní bezpečnostní rodiny dohromady: základ 87,1 (85,8 až 88,4), kandidát 89,7 (88,5 až 90,8).



## B) Hranice automatizace a omylem zavřené

### Rameno `base` (80 sítí, 5506 útoků s toky)

| ukazatel | hodnota | horní mez Wilson 95 % |
|---|---|---|
| útoky s omylem zavřeným nálezem (zavření nebo vyvrácení) | 34 z 5506 (0,62 %) | 0,86 % |
| vyvrácení žebříkem, z nich omylem (nález chybí bez útoku) | 16 z 414 (3,86 %) | 6,19 % |
| zavření kontextem, z nich omylem (kontrafaktuál) | 5 z 56 | 19,26 % |
| potvrzení žebříkem, z nich neškodné (omylem eskalované jako útok) | 535 z 9507 (5,63 %) | 6,11 % |
| případů žebříku rozhodnutých | 57640 | |
| z toho autonomně (potvrzeno + vyvráceno) | 9921 (17,2 %) | |
| předáno člověku (eskalováno) | 47719 (82,8 %); z nich útok 23075, neškodné 24644 | |
| ECE posterioru žebříku (surová, 10 košů), Brier, n | ECE 9,9 %, Brier 0.199, n = 57640 | |
| průměrný čas k rozhodnutí (cykly) | 1.66 | |

### Rameno `kandidat` (80 sítí, 5506 útoků s toky)

| ukazatel | hodnota | horní mez Wilson 95 % |
|---|---|---|
| útoky s omylem zavřeným nálezem (zavření nebo vyvrácení) | 4 z 5506 (0,07 %) | 0,19 % |
| vyvrácení žebříkem, z nich omylem (nález chybí bez útoku) | 0 z 6 (0,00 %) | 39,03 % |
| zavření kontextem, z nich omylem (kontrafaktuál) | 0 z 0 | - % |
| potvrzení žebříkem, z nich neškodné (omylem eskalované jako útok) | 607 z 9570 (6,34 %) | 6,85 % |
| případů žebříku rozhodnutých | 59777 | |
| z toho autonomně (potvrzeno + vyvráceno) | 9576 (16,0 %) | |
| předáno člověku (eskalováno) | 50201 (84,0 %); z nich útok 23870, neškodné 26331 | |
| ECE posterioru žebříku (surová, 10 košů), Brier, n | ECE 9,5 %, Brier 0.199, n = 59777 | |
| průměrný čas k rozhodnutí (cykly) | 1.68 | |


## C) Zbytky detekce po rodinách (útoky s pozorovatelnými toky), kandidát

| rodina | n | detekce | z viditelných (Wilson) | a slepé | a viditelné | b nezobrazeno (důvody) | c nepřipsáno | c typ | do 100 % z viditelných |
|---|---:|---:|---|---:|---:|---|---:|---:|---:|
| ssh_bruteforce | 218 | 94,5 | 96,3 (92,8 až 98,1) | 4 | 2 | 5 (suppressed 28, verifying 1) | 1 | 18 | 3,7 |
| lateral_movement | 172 | 95,3 | 95,3 (91,1 až 97,6) | 0 | 2 | 5 (suppressed 96) | 1 | 22 | 4,7 |
| exploit_attempt | 167 | 82,6 | 85,7 (79,5 až 90,3) | 6 | 9 | 6 (suppressed 23) | 8 | 77 | 14,3 |
| port_scan_vertical | 160 | 88,8 | 94,7 (89,8 až 97,3) | 10 | 1 | 3 (suppressed 58) | 4 | 4 | 5,3 |
| c2_beacon | 148 | 87,8 | 87,8 (81,6 až 92,2) | 0 | 11 | 4 (suppressed 42, verifying 1) | 3 | 40 | 12,2 |
| port_scan_horizontal | 145 | 76,6 | 77,6 (70,1 až 83,7) | 2 | 7 | 18 (suppressed 179, verifying 5) | 7 | 10 | 22,4 |
| slow_scan | 138 | 97,1 | 97,1 (92,8 až 98,9) | 0 | 2 | 2 (suppressed 15) | 0 | 10 | 2,9 |
| exfiltration | 136 | 88,2 | 90,9 (84,8 až 94,7) | 4 | 4 | 4 (suppressed 57) | 4 | 3 | 9,1 |
| credential_stuffing | 99 | 96,0 | 97,9 (92,8 až 99,4) | 2 | 0 | 1 (suppressed 20) | 1 | 5 | 2,1 |
| web_exploit | 86 | 98,8 | 98,8 (93,7 až 99,8) | 0 | 1 | 0 (-) | 0 | 35 | 1,2 |
| dns_tunnel | 72 | 97,2 | 97,2 (90,4 až 99,2) | 0 | 0 | 0 (-) | 2 | 8 | 2,8 |
| ddos_volume | 67 | 100,0 | 100,0 (94,6 až 100,0) | 0 | 0 | 0 (-) | 0 | 3 | 0,0 |
| cryptomining | 64 | 96,9 | 98,4 (91,5 až 99,7) | 1 | 1 | 0 (-) | 0 | 15 | 1,6 |
| rogue_device | 41 | 97,6 | 97,6 (87,4 až 99,6) | 0 | 0 | 1 (suppressed 54) | 0 | 3 | 2,4 |
| insider_hoarding | 40 | 95,0 | 97,4 (86,8 až 99,5) | 1 | 0 | 1 (suppressed 11) | 0 | 1 | 2,6 |
| apt_chain | 40 | 100,0 | 100,0 (91,2 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| kerberos_ticket_request_burst | 37 | 97,3 | 97,3 (86,2 až 99,5) | 0 | 0 | 1 (suppressed 12) | 0 | 0 | 2,7 |
| ransomware | 35 | 100,0 | 100,0 (90,1 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| smb_share_enum_internal | 33 | 78,8 | 78,8 (62,2 až 89,3) | 0 | 0 | 3 (suppressed 99, verifying 1) | 4 | 2 | 21,2 |
| c2_internal_proxy_chain | 33 | 100,0 | 100,0 (89,6 až 100,0) | 0 | 0 | 0 (-) | 0 | 4 | 0,0 |
| resource_hijack_pool_tls | 33 | 100,0 | 100,0 (89,6 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| ldap_bind_spray | 32 | 96,9 | 96,9 (84,3 až 99,4) | 0 | 0 | 0 (-) | 1 | 1 | 3,1 |
| lateral_wmi_dcom | 32 | 96,9 | 96,9 (84,3 až 99,4) | 0 | 0 | 0 (-) | 1 | 2 | 3,1 |
| c2_doh_resolver | 32 | 87,5 | 93,3 (78,7 až 98,2) | 2 | 0 | 0 (-) | 2 | 0 | 6,7 |
| lateral_rdp_hop | 31 | 93,5 | 96,7 (83,3 až 99,4) | 1 | 0 | 1 (suppressed 46) | 0 | 5 | 3,3 |
| c2_slow_long_interval | 31 | 87,1 | 90,0 (74,4 až 96,5) | 1 | 3 | 0 (-) | 0 | 1 | 10,0 |
| drive_by_bulk_download | 30 | 43,3 | 44,8 (28,4 až 62,5) | 1 | 14 | 1 (suppressed 6) | 1 | 12 | 55,2 |
| c2_iot_mqtt_cloud | 30 | 93,3 | 93,3 (78,7 až 98,2) | 0 | 2 | 0 (-) | 0 | 0 | 6,7 |
| cloud_api_discovery_burst | 29 | 41,4 | 42,9 (26,5 až 60,9) | 1 | 15 | 0 (-) | 1 | 9 | 57,1 |
| ftp_bruteforce | 29 | 89,7 | 92,9 (77,4 až 98,0) | 1 | 1 | 1 (suppressed 2) | 0 | 0 | 7,1 |
| bucket_mass_download | 29 | 34,5 | 34,5 (19,9 až 52,7) | 0 | 15 | 4 (suppressed 29) | 0 | 6 | 65,5 |
| smb_sweep_ext | 29 | 65,5 | 65,5 (47,3 až 80,1) | 0 | 1 | 6 (suppressed 52, verifying 1) | 3 | 3 | 34,5 |
| snmp_sweep_ext | 29 | 79,3 | 79,3 (61,6 až 90,2) | 0 | 0 | 3 (suppressed 15) | 3 | 1 | 20,7 |
| c2_high_jitter | 28 | 82,1 | 82,1 (64,4 až 92,1) | 0 | 3 | 1 (suppressed 6) | 0 | 5 | 17,9 |
| c2_irc_style_channel | 28 | 82,1 | 85,2 (67,5 až 94,1) | 1 | 3 | 0 (-) | 1 | 0 | 14,8 |
| c2_dns_txt_beacon | 28 | 75,0 | 75,0 (56,6 až 87,3) | 0 | 2 | 1 (suppressed 37) | 4 | 10 | 25,0 |
| ddos_ntp_amplification | 28 | 100,0 | 100,0 (87,9 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| imap_spray | 27 | 96,3 | 96,3 (81,7 až 99,3) | 0 | 0 | 0 (-) | 1 | 2 | 3,7 |
| c2_udp_custom_port | 27 | 92,6 | 92,6 (76,6 až 97,9) | 0 | 0 | 2 (suppressed 11, verifying 1) | 0 | 0 | 7,4 |
| exfil_cloud_storage_upload | 27 | 44,4 | 48,0 (30,0 až 66,5) | 2 | 11 | 2 (suppressed 10) | 0 | 11 | 52,0 |
| smtp_auth_spray | 27 | 100,0 | 100,0 (87,5 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| exfil_scheduled_chunks | 27 | 92,6 | 92,6 (76,6 až 97,9) | 0 | 1 | 0 (-) | 1 | 3 | 7,4 |
| mail_forward_smtp_exfil | 27 | 88,9 | 92,3 (75,9 až 97,9) | 1 | 2 | 0 (-) | 0 | 1 | 7,7 |
| oauth_token_abuse_periodic | 26 | 92,3 | 92,3 (75,9 až 97,9) | 0 | 2 | 0 (-) | 0 | 0 | 7,7 |
| rdp_bruteforce | 26 | 100,0 | 100,0 (87,1 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| exfil_icmp_payload | 26 | 96,2 | 100,0 (86,7 až 100,0) | 1 | 0 | 0 (-) | 0 | 22 | 0,0 |
| onion_style_circuit_egress | 26 | 84,6 | 88,0 (70,0 až 95,8) | 1 | 3 | 0 (-) | 0 | 0 | 12,0 |
| c2_icmp_tunnel | 26 | 96,2 | 100,0 (86,7 až 100,0) | 1 | 0 | 0 (-) | 0 | 0 | 0,0 |
| mqtt_probe_ext | 26 | 50,0 | 50,0 (32,1 až 67,9) | 0 | 3 | 7 (suppressed 71) | 3 | 2 | 50,0 |
| lateral_cautious_one_target | 25 | 100,0 | 100,0 (86,7 až 100,0) | 0 | 0 | 0 (-) | 0 | 2 | 0,0 |
| exfil_over_c2_trickle | 25 | 84,0 | 84,0 (65,3 až 93,6) | 0 | 2 | 0 (-) | 2 | 0 | 16,0 |
| c2_ntp_port_misuse | 25 | 92,0 | 95,8 (79,8 až 99,3) | 1 | 1 | 0 (-) | 0 | 0 | 4,2 |
| exfil_https_burst | 25 | 56,0 | 58,3 (38,8 až 75,5) | 1 | 8 | 2 (suppressed 28) | 0 | 5 | 41,7 |
| exfil_alt_protocol_ftp | 24 | 79,2 | 82,6 (62,9 až 93,0) | 1 | 3 | 1 (suppressed 7) | 0 | 16 | 17,4 |
| web_scanner_404_storm | 24 | 87,5 | 87,5 (69,0 až 95,7) | 0 | 0 | 3 (suppressed 12) | 0 | 4 | 12,5 |
| ddos_dns_amplification | 24 | 70,8 | 73,9 (53,5 až 87,5) | 1 | 2 | 1 (suppressed 2) | 3 | 5 | 26,1 |
| smb_login_failures | 24 | 100,0 | 100,0 (86,2 až 100,0) | 0 | 0 | 0 (-) | 0 | 1 | 0,0 |
| lateral_smb_admin_shares | 24 | 95,8 | 95,8 (79,8 až 99,3) | 0 | 0 | 0 (-) | 1 | 1 | 4,2 |
| dc_replication_from_workstation | 24 | 100,0 | 100,0 (86,2 až 100,0) | 0 | 0 | 0 (-) | 0 | 2 | 0,0 |
| ntlm_relay_style_fanout | 24 | 91,7 | 91,7 (74,2 až 97,7) | 0 | 0 | 2 (suppressed 89) | 0 | 3 | 8,3 |
| backup_service_probing | 23 | 91,3 | 91,3 (73,2 až 97,6) | 0 | 0 | 1 (suppressed 11, verifying 1) | 1 | 8 | 8,7 |
| exfil_dns_slow | 23 | 91,3 | 91,3 (73,2 až 97,6) | 0 | 0 | 1 (suppressed 13) | 1 | 4 | 8,7 |
| insider_after_hours_cloud_sync | 23 | 73,9 | 73,9 (53,5 až 87,5) | 0 | 4 | 2 (suppressed 32) | 0 | 3 | 26,1 |
| distributed_low_port_probe | 23 | 95,7 | 95,7 (79,0 až 99,2) | 0 | 0 | 1 (suppressed 2) | 0 | 1 | 4,3 |
| telnet_iot_login | 23 | 47,8 | 50,0 (30,7 až 69,3) | 1 | 8 | 3 (suppressed 10, verifying 1) | 0 | 2 | 50,0 |
| c2_alt_port_8443 | 23 | 91,3 | 95,5 (78,2 až 99,2) | 1 | 1 | 0 (-) | 0 | 0 | 4,5 |
| lateral_winrm | 23 | 95,7 | 95,7 (79,0 až 99,2) | 0 | 0 | 0 (-) | 1 | 0 | 4,3 |
| clicks_to_rare_destination | 22 | 4,5 | 4,8 (0,8 až 22,7) | 1 | 17 | 2 (suppressed 3) | 1 | 1 | 95,2 |
| ldap_directory_enum_bulk | 22 | 100,0 | 100,0 (85,1 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| update_channel_compromise_fleet | 22 | 95,5 | 95,5 (78,2 až 99,2) | 0 | 0 | 1 (suppressed 1) | 0 | 2 | 4,5 |
| lateral_ssh_hop | 21 | 85,7 | 85,7 (65,4 až 95,0) | 0 | 0 | 1 (suppressed 57) | 2 | 4 | 14,3 |
| fleet_beacon | 21 | 90,5 | 90,5 (71,1 až 97,3) | 0 | 1 | 1 (suppressed 10) | 0 | 3 | 9,5 |
| vnc_probe_ext | 21 | 76,2 | 76,2 (54,9 až 89,4) | 0 | 2 | 1 (suppressed 8) | 2 | 2 | 23,8 |
| mssql_login_failures | 21 | 85,7 | 85,7 (65,4 až 95,0) | 0 | 0 | 2 (suppressed 13) | 1 | 0 | 14,3 |
| api_enum_distributed | 20 | 95,0 | 95,0 (76,4 až 99,1) | 0 | 1 | 0 (-) | 0 | 0 | 5,0 |
| dns_zone_enum_burst | 20 | 75,0 | 75,0 (53,1 až 88,8) | 0 | 3 | 2 (suppressed 2, verifying 1) | 0 | 14 | 25,0 |
| c2_websocket_long | 20 | 90,0 | 90,0 (69,9 až 97,2) | 0 | 1 | 1 (suppressed 1) | 0 | 0 | 10,0 |
| rdp_sweep_ext | 20 | 70,0 | 73,7 (51,2 až 88,2) | 1 | 0 | 4 (suppressed 25) | 1 | 1 | 26,3 |

Rodin (n ≥ 20): 78; z viditelných útoků nad 90 %: 50, nad 95 %: 35, na 100 %: 14.
