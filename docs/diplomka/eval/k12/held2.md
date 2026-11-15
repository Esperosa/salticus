# Krok 12: druhá dávka držených seedů (jednou) po opravách

Seedy 20264201, 20264202, 20264301, 20264302 (160 sítí, 13 084 útoků s toky, svět k10 s `--l7 on`), nikdy dřív nepoužité. Základ = `recommended` bez přepínačů kroku 12; kandidát = `breadth`, `bulk_clear`, `strict_close` (včetně opravy pohlcení vyvráceného klíče), `l7_tls`, `l7_dns`, `icmp_payload`. Binárka `k12-j` (po opravě bodu 1 a bez `redisplay_age`, `l7_ladder`, `hypotheses`).

## A) Základ proti kandidátu

| ukazatel | základ | kandidát |
|---|---|---|
| sítí | 160 | 160 |
| zobrazené FP na síť-den | 18.46 | 19.69 (poměr 1.067) |
| útoky s omylem zavřeným nálezem | 64 (0,5 %) | 0 (0,0 %) |
| detekce bezpečnostních útoků (bez poruch a hn_*) | 83,9 (83,1 až 84,6) | 86,8 (86,1 až 87,5) |

### Opravené rodiny

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| drive_by_bulk_download | 51/51 | 7,8 (3,1 až 18,5) | 64,7 (51,0 až 76,4) | +56,9 |
| bucket_mass_download | 58/58 | 13,8 (7,2 až 24,9) | 39,7 (28,1 až 52,5) | +25,9 |
| exfil_alt_protocol_ftp | 44/44 | 6,8 (2,3 až 18,2) | 63,6 (48,9 až 76,2) | +56,8 |
| cloud_api_discovery_burst | 47/47 | 4,3 (1,2 až 14,2) | 31,9 (20,4 až 46,2) | +27,7 |
| clicks_to_rare_destination | 58/58 | 5,2 (1,8 až 14,1) | 8,6 (3,7 až 18,6) | +3,4 |
| port_scan_horizontal | 360/360 | 90,0 (86,5 až 92,7) | 90,6 (87,1 až 93,2) | +0,6 |

### Velké rodiny (kontrola, že se nezhoršily)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| c2_beacon | 457/457 | 85,6 (82,0 až 88,5) | 86,4 (83,0 až 89,3) | +0,9 |
| port_scan_horizontal | 360/360 | 90,0 (86,5 až 92,7) | 90,6 (87,1 až 93,2) | +0,6 |
| port_scan_vertical | 445/445 | 82,7 (78,9 až 85,9) | 82,7 (78,9 až 85,9) | +0,0 |
| exploit_attempt | 452/452 | 86,9 (83,5 až 89,7) | 87,2 (83,8 až 89,9) | +0,2 |
| exfiltration | 321/321 | 89,1 (85,2 až 92,1) | 89,4 (85,6 až 92,3) | +0,3 |
| credential_stuffing | 332/332 | 90,7 (87,1 až 93,3) | 91,0 (87,4 až 93,6) | +0,3 |
| cryptomining | 211/211 | 88,6 (83,6 až 92,2) | 88,2 (83,1 až 91,8) | -0,5 |

### Neškodné změny hn_* (podíl zobrazených = FP z pohledu útoku)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| hn_admin_bulk_ssh | 267/267 | 83,5 (78,6 až 87,5) | 84,6 (79,8 až 88,5) | +1,1 |
| hn_authorized_internal_scan | 293/293 | 93,9 (90,5 až 96,1) | 93,9 (90,5 až 96,1) | +0,0 |
| hn_cdn_update_download | 291/291 | 9,3 (6,5 až 13,2) | 11,0 (7,9 až 15,1) | +1,7 |
| hn_db_replication_bulk | 287/287 | 78,7 (73,6 až 83,1) | 79,8 (74,8 až 84,0) | +1,0 |
| hn_mail_newsletter_burst | 287/287 | 8,7 (6,0 až 12,5) | 10,1 (7,1 až 14,1) | +1,4 |
| hn_monitoring_snmp_sweep | 277/277 | 79,1 (73,9 až 83,4) | 78,7 (73,5 až 83,1) | -0,4 |
| hn_nightly_cloud_backup_upload | 298/298 | 50,0 (44,4 až 55,6) | 50,3 (44,7 až 56,0) | +0,3 |
| hn_password_sync_periodic | 276/276 | 89,9 (85,7 až 92,9) | 90,2 (86,1 až 93,2) | +0,4 |

### Přenos na ostatní bezpečnostní rodiny (největší změny, LOFO)

| rodina | n | základ | kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| dns_zone_enum_burst | 55 | 14,5 (7,6 až 26,2) | 63,6 (50,4 až 75,1) | +49,1 |
| ddos_dns_amplification | 50 | 52,0 (38,5 až 65,2) | 88,0 (76,2 až 94,4) | +36,0 |
| c2_dns_txt_beacon | 45 | 53,3 (39,1 až 67,1) | 84,4 (71,2 až 92,3) | +31,1 |
| exfil_icmp_payload | 74 | 62,2 (50,8 až 72,4) | 90,5 (81,7 až 95,3) | +28,4 |
| exfil_over_c2_trickle | 49 | 55,1 (41,3 až 68,1) | 81,6 (68,6 až 90,0) | +26,5 |
| exfil_cloud_storage_upload | 66 | 21,2 (13,1 až 32,5) | 47,0 (35,4 až 58,8) | +25,8 |
| exfil_dns_slow | 54 | 55,6 (42,4 až 68,0) | 79,6 (67,1 až 88,2) | +24,1 |
| mail_forward_smtp_exfil | 60 | 66,7 (54,1 až 77,3) | 88,3 (77,8 až 94,2) | +21,7 |
| lateral_movement | 385 | 98,7 (97,0 až 99,4) | 98,4 (96,6 až 99,3) | -0,3 |

Všechny ostatní bezpečnostní rodiny dohromady: základ 85,6 (84,7 až 86,5), kandidát 88,4 (87,6 až 89,2).



## B) Hranice automatizace

### Rameno `base` (160 sítí, 13084 útoků s toky)

| ukazatel | hodnota | horní mez Wilson 95 % |
|---|---|---|
| útoky s omylem zavřeným nálezem (zavření nebo vyvrácení) | 64 z 13084 (0,49 %) | 0,62 % |
| vyvrácení žebříkem, z nich omylem (nález chybí bez útoku) | 46 z 2228 (2,06 %) | 2,74 % |
| zavření kontextem, z nich omylem (kontrafaktuál) | 5 z 44 | 23,98 % |
| potvrzení žebříkem, z nich neškodné (omylem eskalované jako útok) | 1852 z 23950 (7,73 %) | 8,08 % |
| případů žebříku rozhodnutých | 158799 | |
| z toho autonomně (potvrzeno + vyvráceno) | 26178 (16,5 %) | |
| předáno člověku (eskalováno) | 132621 (83,5 %); z nich útok 56675, neškodné 75946 | |
| ECE posterioru žebříku (surová, 10 košů), Brier, n | ECE 6,1 %, Brier 0.180, n = 158799 | |
| průměrný čas k rozhodnutí (cykly) | 1.69 | |

### Rameno `kandidat` (160 sítí, 13084 útoků s toky)

| ukazatel | hodnota | horní mez Wilson 95 % |
|---|---|---|
| útoky s omylem zavřeným nálezem (zavření nebo vyvrácení) | 0 z 13084 (0,00 %) | 0,03 % |
| vyvrácení žebříkem, z nich omylem (nález chybí bez útoku) | 0 z 52 (0,00 %) | 6,88 % |
| zavření kontextem, z nich omylem (kontrafaktuál) | 0 z 0 | - % |
| potvrzení žebříkem, z nich neškodné (omylem eskalované jako útok) | 2279 z 24536 (9,29 %) | 9,66 % |
| případů žebříku rozhodnutých | 166365 | |
| z toho autonomně (potvrzeno + vyvráceno) | 24588 (14,8 %) | |
| předáno člověku (eskalováno) | 141777 (85,2 %); z nich útok 59300, neškodné 82477 | |
| ECE posterioru žebříku (surová, 10 košů), Brier, n | ECE 6,8 %, Brier 0.183, n = 166365 | |
| průměrný čas k rozhodnutí (cykly) | 1.70 | |


## C) Zbytky detekce po rodinách, kandidát

| rodina | n | detekce | z viditelných (Wilson) | a slepé | a viditelné | b nezobrazeno (důvody) | c nepřipsáno | c typ | do 100 % z viditelných |
|---|---:|---:|---|---:|---:|---|---:|---:|---:|
| ssh_bruteforce | 600 | 92,3 | 99,1 (97,9 až 99,6) | 41 | 0 | 3 (suppressed 89, state_confirmed 54, state_open 35) | 2 | 35 | 0,9 |
| c2_beacon | 457 | 86,4 | 87,0 (83,6 až 89,8) | 3 | 22 | 21 (suppressed 244, state_open 193, state_confirmed 52) | 16 | 102 | 13,0 |
| exploit_attempt | 452 | 87,2 | 88,9 (85,7 až 91,5) | 9 | 28 | 16 (suppressed 126, state_open 88, state_confirmed 38) | 5 | 171 | 11,1 |
| port_scan_vertical | 445 | 82,7 | 94,8 (92,2 až 96,6) | 57 | 9 | 6 (suppressed 32, state_open 30, state_confirmed 2) | 5 | 4 | 5,2 |
| lateral_movement | 385 | 98,4 | 98,4 (96,6 až 99,3) | 0 | 1 | 4 (suppressed 56, state_open 45, state_confirmed 11) | 1 | 40 | 1,6 |
| port_scan_horizontal | 360 | 90,6 | 91,8 (88,5 až 94,3) | 5 | 5 | 14 (suppressed 184, state_open 169, state_confirmed 15) | 10 | 16 | 8,2 |
| credential_stuffing | 332 | 91,0 | 97,1 (94,6 až 98,5) | 21 | 1 | 4 (state_open 121, suppressed 121) | 4 | 10 | 2,9 |
| web_exploit | 330 | 97,3 | 98,8 (96,9 až 99,5) | 5 | 1 | 1 (suppressed 14, state_confirmed 8, state_open 6) | 2 | 77 | 1,2 |
| exfiltration | 321 | 89,4 | 94,7 (91,6 až 96,7) | 18 | 3 | 8 (suppressed 59, state_open 48, state_confirmed 11) | 5 | 6 | 5,3 |
| slow_scan | 308 | 93,8 | 94,4 (91,3 až 96,5) | 2 | 6 | 5 (suppressed 168, state_open 123, state_confirmed 45) | 6 | 14 | 5,6 |
| cryptomining | 211 | 88,2 | 88,6 (83,6 až 92,2) | 1 | 13 | 8 (suppressed 49, state_confirmed 29, state_open 20) | 3 | 28 | 11,4 |
| dns_tunnel | 206 | 93,2 | 94,1 (90,0 až 96,6) | 2 | 2 | 2 (state_open 36, suppressed 36) | 8 | 49 | 5,9 |
| ransomware | 185 | 98,4 | 98,9 (96,1 až 99,7) | 1 | 0 | 0 (-) | 2 | 13 | 1,1 |
| ddos_volume | 147 | 81,6 | 99,2 (95,5 až 99,9) | 26 | 0 | 1 (state_open 5, suppressed 5) | 0 | 1 | 0,8 |
| rogue_device | 126 | 96,8 | 96,8 (92,1 až 98,8) | 0 | 1 | 3 (state_confirmed 34, suppressed 34, state_reopened 1) | 0 | 4 | 3,2 |
| insider_hoarding | 102 | 97,1 | 99,0 (94,6 až 99,8) | 2 | 0 | 1 (state_open 2, suppressed 2) | 0 | 2 | 1,0 |
| apt_chain | 96 | 99,0 | 100,0 (96,1 až 100,0) | 1 | 0 | 0 (-) | 0 | 0 | 0,0 |
| fleet_beacon | 82 | 92,7 | 92,7 (84,9 až 96,6) | 0 | 0 | 2 (state_open 13, suppressed 13) | 4 | 13 | 7,3 |
| exfil_icmp_payload | 74 | 90,5 | 97,1 (90,0 až 99,2) | 5 | 2 | 0 (-) | 0 | 56 | 2,9 |
| c2_iot_mqtt_cloud | 69 | 91,3 | 96,9 (89,5 až 99,2) | 4 | 1 | 0 (-) | 1 | 3 | 3,1 |
| lateral_smb_admin_shares | 68 | 95,6 | 97,0 (89,8 až 99,2) | 1 | 0 | 1 (state_open 6, suppressed 6) | 1 | 1 | 3,0 |
| ldap_directory_enum_bulk | 68 | 97,1 | 97,1 (89,9 až 99,2) | 0 | 0 | 1 (state_open 10, suppressed 10) | 1 | 3 | 2,9 |
| ddos_ntp_amplification | 67 | 91,0 | 100,0 (94,1 až 100,0) | 6 | 0 | 0 (-) | 0 | 1 | 0,0 |
| exfil_cloud_storage_upload | 66 | 47,0 | 55,4 (42,4 až 67,6) | 10 | 20 | 2 (state_confirmed 1, suppressed 1, state_new 1) | 3 | 20 | 44,6 |
| oauth_token_abuse_periodic | 66 | 90,9 | 92,3 (83,2 až 96,7) | 1 | 4 | 0 (-) | 1 | 3 | 7,7 |
| exfil_scheduled_chunks | 65 | 87,7 | 95,0 (86,3 až 98,3) | 5 | 2 | 0 (-) | 1 | 2 | 5,0 |
| data_staging_smb_internal | 64 | 89,1 | 90,5 (80,7 až 95,6) | 1 | 2 | 2 (state_open 16, suppressed 16) | 2 | 5 | 9,5 |
| imap_spray | 62 | 91,9 | 96,6 (88,5 až 99,1) | 3 | 1 | 0 (-) | 1 | 0 | 3,4 |
| rdp_sweep_ext | 62 | 88,7 | 91,7 (81,9 až 96,4) | 2 | 2 | 2 (state_open 12, suppressed 12) | 1 | 2 | 8,3 |
| lateral_ssh_hop | 61 | 85,2 | 86,7 (75,8 až 93,1) | 1 | 0 | 5 (state_open 92, suppressed 92) | 3 | 5 | 13,3 |
| ntlm_relay_style_fanout | 60 | 80,0 | 81,4 (69,6 až 89,3) | 1 | 0 | 4 (state_open 263, suppressed 263) | 7 | 1 | 18,6 |
| mail_forward_smtp_exfil | 60 | 88,3 | 93,0 (83,3 až 97,2) | 3 | 4 | 0 (-) | 0 | 7 | 7,0 |
| lateral_winrm | 59 | 98,3 | 98,3 (91,0 až 99,7) | 0 | 0 | 1 (state_open 29, suppressed 29) | 0 | 4 | 1,7 |
| ldap_bind_spray | 58 | 94,8 | 96,5 (88,1 až 99,0) | 1 | 0 | 2 (suppressed 10, state_confirmed 6, state_open 5) | 0 | 1 | 3,5 |
| mysql_login_failures | 58 | 72,4 | 93,3 (82,1 až 97,7) | 13 | 3 | 0 (-) | 0 | 2 | 6,7 |
| snmp_walk_internal | 58 | 93,1 | 94,7 (85,6 až 98,2) | 1 | 0 | 2 (suppressed 22, state_open 17, state_confirmed 5) | 1 | 1 | 5,3 |
| c2_ntp_port_misuse | 58 | 86,2 | 92,6 (82,4 až 97,1) | 4 | 3 | 1 (state_confirmed 1, suppressed 1) | 0 | 0 | 7,4 |
| clicks_to_rare_destination | 58 | 8,6 | 10,0 (4,3 až 21,4) | 8 | 39 | 6 (suppressed 18, state_open 10, state_confirmed 8) | 0 | 5 | 90,0 |
| bucket_mass_download | 58 | 39,7 | 44,2 (31,6 až 57,7) | 6 | 26 | 1 (state_open 1, suppressed 1) | 2 | 21 | 55,8 |
| c2_icmp_tunnel | 57 | 89,5 | 98,1 (89,9 až 99,7) | 5 | 0 | 0 (-) | 1 | 6 | 1,9 |
| update_channel_compromise_fleet | 57 | 94,7 | 94,7 (85,6 až 98,2) | 0 | 1 | 2 (state_open 27, suppressed 27) | 0 | 3 | 5,3 |
| lateral_wmi_dcom | 56 | 92,9 | 92,9 (83,0 až 97,2) | 0 | 0 | 1 (state_confirmed 6, suppressed 6) | 3 | 2 | 7,1 |
| c2_https_legit_service | 56 | 76,8 | 81,1 (68,6 až 89,4) | 3 | 8 | 2 (state_open 6, suppressed 6) | 0 | 0 | 18,9 |
| ddos_syn_flood_distributed | 56 | 80,4 | 90,0 (78,6 až 95,7) | 6 | 0 | 4 (state_open 16, suppressed 16) | 1 | 2 | 10,0 |
| dns_zone_enum_burst | 55 | 63,6 | 66,0 (52,6 až 77,3) | 2 | 7 | 8 (state_open 47, suppressed 47) | 3 | 31 | 34,0 |
| ssh_spray_slow_distributed | 55 | 85,5 | 90,4 (79,4 až 95,8) | 3 | 0 | 3 (state_open 27, suppressed 27, state_reopened 1) | 2 | 2 | 9,6 |
| c2_high_jitter | 55 | 69,1 | 77,6 (64,1 až 87,0) | 6 | 10 | 0 (-) | 1 | 6 | 22,4 |
| c2_cdn_fronted | 55 | 80,0 | 89,8 (78,2 až 95,6) | 6 | 4 | 1 (state_open 3, suppressed 2, verifying 1) | 0 | 0 | 10,2 |
| exfil_dns_slow | 54 | 79,6 | 82,7 (70,3 až 90,6) | 2 | 1 | 2 (state_open 16, suppressed 16) | 6 | 23 | 17,3 |
| smb_login_failures | 54 | 98,1 | 98,1 (90,2 až 99,7) | 0 | 0 | 0 (-) | 1 | 2 | 1,9 |
| data_destruction_smb_wave | 54 | 81,5 | 84,6 (72,5 až 92,0) | 2 | 0 | 7 (suppressed 92, state_open 89, state_confirmed 3) | 1 | 2 | 15,4 |
| c2_udp_custom_port | 54 | 94,4 | 94,4 (84,9 až 98,1) | 0 | 3 | 0 (-) | 0 | 1 | 5,6 |
| exfil_https_burst | 54 | 59,3 | 69,6 (55,2 až 80,9) | 8 | 11 | 2 (state_open 12, suppressed 12) | 1 | 12 | 30,4 |
| lateral_cautious_one_target | 53 | 96,2 | 96,2 (87,2 až 99,0) | 0 | 0 | 1 (state_open 96, suppressed 96) | 1 | 3 | 3,8 |
| dc_replication_from_workstation | 53 | 94,3 | 96,2 (87,0 až 98,9) | 1 | 0 | 1 (suppressed 11, state_confirmed 6, state_open 5) | 1 | 7 | 3,8 |
| lateral_rdp_hop | 52 | 90,4 | 90,4 (79,4 až 95,8) | 0 | 0 | 3 (suppressed 79, state_open 73, state_confirmed 7) | 2 | 7 | 9,6 |
| drive_by_bulk_download | 51 | 64,7 | 71,7 (57,5 až 82,7) | 5 | 11 | 2 (state_open 3, suppressed 3) | 0 | 31 | 28,3 |
| mqtt_probe_ext | 51 | 72,5 | 72,5 (59,1 až 82,9) | 0 | 9 | 3 (state_open 16, suppressed 16) | 2 | 2 | 27,5 |
| ftp_bruteforce | 51 | 84,3 | 95,6 (85,2 až 98,8) | 6 | 0 | 0 (-) | 2 | 0 | 4,4 |
| c2_doh_resolver | 51 | 90,2 | 95,8 (86,0 až 98,8) | 3 | 2 | 0 (-) | 0 | 3 | 4,2 |
| c2_internal_proxy_chain | 51 | 98,0 | 98,0 (89,7 až 99,7) | 0 | 0 | 0 (-) | 1 | 6 | 2,0 |
| vnc_probe_ext | 50 | 96,0 | 96,0 (86,5 až 98,9) | 0 | 0 | 1 (state_open 15, suppressed 15) | 1 | 2 | 4,0 |
| snmp_sweep_ext | 50 | 94,0 | 95,9 (86,3 až 98,9) | 1 | 0 | 2 (suppressed 37, state_open 24, state_confirmed 13) | 0 | 0 | 4,1 |
| ddos_dns_amplification | 50 | 88,0 | 91,7 (80,4 až 96,7) | 2 | 1 | 1 (suppressed 184, state_confirmed 143, state_open 41) | 2 | 18 | 8,3 |
| web_scanner_404_storm | 50 | 92,0 | 97,9 (88,9 až 99,6) | 3 | 0 | 1 (state_open 6, suppressed 6) | 0 | 7 | 2,1 |
| distributed_low_port_probe | 50 | 80,0 | 85,1 (72,3 až 92,6) | 3 | 1 | 5 (suppressed 50, state_open 33, state_confirmed 17) | 1 | 0 | 14,9 |
| insider_after_hours_cloud_sync | 50 | 66,0 | 75,0 (60,6 až 85,4) | 6 | 9 | 0 (-) | 2 | 12 | 25,0 |
| share_encryption_wave_slow | 49 | 95,9 | 95,9 (86,3 až 98,9) | 0 | 0 | 1 (state_open 2, suppressed 2) | 1 | 6 | 4,1 |
| public_app_probe_trickle | 49 | 77,6 | 79,2 (65,7 až 88,3) | 1 | 4 | 2 (state_open 2, suppressed 2) | 4 | 25 | 20,8 |
| exfil_over_c2_trickle | 49 | 81,6 | 83,3 (70,4 až 91,3) | 1 | 7 | 0 (-) | 1 | 4 | 16,7 |
| vendor_remote_access_odd_hours | 49 | 44,9 | 46,8 (33,3 až 60,8) | 2 | 14 | 7 (state_open 54, suppressed 54) | 4 | 17 | 53,2 |
| resource_hijack_pool_tls | 49 | 95,9 | 97,9 (89,1 až 99,6) | 1 | 0 | 0 (-) | 0 | 1 | 2,1 |
| smb_share_enum_internal | 49 | 77,6 | 77,6 (64,1 až 87,0) | 0 | 1 | 3 (suppressed 90, state_open 83, state_confirmed 7) | 7 | 2 | 22,4 |
| api_enum_distributed | 48 | 83,3 | 90,9 (78,8 až 96,4) | 4 | 0 | 1 (state_open 2, suppressed 2) | 3 | 1 | 9,1 |
| c2_cloud_storage_dead_drop | 48 | 47,9 | 57,5 (42,2 až 71,5) | 8 | 10 | 2 (state_open 2, suppressed 2) | 5 | 18 | 42,5 |
| cloud_api_discovery_burst | 47 | 31,9 | 35,7 (23,0 až 50,8) | 5 | 25 | 2 (suppressed 17, state_open 14, state_confirmed 3) | 0 | 14 | 64,3 |
| http_slow_connections_dos | 47 | 61,7 | 67,4 (52,5 až 79,5) | 4 | 2 | 9 (suppressed 66, state_open 52, state_confirmed 14) | 3 | 6 | 32,6 |
| c2_slow_long_interval | 45 | 82,2 | 86,0 (72,7 až 93,4) | 2 | 3 | 0 (-) | 3 | 2 | 14,0 |
| c2_dns_txt_beacon | 45 | 84,4 | 86,4 (73,3 až 93,6) | 1 | 2 | 2 (state_open 1450, suppressed 1450) | 2 | 28 | 13,6 |
| c2_irc_style_channel | 44 | 86,4 | 92,7 (80,6 až 97,5) | 3 | 3 | 0 (-) | 0 | 0 | 7,3 |
| rdp_bruteforce | 44 | 100,0 | 100,0 (92,0 až 100,0) | 0 | 0 | 0 (-) | 0 | 0 | 0,0 |
| exfil_alt_protocol_ftp | 44 | 63,6 | 73,7 (58,0 až 85,0) | 6 | 10 | 0 (-) | 0 | 25 | 26,3 |
| kerberos_ticket_request_burst | 44 | 95,5 | 97,7 (87,9 až 99,6) | 1 | 0 | 1 (state_open 6, suppressed 6) | 0 | 3 | 2,3 |
| smb_sweep_ext | 43 | 81,4 | 81,4 (67,4 až 90,3) | 0 | 1 | 5 (state_open 42, suppressed 42) | 2 | 3 | 18,6 |
| onion_style_circuit_egress | 43 | 81,4 | 94,6 (82,3 až 98,5) | 6 | 1 | 0 (-) | 1 | 0 | 5,4 |
| backup_service_probing | 41 | 95,1 | 95,1 (83,9 až 98,7) | 0 | 0 | 1 (state_open 1, suppressed 1) | 1 | 7 | 4,9 |
| smtp_auth_spray | 40 | 90,0 | 94,7 (82,7 až 98,5) | 2 | 0 | 0 (-) | 2 | 0 | 5,3 |
| c2_websocket_long | 40 | 80,0 | 86,5 (72,0 až 94,1) | 3 | 4 | 1 (state_open 4, suppressed 4) | 0 | 0 | 13,5 |
| mssql_login_failures | 39 | 84,6 | 100,0 (89,6 až 100,0) | 6 | 0 | 0 (-) | 0 | 0 | 0,0 |
| app_layer_flood_api | 39 | 89,7 | 100,0 (90,1 až 100,0) | 4 | 0 | 0 (-) | 0 | 0 | 0,0 |
| c2_alt_port_8443 | 37 | 86,5 | 97,0 (84,7 až 99,5) | 4 | 1 | 0 (-) | 0 | 0 | 3,0 |
| vpn_password_spray_slow | 36 | 61,1 | 61,1 (44,9 až 75,2) | 0 | 5 | 2 (state_open 56, suppressed 56) | 6 | 6 | 38,9 |
| telnet_iot_login | 35 | 54,3 | 57,6 (40,8 až 72,8) | 2 | 13 | 0 (-) | 1 | 1 | 42,4 |

Rodin (n ≥ 20): 93; z viditelných útoků nad 90 %: 60, nad 95 %: 36, na 100 %: 5.
