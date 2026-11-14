## Krok 11: držené seedy 20263101 a 20263102, základ proti kandidátu B (breadth + bulk_novel + peer_burst + scan_fresh)

| ukazatel | základ | kandidát |
|---|---|---|
| sítí | 80 | 80 |
| zobrazené FP na síť-den | 8.98 | 10.26 (poměr 1.142) |
| útoky s omylem zavřeným nálezem | 50 (0,7 %) | 45 (0,6 %) |
| detekce bezpečnostních útoků (bez poruch a hn_*) | 85,9 (84,9 až 86,9) | 89,4 (88,5 až 90,2) |

### Opravené rodiny

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| drive_by_bulk_download | 25/25 | 8,0 (2,2 až 25,0) | 52,0 (33,5 až 70,0) | +44,0 |
| bucket_mass_download | 26/26 | 3,8 (0,7 až 18,9) | 80,8 (62,1 až 91,5) | +76,9 |
| exfil_alt_protocol_ftp | 26/26 | 19,2 (8,5 až 37,9) | 76,9 (57,9 až 89,0) | +57,7 |
| cloud_api_discovery_burst | 35/35 | 17,1 (8,1 až 32,7) | 80,0 (64,1 až 90,0) | +62,9 |
| clicks_to_rare_destination | 31/31 | 6,5 (1,8 až 20,7) | 19,4 (9,2 až 36,3) | +12,9 |
| port_scan_horizontal | 196/196 | 88,8 (83,6 až 92,5) | 91,3 (86,5 až 94,5) | +2,6 |

### Velké rodiny (kontrola, že se nezhoršily)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| c2_beacon | 226/226 | 85,0 (79,7 až 89,0) | 92,5 (88,3 až 95,3) | +7,5 |
| port_scan_horizontal | 196/196 | 88,8 (83,6 až 92,5) | 91,3 (86,5 až 94,5) | +2,6 |
| port_scan_vertical | 219/219 | 90,9 (86,3 až 94,0) | 93,6 (89,6 až 96,2) | +2,7 |
| exploit_attempt | 260/260 | 85,4 (80,6 až 89,2) | 85,8 (81,0 až 89,5) | +0,4 |
| exfiltration | 163/163 | 89,0 (83,2 až 92,9) | 92,6 (87,6 až 95,7) | +3,7 |
| credential_stuffing | 149/149 | 90,6 (84,8 až 94,3) | 90,6 (84,8 až 94,3) | +0,0 |
| cryptomining | 114/114 | 93,9 (87,9 až 97,0) | 93,9 (87,9 až 97,0) | +0,0 |

### Neškodné změny hn_* (podíl zobrazených = FP z pohledu útoku)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| hn_admin_bulk_ssh | 174/174 | 84,5 (78,4 až 89,1) | 85,1 (79,0 až 89,6) | +0,6 |
| hn_authorized_internal_scan | 158/158 | 98,1 (94,6 až 99,4) | 98,1 (94,6 až 99,4) | +0,0 |
| hn_cdn_update_download | 178/178 | 10,1 (6,5 až 15,4) | 79,8 (73,3 až 85,0) | +69,7 |
| hn_db_replication_bulk | 140/140 | 79,3 (71,8 až 85,2) | 79,3 (71,8 až 85,2) | +0,0 |
| hn_mail_newsletter_burst | 163/163 | 9,2 (5,7 až 14,6) | 79,8 (72,9 až 85,2) | +70,6 |
| hn_monitoring_snmp_sweep | 171/171 | 81,9 (75,4 až 86,9) | 83,0 (76,7 až 87,9) | +1,2 |
| hn_nightly_cloud_backup_upload | 171/171 | 55,0 (47,5 až 62,2) | 84,2 (78,0 až 88,9) | +29,2 |
| hn_password_sync_periodic | 174/174 | 93,1 (88,3 až 96,0) | 93,7 (89,0 až 96,4) | +0,6 |

### Přenos na ostatní bezpečnostní rodiny (největší změny, LOFO)

| rodina | n | základ | kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| exfil_cloud_storage_upload | 31 | 35,5 (21,1 až 53,1) | 80,6 (63,7 až 90,8) | +45,2 |
| exfil_https_burst | 34 | 64,7 (47,9 až 78,5) | 91,2 (77,0 až 97,0) | +26,5 |
| mail_forward_smtp_exfil | 22 | 63,6 (43,0 až 80,3) | 86,4 (66,7 až 95,3) | +22,7 |
| insider_after_hours_cloud_sync | 18 | 55,6 (33,7 až 75,4) | 77,8 (54,8 až 91,0) | +22,2 |
| mqtt_probe_ext | 23 | 34,8 (18,8 až 55,1) | 52,2 (33,0 až 70,8) | +17,4 |
| exfil_over_c2_trickle | 30 | 70,0 (52,1 až 83,3) | 83,3 (66,4 až 92,7) | +13,3 |
| smb_sweep_ext | 35 | 77,1 (61,0 až 87,9) | 85,7 (70,6 až 93,7) | +8,6 |
| exfil_icmp_payload | 29 | 69,0 (50,8 až 82,7) | 75,9 (57,9 až 87,8) | +6,9 |
| ftp_bruteforce | 29 | 96,6 (82,8 až 99,4) | 93,1 (78,0 až 98,1) | -3,4 |
| smb_login_failures | 27 | 100,0 (87,5 až 100,0) | 96,3 (81,7 až 99,3) | -3,7 |
| api_enum_distributed | 21 | 85,7 (65,4 až 95,0) | 81,0 (60,0 až 92,3) | -4,8 |

Všechny ostatní bezpečnostní rodiny dohromady: základ 88,1 (87,0 až 89,2), kandidát 89,9 (88,8 až 90,9).

