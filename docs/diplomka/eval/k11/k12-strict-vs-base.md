## krok12 phase1

| ukazatel | základ | kandidát |
|---|---|---|
| sítí | 40 | 40 |
| zobrazené FP na síť-den | 10.47 | 11.73 (poměr 1.120) |
| útoky s omylem zavřeným nálezem | 26 (0,7 %) | 1 (0,0 %) |
| detekce bezpečnostních útoků (bez poruch a hn_*) | 85,6 (84,2 až 87,0) | 86,7 (85,3 až 88,0) |

### Opravené rodiny

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| drive_by_bulk_download | 13/13 | 15,4 (4,3 až 42,2) | 61,5 (35,5 až 82,3) | +46,2 |
| bucket_mass_download | 12/12 | 0,0 (0,0 až 24,2) | 0,0 (0,0 až 24,2) | +0,0 |
| exfil_alt_protocol_ftp | 14/14 | 21,4 (7,6 až 47,6) | 78,6 (52,4 až 92,4) | +57,1 |
| cloud_api_discovery_burst | 20/20 | 25,0 (11,2 až 46,9) | 25,0 (11,2 až 46,9) | +0,0 |
| clicks_to_rare_destination | 13/13 | 0,0 (0,0 až 22,8) | 0,0 (0,0 až 22,8) | +0,0 |
| port_scan_horizontal | 101/101 | 88,1 (80,4 až 93,1) | 88,1 (80,4 až 93,1) | +0,0 |

### Velké rodiny (kontrola, že se nezhoršily)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| c2_beacon | 114/114 | 86,8 (79,4 až 91,9) | 87,7 (80,4 až 92,5) | +0,9 |
| port_scan_horizontal | 101/101 | 88,1 (80,4 až 93,1) | 88,1 (80,4 až 93,1) | +0,0 |
| port_scan_vertical | 109/109 | 90,8 (83,9 až 94,9) | 90,8 (83,9 až 94,9) | +0,0 |
| exploit_attempt | 119/119 | 85,7 (78,3 až 90,9) | 85,7 (78,3 až 90,9) | +0,0 |
| exfiltration | 83/83 | 85,5 (76,4 až 91,5) | 85,5 (76,4 až 91,5) | +0,0 |
| credential_stuffing | 84/84 | 84,5 (75,3 až 90,7) | 84,5 (75,3 až 90,7) | +0,0 |
| cryptomining | 53/53 | 92,5 (82,1 až 97,0) | 92,5 (82,1 až 97,0) | +0,0 |

### Neškodné změny hn_* (podíl zobrazených = FP z pohledu útoku)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| hn_admin_bulk_ssh | 88/88 | 86,4 (77,7 až 92,0) | 87,5 (79,0 až 92,9) | +1,1 |
| hn_authorized_internal_scan | 73/73 | 98,6 (92,6 až 99,8) | 97,3 (90,5 až 99,2) | -1,4 |
| hn_cdn_update_download | 88/88 | 9,1 (4,7 až 16,9) | 10,2 (5,5 až 18,3) | +1,1 |
| hn_db_replication_bulk | 82/82 | 78,0 (67,9 až 85,6) | 76,8 (66,6 až 84,6) | -1,2 |
| hn_mail_newsletter_burst | 70/70 | 8,6 (4,0 až 17,5) | 10,0 (4,9 až 19,2) | +1,4 |
| hn_monitoring_snmp_sweep | 84/84 | 85,7 (76,7 až 91,6) | 85,7 (76,7 až 91,6) | +0,0 |
| hn_nightly_cloud_backup_upload | 73/73 | 56,2 (44,8 až 67,0) | 56,2 (44,8 až 67,0) | +0,0 |
| hn_password_sync_periodic | 93/93 | 93,5 (86,6 až 97,0) | 92,5 (85,3 až 96,3) | -1,1 |

### Přenos na ostatní bezpečnostní rodiny (největší změny, LOFO)

| rodina | n | základ | kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| exfil_over_c2_trickle | 15 | 73,3 (48,0 až 89,1) | 93,3 (70,2 až 98,8) | +20,0 |
| mail_forward_smtp_exfil | 10 | 80,0 (49,0 až 94,3) | 100,0 (72,2 až 100,0) | +20,0 |
| exfil_cloud_storage_upload | 18 | 27,8 (12,5 až 50,9) | 44,4 (24,6 až 66,3) | +16,7 |
| data_staging_smb_internal | 12 | 91,7 (64,6 až 98,5) | 100,0 (75,8 až 100,0) | +8,3 |
| exfil_scheduled_chunks | 14 | 85,7 (60,1 až 96,0) | 92,9 (68,5 až 98,7) | +7,1 |
| exfil_https_burst | 15 | 73,3 (48,0 až 89,1) | 80,0 (54,8 až 93,0) | +6,7 |
| mqtt_probe_ext | 15 | 33,3 (15,2 až 58,3) | 40,0 (19,8 až 64,3) | +6,7 |
| telnet_iot_login | 15 | 53,3 (30,1 až 75,2) | 60,0 (35,7 až 80,2) | +6,7 |
| c2_high_jitter | 14 | 64,3 (38,8 až 83,7) | 57,1 (32,6 až 78,6) | -7,1 |
| ftp_bruteforce | 10 | 90,0 (59,6 až 98,2) | 80,0 (49,0 až 94,3) | -10,0 |

Všechny ostatní bezpečnostní rodiny dohromady: základ 87,9 (86,3 až 89,4), kandidát 88,6 (87,0 až 90,1).

