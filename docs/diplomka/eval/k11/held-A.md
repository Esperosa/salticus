## Krok 11: držené seedy (jednou), základ proti kandidátu A (breadth + bulk_clear)

| ukazatel | základ | kandidát |
|---|---|---|
| sítí | 240 | 240 |
| zobrazené FP na síť-den | 9.29 | 10.04 (poměr 1.081) |
| útoky s omylem zavřeným nálezem | 154 (0,7 %) | 148 (0,7 %) |
| detekce bezpečnostních útoků (bez poruch a hn_*) | 85,9 (85,3 až 86,4) | 86,8 (86,3 až 87,4) |

### Opravené rodiny

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| drive_by_bulk_download | 75/75 | 8,0 (3,7 až 16,4) | 52,0 (40,9 až 62,9) | +44,0 |
| bucket_mass_download | 90/90 | 5,6 (2,4 až 12,4) | 6,7 (3,1 až 13,8) | +1,1 |
| exfil_alt_protocol_ftp | 76/76 | 18,4 (11,3 až 28,6) | 78,9 (68,5 až 86,6) | +60,5 |
| cloud_api_discovery_burst | 88/88 | 13,6 (8,0 až 22,3) | 13,6 (8,0 až 22,3) | +0,0 |
| clicks_to_rare_destination | 84/84 | 9,5 (4,9 až 17,7) | 9,5 (4,9 až 17,7) | +0,0 |
| port_scan_horizontal | 560/560 | 85,5 (82,4 až 88,2) | 85,4 (82,2 až 88,0) | -0,2 |

### Velké rodiny (kontrola, že se nezhoršily)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| c2_beacon | 716/716 | 85,8 (83,0 až 88,1) | 86,0 (83,3 až 88,4) | +0,3 |
| port_scan_horizontal | 560/560 | 85,5 (82,4 až 88,2) | 85,4 (82,2 až 88,0) | -0,2 |
| port_scan_vertical | 644/644 | 90,7 (88,2 až 92,7) | 90,7 (88,2 až 92,7) | +0,0 |
| exploit_attempt | 783/783 | 88,0 (85,5 až 90,1) | 88,0 (85,5 až 90,1) | +0,0 |
| exfiltration | 522/522 | 91,4 (88,7 až 93,5) | 91,4 (88,7 až 93,5) | +0,0 |
| credential_stuffing | 426/426 | 91,8 (88,8 až 94,0) | 91,8 (88,8 až 94,0) | +0,0 |
| cryptomining | 336/336 | 94,9 (92,0 až 96,8) | 95,2 (92,4 až 97,0) | +0,3 |

### Neškodné změny hn_* (podíl zobrazených = FP z pohledu útoku)

| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| hn_admin_bulk_ssh | 471/471 | 81,7 (78,0 až 85,0) | 81,3 (77,5 až 84,6) | -0,4 |
| hn_authorized_internal_scan | 462/462 | 97,4 (95,5 až 98,5) | 97,4 (95,5 až 98,5) | +0,0 |
| hn_cdn_update_download | 489/489 | 11,7 (9,1 až 14,8) | 11,7 (9,1 až 14,8) | +0,0 |
| hn_db_replication_bulk | 461/461 | 80,0 (76,2 až 83,4) | 80,3 (76,4 až 83,6) | +0,2 |
| hn_mail_newsletter_burst | 455/455 | 8,1 (6,0 až 11,0) | 8,8 (6,5 až 11,8) | +0,7 |
| hn_monitoring_snmp_sweep | 453/453 | 80,8 (76,9 až 84,2) | 80,6 (76,7 až 84,0) | -0,2 |
| hn_nightly_cloud_backup_upload | 447/447 | 51,9 (47,3 až 56,5) | 52,1 (47,5 až 56,7) | +0,2 |
| hn_password_sync_periodic | 467/467 | 94,2 (91,7 až 96,0) | 94,2 (91,7 až 96,0) | +0,0 |

### Přenos na ostatní bezpečnostní rodiny (největší změny, LOFO)

| rodina | n | základ | kandidát | rozdíl p. b. |
|---|---:|---|---|---:|
| mail_forward_smtp_exfil | 70 | 61,4 (49,7 až 72,0) | 84,3 (74,0 až 91,0) | +22,9 |
| exfil_over_c2_trickle | 83 | 66,3 (55,6 až 75,5) | 84,3 (75,0 až 90,6) | +18,1 |
| exfil_cloud_storage_upload | 82 | 32,9 (23,7 až 43,7) | 40,2 (30,3 až 51,1) | +7,3 |
| mqtt_probe_ext | 76 | 51,3 (40,3 až 62,2) | 55,3 (44,1 až 65,9) | +3,9 |
| vendor_remote_access_odd_hours | 42 | 26,2 (15,3 až 41,1) | 28,6 (17,2 až 43,6) | +2,4 |
| exfil_icmp_payload | 88 | 62,5 (52,1 až 71,9) | 64,8 (54,4 až 73,9) | +2,3 |
| c2_dns_txt_beacon | 97 | 61,9 (51,9 až 70,9) | 63,9 (54,0 až 72,8) | +2,1 |
| smb_share_enum_internal | 73 | 83,6 (73,4 až 90,3) | 84,9 (75,0 až 91,4) | +1,4 |
| dc_replication_from_workstation | 88 | 97,7 (92,1 až 99,4) | 96,6 (90,5 až 98,8) | -1,1 |
| smb_login_failures | 81 | 97,5 (91,4 až 99,3) | 96,3 (89,7 až 98,7) | -1,2 |
| imap_spray | 78 | 92,3 (84,2 až 96,4) | 91,0 (82,6 až 95,6) | -1,3 |
| api_enum_distributed | 58 | 91,4 (81,4 až 96,3) | 89,7 (79,2 až 95,2) | -1,7 |

Všechny ostatní bezpečnostní rodiny dohromady: základ 87,7 (87,0 až 88,3), kandidát 88,3 (87,6 až 88,9).

