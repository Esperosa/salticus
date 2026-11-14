# Krok 11: ladění, základ (kb) proti kandidátu c1 (breadth + bulk_novel + peer_burst + scan_fresh), seedy 20261102 a 20261103

Rameno `kb` (základ) proti `c1` (kandidát), párově po sítích: 80 sítí, 6132 útoků a poruch s toky, 769 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 80,9 (79,9 až 81,9) | 86,6 (85,8 až 87,5) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 8,09 | 8,88 | poměr 1,098 (1,067 až 1,139); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 127,9 | 133,0 | poměr 1,040 (1,028 až 1,055) |
| útoky s omylem zavřeným nálezem | 49 (0,8 %) | 54 (0,9 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 55868 | 59359 |
| potvrzeno | 6566 | 7453 |
| vyvráceno | 351 | 305 |
| eskalováno (nerozhodnuto) | 48692 | 51320 |
| vyvráceno omylem (kontrafaktuál) | 17 | 17 |
| podíl případů pravdivého útoku mezi případy žebříku (kb) | 52,9 % z 55609 |
| podíl případů pravdivého útoku mezi případy žebříku (c1) | 52,5 % z 59078 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 334 z 351, kandidát 288 z 305. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 6067 z 6566, kandidát 6894 z 7453. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| hn_admin_bulk_ssh | benign_change | - | none | 152 | 80,9 (73,9 až 86,4) | 80,9 (73,9 až 86,4) | 69,7 (62,0 až 76,5) | pod prahem | c (otevřené) |
| hn_authorized_internal_scan | benign_change | - | none | 152 | 95,4 (90,8 až 97,8) | 95,4 (90,8 až 97,8) | 90,1 (84,4 až 93,9) | splněno | - |
| hn_cdn_update_download | benign_change | - | none | 139 | 11,5 (7,2 až 17,9) | 73,4 (65,5 až 80,0) | 2,9 (1,1 až 7,2) | pod prahem | b (zmírněno, zbývá mezera) |
| hn_db_replication_bulk | benign_change | - | none | 141 | 84,4 (77,5 až 89,5) | 85,8 (79,1 až 90,6) | 75,2 (67,4 až 81,6) | pod prahem | b (zmírněno, zbývá mezera) |
| hn_mail_newsletter_burst | benign_change | - | none | 121 | 2,5 (0,8 až 7,0) | 69,4 (60,7 až 76,9) | 1,7 (0,5 až 5,8) | pod prahem | b (zmírněno, zbývá mezera) |
| hn_monitoring_snmp_sweep | benign_change | - | none | 117 | 74,4 (65,8 až 81,4) | 74,4 (65,8 až 81,4) | 67,5 (58,6 až 75,3) | pod prahem | c (otevřené) |
| hn_nightly_cloud_backup_upload | benign_change | - | none | 147 | 60,5 (52,5 až 68,1) | 86,4 (79,9 až 91,0) | 51,7 (43,7 až 59,6) | pod prahem | b (zmírněno, zbývá mezera) |
| hn_password_sync_periodic | benign_change | - | none | 131 | 93,1 (87,5 až 96,3) | 93,1 (87,5 až 96,3) | 93,1 (87,5 až 96,3) | splněno | - |
| planned_maintenance_window | benign_change | - | none | 46 | 95,7 (85,5 až 98,8) | 95,7 (85,5 až 98,8) | 95,7 (85,5 až 98,8) | nedostatek dat | - |
| planned_patch_reboot_wave | benign_change | - | none | 28 | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | nedostatek dat | - |
| seasonal_peak_web | benign_change | - | none | 21 | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | 90,5 (71,1 až 97,3) | nedostatek dat | - |
| access_point_controller_failure | ops_fault | - | none | 28 | 92,9 (77,4 až 98,0) | 92,9 (77,4 až 98,0) | 89,3 (72,8 až 96,3) | nedostatek dat | - |
| app_server_crash_cascade | ops_fault | - | none | 33 | 100,0 (89,6 až 100,0) | 100,0 (89,6 až 100,0) | 100,0 (89,6 až 100,0) | nedostatek dat | - |
| backup_window_overrun | ops_fault | - | none | 20 | 90,0 (69,9 až 97,2) | 90,0 (69,9 až 97,2) | 75,0 (53,1 až 88,8) | nedostatek dat | - |
| broadcast_storm_loop | ops_fault | - | none | 23 | 21,7 (9,7 až 41,9) | 39,1 (22,2 až 59,2) | 34,8 (18,8 až 55,1) | nedostatek dat | - |
| cert_chain_misconfig_external | ops_fault | - | none | 36 | 91,7 (78,2 až 97,1) | 91,7 (78,2 až 97,1) | 88,9 (74,7 až 95,6) | nedostatek dat | - |
| cert_expired_internal_service | ops_fault | - | none | 19 | 15,8 (5,5 až 37,6) | 15,8 (5,5 až 37,6) | 10,5 (2,9 až 31,4) | nedostatek dat | - |
| core_router_flapping | ops_fault | - | none | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| db_overload_degradation | ops_fault | - | none | 23 | 100,0 (85,7 až 100,0) | 100,0 (85,7 až 100,0) | 100,0 (85,7 až 100,0) | nedostatek dat | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 29 | 13,8 (5,5 až 30,6) | 20,7 (9,8 až 38,4) | 10,3 (3,6 až 26,4) | nedostatek dat | - |
| dhcp_server_down | ops_fault | - | none | 28 | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | nedostatek dat | - |
| disk_full_backup_failure | ops_fault | - | none | 20 | 95,0 (76,4 až 99,1) | 95,0 (76,4 až 99,1) | 90,0 (69,9 až 97,2) | nedostatek dat | - |
| dns_partial_failure | ops_fault | - | none | 42 | 78,6 (64,1 až 88,3) | 78,6 (64,1 až 88,3) | 66,7 (51,6 až 79,0) | nedostatek dat | - |
| dns_slow_resolution | ops_fault | - | none | 34 | 55,9 (39,5 až 71,1) | 52,9 (36,7 až 68,5) | 47,1 (31,5 až 63,3) | nedostatek dat | - |
| duplicate_ip_conflict | ops_fault | - | none | 37 | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | 91,9 (78,7 až 97,2) | nedostatek dat | - |
| flapping_service | ops_fault | - | none | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 26 | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | nedostatek dat | - |
| load_balancer_partial_outage | ops_fault | - | none | 16 | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | 93,8 (71,7 až 98,9) | nedostatek dat | - |
| mail_relay_queue_retry | ops_fault | - | none | 39 | 100,0 (91,0 až 100,0) | 100,0 (91,0 až 100,0) | 100,0 (91,0 až 100,0) | nedostatek dat | - |
| mdns_ssdp_storm | ops_fault | - | none | 25 | 12,0 (4,2 až 30,0) | 40,0 (23,4 až 59,3) | 36,0 (20,2 až 55,5) | nedostatek dat | - |
| memory_exhaustion_stall | ops_fault | - | none | 32 | 96,9 (84,3 až 99,4) | 96,9 (84,3 až 99,4) | 96,9 (84,3 až 99,4) | nedostatek dat | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 23 | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | nedostatek dat | - |
| ntp_clock_drift_host | ops_fault | - | none | 34 | 94,1 (80,9 až 98,4) | 94,1 (80,9 až 98,4) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| ntp_unreachable | ops_fault | - | none | 34 | 61,8 (45,0 až 76,1) | 61,8 (45,0 až 76,1) | 38,2 (23,9 až 55,0) | nedostatek dat | - |
| slow_link_loss_degradation | ops_fault | - | none | 35 | 100,0 (90,1 až 100,0) | 100,0 (90,1 až 100,0) | 100,0 (90,1 až 100,0) | nedostatek dat | - |
| switch_outage_subnet | ops_fault | - | none | 26 | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | nedostatek dat | - |
| uplink_saturation | ops_fault | - | none | 28 | 17,9 (7,9 až 35,6) | 10,7 (3,7 až 27,2) | 3,6 (0,6 až 17,7) | nedostatek dat | - |
| vpn_concentrator_down | ops_fault | - | none | 19 | 89,5 (68,6 až 97,1) | 89,5 (68,6 až 97,1) | 89,5 (68,6 až 97,1) | nedostatek dat | - |
| api_enum_distributed | security | T1595.002 | reconnaissance | 18 | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | nedostatek dat | - |
| app_layer_flood_api | security | T1499.003 | impact | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 88,0 (70,0 až 95,8) | nedostatek dat | - |
| apt_chain | security | - | lateral-movement | 34 | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | nedostatek dat | - |
| backup_service_probing | security | T1490 | impact | 19 | 84,2 (62,4 až 94,5) | 89,5 (68,6 až 97,1) | 84,2 (62,4 až 94,5) | nedostatek dat | - |
| bucket_mass_download | security | T1530 | collection | 24 | 20,8 (9,2 až 40,5) | 79,2 (59,5 až 90,8) | 8,3 (2,3 až 25,8) | nedostatek dat | - |
| c2_alt_port_8443 | security | T1571 | command-and-control | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | nedostatek dat | - |
| c2_beacon | security | - | command-and-control | 183 | 91,3 (86,3 až 94,5) | 93,4 (88,9 až 96,2) | 70,5 (63,5 až 76,6) | detekce ano, typ ne | - |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 29 | 82,8 (65,5 až 92,4) | 82,8 (65,5 až 92,4) | 82,8 (65,5 až 92,4) | nedostatek dat | - |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 24 | 70,8 (50,8 až 85,1) | 70,8 (50,8 až 85,1) | 16,7 (6,7 až 35,9) | nedostatek dat | - |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 32 | 53,1 (36,4 až 69,1) | 56,2 (39,3 až 71,8) | 31,2 (18,0 až 48,6) | nedostatek dat | - |
| c2_doh_resolver | security | T1572 | command-and-control | 33 | 90,9 (76,4 až 96,9) | 90,9 (76,4 až 96,9) | 87,9 (72,7 až 95,2) | nedostatek dat | - |
| c2_high_jitter | security | T1071.001 | command-and-control | 22 | 59,1 (38,7 až 76,7) | 59,1 (38,7 až 76,7) | 54,5 (34,7 až 73,1) | nedostatek dat | - |
| c2_https_legit_service | security | T1102 | command-and-control | 31 | 90,3 (75,1 až 96,7) | 90,3 (75,1 až 96,7) | 90,3 (75,1 až 96,7) | nedostatek dat | - |
| c2_icmp_tunnel | security | T1095 | command-and-control | 31 | 96,8 (83,8 až 99,4) | 96,8 (83,8 až 99,4) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 37 | 100,0 (90,6 až 100,0) | 100,0 (90,6 až 100,0) | 97,3 (86,2 až 99,5) | nedostatek dat | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 30 | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | nedostatek dat | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 40 | 85,0 (70,9 až 92,9) | 85,0 (70,9 až 92,9) | 85,0 (70,9 až 92,9) | nedostatek dat | - |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 26 | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | nedostatek dat | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 35 | 91,4 (77,6 až 97,0) | 91,4 (77,6 až 97,0) | 85,7 (70,6 až 93,7) | nedostatek dat | - |
| c2_udp_custom_port | security | T1095 | command-and-control | 31 | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| c2_websocket_long | security | T1071.001 | command-and-control | 35 | 88,6 (74,0 až 95,5) | 88,6 (74,0 až 95,5) | 88,6 (74,0 až 95,5) | nedostatek dat | - |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 33 | 12,1 (4,8 až 27,3) | 33,3 (19,8 až 50,4) | 3,0 (0,5 až 15,3) | nedostatek dat | - |
| cloud_api_discovery_burst | security | T1580 | discovery | 24 | 4,2 (0,7 až 20,2) | 75,0 (55,1 až 88,0) | 0,0 (0,0 až 13,8) | nedostatek dat | - |
| credential_stuffing | security | - | credential-access | 97 | 86,6 (78,4 až 92,0) | 86,6 (78,4 až 92,0) | 84,5 (76,0 až 90,4) | pod prahem | c (otevřené) |
| cryptomining | security | - | impact | 91 | 87,9 (79,6 až 93,1) | 87,9 (79,6 až 93,1) | 82,4 (73,3 až 88,9) | pod prahem | c (otevřené) |
| data_destruction_smb_wave | security | T1485 | impact | 17 | 82,4 (59,0 až 93,8) | 82,4 (59,0 až 93,8) | 76,5 (52,7 až 90,4) | nedostatek dat | - |
| data_staging_smb_internal | security | T1039 | collection | 26 | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | 76,9 (57,9 až 89,0) | nedostatek dat | - |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 23 | 100,0 (85,7 až 100,0) | 100,0 (85,7 až 100,0) | 95,7 (79,0 až 99,2) | nedostatek dat | - |
| ddos_dns_amplification | security | T1498.002 | impact | 27 | 66,7 (47,8 až 81,4) | 66,7 (47,8 až 81,4) | 66,7 (47,8 až 81,4) | nedostatek dat | - |
| ddos_ntp_amplification | security | T1498.002 | impact | 38 | 100,0 (90,8 až 100,0) | 100,0 (90,8 až 100,0) | 97,4 (86,5 až 99,5) | nedostatek dat | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat | - |
| ddos_volume | security | - | impact | 66 | 95,5 (87,5 až 98,4) | 95,5 (87,5 až 98,4) | 92,4 (83,5 až 96,7) | splněno | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 36 | 83,3 (68,1 až 92,1) | 86,1 (71,3 až 93,9) | 83,3 (68,1 až 92,1) | nedostatek dat | - |
| dns_tunnel | security | - | command-and-control | 103 | 96,1 (90,4 až 98,5) | 98,1 (93,2 až 99,5) | 78,6 (69,8 až 85,5) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 21 | 9,5 (2,7 až 28,9) | 4,8 (0,8 až 22,7) | 4,8 (0,8 až 22,7) | nedostatek dat | - |
| drive_by_bulk_download | security | T1189 | initial-access | 35 | 11,4 (4,5 až 26,0) | 57,1 (40,9 až 72,0) | 0,0 (0,0 až 9,9) | nedostatek dat | - |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 15 | 13,3 (3,7 až 37,9) | 66,7 (41,7 až 84,8) | 13,3 (3,7 až 37,9) | nedostatek dat | - |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 28 | 28,6 (15,3 až 47,1) | 82,1 (64,4 až 92,1) | 17,9 (7,9 až 35,6) | nedostatek dat | - |
| exfil_dns_slow | security | T1048.003 | exfiltration | 43 | 81,4 (67,4 až 90,3) | 81,4 (67,4 až 90,3) | 60,5 (45,6 až 73,6) | nedostatek dat | - |
| exfil_https_burst | security | T1041 | exfiltration | 38 | 65,8 (49,9 až 78,8) | 89,5 (75,9 až 95,8) | 63,2 (47,3 až 76,6) | nedostatek dat | - |
| exfil_icmp_payload | security | T1048 | exfiltration | 25 | 36,0 (20,2 až 55,5) | 52,0 (33,5 až 70,0) | 8,0 (2,2 až 25,0) | nedostatek dat | - |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 25 | 56,0 (37,1 až 73,3) | 76,0 (56,6 až 88,5) | 76,0 (56,6 až 88,5) | nedostatek dat | - |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 28 | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | nedostatek dat | - |
| exfiltration | security | - | exfiltration | 133 | 94,0 (88,6 až 96,9) | 95,5 (90,5 až 97,9) | 92,5 (86,7 až 95,9) | splněno | - |
| exploit_attempt | security | - | initial-access | 228 | 89,5 (84,8 až 92,8) | 89,0 (84,3 až 92,5) | 48,2 (41,8 až 54,7) | pod prahem | c (otevřené) |
| fleet_beacon | security | - | command-and-control | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 80,0 (60,9 až 91,1) | nedostatek dat | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 30 | 86,7 (70,3 až 94,7) | 86,7 (70,3 až 94,7) | 83,3 (66,4 až 92,7) | nedostatek dat | - |
| http_slow_connections_dos | security | T1499.002 | impact | 16 | 68,8 (44,4 až 85,8) | 68,8 (44,4 až 85,8) | 56,2 (33,2 až 76,9) | nedostatek dat | - |
| ics_attack | security | - | impact | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat | - |
| ics_slow_poll_new_source | security | T0801 | collection | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 26 | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | nedostatek dat | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 24 | 37,5 (21,2 až 57,3) | 70,8 (50,8 až 85,1) | 37,5 (21,2 až 57,3) | nedostatek dat | - |
| insider_hoarding | security | - | exfiltration | 31 | 96,8 (83,8 až 99,4) | 96,8 (83,8 až 99,4) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 34 | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| lateral_movement | security | - | lateral-movement | 199 | 98,0 (94,9 až 99,2) | 98,0 (94,9 až 99,2) | 73,9 (67,4 až 79,5) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 38 | 89,5 (75,9 až 95,8) | 89,5 (75,9 až 95,8) | 73,7 (58,0 až 85,0) | nedostatek dat | - |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 27 | 88,9 (71,9 až 96,1) | 92,6 (76,6 až 97,9) | 88,9 (71,9 až 96,1) | nedostatek dat | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 36 | 83,3 (68,1 až 92,1) | 88,9 (74,7 až 95,6) | 83,3 (68,1 až 92,1) | nedostatek dat | - |
| lateral_winrm | security | T1021.006 | lateral-movement | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| lateral_wmi_dcom | security | T1047 | execution | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | nedostatek dat | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 25 | 96,0 (80,5 až 99,3) | 96,0 (80,5 až 99,3) | 92,0 (75,0 až 97,8) | nedostatek dat | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 28 | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | 92,9 (77,4 až 98,0) | nedostatek dat | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 26 | 65,4 (46,2 až 80,6) | 80,8 (62,1 až 91,5) | 73,1 (53,9 až 86,3) | nedostatek dat | - |
| mqtt_probe_ext | security | T1046 | discovery | 30 | 83,3 (66,4 až 92,7) | 86,7 (70,3 až 94,7) | 86,7 (70,3 až 94,7) | nedostatek dat | - |
| mssql_login_failures | security | T1110.001 | credential-access | 29 | 89,7 (73,6 až 96,4) | 89,7 (73,6 až 96,4) | 89,7 (73,6 až 96,4) | nedostatek dat | - |
| mysql_login_failures | security | T1110.001 | credential-access | 28 | 85,7 (68,5 až 94,3) | 85,7 (68,5 až 94,3) | 82,1 (64,4 až 92,1) | nedostatek dat | - |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 26 | 88,5 (71,0 až 96,0) | 84,6 (66,5 až 93,8) | 84,6 (66,5 až 93,8) | nedostatek dat | - |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 32 | 87,5 (71,9 až 95,0) | 87,5 (71,9 až 95,0) | 87,5 (71,9 až 95,0) | nedostatek dat | - |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 27 | 88,9 (71,9 až 96,1) | 88,9 (71,9 až 96,1) | 88,9 (71,9 až 96,1) | nedostatek dat | - |
| port_scan_horizontal | security | - | discovery | 147 | 85,0 (78,4 až 89,9) | 87,1 (80,7 až 91,6) | 83,0 (76,1 až 88,2) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 167 | 88,0 (82,2 až 92,1) | 88,6 (82,9 až 92,6) | 85,6 (79,5 až 90,1) | pod prahem | b (zmírněno, zbývá mezera) |
| public_app_probe_trickle | security | T1190 | initial-access | 12 | 91,7 (64,6 až 98,5) | 91,7 (64,6 až 98,5) | 50,0 (25,4 až 74,6) | nedostatek dat | - |
| ransomware | security | - | impact | 68 | 100,0 (94,7 až 100,0) | 100,0 (94,7 až 100,0) | 97,1 (89,9 až 99,2) | splněno | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat | - |
| rdp_sweep_ext | security | T1046 | discovery | 25 | 88,0 (70,0 až 95,8) | 96,0 (80,5 až 99,3) | 76,0 (56,6 až 88,5) | nedostatek dat | - |
| resource_hijack_pool_tls | security | T1496 | impact | 22 | 100,0 (85,1 až 100,0) | 100,0 (85,1 až 100,0) | 100,0 (85,1 až 100,0) | nedostatek dat | - |
| rogue_device | security | - | initial-access | 37 | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | 89,2 (75,3 až 95,7) | nedostatek dat | - |
| share_encryption_wave_slow | security | T1486 | impact | 22 | 90,9 (72,2 až 97,5) | 90,9 (72,2 až 97,5) | 77,3 (56,6 až 89,9) | nedostatek dat | - |
| slow_scan | security | - | discovery | 153 | 92,2 (86,8 až 95,5) | 96,7 (92,6 až 98,6) | 92,8 (87,6 až 95,9) | splněno | - |
| smb_login_failures | security | T1110 | credential-access | 30 | 96,7 (83,3 až 99,4) | 100,0 (88,6 až 100,0) | 96,7 (83,3 až 99,4) | nedostatek dat | - |
| smb_share_enum_internal | security | T1135 | discovery | 17 | 52,9 (31,0 až 73,8) | 52,9 (31,0 až 73,8) | 52,9 (31,0 až 73,8) | nedostatek dat | - |
| smb_sweep_ext | security | T1046 | discovery | 20 | 75,0 (53,1 až 88,8) | 80,0 (58,4 až 91,9) | 70,0 (48,1 až 85,5) | nedostatek dat | - |
| smtp_auth_spray | security | T1110.003 | credential-access | 24 | 83,3 (64,1 až 93,3) | 87,5 (69,0 až 95,7) | 87,5 (69,0 až 95,7) | nedostatek dat | - |
| snmp_sweep_ext | security | T1046 | discovery | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 84,0 (65,3 až 93,6) | nedostatek dat | - |
| snmp_walk_internal | security | T1602.001 | collection | 20 | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | nedostatek dat | - |
| ssh_bruteforce | security | - | credential-access | 245 | 94,3 (90,6 až 96,6) | 94,3 (90,6 až 96,6) | 83,3 (78,1 až 87,4) | detekce ano, typ ne | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 38 | 81,6 (66,6 až 90,8) | 81,6 (66,6 až 90,8) | 73,7 (58,0 až 85,0) | nedostatek dat | - |
| telnet_iot_login | security | T1110.001 | credential-access | 24 | 41,7 (24,5 až 61,2) | 41,7 (24,5 až 61,2) | 33,3 (18,0 až 53,3) | nedostatek dat | - |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 20 | 60,0 (38,7 až 78,1) | 60,0 (38,7 až 78,1) | 5,0 (0,9 až 23,6) | nedostatek dat | - |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 32 | 65,6 (48,3 až 79,6) | 65,6 (48,3 až 79,6) | 59,4 (42,3 až 74,5) | nedostatek dat | - |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 15 | 46,7 (24,8 až 69,9) | 46,7 (24,8 až 69,9) | 33,3 (15,2 až 58,3) | nedostatek dat | - |
| web_exploit | security | - | initial-access | 137 | 94,2 (88,9 až 97,0) | 94,2 (88,9 až 97,0) | 74,5 (66,6 až 81,0) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 23 | 95,7 (79,0 až 99,2) | 95,7 (79,0 až 99,2) | 78,3 (58,1 až 90,3) | nedostatek dat | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 97 | 69,1 (59,3 až 77,4) | 87,6 (79,6 až 92,8) | 63,9 (54,0 až 72,8) |
| command-and-control | 796 | 89,2 (86,8 až 91,2) | 90,1 (87,8 až 92,0) | 78,5 (75,5 až 81,2) |
| credential-access | 722 | 89,1 (86,6 až 91,1) | 89,3 (86,9 až 91,4) | 83,7 (80,8 až 86,2) |
| discovery | 636 | 84,1 (81,1 až 86,8) | 89,2 (86,5 až 91,3) | 82,1 (78,9 až 84,9) |
| execution | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) |
| exfiltration | 390 | 72,8 (68,2 až 77,0) | 85,9 (82,1 až 89,0) | 68,2 (63,4 až 72,6) |
| impact | 433 | 90,3 (87,1 až 92,7) | 90,5 (87,4 až 92,9) | 86,1 (82,6 až 89,1) |
| initial-access | 529 | 80,5 (76,9 až 83,7) | 84,7 (81,4 až 87,5) | 52,9 (48,7 až 57,1) |
| lateral-movement | 453 | 93,2 (90,5 až 95,1) | 93,6 (91,0 až 95,5) | 79,9 (76,0 až 83,3) |
| none | 1956 | 71,2 (69,2 až 73,2) | 82,3 (80,6 až 83,9) | 66,4 (64,2 až 68,4) |
| reconnaissance | 98 | 69,4 (59,7 až 77,6) | 69,4 (59,7 až 77,6) | 64,3 (54,4 až 73,1) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 1195 | 66,6 (63,9 až 69,2) | 83,9 (81,7 až 85,9) | 60,5 (57,7 až 63,2) | 0,0 % |
| ops_fault | 761 | 78,4 (75,4 až 81,2) | 79,8 (76,8 až 82,5) | 75,6 (72,4 až 78,5) | 0,0 % |
| security | 4176 | 85,4 (84,3 až 86,5) | 88,6 (87,7 až 89,6) | 76,1 (74,8 až 77,4) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 722 | 89,1 (86,6 až 91,1) | 89,3 (86,9 až 91,4) | 83,7 (80,8 až 86,2) | nedosaženo |
| taktika discovery | 636 | 84,1 (81,1 až 86,8) | 89,2 (86,5 až 91,3) | 82,1 (78,9 až 84,9) | nedosaženo |
| taktika lateral-movement | 453 | 93,2 (90,5 až 95,1) | 93,6 (91,0 až 95,5) | 79,9 (76,0 až 83,3) | splněno |
| rodina c2_slow_long_interval | 35 | 91,4 (77,6 až 97,0) | 91,4 (77,6 až 97,0) | 85,7 (70,6 až 93,7) | nedostatek dat |
| rodina ssh_spray_slow_distributed | 38 | 81,6 (66,6 až 90,8) | 81,6 (66,6 až 90,8) | 73,7 (58,0 až 85,0) | nedostatek dat |
| rodina data_staging_smb_internal | 26 | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | 76,9 (57,9 až 89,0) | nedostatek dat |
| rodina kerberos_ticket_request_burst | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat |
| rodina ics_attack | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat |
| rodina cloud_api_discovery_burst | 24 | 4,2 (0,7 až 20,2) | 75,0 (55,1 až 88,0) | 0,0 (0,0 až 13,8) | nedostatek dat |
| rodina rdp_bruteforce | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat |
| rodina ddos_syn_flood_distributed | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| hn_mail_newsletter_burst (benign_change) | 121 | 69,4 | b (zmírněno, zbývá mezera) |
| hn_cdn_update_download (benign_change) | 139 | 73,4 | b (zmírněno, zbývá mezera) |
| hn_monitoring_snmp_sweep (benign_change) | 117 | 74,4 | c (otevřené) |
| hn_admin_bulk_ssh (benign_change) | 152 | 80,9 | c (otevřené) |
| hn_db_replication_bulk (benign_change) | 141 | 85,8 | b (zmírněno, zbývá mezera) |
| hn_nightly_cloud_backup_upload (benign_change) | 147 | 86,4 | b (zmírněno, zbývá mezera) |
| credential_stuffing (security) | 97 | 86,6 | c (otevřené) |
| port_scan_horizontal (security) | 147 | 87,1 | b (zmírněno, zbývá mezera) |
| cryptomining (security) | 91 | 87,9 | c (otevřené) |
| port_scan_vertical (security) | 167 | 88,6 | b (zmírněno, zbývá mezera) |
| exploit_attempt (security) | 228 | 89,0 | c (otevřené) |

