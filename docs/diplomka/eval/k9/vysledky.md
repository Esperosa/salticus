# Výsledky kroku 9, ladicí seedy

Rameno `base` (základ) proti `cand` (kandidát), párově po sítích: 80 sítí, 5032 útoků a poruch s toky, 769 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 84,0 (83,0 až 85,0) | 84,5 (83,4 až 85,4) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 8,70 | 9,05 | poměr 1,041 (1,025 až 1,062); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 126,1 | 128,2 | poměr 1,017 (1,010 až 1,026) |
| útoky s omylem zavřeným nálezem | 46 (0,9 %) | 51 (1,0 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 55014 | 56654 |
| potvrzeno | 6166 | 6591 |
| vyvráceno | 302 | 366 |
| eskalováno (nerozhodnuto) | 48282 | 49432 |
| vyvráceno omylem (kontrafaktuál) | 12 | 17 |
| podíl případů pravdivého útoku mezi případy žebříku (base) | 52,0 % z 54750 |
| podíl případů pravdivého útoku mezi případy žebříku (cand) | 50,8 % z 56389 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 290 z 302, kandidát 349 z 366. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 5671 z 6166, kandidát 6046 z 6591. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| planned_maintenance_window | benign_change | - | none | 46 | 95,7 (85,5 až 98,8) | 95,7 (85,5 až 98,8) | 95,7 (85,5 až 98,8) | nedostatek dat | - |
| planned_patch_reboot_wave | benign_change | - | none | 28 | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | nedostatek dat | - |
| seasonal_peak_web | benign_change | - | none | 21 | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | 90,5 (71,1 až 97,3) | nedostatek dat | - |
| access_point_controller_failure | ops_fault | - | none | 28 | 92,9 (77,4 až 98,0) | 92,9 (77,4 až 98,0) | 89,3 (72,8 až 96,3) | nedostatek dat | - |
| app_server_crash_cascade | ops_fault | - | none | 33 | 100,0 (89,6 až 100,0) | 100,0 (89,6 až 100,0) | 100,0 (89,6 až 100,0) | nedostatek dat | - |
| backup_window_overrun | ops_fault | - | none | 20 | 90,0 (69,9 až 97,2) | 90,0 (69,9 až 97,2) | 75,0 (53,1 až 88,8) | nedostatek dat | - |
| broadcast_storm_loop | ops_fault | - | none | 23 | 21,7 (9,7 až 41,9) | 39,1 (22,2 až 59,2) | 34,8 (18,8 až 55,1) | nedostatek dat | - |
| cert_chain_misconfig_external | ops_fault | - | none | 36 | 88,9 (74,7 až 95,6) | 88,9 (74,7 až 95,6) | 88,9 (74,7 až 95,6) | nedostatek dat | - |
| cert_expired_internal_service | ops_fault | - | none | 19 | 15,8 (5,5 až 37,6) | 15,8 (5,5 až 37,6) | 10,5 (2,9 až 31,4) | nedostatek dat | - |
| core_router_flapping | ops_fault | - | none | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| db_overload_degradation | ops_fault | - | none | 23 | 100,0 (85,7 až 100,0) | 100,0 (85,7 až 100,0) | 100,0 (85,7 až 100,0) | nedostatek dat | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 29 | 10,3 (3,6 až 26,4) | 13,8 (5,5 až 30,6) | 10,3 (3,6 až 26,4) | nedostatek dat | - |
| dhcp_server_down | ops_fault | - | none | 28 | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | nedostatek dat | - |
| disk_full_backup_failure | ops_fault | - | none | 20 | 95,0 (76,4 až 99,1) | 95,0 (76,4 až 99,1) | 90,0 (69,9 až 97,2) | nedostatek dat | - |
| dns_partial_failure | ops_fault | - | none | 42 | 78,6 (64,1 až 88,3) | 78,6 (64,1 až 88,3) | 66,7 (51,6 až 79,0) | nedostatek dat | - |
| dns_slow_resolution | ops_fault | - | none | 34 | 55,9 (39,5 až 71,1) | 52,9 (36,7 až 68,5) | 47,1 (31,5 až 63,3) | nedostatek dat | - |
| duplicate_ip_conflict | ops_fault | - | none | 37 | 91,9 (78,7 až 97,2) | 91,9 (78,7 až 97,2) | 91,9 (78,7 až 97,2) | nedostatek dat | - |
| flapping_service | ops_fault | - | none | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 26 | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | nedostatek dat | - |
| load_balancer_partial_outage | ops_fault | - | none | 16 | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | 93,8 (71,7 až 98,9) | nedostatek dat | - |
| mail_relay_queue_retry | ops_fault | - | none | 39 | 100,0 (91,0 až 100,0) | 100,0 (91,0 až 100,0) | 100,0 (91,0 až 100,0) | nedostatek dat | - |
| mdns_ssdp_storm | ops_fault | - | none | 25 | 12,0 (4,2 až 30,0) | 40,0 (23,4 až 59,3) | 36,0 (20,2 až 55,5) | nedostatek dat | - |
| memory_exhaustion_stall | ops_fault | - | none | 32 | 96,9 (84,3 až 99,4) | 96,9 (84,3 až 99,4) | 96,9 (84,3 až 99,4) | nedostatek dat | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 23 | 82,6 (62,9 až 93,0) | 82,6 (62,9 až 93,0) | 78,3 (58,1 až 90,3) | nedostatek dat | - |
| ntp_clock_drift_host | ops_fault | - | none | 34 | 94,1 (80,9 až 98,4) | 94,1 (80,9 až 98,4) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| ntp_unreachable | ops_fault | - | none | 34 | 58,8 (42,2 až 73,6) | 58,8 (42,2 až 73,6) | 38,2 (23,9 až 55,0) | nedostatek dat | - |
| slow_link_loss_degradation | ops_fault | - | none | 35 | 100,0 (90,1 až 100,0) | 100,0 (90,1 až 100,0) | 100,0 (90,1 až 100,0) | nedostatek dat | - |
| switch_outage_subnet | ops_fault | - | none | 26 | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | nedostatek dat | - |
| uplink_saturation | ops_fault | - | none | 28 | 17,9 (7,9 až 35,6) | 14,3 (5,7 až 31,5) | 3,6 (0,6 až 17,7) | nedostatek dat | - |
| vpn_concentrator_down | ops_fault | - | none | 19 | 89,5 (68,6 až 97,1) | 89,5 (68,6 až 97,1) | 89,5 (68,6 až 97,1) | nedostatek dat | - |
| api_enum_distributed | security | T1595.002 | reconnaissance | 18 | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | nedostatek dat | - |
| app_layer_flood_api | security | T1499.003 | impact | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 88,0 (70,0 až 95,8) | nedostatek dat | - |
| apt_chain | security | - | lateral-movement | 34 | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | nedostatek dat | - |
| backup_service_probing | security | T1490 | impact | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat | - |
| bucket_mass_download | security | T1530 | collection | 24 | 16,7 (6,7 až 35,9) | 16,7 (6,7 až 35,9) | 8,3 (2,3 až 25,8) | nedostatek dat | - |
| c2_alt_port_8443 | security | T1571 | command-and-control | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | nedostatek dat | - |
| c2_beacon | security | - | command-and-control | 183 | 88,5 (83,1 až 92,4) | 88,0 (82,5 až 91,9) | 68,9 (61,8 až 75,1) | pod prahem | c (otevřené) |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 29 | 82,8 (65,5 až 92,4) | 82,8 (65,5 až 92,4) | 82,8 (65,5 až 92,4) | nedostatek dat | - |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 24 | 70,8 (50,8 až 85,1) | 70,8 (50,8 až 85,1) | 16,7 (6,7 až 35,9) | nedostatek dat | - |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 32 | 50,0 (33,6 až 66,4) | 53,1 (36,4 až 69,1) | 25,0 (13,3 až 42,1) | nedostatek dat | - |
| c2_doh_resolver | security | T1572 | command-and-control | 33 | 87,9 (72,7 až 95,2) | 87,9 (72,7 až 95,2) | 87,9 (72,7 až 95,2) | nedostatek dat | - |
| c2_high_jitter | security | T1071.001 | command-and-control | 22 | 59,1 (38,7 až 76,7) | 59,1 (38,7 až 76,7) | 54,5 (34,7 až 73,1) | nedostatek dat | - |
| c2_https_legit_service | security | T1102 | command-and-control | 31 | 90,3 (75,1 až 96,7) | 90,3 (75,1 až 96,7) | 90,3 (75,1 až 96,7) | nedostatek dat | - |
| c2_icmp_tunnel | security | T1095 | command-and-control | 31 | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 37 | 100,0 (90,6 až 100,0) | 100,0 (90,6 až 100,0) | 94,6 (82,3 až 98,5) | nedostatek dat | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 30 | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | nedostatek dat | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 40 | 85,0 (70,9 až 92,9) | 85,0 (70,9 až 92,9) | 85,0 (70,9 až 92,9) | nedostatek dat | - |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 26 | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | 96,2 (81,1 až 99,3) | nedostatek dat | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 35 | 88,6 (74,0 až 95,5) | 88,6 (74,0 až 95,5) | 85,7 (70,6 až 93,7) | nedostatek dat | - |
| c2_udp_custom_port | security | T1095 | command-and-control | 31 | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| c2_websocket_long | security | T1071.001 | command-and-control | 35 | 85,7 (70,6 až 93,7) | 88,6 (74,0 až 95,5) | 85,7 (70,6 až 93,7) | nedostatek dat | - |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 33 | 9,1 (3,1 až 23,6) | 9,1 (3,1 až 23,6) | 3,0 (0,5 až 15,3) | nedostatek dat | - |
| cloud_api_discovery_burst | security | T1580 | discovery | 24 | 4,2 (0,7 až 20,2) | 4,2 (0,7 až 20,2) | 0,0 (0,0 až 13,8) | nedostatek dat | - |
| credential_stuffing | security | - | credential-access | 97 | 87,6 (79,6 až 92,8) | 87,6 (79,6 až 92,8) | 84,5 (76,0 až 90,4) | pod prahem | c (otevřené) |
| cryptomining | security | - | impact | 91 | 86,8 (78,4 až 92,3) | 86,8 (78,4 až 92,3) | 81,3 (72,1 až 88,0) | pod prahem | c (otevřené) |
| data_destruction_smb_wave | security | T1485 | impact | 17 | 70,6 (46,9 až 86,7) | 70,6 (46,9 až 86,7) | 64,7 (41,3 až 82,7) | nedostatek dat | - |
| data_staging_smb_internal | security | T1039 | collection | 26 | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | 76,9 (57,9 až 89,0) | nedostatek dat | - |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 23 | 100,0 (85,7 až 100,0) | 100,0 (85,7 až 100,0) | 95,7 (79,0 až 99,2) | nedostatek dat | - |
| ddos_dns_amplification | security | T1498.002 | impact | 27 | 66,7 (47,8 až 81,4) | 66,7 (47,8 až 81,4) | 66,7 (47,8 až 81,4) | nedostatek dat | - |
| ddos_ntp_amplification | security | T1498.002 | impact | 38 | 100,0 (90,8 až 100,0) | 100,0 (90,8 až 100,0) | 97,4 (86,5 až 99,5) | nedostatek dat | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat | - |
| ddos_volume | security | - | impact | 66 | 95,5 (87,5 až 98,4) | 95,5 (87,5 až 98,4) | 92,4 (83,5 až 96,7) | splněno | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 36 | 83,3 (68,1 až 92,1) | 83,3 (68,1 až 92,1) | 75,0 (58,9 až 86,2) | nedostatek dat | - |
| dns_tunnel | security | - | command-and-control | 103 | 96,1 (90,4 až 98,5) | 95,1 (89,1 až 97,9) | 78,6 (69,8 až 85,5) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 21 | 9,5 (2,7 až 28,9) | 9,5 (2,7 až 28,9) | 4,8 (0,8 až 22,7) | nedostatek dat | - |
| drive_by_bulk_download | security | T1189 | initial-access | 35 | 8,6 (3,0 až 22,4) | 8,6 (3,0 až 22,4) | 0,0 (0,0 až 9,9) | nedostatek dat | - |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 15 | 13,3 (3,7 až 37,9) | 13,3 (3,7 až 37,9) | 13,3 (3,7 až 37,9) | nedostatek dat | - |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 28 | 32,1 (17,9 až 50,7) | 39,3 (23,6 až 57,6) | 14,3 (5,7 až 31,5) | nedostatek dat | - |
| exfil_dns_slow | security | T1048.003 | exfiltration | 43 | 76,7 (62,3 až 86,8) | 76,7 (62,3 až 86,8) | 58,1 (43,3 až 71,6) | nedostatek dat | - |
| exfil_https_burst | security | T1041 | exfiltration | 38 | 65,8 (49,9 až 78,8) | 65,8 (49,9 až 78,8) | 63,2 (47,3 až 76,6) | nedostatek dat | - |
| exfil_icmp_payload | security | T1048 | exfiltration | 25 | 32,0 (17,2 až 51,6) | 32,0 (17,2 až 51,6) | 8,0 (2,2 až 25,0) | nedostatek dat | - |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 25 | 52,0 (33,5 až 70,0) | 76,0 (56,6 až 88,5) | 76,0 (56,6 až 88,5) | nedostatek dat | - |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 28 | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | nedostatek dat | - |
| exfiltration | security | - | exfiltration | 133 | 94,0 (88,6 až 96,9) | 94,0 (88,6 až 96,9) | 93,2 (87,6 až 96,4) | splněno | - |
| exploit_attempt | security | - | initial-access | 228 | 89,5 (84,8 až 92,8) | 89,5 (84,8 až 92,8) | 48,2 (41,8 až 54,7) | pod prahem | c (otevřené) |
| fleet_beacon | security | - | command-and-control | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 80,0 (60,9 až 91,1) | nedostatek dat | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 30 | 86,7 (70,3 až 94,7) | 86,7 (70,3 až 94,7) | 83,3 (66,4 až 92,7) | nedostatek dat | - |
| http_slow_connections_dos | security | T1499.002 | impact | 16 | 68,8 (44,4 až 85,8) | 68,8 (44,4 až 85,8) | 56,2 (33,2 až 76,9) | nedostatek dat | - |
| ics_attack | security | - | impact | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat | - |
| ics_slow_poll_new_source | security | T0801 | collection | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 26 | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | nedostatek dat | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 24 | 37,5 (21,2 až 57,3) | 37,5 (21,2 až 57,3) | 37,5 (21,2 až 57,3) | nedostatek dat | - |
| insider_hoarding | security | - | exfiltration | 31 | 96,8 (83,8 až 99,4) | 96,8 (83,8 až 99,4) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 34 | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| lateral_movement | security | - | lateral-movement | 199 | 97,5 (94,3 až 98,9) | 97,5 (94,3 až 98,9) | 72,9 (66,3 až 78,6) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 38 | 89,5 (75,9 až 95,8) | 89,5 (75,9 až 95,8) | 71,1 (55,2 až 83,0) | nedostatek dat | - |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 27 | 88,9 (71,9 až 96,1) | 88,9 (71,9 až 96,1) | 88,9 (71,9 až 96,1) | nedostatek dat | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 36 | 83,3 (68,1 až 92,1) | 83,3 (68,1 až 92,1) | 80,6 (65,0 až 90,2) | nedostatek dat | - |
| lateral_winrm | security | T1021.006 | lateral-movement | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| lateral_wmi_dcom | security | T1047 | execution | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | nedostatek dat | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 25 | 96,0 (80,5 až 99,3) | 96,0 (80,5 až 99,3) | 92,0 (75,0 až 97,8) | nedostatek dat | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 28 | 96,4 (82,3 až 99,4) | 96,4 (82,3 až 99,4) | 92,9 (77,4 až 98,0) | nedostatek dat | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 26 | 65,4 (46,2 až 80,6) | 73,1 (53,9 až 86,3) | 73,1 (53,9 až 86,3) | nedostatek dat | - |
| mqtt_probe_ext | security | T1046 | discovery | 30 | 83,3 (66,4 až 92,7) | 83,3 (66,4 až 92,7) | 83,3 (66,4 až 92,7) | nedostatek dat | - |
| mssql_login_failures | security | T1110.001 | credential-access | 29 | 89,7 (73,6 až 96,4) | 89,7 (73,6 až 96,4) | 89,7 (73,6 až 96,4) | nedostatek dat | - |
| mysql_login_failures | security | T1110.001 | credential-access | 28 | 85,7 (68,5 až 94,3) | 85,7 (68,5 až 94,3) | 82,1 (64,4 až 92,1) | nedostatek dat | - |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 26 | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | nedostatek dat | - |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 32 | 87,5 (71,9 až 95,0) | 87,5 (71,9 až 95,0) | 87,5 (71,9 až 95,0) | nedostatek dat | - |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 27 | 88,9 (71,9 až 96,1) | 88,9 (71,9 až 96,1) | 88,9 (71,9 až 96,1) | nedostatek dat | - |
| port_scan_horizontal | security | - | discovery | 147 | 85,0 (78,4 až 89,9) | 85,0 (78,4 až 89,9) | 78,2 (70,9 až 84,1) | pod prahem | c (otevřené) |
| port_scan_vertical | security | - | discovery | 167 | 88,0 (82,2 až 92,1) | 88,0 (82,2 až 92,1) | 85,0 (78,8 až 89,6) | pod prahem | c (otevřené) |
| public_app_probe_trickle | security | T1190 | initial-access | 12 | 91,7 (64,6 až 98,5) | 91,7 (64,6 až 98,5) | 50,0 (25,4 až 74,6) | nedostatek dat | - |
| ransomware | security | - | impact | 68 | 100,0 (94,7 až 100,0) | 100,0 (94,7 až 100,0) | 97,1 (89,9 až 99,2) | splněno | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat | - |
| rdp_sweep_ext | security | T1046 | discovery | 25 | 84,0 (65,3 až 93,6) | 88,0 (70,0 až 95,8) | 68,0 (48,4 až 82,8) | nedostatek dat | - |
| resource_hijack_pool_tls | security | T1496 | impact | 22 | 100,0 (85,1 až 100,0) | 100,0 (85,1 až 100,0) | 100,0 (85,1 až 100,0) | nedostatek dat | - |
| rogue_device | security | - | initial-access | 37 | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | 89,2 (75,3 až 95,7) | nedostatek dat | - |
| share_encryption_wave_slow | security | T1486 | impact | 22 | 90,9 (72,2 až 97,5) | 90,9 (72,2 až 97,5) | 72,7 (51,8 až 86,8) | nedostatek dat | - |
| slow_scan | security | - | discovery | 153 | 90,8 (85,2 až 94,5) | 92,2 (86,8 až 95,5) | 87,6 (81,4 až 91,9) | splněno | - |
| smb_login_failures | security | T1110 | credential-access | 30 | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | nedostatek dat | - |
| smb_share_enum_internal | security | T1135 | discovery | 17 | 58,8 (36,0 až 78,4) | 58,8 (36,0 až 78,4) | 58,8 (36,0 až 78,4) | nedostatek dat | - |
| smb_sweep_ext | security | T1046 | discovery | 20 | 70,0 (48,1 až 85,5) | 70,0 (48,1 až 85,5) | 70,0 (48,1 až 85,5) | nedostatek dat | - |
| smtp_auth_spray | security | T1110.003 | credential-access | 24 | 83,3 (64,1 až 93,3) | 83,3 (64,1 až 93,3) | 83,3 (64,1 až 93,3) | nedostatek dat | - |
| snmp_sweep_ext | security | T1046 | discovery | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 84,0 (65,3 až 93,6) | nedostatek dat | - |
| snmp_walk_internal | security | T1602.001 | collection | 20 | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | nedostatek dat | - |
| ssh_bruteforce | security | - | credential-access | 245 | 94,3 (90,6 až 96,6) | 94,3 (90,6 až 96,6) | 83,3 (78,1 až 87,4) | detekce ano, typ ne | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 38 | 81,6 (66,6 až 90,8) | 81,6 (66,6 až 90,8) | 73,7 (58,0 až 85,0) | nedostatek dat | - |
| telnet_iot_login | security | T1110.001 | credential-access | 24 | 41,7 (24,5 až 61,2) | 41,7 (24,5 až 61,2) | 33,3 (18,0 až 53,3) | nedostatek dat | - |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 20 | 55,0 (34,2 až 74,2) | 55,0 (34,2 až 74,2) | 5,0 (0,9 až 23,6) | nedostatek dat | - |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 32 | 62,5 (45,3 až 77,1) | 62,5 (45,3 až 77,1) | 56,2 (39,3 až 71,8) | nedostatek dat | - |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 15 | 46,7 (24,8 až 69,9) | 46,7 (24,8 až 69,9) | 33,3 (15,2 až 58,3) | nedostatek dat | - |
| web_exploit | security | - | initial-access | 137 | 94,2 (88,9 až 97,0) | 94,2 (88,9 až 97,0) | 74,5 (66,6 až 81,0) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 23 | 95,7 (79,0 až 99,2) | 95,7 (79,0 až 99,2) | 78,3 (58,1 až 90,3) | nedostatek dat | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 97 | 68,0 (58,2 až 76,5) | 70,1 (60,4 až 78,3) | 63,9 (54,0 až 72,8) |
| command-and-control | 796 | 87,9 (85,5 až 90,0) | 87,9 (85,5 až 90,0) | 77,6 (74,6 až 80,4) |
| credential-access | 722 | 89,2 (86,7 až 91,3) | 89,2 (86,7 až 91,3) | 83,5 (80,6 až 86,0) |
| discovery | 636 | 83,6 (80,6 až 86,3) | 84,1 (81,1 až 86,8) | 79,2 (75,9 až 82,2) |
| execution | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) |
| exfiltration | 390 | 72,1 (67,4 až 76,3) | 74,1 (69,5 až 78,2) | 67,9 (63,2 až 72,4) |
| impact | 433 | 89,6 (86,4 až 92,1) | 89,6 (86,4 až 92,1) | 85,2 (81,6 až 88,3) |
| initial-access | 529 | 80,0 (76,3 až 83,2) | 80,0 (76,3 až 83,2) | 52,9 (48,7 až 57,1) |
| lateral-movement | 453 | 92,7 (89,9 až 94,8) | 92,7 (89,9 až 94,8) | 79,0 (75,0 až 82,5) |
| none | 856 | 79,9 (77,1 až 82,5) | 81,1 (78,3 až 83,6) | 77,6 (74,7 až 80,2) |
| reconnaissance | 98 | 69,4 (59,7 až 77,6) | 69,4 (59,7 až 77,6) | 61,2 (51,3 až 70,3) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 95 | 96,8 (91,1 až 98,9) | 96,8 (91,1 až 98,9) | 95,8 (89,7 až 98,4) | 0,0 % |
| ops_fault | 761 | 77,8 (74,7 až 80,6) | 79,1 (76,1 až 81,8) | 75,3 (72,1 až 78,2) | 0,0 % |
| security | 4176 | 84,8 (83,7 až 85,9) | 85,2 (84,0 až 86,2) | 75,2 (73,9 až 76,5) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 722 | 89,2 (86,7 až 91,3) | 89,2 (86,7 až 91,3) | 83,5 (80,6 až 86,0) | nedosaženo |
| taktika discovery | 636 | 83,6 (80,6 až 86,3) | 84,1 (81,1 až 86,8) | 79,2 (75,9 až 82,2) | nedosaženo |
| taktika lateral-movement | 453 | 92,7 (89,9 až 94,8) | 92,7 (89,9 až 94,8) | 79,0 (75,0 až 82,5) | splněno |
| rodina c2_slow_long_interval | 35 | 88,6 (74,0 až 95,5) | 88,6 (74,0 až 95,5) | 85,7 (70,6 až 93,7) | nedostatek dat |
| rodina ssh_spray_slow_distributed | 38 | 81,6 (66,6 až 90,8) | 81,6 (66,6 až 90,8) | 73,7 (58,0 až 85,0) | nedostatek dat |
| rodina data_staging_smb_internal | 26 | 92,3 (75,9 až 97,9) | 92,3 (75,9 až 97,9) | 76,9 (57,9 až 89,0) | nedostatek dat |
| rodina kerberos_ticket_request_burst | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat |
| rodina ics_attack | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat |
| rodina cloud_api_discovery_burst | 24 | 4,2 (0,7 až 20,2) | 4,2 (0,7 až 20,2) | 0,0 (0,0 až 13,8) | nedostatek dat |
| rodina rdp_bruteforce | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat |
| rodina ddos_syn_flood_distributed | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| port_scan_horizontal (security) | 147 | 85,0 | c (otevřené) |
| cryptomining (security) | 91 | 86,8 | c (otevřené) |
| credential_stuffing (security) | 97 | 87,6 | c (otevřené) |
| c2_beacon (security) | 183 | 88,0 | c (otevřené) |
| port_scan_vertical (security) | 167 | 88,0 | c (otevřené) |
| exploit_attempt (security) | 228 | 89,5 | c (otevřené) |

