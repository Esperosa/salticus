# Krok 10: šum 10x (kombinace útok + porucha + šum + výpadek senzoru)

Rameno `base` (základ) proti `cand` (kandidát), párově po sítích: 40 sítí, 2626 útoků a poruch s toky, 344 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 81,5 (79,9 až 82,9) | 82,3 (80,7 až 83,7) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 21,80 | 23,54 | poměr 1,080 (1,025 až 1,138); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 192,5 | 196,6 | poměr 1,021 (1,011 až 1,036) |
| útoky s omylem zavřeným nálezem | 24 (0,9 %) | 24 (0,9 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 36129 | 37579 |
| potvrzeno | 3864 | 4167 |
| vyvráceno | 327 | 256 |
| eskalováno (nerozhodnuto) | 31821 | 33028 |
| vyvráceno omylem (kontrafaktuál) | 7 | 9 |
| podíl případů pravdivého útoku mezi případy žebříku (base) | 46,9 % z 36012 |
| podíl případů pravdivého útoku mezi případy žebříku (cand) | 45,6 % z 37451 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 320 z 327, kandidát 247 z 256. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 3567 z 3864, kandidát 3826 z 4167. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| planned_maintenance_window | benign_change | - | none | 13 | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | nedostatek dat | - |
| planned_patch_reboot_wave | benign_change | - | none | 12 | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | nedostatek dat | - |
| seasonal_peak_web | benign_change | - | none | 7 | 85,7 (48,7 až 97,4) | 85,7 (48,7 až 97,4) | 71,4 (35,9 až 91,8) | nedostatek dat | - |
| access_point_controller_failure | ops_fault | - | none | 16 | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | nedostatek dat | - |
| app_server_crash_cascade | ops_fault | - | none | 21 | 100,0 (84,5 až 100,0) | 100,0 (84,5 až 100,0) | 100,0 (84,5 až 100,0) | nedostatek dat | - |
| backup_window_overrun | ops_fault | - | none | 8 | 87,5 (52,9 až 97,8) | 87,5 (52,9 až 97,8) | 62,5 (30,6 až 86,3) | nedostatek dat | - |
| broadcast_storm_loop | ops_fault | - | none | 19 | 15,8 (5,5 až 37,6) | 42,1 (23,1 až 63,7) | 36,8 (19,1 až 59,0) | nedostatek dat | - |
| cert_chain_misconfig_external | ops_fault | - | none | 18 | 94,4 (74,2 až 99,0) | 94,4 (74,2 až 99,0) | 94,4 (74,2 až 99,0) | nedostatek dat | - |
| cert_expired_internal_service | ops_fault | - | none | 13 | 30,8 (12,7 až 57,6) | 30,8 (12,7 až 57,6) | 30,8 (12,7 až 57,6) | nedostatek dat | - |
| core_router_flapping | ops_fault | - | none | 12 | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | nedostatek dat | - |
| db_overload_degradation | ops_fault | - | none | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | nedostatek dat | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 23 | 21,7 (9,7 až 41,9) | 30,4 (15,6 až 50,9) | 13,0 (4,5 až 32,1) | nedostatek dat | - |
| dhcp_server_down | ops_fault | - | none | 13 | 100,0 (77,2 až 100,0) | 100,0 (77,2 až 100,0) | 92,3 (66,7 až 98,6) | nedostatek dat | - |
| disk_full_backup_failure | ops_fault | - | none | 12 | 83,3 (55,2 až 95,3) | 83,3 (55,2 až 95,3) | 83,3 (55,2 až 95,3) | nedostatek dat | - |
| dns_partial_failure | ops_fault | - | none | 19 | 63,2 (41,0 až 80,9) | 63,2 (41,0 až 80,9) | 52,6 (31,7 až 72,7) | nedostatek dat | - |
| dns_slow_resolution | ops_fault | - | none | 12 | 75,0 (46,8 až 91,1) | 75,0 (46,8 až 91,1) | 66,7 (39,1 až 86,2) | nedostatek dat | - |
| duplicate_ip_conflict | ops_fault | - | none | 17 | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | 94,1 (73,0 až 99,0) | nedostatek dat | - |
| flapping_service | ops_fault | - | none | 17 | 82,4 (59,0 až 93,8) | 82,4 (59,0 až 93,8) | 82,4 (59,0 až 93,8) | nedostatek dat | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 16 | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | nedostatek dat | - |
| load_balancer_partial_outage | ops_fault | - | none | 15 | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | nedostatek dat | - |
| mail_relay_queue_retry | ops_fault | - | none | 22 | 100,0 (85,1 až 100,0) | 100,0 (85,1 až 100,0) | 100,0 (85,1 až 100,0) | nedostatek dat | - |
| mdns_ssdp_storm | ops_fault | - | none | 15 | 0,0 (0,0 až 20,4) | 13,3 (3,7 až 37,9) | 13,3 (3,7 až 37,9) | nedostatek dat | - |
| memory_exhaustion_stall | ops_fault | - | none | 12 | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | 91,7 (64,6 až 98,5) | nedostatek dat | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 10 | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | 90,0 (59,6 až 98,2) | nedostatek dat | - |
| ntp_clock_drift_host | ops_fault | - | none | 21 | 76,2 (54,9 až 89,4) | 76,2 (54,9 až 89,4) | 61,9 (40,9 až 79,2) | nedostatek dat | - |
| ntp_unreachable | ops_fault | - | none | 16 | 62,5 (38,6 až 81,5) | 62,5 (38,6 až 81,5) | 43,8 (23,1 až 66,8) | nedostatek dat | - |
| slow_link_loss_degradation | ops_fault | - | none | 20 | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | nedostatek dat | - |
| switch_outage_subnet | ops_fault | - | none | 18 | 88,9 (67,2 až 96,9) | 88,9 (67,2 až 96,9) | 88,9 (67,2 až 96,9) | nedostatek dat | - |
| uplink_saturation | ops_fault | - | none | 19 | 15,8 (5,5 až 37,6) | 15,8 (5,5 až 37,6) | 0,0 (0,0 až 16,8) | nedostatek dat | - |
| vpn_concentrator_down | ops_fault | - | none | 12 | 91,7 (64,6 až 98,5) | 91,7 (64,6 až 98,5) | 91,7 (64,6 až 98,5) | nedostatek dat | - |
| api_enum_distributed | security | T1595.002 | reconnaissance | 14 | 78,6 (52,4 až 92,4) | 78,6 (52,4 až 92,4) | 78,6 (52,4 až 92,4) | nedostatek dat | - |
| app_layer_flood_api | security | T1499.003 | impact | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | nedostatek dat | - |
| apt_chain | security | - | lateral-movement | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| backup_service_probing | security | T1490 | impact | 20 | 80,0 (58,4 až 91,9) | 80,0 (58,4 až 91,9) | 40,0 (21,9 až 61,3) | nedostatek dat | - |
| bucket_mass_download | security | T1530 | collection | 17 | 5,9 (1,0 až 27,0) | 5,9 (1,0 až 27,0) | 0,0 (0,0 až 18,4) | nedostatek dat | - |
| c2_alt_port_8443 | security | T1571 | command-and-control | 9 | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | nedostatek dat | - |
| c2_beacon | security | - | command-and-control | 104 | 84,6 (76,5 až 90,3) | 84,6 (76,5 až 90,3) | 60,6 (51,0 až 69,4) | pod prahem | c (otevřené) |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 18 | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | nedostatek dat | - |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 20 | 70,0 (48,1 až 85,5) | 70,0 (48,1 až 85,5) | 5,0 (0,9 až 23,6) | nedostatek dat | - |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 12 | 66,7 (39,1 až 86,2) | 66,7 (39,1 až 86,2) | 33,3 (13,8 až 60,9) | nedostatek dat | - |
| c2_doh_resolver | security | T1572 | command-and-control | 14 | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | nedostatek dat | - |
| c2_high_jitter | security | T1071.001 | command-and-control | 15 | 66,7 (41,7 až 84,8) | 66,7 (41,7 až 84,8) | 53,3 (30,1 až 75,2) | nedostatek dat | - |
| c2_https_legit_service | security | T1102 | command-and-control | 10 | 80,0 (49,0 až 94,3) | 80,0 (49,0 až 94,3) | 80,0 (49,0 až 94,3) | nedostatek dat | - |
| c2_icmp_tunnel | security | T1095 | command-and-control | 15 | 93,3 (70,2 až 98,8) | 93,3 (70,2 až 98,8) | 93,3 (70,2 až 98,8) | nedostatek dat | - |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 8 | 100,0 (67,6 až 100,0) | 100,0 (67,6 až 100,0) | 87,5 (52,9 až 97,8) | nedostatek dat | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 90,9 (72,2 až 97,5) | nedostatek dat | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 15 | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | nedostatek dat | - |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | nedostatek dat | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 13 | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | nedostatek dat | - |
| c2_udp_custom_port | security | T1095 | command-and-control | 10 | 90,0 (59,6 až 98,2) | 90,0 (59,6 až 98,2) | 90,0 (59,6 až 98,2) | nedostatek dat | - |
| c2_websocket_long | security | T1071.001 | command-and-control | 12 | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | 91,7 (64,6 až 98,5) | nedostatek dat | - |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 19 | 15,8 (5,5 až 37,6) | 10,5 (2,9 až 31,4) | 10,5 (2,9 až 31,4) | nedostatek dat | - |
| cloud_api_discovery_burst | security | T1580 | discovery | 8 | 37,5 (13,7 až 69,4) | 37,5 (13,7 až 69,4) | 0,0 (0,0 až 32,4) | nedostatek dat | - |
| credential_stuffing | security | - | credential-access | 58 | 75,9 (63,5 až 85,0) | 75,9 (63,5 až 85,0) | 70,7 (58,0 až 80,8) | pod prahem | c (otevřené) |
| cryptomining | security | - | impact | 44 | 84,1 (70,6 až 92,1) | 84,1 (70,6 až 92,1) | 65,9 (51,1 až 78,1) | nedostatek dat | - |
| data_destruction_smb_wave | security | T1485 | impact | 18 | 72,2 (49,1 až 87,5) | 72,2 (49,1 až 87,5) | 55,6 (33,7 až 75,4) | nedostatek dat | - |
| data_staging_smb_internal | security | T1039 | collection | 18 | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | 50,0 (29,0 až 71,0) | nedostatek dat | - |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 18 | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | 94,4 (74,2 až 99,0) | nedostatek dat | - |
| ddos_dns_amplification | security | T1498.002 | impact | 13 | 38,5 (17,7 až 64,5) | 38,5 (17,7 až 64,5) | 30,8 (12,7 až 57,6) | nedostatek dat | - |
| ddos_ntp_amplification | security | T1498.002 | impact | 21 | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | nedostatek dat | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 11 | 36,4 (15,2 až 64,6) | 36,4 (15,2 až 64,6) | 27,3 (9,7 až 56,6) | nedostatek dat | - |
| ddos_volume | security | - | impact | 20 | 90,0 (69,9 až 97,2) | 90,0 (69,9 až 97,2) | 90,0 (69,9 až 97,2) | nedostatek dat | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 8 | 100,0 (67,6 až 100,0) | 100,0 (67,6 až 100,0) | 100,0 (67,6 až 100,0) | nedostatek dat | - |
| dns_tunnel | security | - | command-and-control | 47 | 97,9 (88,9 až 99,6) | 97,9 (88,9 až 99,6) | 70,2 (56,0 až 81,3) | nedostatek dat | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 17 | 23,5 (9,6 až 47,3) | 23,5 (9,6 až 47,3) | 23,5 (9,6 až 47,3) | nedostatek dat | - |
| drive_by_bulk_download | security | T1189 | initial-access | 12 | 8,3 (1,5 až 35,4) | 8,3 (1,5 až 35,4) | 0,0 (0,0 až 24,2) | nedostatek dat | - |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 14 | 21,4 (7,6 až 47,6) | 21,4 (7,6 až 47,6) | 14,3 (4,0 až 39,9) | nedostatek dat | - |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 13 | 38,5 (17,7 až 64,5) | 46,2 (23,2 až 70,9) | 15,4 (4,3 až 42,2) | nedostatek dat | - |
| exfil_dns_slow | security | T1048.003 | exfiltration | 15 | 66,7 (41,7 až 84,8) | 66,7 (41,7 až 84,8) | 46,7 (24,8 až 69,9) | nedostatek dat | - |
| exfil_https_burst | security | T1041 | exfiltration | 10 | 50,0 (23,7 až 76,3) | 50,0 (23,7 až 76,3) | 50,0 (23,7 až 76,3) | nedostatek dat | - |
| exfil_icmp_payload | security | T1048 | exfiltration | 10 | 60,0 (31,3 až 83,2) | 60,0 (31,3 až 83,2) | 20,0 (5,7 až 51,0) | nedostatek dat | - |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 17 | 64,7 (41,3 až 82,7) | 82,4 (59,0 až 93,8) | 70,6 (46,9 až 86,7) | nedostatek dat | - |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 9 | 77,8 (45,3 až 93,7) | 88,9 (56,5 až 98,0) | 66,7 (35,4 až 87,9) | nedostatek dat | - |
| exfiltration | security | - | exfiltration | 75 | 89,3 (80,3 až 94,5) | 89,3 (80,3 až 94,5) | 85,3 (75,6 až 91,6) | pod prahem | c (otevřené) |
| exploit_attempt | security | - | initial-access | 110 | 83,6 (75,6 až 89,4) | 83,6 (75,6 až 89,4) | 48,2 (39,1 až 57,4) | pod prahem | c (otevřené) |
| fleet_beacon | security | - | command-and-control | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 78,6 (52,4 až 92,4) | nedostatek dat | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 13 | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | nedostatek dat | - |
| http_slow_connections_dos | security | T1499.002 | impact | 11 | 63,6 (35,4 až 84,8) | 63,6 (35,4 až 84,8) | 18,2 (5,1 až 47,7) | nedostatek dat | - |
| ics_attack | security | - | impact | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| ics_modbus_write_burst | security | T0836 | impact | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 17 | 88,2 (65,7 až 96,7) | 88,2 (65,7 až 96,7) | 88,2 (65,7 až 96,7) | nedostatek dat | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 15 | 46,7 (24,8 až 69,9) | 46,7 (24,8 až 69,9) | 46,7 (24,8 až 69,9) | nedostatek dat | - |
| insider_hoarding | security | - | exfiltration | 27 | 96,3 (81,7 až 99,3) | 96,3 (81,7 až 99,3) | 96,3 (81,7 až 99,3) | nedostatek dat | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 16 | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | 81,2 (57,0 až 93,4) | nedostatek dat | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 9 | 88,9 (56,5 až 98,0) | 88,9 (56,5 až 98,0) | 77,8 (45,3 až 93,7) | nedostatek dat | - |
| lateral_movement | security | - | lateral-movement | 104 | 97,1 (91,9 až 99,0) | 98,1 (93,3 až 99,5) | 86,5 (78,7 až 91,8) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 17 | 88,2 (65,7 až 96,7) | 88,2 (65,7 až 96,7) | 82,4 (59,0 až 93,8) | nedostatek dat | - |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 10 | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | nedostatek dat | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 20 | 75,0 (53,1 až 88,8) | 75,0 (53,1 až 88,8) | 70,0 (48,1 až 85,5) | nedostatek dat | - |
| lateral_winrm | security | T1021.006 | lateral-movement | 15 | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | 93,3 (70,2 až 98,8) | nedostatek dat | - |
| lateral_wmi_dcom | security | T1047 | execution | 21 | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | nedostatek dat | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 92,9 (68,5 až 98,7) | nedostatek dat | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 17 | 88,2 (65,7 až 96,7) | 88,2 (65,7 až 96,7) | 82,4 (59,0 až 93,8) | nedostatek dat | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 13 | 46,2 (23,2 až 70,9) | 69,2 (42,4 až 87,3) | 61,5 (35,5 až 82,3) | nedostatek dat | - |
| mqtt_probe_ext | security | T1046 | discovery | 12 | 58,3 (32,0 až 80,7) | 58,3 (32,0 až 80,7) | 58,3 (32,0 až 80,7) | nedostatek dat | - |
| mssql_login_failures | security | T1110.001 | credential-access | 15 | 93,3 (70,2 až 98,8) | 93,3 (70,2 až 98,8) | 93,3 (70,2 až 98,8) | nedostatek dat | - |
| mysql_login_failures | security | T1110.001 | credential-access | 15 | 80,0 (54,8 až 93,0) | 80,0 (54,8 až 93,0) | 73,3 (48,0 až 89,1) | nedostatek dat | - |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 17 | 76,5 (52,7 až 90,4) | 76,5 (52,7 až 90,4) | 70,6 (46,9 až 86,7) | nedostatek dat | - |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 9 | 88,9 (56,5 až 98,0) | 88,9 (56,5 až 98,0) | 88,9 (56,5 až 98,0) | nedostatek dat | - |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 12 | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | nedostatek dat | - |
| port_scan_horizontal | security | - | discovery | 78 | 88,5 (79,5 až 93,8) | 91,0 (82,6 až 95,6) | 80,8 (70,7 až 88,0) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 92 | 89,1 (81,1 až 94,0) | 89,1 (81,1 až 94,0) | 88,0 (79,8 až 93,2) | pod prahem | c (otevřené) |
| public_app_probe_trickle | security | T1190 | initial-access | 11 | 72,7 (43,4 až 90,3) | 72,7 (43,4 až 90,3) | 54,5 (28,0 až 78,7) | nedostatek dat | - |
| ransomware | security | - | impact | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 90,9 (62,3 až 98,4) | nedostatek dat | - |
| rdp_sweep_ext | security | T1046 | discovery | 21 | 81,0 (60,0 až 92,3) | 81,0 (60,0 až 92,3) | 81,0 (60,0 až 92,3) | nedostatek dat | - |
| resource_hijack_pool_tls | security | T1496 | impact | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | nedostatek dat | - |
| rogue_device | security | - | initial-access | 23 | 95,7 (79,0 až 99,2) | 95,7 (79,0 až 99,2) | 87,0 (67,9 až 95,5) | nedostatek dat | - |
| share_encryption_wave_slow | security | T1486 | impact | 13 | 69,2 (42,4 až 87,3) | 76,9 (49,7 až 91,8) | 61,5 (35,5 až 82,3) | nedostatek dat | - |
| slow_scan | security | - | discovery | 71 | 94,4 (86,4 až 97,8) | 94,4 (86,4 až 97,8) | 87,3 (77,6 až 93,2) | detekce ano, typ ne | - |
| smb_login_failures | security | T1110 | credential-access | 23 | 95,7 (79,0 až 99,2) | 95,7 (79,0 až 99,2) | 82,6 (62,9 až 93,0) | nedostatek dat | - |
| smb_share_enum_internal | security | T1135 | discovery | 8 | 87,5 (52,9 až 97,8) | 87,5 (52,9 až 97,8) | 87,5 (52,9 až 97,8) | nedostatek dat | - |
| smb_sweep_ext | security | T1046 | discovery | 18 | 88,9 (67,2 až 96,9) | 88,9 (67,2 až 96,9) | 77,8 (54,8 až 91,0) | nedostatek dat | - |
| smtp_auth_spray | security | T1110.003 | credential-access | 16 | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | nedostatek dat | - |
| snmp_sweep_ext | security | T1046 | discovery | 27 | 74,1 (55,3 až 86,8) | 74,1 (55,3 až 86,8) | 70,4 (51,5 až 84,1) | nedostatek dat | - |
| snmp_walk_internal | security | T1602.001 | collection | 20 | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | nedostatek dat | - |
| ssh_bruteforce | security | - | credential-access | 108 | 83,3 (75,2 až 89,2) | 83,3 (75,2 až 89,2) | 75,0 (66,1 až 82,2) | pod prahem | c (otevřené) |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 10 | 70,0 (39,7 až 89,2) | 70,0 (39,7 až 89,2) | 50,0 (23,7 až 76,3) | nedostatek dat | - |
| telnet_iot_login | security | T1110.001 | credential-access | 7 | 57,1 (25,0 až 84,2) | 57,1 (25,0 až 84,2) | 57,1 (25,0 až 84,2) | nedostatek dat | - |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 13 | 100,0 (77,2 až 100,0) | 100,0 (77,2 až 100,0) | 92,3 (66,7 až 98,6) | nedostatek dat | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 12 | 50,0 (25,4 až 74,6) | 50,0 (25,4 až 74,6) | 0,0 (0,0 až 24,2) | nedostatek dat | - |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 14 | 64,3 (38,8 až 83,7) | 71,4 (45,4 až 88,3) | 57,1 (32,6 až 78,6) | nedostatek dat | - |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 13 | 30,8 (12,7 až 57,6) | 30,8 (12,7 až 57,6) | 23,1 (8,2 až 50,3) | nedostatek dat | - |
| web_exploit | security | - | initial-access | 63 | 85,7 (75,0 až 92,3) | 85,7 (75,0 až 92,3) | 66,7 (54,4 až 77,1) | pod prahem | c (otevřené) |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 9 | 66,7 (35,4 až 87,9) | 66,7 (35,4 až 87,9) | 66,7 (35,4 až 87,9) | nedostatek dat | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 68 | 60,3 (48,4 až 71,1) | 64,7 (52,8 až 75,0) | 54,4 (42,7 až 65,7) |
| command-and-control | 384 | 89,8 (86,4 až 92,5) | 89,8 (86,4 až 92,5) | 73,4 (68,8 až 77,6) |
| credential-access | 363 | 83,7 (79,6 až 87,2) | 83,7 (79,6 až 87,2) | 77,4 (72,8 až 81,4) |
| discovery | 352 | 86,1 (82,1 až 89,3) | 86,6 (82,7 až 89,8) | 80,7 (76,2 až 84,5) |
| execution | 21 | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) |
| exfiltration | 205 | 71,7 (65,2 až 77,4) | 74,1 (67,7 až 79,7) | 64,9 (58,1 až 71,1) |
| impact | 228 | 81,6 (76,0 až 86,1) | 82,0 (76,5 až 86,5) | 69,7 (63,5 až 75,3) |
| initial-access | 263 | 75,7 (70,1 až 80,5) | 75,3 (69,7 až 80,1) | 51,3 (45,3 až 57,3) |
| lateral-movement | 232 | 91,4 (87,1 až 94,4) | 92,2 (88,1 až 95,0) | 84,1 (78,8 až 88,2) |
| none | 462 | 76,4 (72,3 až 80,1) | 78,4 (74,4 až 81,9) | 73,2 (68,9 až 77,0) |
| reconnaissance | 48 | 60,4 (46,3 až 73,0) | 60,4 (46,3 až 73,0) | 60,4 (46,3 až 73,0) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 32 | 93,8 (79,9 až 98,3) | 93,8 (79,9 až 98,3) | 90,6 (75,8 až 96,8) | 0,0 % |
| ops_fault | 430 | 75,1 (70,8 až 79,0) | 77,2 (73,0 až 80,9) | 71,9 (67,4 až 75,9) | 0,0 % |
| security | 2164 | 82,5 (80,9 až 84,1) | 83,1 (81,4 až 84,6) | 71,9 (69,9 až 73,7) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 363 | 83,7 (79,6 až 87,2) | 83,7 (79,6 až 87,2) | 77,4 (72,8 až 81,4) | nedosaženo |
| taktika discovery | 352 | 86,1 (82,1 až 89,3) | 86,6 (82,7 až 89,8) | 80,7 (76,2 až 84,5) | nedosaženo |
| taktika lateral-movement | 232 | 91,4 (87,1 až 94,4) | 92,2 (88,1 až 95,0) | 84,1 (78,8 až 88,2) | splněno |
| rodina c2_slow_long_interval | 13 | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | nedostatek dat |
| rodina ssh_spray_slow_distributed | 10 | 70,0 (39,7 až 89,2) | 70,0 (39,7 až 89,2) | 50,0 (23,7 až 76,3) | nedostatek dat |
| rodina data_staging_smb_internal | 18 | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | 50,0 (29,0 až 71,0) | nedostatek dat |
| rodina kerberos_ticket_request_burst | 16 | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | 81,2 (57,0 až 93,4) | nedostatek dat |
| rodina ics_attack | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat |
| rodina cloud_api_discovery_burst | 8 | 37,5 (13,7 až 69,4) | 37,5 (13,7 až 69,4) | 0,0 (0,0 až 32,4) | nedostatek dat |
| rodina rdp_bruteforce | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 90,9 (62,3 až 98,4) | nedostatek dat |
| rodina ddos_syn_flood_distributed | 11 | 36,4 (15,2 až 64,6) | 36,4 (15,2 až 64,6) | 27,3 (9,7 až 56,6) | nedostatek dat |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| credential_stuffing (security) | 58 | 75,9 | c (otevřené) |
| ssh_bruteforce (security) | 108 | 83,3 | c (otevřené) |
| exploit_attempt (security) | 110 | 83,6 | c (otevřené) |
| c2_beacon (security) | 104 | 84,6 | c (otevřené) |
| web_exploit (security) | 63 | 85,7 | c (otevřené) |
| port_scan_vertical (security) | 92 | 89,1 | c (otevřené) |
| exfiltration (security) | 75 | 89,3 | c (otevřené) |
| port_scan_horizontal (security) | 78 | 91,0 | b (zmírněno, zbývá mezera) |

