# Koncová telemetrie: vypnuto (základ) proti zapnuto (kandidát)

Rameno `off` (základ) proti `on` (kandidát), párově po sítích: 40 sítí, 2847 útoků a poruch s toky, 402 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 82,0 (80,6 až 83,4) | 84,8 (83,4 až 86,1) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 11,47 | 11,91 | poměr 1,038 (1,023 až 1,054); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 135,2 | 139,2 | poměr 1,030 (1,024 až 1,035) |
| útoky s omylem zavřeným nálezem | 30 (1,1 %) | 23 (0,8 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 33615 | 34612 |
| potvrzeno | 2563 | 3663 |
| vyvráceno | 247 | 216 |
| eskalováno (nerozhodnuto) | 30588 | 30519 |
| vyvráceno omylem (kontrafaktuál) | 11 | 10 |
| podíl případů pravdivého útoku mezi případy žebříku (off) | 41,9 % z 33398 |
| podíl případů pravdivého útoku mezi případy žebříku (on) | 43,1 % z 34398 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 236 z 247, kandidát 206 z 216. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 2314 z 2563, kandidát 3303 z 3663. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| planned_maintenance_window | benign_change | - | none | 24 | 100,0 (86,2 až 100,0) | 100,0 (86,2 až 100,0) | 100,0 (86,2 až 100,0) | nedostatek dat | - |
| planned_patch_reboot_wave | benign_change | - | none | 17 | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | nedostatek dat | - |
| seasonal_peak_web | benign_change | - | none | 11 | 90,9 (62,3 až 98,4) | 90,9 (62,3 až 98,4) | 90,9 (62,3 až 98,4) | nedostatek dat | - |
| access_point_controller_failure | ops_fault | - | none | 17 | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | nedostatek dat | - |
| app_server_crash_cascade | ops_fault | - | none | 18 | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | nedostatek dat | - |
| backup_window_overrun | ops_fault | - | none | 12 | 91,7 (64,6 až 98,5) | 91,7 (64,6 až 98,5) | 83,3 (55,2 až 95,3) | nedostatek dat | - |
| broadcast_storm_loop | ops_fault | - | none | 16 | 37,5 (18,5 až 61,4) | 37,5 (18,5 až 61,4) | 31,2 (14,2 až 55,6) | nedostatek dat | - |
| cert_chain_misconfig_external | ops_fault | - | none | 18 | 83,3 (60,8 až 94,2) | 83,3 (60,8 až 94,2) | 83,3 (60,8 až 94,2) | nedostatek dat | - |
| cert_expired_internal_service | ops_fault | - | none | 13 | 7,7 (1,4 až 33,3) | 7,7 (1,4 až 33,3) | 0,0 (0,0 až 22,8) | nedostatek dat | - |
| core_router_flapping | ops_fault | - | none | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | nedostatek dat | - |
| db_overload_degradation | ops_fault | - | none | 13 | 100,0 (77,2 až 100,0) | 100,0 (77,2 až 100,0) | 100,0 (77,2 až 100,0) | nedostatek dat | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 17 | 23,5 (9,6 až 47,3) | 23,5 (9,6 až 47,3) | 17,6 (6,2 až 41,0) | nedostatek dat | - |
| dhcp_server_down | ops_fault | - | none | 18 | 94,4 (74,2 až 99,0) | 94,4 (74,2 až 99,0) | 94,4 (74,2 až 99,0) | nedostatek dat | - |
| disk_full_backup_failure | ops_fault | - | none | 10 | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | nedostatek dat | - |
| dns_partial_failure | ops_fault | - | none | 23 | 82,6 (62,9 až 93,0) | 82,6 (62,9 až 93,0) | 65,2 (44,9 až 81,2) | nedostatek dat | - |
| dns_slow_resolution | ops_fault | - | none | 19 | 57,9 (36,3 až 76,9) | 57,9 (36,3 až 76,9) | 42,1 (23,1 až 63,7) | nedostatek dat | - |
| duplicate_ip_conflict | ops_fault | - | none | 23 | 95,7 (79,0 až 99,2) | 95,7 (79,0 až 99,2) | 95,7 (79,0 až 99,2) | nedostatek dat | - |
| flapping_service | ops_fault | - | none | 15 | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | nedostatek dat | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 16 | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | nedostatek dat | - |
| load_balancer_partial_outage | ops_fault | - | none | 7 | 100,0 (64,6 až 100,0) | 100,0 (64,6 až 100,0) | 100,0 (64,6 až 100,0) | nedostatek dat | - |
| mail_relay_queue_retry | ops_fault | - | none | 20 | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | 100,0 (83,9 až 100,0) | nedostatek dat | - |
| mdns_ssdp_storm | ops_fault | - | none | 15 | 20,0 (7,0 až 45,2) | 20,0 (7,0 až 45,2) | 13,3 (3,7 až 37,9) | nedostatek dat | - |
| memory_exhaustion_stall | ops_fault | - | none | 15 | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | nedostatek dat | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 16 | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | nedostatek dat | - |
| ntp_clock_drift_host | ops_fault | - | none | 23 | 91,3 (73,2 až 97,6) | 91,3 (73,2 až 97,6) | 91,3 (73,2 až 97,6) | nedostatek dat | - |
| ntp_unreachable | ops_fault | - | none | 22 | 50,0 (30,7 až 69,3) | 54,5 (34,7 až 73,1) | 31,8 (16,4 až 52,7) | nedostatek dat | - |
| slow_link_loss_degradation | ops_fault | - | none | 18 | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | 100,0 (82,4 až 100,0) | nedostatek dat | - |
| switch_outage_subnet | ops_fault | - | none | 17 | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | nedostatek dat | - |
| uplink_saturation | ops_fault | - | none | 18 | 22,2 (9,0 až 45,2) | 22,2 (9,0 až 45,2) | 5,6 (1,0 až 25,8) | nedostatek dat | - |
| vpn_concentrator_down | ops_fault | - | none | 11 | 90,9 (62,3 až 98,4) | 90,9 (62,3 až 98,4) | 90,9 (62,3 až 98,4) | nedostatek dat | - |
| api_enum_distributed | security | T1595.002 | reconnaissance | 12 | 75,0 (46,8 až 91,1) | 75,0 (46,8 až 91,1) | 75,0 (46,8 až 91,1) | nedostatek dat | - |
| app_layer_flood_api | security | T1499.003 | impact | 14 | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | nedostatek dat | - |
| apt_chain | security | - | lateral-movement | 19 | 100,0 (83,2 až 100,0) | 100,0 (83,2 až 100,0) | 100,0 (83,2 až 100,0) | nedostatek dat | - |
| backup_service_probing | security | T1490 | impact | 7 | 100,0 (64,6 až 100,0) | 100,0 (64,6 až 100,0) | 100,0 (64,6 až 100,0) | nedostatek dat | - |
| bucket_mass_download | security | T1530 | collection | 15 | 53,3 (30,1 až 75,2) | 53,3 (30,1 až 75,2) | 53,3 (30,1 až 75,2) | nedostatek dat | - |
| c2_alt_port_8443 | security | T1571 | command-and-control | 16 | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | nedostatek dat | - |
| c2_beacon | security | - | command-and-control | 105 | 82,9 (74,5 až 88,9) | 92,4 (85,7 až 96,1) | 66,7 (57,2 až 75,0) | detekce ano, typ ne | - |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 15 | 86,7 (62,1 až 96,3) | 86,7 (62,1 až 96,3) | 86,7 (62,1 až 96,3) | nedostatek dat | - |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 12 | 66,7 (39,1 až 86,2) | 66,7 (39,1 až 86,2) | 16,7 (4,7 až 44,8) | nedostatek dat | - |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 21 | 57,1 (36,5 až 75,5) | 57,1 (36,5 až 75,5) | 38,1 (20,8 až 59,1) | nedostatek dat | - |
| c2_doh_resolver | security | T1572 | command-and-control | 19 | 94,7 (75,4 až 99,1) | 94,7 (75,4 až 99,1) | 89,5 (68,6 až 97,1) | nedostatek dat | - |
| c2_high_jitter | security | T1071.001 | command-and-control | 13 | 69,2 (42,4 až 87,3) | 69,2 (42,4 až 87,3) | 53,8 (29,1 až 76,8) | nedostatek dat | - |
| c2_https_legit_service | security | T1102 | command-and-control | 23 | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | nedostatek dat | - |
| c2_icmp_tunnel | security | T1095 | command-and-control | 19 | 94,7 (75,4 až 99,1) | 94,7 (75,4 až 99,1) | 94,7 (75,4 až 99,1) | nedostatek dat | - |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 17 | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | nedostatek dat | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 16 | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | nedostatek dat | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 23 | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | nedostatek dat | - |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | nedostatek dat | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat | - |
| c2_udp_custom_port | security | T1095 | command-and-control | 19 | 94,7 (75,4 až 99,1) | 94,7 (75,4 až 99,1) | 94,7 (75,4 až 99,1) | nedostatek dat | - |
| c2_websocket_long | security | T1071.001 | command-and-control | 23 | 91,3 (73,2 až 97,6) | 91,3 (73,2 až 97,6) | 91,3 (73,2 až 97,6) | nedostatek dat | - |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 16 | 12,5 (3,5 až 36,0) | 12,5 (3,5 až 36,0) | 0,0 (0,0 až 19,4) | nedostatek dat | - |
| cloud_api_discovery_burst | security | T1580 | discovery | 13 | 7,7 (1,4 až 33,3) | 7,7 (1,4 až 33,3) | 0,0 (0,0 až 22,8) | nedostatek dat | - |
| credential_stuffing | security | - | credential-access | 50 | 80,0 (67,0 až 88,8) | 82,0 (69,2 až 90,2) | 76,0 (62,6 až 85,7) | pod prahem | b (zmírněno, zbývá mezera) |
| cryptomining | security | - | impact | 52 | 82,7 (70,3 až 90,6) | 88,5 (77,0 až 94,6) | 80,8 (68,1 až 89,2) | pod prahem | b (zmírněno, zbývá mezera) |
| data_destruction_smb_wave | security | T1485 | impact | 13 | 92,3 (66,7 až 98,6) | 92,3 (66,7 až 98,6) | 69,2 (42,4 až 87,3) | nedostatek dat | - |
| data_staging_smb_internal | security | T1039 | collection | 13 | 84,6 (57,8 až 95,7) | 84,6 (57,8 až 95,7) | 76,9 (49,7 až 91,8) | nedostatek dat | - |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 19 | 100,0 (83,2 až 100,0) | 100,0 (83,2 až 100,0) | 94,7 (75,4 až 99,1) | nedostatek dat | - |
| ddos_dns_amplification | security | T1498.002 | impact | 15 | 66,7 (41,7 až 84,8) | 66,7 (41,7 až 84,8) | 60,0 (35,7 až 80,2) | nedostatek dat | - |
| ddos_ntp_amplification | security | T1498.002 | impact | 25 | 100,0 (86,7 až 100,0) | 100,0 (86,7 až 100,0) | 96,0 (80,5 až 99,3) | nedostatek dat | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 9 | 77,8 (45,3 až 93,7) | 77,8 (45,3 až 93,7) | 77,8 (45,3 až 93,7) | nedostatek dat | - |
| ddos_volume | security | - | impact | 40 | 97,5 (87,1 až 99,6) | 97,5 (87,1 až 99,6) | 95,0 (83,5 až 98,6) | nedostatek dat | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 22 | 86,4 (66,7 až 95,3) | 86,4 (66,7 až 95,3) | 81,8 (61,5 až 92,7) | nedostatek dat | - |
| dns_tunnel | security | - | command-and-control | 51 | 96,1 (86,8 až 98,9) | 96,1 (86,8 až 98,9) | 74,5 (61,1 až 84,5) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 13 | 23,1 (8,2 až 50,3) | 23,1 (8,2 až 50,3) | 15,4 (4,3 až 42,2) | nedostatek dat | - |
| drive_by_bulk_download | security | T1189 | initial-access | 21 | 9,5 (2,7 až 28,9) | 9,5 (2,7 až 28,9) | 0,0 (0,0 až 15,5) | nedostatek dat | - |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 10 | 10,0 (1,8 až 40,4) | 10,0 (1,8 až 40,4) | 10,0 (1,8 až 40,4) | nedostatek dat | - |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 16 | 25,0 (10,2 až 49,5) | 25,0 (10,2 až 49,5) | 6,2 (1,1 až 28,3) | nedostatek dat | - |
| exfil_dns_slow | security | T1048.003 | exfiltration | 23 | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | 56,5 (36,8 až 74,4) | nedostatek dat | - |
| exfil_https_burst | security | T1041 | exfiltration | 20 | 65,0 (43,3 až 81,9) | 65,0 (43,3 až 81,9) | 60,0 (38,7 až 78,1) | nedostatek dat | - |
| exfil_icmp_payload | security | T1048 | exfiltration | 20 | 35,0 (18,1 až 56,7) | 35,0 (18,1 až 56,7) | 10,0 (2,8 až 30,1) | nedostatek dat | - |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 15 | 80,0 (54,8 až 93,0) | 80,0 (54,8 až 93,0) | 80,0 (54,8 až 93,0) | nedostatek dat | - |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 16 | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | 100,0 (80,6 až 100,0) | nedostatek dat | - |
| exfiltration | security | - | exfiltration | 71 | 94,4 (86,4 až 97,8) | 94,4 (86,4 až 97,8) | 93,0 (84,6 až 97,0) | splněno | - |
| exploit_attempt | security | - | initial-access | 134 | 56,7 (48,3 až 64,8) | 88,8 (82,4 až 93,1) | 45,5 (37,3 až 54,0) | pod prahem | b (zmírněno, zbývá mezera) |
| fleet_beacon | security | - | command-and-control | 16 | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | 87,5 (64,0 až 96,5) | nedostatek dat | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 22 | 86,4 (66,7 až 95,3) | 86,4 (66,7 až 95,3) | 86,4 (66,7 až 95,3) | nedostatek dat | - |
| http_slow_connections_dos | security | T1499.002 | impact | 9 | 66,7 (35,4 až 87,9) | 66,7 (35,4 až 87,9) | 44,4 (18,9 až 73,3) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 10 | 90,0 (59,6 až 98,2) | 90,0 (59,6 až 98,2) | 90,0 (59,6 až 98,2) | nedostatek dat | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 14 | 28,6 (11,7 až 54,6) | 28,6 (11,7 až 54,6) | 28,6 (11,7 až 54,6) | nedostatek dat | - |
| insider_hoarding | security | - | exfiltration | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 92,9 (68,5 až 98,7) | nedostatek dat | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | nedostatek dat | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 24 | 100,0 (86,2 až 100,0) | 100,0 (86,2 až 100,0) | 91,7 (74,2 až 97,7) | nedostatek dat | - |
| lateral_movement | security | - | lateral-movement | 103 | 90,3 (83,0 až 94,6) | 100,0 (96,4 až 100,0) | 80,6 (71,9 až 87,1) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 24 | 91,7 (74,2 až 97,7) | 91,7 (74,2 až 97,7) | 75,0 (55,1 až 88,0) | nedostatek dat | - |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 11 | 81,8 (52,3 až 94,9) | 81,8 (52,3 až 94,9) | 81,8 (52,3 až 94,9) | nedostatek dat | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 21 | 76,2 (54,9 až 89,4) | 81,0 (60,0 až 92,3) | 76,2 (54,9 až 89,4) | nedostatek dat | - |
| lateral_winrm | security | T1021.006 | lateral-movement | 12 | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | 100,0 (75,8 až 100,0) | nedostatek dat | - |
| lateral_wmi_dcom | security | T1047 | execution | 9 | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | nedostatek dat | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 17 | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | 88,2 (65,7 až 96,7) | nedostatek dat | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 19 | 94,7 (75,4 až 99,1) | 94,7 (75,4 až 99,1) | 89,5 (68,6 až 97,1) | nedostatek dat | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 18 | 72,2 (49,1 až 87,5) | 72,2 (49,1 až 87,5) | 72,2 (49,1 až 87,5) | nedostatek dat | - |
| mqtt_probe_ext | security | T1046 | discovery | 22 | 90,9 (72,2 až 97,5) | 90,9 (72,2 až 97,5) | 90,9 (72,2 až 97,5) | nedostatek dat | - |
| mssql_login_failures | security | T1110.001 | credential-access | 15 | 86,7 (62,1 až 96,3) | 86,7 (62,1 až 96,3) | 86,7 (62,1 až 96,3) | nedostatek dat | - |
| mysql_login_failures | security | T1110.001 | credential-access | 16 | 87,5 (64,0 až 96,5) | 87,5 (64,0 až 96,5) | 81,2 (57,0 až 93,4) | nedostatek dat | - |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 14 | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | nedostatek dat | - |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 22 | 86,4 (66,7 až 95,3) | 86,4 (66,7 až 95,3) | 86,4 (66,7 až 95,3) | nedostatek dat | - |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 14 | 78,6 (52,4 až 92,4) | 78,6 (52,4 až 92,4) | 78,6 (52,4 až 92,4) | nedostatek dat | - |
| port_scan_horizontal | security | - | discovery | 73 | 87,7 (78,2 až 93,4) | 89,0 (79,8 až 94,3) | 80,8 (70,3 až 88,2) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 103 | 86,4 (78,5 až 91,7) | 86,4 (78,5 až 91,7) | 84,5 (76,2 až 90,2) | pod prahem | c (otevřené) |
| public_app_probe_trickle | security | T1190 | initial-access | 5 | 100,0 (56,6 až 100,0) | 100,0 (56,6 až 100,0) | 80,0 (37,6 až 96,4) | nedostatek dat | - |
| ransomware | security | - | impact | 38 | 97,4 (86,5 až 99,5) | 100,0 (90,8 až 100,0) | 97,4 (86,5 až 99,5) | nedostatek dat | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 17 | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | nedostatek dat | - |
| rdp_sweep_ext | security | T1046 | discovery | 10 | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | 80,0 (49,0 až 94,3) | nedostatek dat | - |
| resource_hijack_pool_tls | security | T1496 | impact | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | nedostatek dat | - |
| rogue_device | security | - | initial-access | 19 | 89,5 (68,6 až 97,1) | 89,5 (68,6 až 97,1) | 84,2 (62,4 až 94,5) | nedostatek dat | - |
| share_encryption_wave_slow | security | T1486 | impact | 14 | 100,0 (78,5 až 100,0) | 100,0 (78,5 až 100,0) | 71,4 (45,4 až 88,3) | nedostatek dat | - |
| slow_scan | security | - | discovery | 85 | 96,5 (90,1 až 98,8) | 96,5 (90,1 až 98,8) | 89,4 (81,1 až 94,3) | splněno | - |
| smb_login_failures | security | T1110 | credential-access | 21 | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | 95,2 (77,3 až 99,2) | nedostatek dat | - |
| smb_share_enum_internal | security | T1135 | discovery | 10 | 60,0 (31,3 až 83,2) | 60,0 (31,3 až 83,2) | 50,0 (23,7 až 76,3) | nedostatek dat | - |
| smb_sweep_ext | security | T1046 | discovery | 13 | 76,9 (49,7 až 91,8) | 69,2 (42,4 až 87,3) | 69,2 (42,4 až 87,3) | nedostatek dat | - |
| smtp_auth_spray | security | T1110.003 | credential-access | 16 | 81,2 (57,0 až 93,4) | 81,2 (57,0 až 93,4) | 81,2 (57,0 až 93,4) | nedostatek dat | - |
| snmp_sweep_ext | security | T1046 | discovery | 14 | 92,9 (68,5 až 98,7) | 92,9 (68,5 až 98,7) | 85,7 (60,1 až 96,0) | nedostatek dat | - |
| snmp_walk_internal | security | T1602.001 | collection | 9 | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | nedostatek dat | - |
| ssh_bruteforce | security | - | credential-access | 131 | 92,4 (86,5 až 95,8) | 92,4 (86,5 až 95,8) | 81,7 (74,2 až 87,4) | detekce ano, typ ne | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 18 | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | 66,7 (43,7 až 83,7) | nedostatek dat | - |
| telnet_iot_login | security | T1110.001 | credential-access | 14 | 35,7 (16,3 až 61,2) | 35,7 (16,3 až 61,2) | 28,6 (11,7 až 54,6) | nedostatek dat | - |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 10 | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | 100,0 (72,2 až 100,0) | nedostatek dat | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 10 | 70,0 (39,7 až 89,2) | 80,0 (49,0 až 94,3) | 0,0 (0,0 až 27,8) | nedostatek dat | - |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 17 | 52,9 (31,0 až 73,8) | 52,9 (31,0 až 73,8) | 47,1 (26,2 až 69,0) | nedostatek dat | - |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 9 | 44,4 (18,9 až 73,3) | 44,4 (18,9 až 73,3) | 44,4 (18,9 až 73,3) | nedostatek dat | - |
| web_exploit | security | - | initial-access | 77 | 83,1 (73,2 až 89,9) | 93,5 (85,7 až 97,2) | 74,0 (63,3 až 82,5) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 15 | 100,0 (79,6 až 100,0) | 100,0 (79,6 až 100,0) | 73,3 (48,0 až 89,1) | nedostatek dat | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 55 | 74,5 (61,7 až 84,2) | 74,5 (61,7 až 84,2) | 72,7 (59,8 až 82,7) |
| command-and-control | 452 | 87,2 (83,8 až 89,9) | 89,4 (86,2 až 91,9) | 77,9 (73,8 až 81,5) |
| credential-access | 408 | 86,8 (83,1 až 89,7) | 87,0 (83,4 až 89,9) | 81,4 (77,3 až 84,9) |
| discovery | 362 | 86,5 (82,6 až 89,6) | 86,5 (82,6 až 89,6) | 80,9 (76,6 až 84,7) |
| execution | 9 | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) | 100,0 (70,1 až 100,0) |
| exfiltration | 219 | 72,1 (65,9 až 77,7) | 72,1 (65,9 až 77,7) | 63,9 (57,4 až 70,0) |
| impact | 247 | 90,7 (86,4 až 93,7) | 92,3 (88,3 až 95,0) | 85,4 (80,5 až 89,3) |
| initial-access | 292 | 62,7 (57,0 až 68,0) | 80,5 (75,5 až 84,6) | 50,7 (45,0 až 56,4) |
| lateral-movement | 245 | 88,6 (84,0 až 92,0) | 93,1 (89,2 až 95,6) | 81,6 (76,3 až 86,0) |
| none | 496 | 79,8 (76,1 až 83,1) | 80,0 (76,3 až 83,3) | 76,0 (72,1 až 79,6) |
| reconnaissance | 62 | 74,2 (62,1 až 83,4) | 74,2 (62,1 až 83,4) | 64,5 (52,1 až 75,3) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 52 | 98,1 (89,9 až 99,7) | 98,1 (89,9 až 99,7) | 98,1 (89,9 až 99,7) | 0,0 % |
| ops_fault | 444 | 77,7 (73,6 až 81,3) | 77,9 (73,8 až 81,5) | 73,4 (69,1 až 77,3) | 0,0 % |
| security | 2351 | 82,5 (80,9 až 84,0) | 85,8 (84,3 až 87,1) | 75,1 (73,3 až 76,8) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 408 | 86,8 (83,1 až 89,7) | 87,0 (83,4 až 89,9) | 81,4 (77,3 až 84,9) | nedosaženo |
| taktika discovery | 362 | 86,5 (82,6 až 89,6) | 86,5 (82,6 až 89,6) | 80,9 (76,6 až 84,7) | nedosaženo |
| taktika lateral-movement | 245 | 88,6 (84,0 až 92,0) | 93,1 (89,2 až 95,6) | 81,6 (76,3 až 86,0) | splněno |
| rodina c2_slow_long_interval | 19 | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | 84,2 (62,4 až 94,5) | nedostatek dat |
| rodina ssh_spray_slow_distributed | 18 | 77,8 (54,8 až 91,0) | 77,8 (54,8 až 91,0) | 66,7 (43,7 až 83,7) | nedostatek dat |
| rodina data_staging_smb_internal | 13 | 84,6 (57,8 až 95,7) | 84,6 (57,8 až 95,7) | 76,9 (49,7 až 91,8) | nedostatek dat |
| rodina kerberos_ticket_request_burst | 11 | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | 100,0 (74,1 až 100,0) | nedostatek dat |
| rodina ics_attack | 0 | - | - | - | nepokryto v běhu |
| rodina cloud_api_discovery_burst | 13 | 7,7 (1,4 až 33,3) | 7,7 (1,4 až 33,3) | 0,0 (0,0 až 22,8) | nedostatek dat |
| rodina rdp_bruteforce | 17 | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | 100,0 (81,6 až 100,0) | nedostatek dat |
| rodina ddos_syn_flood_distributed | 9 | 77,8 (45,3 až 93,7) | 77,8 (45,3 až 93,7) | 77,8 (45,3 až 93,7) | nedostatek dat |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| credential_stuffing (security) | 50 | 82,0 | b (zmírněno, zbývá mezera) |
| port_scan_vertical (security) | 103 | 86,4 | c (otevřené) |
| cryptomining (security) | 52 | 88,5 | b (zmírněno, zbývá mezera) |
| exploit_attempt (security) | 134 | 88,8 | b (zmírněno, zbývá mezera) |
| port_scan_horizontal (security) | 73 | 89,0 | b (zmírněno, zbývá mezera) |

