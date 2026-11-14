# Krok 10: tvrdé záporné scénáře a nové seedy (svět k10)

Rameno `base` (základ) proti `cand` (kandidát), párově po sítích: 80 sítí, 6377 útoků a poruch s toky, 635 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 78,4 (77,4 až 79,4) | 78,9 (77,9 až 79,9) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 10,37 | 10,86 | poměr 1,048 (1,029 až 1,071); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 167,0 | 170,0 | poměr 1,018 (1,011 až 1,026) |
| útoky s omylem zavřeným nálezem | 34 (0,5 %) | 34 (0,5 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 60684 | 62519 |
| potvrzeno | 6963 | 7319 |
| vyvráceno | 591 | 575 |
| eskalováno (nerozhodnuto) | 52822 | 54292 |
| vyvráceno omylem (kontrafaktuál) | 15 | 32 |
| podíl případů pravdivého útoku mezi případy žebříku (base) | 49,0 % z 60376 |
| podíl případů pravdivého útoku mezi případy žebříku (cand) | 48,1 % z 62186 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 576 z 591, kandidát 543 z 575. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 6230 z 6963, kandidát 6551 z 7319. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| hn_admin_bulk_ssh | benign_change | - | none | 146 | 82,9 (75,9 až 88,1) | 82,9 (75,9 až 88,1) | 78,8 (71,4 až 84,6) | pod prahem | c (otevřené) |
| hn_authorized_internal_scan | benign_change | - | none | 166 | 95,8 (91,6 až 97,9) | 95,8 (91,6 až 97,9) | 92,8 (87,8 až 95,8) | splněno | - |
| hn_cdn_update_download | benign_change | - | none | 153 | 6,5 (3,6 až 11,6) | 6,5 (3,6 až 11,6) | 2,0 (0,7 až 5,6) | pod prahem | c (otevřené) |
| hn_db_replication_bulk | benign_change | - | none | 157 | 79,0 (72,0 až 84,6) | 79,0 (72,0 až 84,6) | 69,4 (61,8 až 76,1) | pod prahem | c (otevřené) |
| hn_mail_newsletter_burst | benign_change | - | none | 146 | 7,5 (4,3 až 13,0) | 7,5 (4,3 až 13,0) | 2,7 (1,1 až 6,8) | pod prahem | c (otevřené) |
| hn_monitoring_snmp_sweep | benign_change | - | none | 160 | 83,1 (76,6 až 88,1) | 83,1 (76,6 až 88,1) | 80,0 (73,1 až 85,5) | pod prahem | c (otevřené) |
| hn_nightly_cloud_backup_upload | benign_change | - | none | 166 | 47,6 (40,1 až 55,2) | 48,2 (40,7 až 55,7) | 43,4 (36,1 až 51,0) | pod prahem | b (zmírněno, zbývá mezera) |
| hn_password_sync_periodic | benign_change | - | none | 149 | 92,6 (87,3 až 95,8) | 92,6 (87,3 až 95,8) | 92,6 (87,3 až 95,8) | splněno | - |
| planned_maintenance_window | benign_change | - | none | 34 | 94,1 (80,9 až 98,4) | 94,1 (80,9 až 98,4) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| planned_patch_reboot_wave | benign_change | - | none | 25 | 100,0 (86,7 až 100,0) | 100,0 (86,7 až 100,0) | 100,0 (86,7 až 100,0) | nedostatek dat | - |
| seasonal_peak_web | benign_change | - | none | 18 | 94,4 (74,2 až 99,0) | 94,4 (74,2 až 99,0) | 94,4 (74,2 až 99,0) | nedostatek dat | - |
| access_point_controller_failure | ops_fault | - | none | 37 | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | nedostatek dat | - |
| app_server_crash_cascade | ops_fault | - | none | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| backup_window_overrun | ops_fault | - | none | 35 | 94,3 (81,4 až 98,4) | 94,3 (81,4 až 98,4) | 91,4 (77,6 až 97,0) | nedostatek dat | - |
| broadcast_storm_loop | ops_fault | - | none | 43 | 2,3 (0,4 až 12,1) | 14,0 (6,6 až 27,3) | 14,0 (6,6 až 27,3) | nedostatek dat | - |
| cert_chain_misconfig_external | ops_fault | - | none | 39 | 94,9 (83,1 až 98,6) | 94,9 (83,1 až 98,6) | 94,9 (83,1 až 98,6) | nedostatek dat | - |
| cert_expired_internal_service | ops_fault | - | none | 26 | 23,1 (11,0 až 42,1) | 23,1 (11,0 až 42,1) | 11,5 (4,0 až 29,0) | nedostatek dat | - |
| core_router_flapping | ops_fault | - | none | 37 | 97,3 (86,2 až 99,5) | 97,3 (86,2 až 99,5) | 94,6 (82,3 až 98,5) | nedostatek dat | - |
| db_overload_degradation | ops_fault | - | none | 31 | 100,0 (89,0 až 100,0) | 100,0 (89,0 až 100,0) | 100,0 (89,0 až 100,0) | nedostatek dat | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 24 | 4,2 (0,7 až 20,2) | 4,2 (0,7 až 20,2) | 4,2 (0,7 až 20,2) | nedostatek dat | - |
| dhcp_server_down | ops_fault | - | none | 28 | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | nedostatek dat | - |
| disk_full_backup_failure | ops_fault | - | none | 16 | 75,0 (50,5 až 89,8) | 75,0 (50,5 až 89,8) | 75,0 (50,5 až 89,8) | nedostatek dat | - |
| dns_partial_failure | ops_fault | - | none | 40 | 57,5 (42,2 až 71,5) | 57,5 (42,2 až 71,5) | 50,0 (35,2 až 64,8) | nedostatek dat | - |
| dns_slow_resolution | ops_fault | - | none | 40 | 60,0 (44,6 až 73,7) | 60,0 (44,6 až 73,7) | 45,0 (30,7 až 60,2) | nedostatek dat | - |
| duplicate_ip_conflict | ops_fault | - | none | 29 | 100,0 (88,3 až 100,0) | 100,0 (88,3 až 100,0) | 100,0 (88,3 až 100,0) | nedostatek dat | - |
| flapping_service | ops_fault | - | none | 33 | 93,9 (80,4 až 98,3) | 93,9 (80,4 až 98,3) | 93,9 (80,4 až 98,3) | nedostatek dat | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 37 | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | 94,6 (82,3 až 98,5) | nedostatek dat | - |
| load_balancer_partial_outage | ops_fault | - | none | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 96,3 (81,7 až 99,3) | nedostatek dat | - |
| mail_relay_queue_retry | ops_fault | - | none | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat | - |
| mdns_ssdp_storm | ops_fault | - | none | 35 | 0,0 (0,0 až 9,9) | 14,3 (6,3 až 29,4) | 14,3 (6,3 až 29,4) | nedostatek dat | - |
| memory_exhaustion_stall | ops_fault | - | none | 30 | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | 100,0 (88,6 až 100,0) | nedostatek dat | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 24 | 79,2 (59,5 až 90,8) | 79,2 (59,5 až 90,8) | 66,7 (46,7 až 82,0) | nedostatek dat | - |
| ntp_clock_drift_host | ops_fault | - | none | 29 | 93,1 (78,0 až 98,1) | 93,1 (78,0 až 98,1) | 79,3 (61,6 až 90,2) | nedostatek dat | - |
| ntp_unreachable | ops_fault | - | none | 29 | 44,8 (28,4 až 62,5) | 48,3 (31,4 až 65,6) | 34,5 (19,9 až 52,7) | nedostatek dat | - |
| slow_link_loss_degradation | ops_fault | - | none | 24 | 100,0 (86,2 až 100,0) | 100,0 (86,2 až 100,0) | 100,0 (86,2 až 100,0) | nedostatek dat | - |
| switch_outage_subnet | ops_fault | - | none | 34 | 79,4 (63,2 až 89,7) | 79,4 (63,2 až 89,7) | 79,4 (63,2 až 89,7) | nedostatek dat | - |
| uplink_saturation | ops_fault | - | none | 39 | 17,9 (9,0 až 32,7) | 17,9 (9,0 až 32,7) | 7,7 (2,7 až 20,3) | nedostatek dat | - |
| vpn_concentrator_down | ops_fault | - | none | 24 | 91,7 (74,2 až 97,7) | 91,7 (74,2 až 97,7) | 91,7 (74,2 až 97,7) | nedostatek dat | - |
| api_enum_distributed | security | T1595.002 | reconnaissance | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| app_layer_flood_api | security | T1499.003 | impact | 28 | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | nedostatek dat | - |
| apt_chain | security | - | lateral-movement | 42 | 95,2 (84,2 až 98,7) | 95,2 (84,2 až 98,7) | 95,2 (84,2 až 98,7) | nedostatek dat | - |
| backup_service_probing | security | T1490 | impact | 24 | 75,0 (55,1 až 88,0) | 75,0 (55,1 až 88,0) | 70,8 (50,8 až 85,1) | nedostatek dat | - |
| bucket_mass_download | security | T1530 | collection | 24 | 4,2 (0,7 až 20,2) | 4,2 (0,7 až 20,2) | 0,0 (0,0 až 13,8) | nedostatek dat | - |
| c2_alt_port_8443 | security | T1571 | command-and-control | 27 | 92,6 (76,6 až 97,9) | 92,6 (76,6 až 97,9) | 92,6 (76,6 až 97,9) | nedostatek dat | - |
| c2_beacon | security | - | command-and-control | 165 | 84,2 (77,9 až 89,0) | 84,2 (77,9 až 89,0) | 61,8 (54,2 až 68,9) | pod prahem | c (otevřené) |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 42 | 92,9 (81,0 až 97,5) | 92,9 (81,0 až 97,5) | 92,9 (81,0 až 97,5) | nedostatek dat | - |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 31 | 45,2 (29,2 až 62,2) | 45,2 (29,2 až 62,2) | 3,2 (0,6 až 16,2) | nedostatek dat | - |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 25 | 52,0 (33,5 až 70,0) | 52,0 (33,5 až 70,0) | 20,0 (8,9 až 39,1) | nedostatek dat | - |
| c2_doh_resolver | security | T1572 | command-and-control | 31 | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| c2_high_jitter | security | T1071.001 | command-and-control | 25 | 76,0 (56,6 až 88,5) | 76,0 (56,6 až 88,5) | 76,0 (56,6 až 88,5) | nedostatek dat | - |
| c2_https_legit_service | security | T1102 | command-and-control | 23 | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | 87,0 (67,9 až 95,5) | nedostatek dat | - |
| c2_icmp_tunnel | security | T1095 | command-and-control | 31 | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | 93,5 (79,3 až 98,2) | nedostatek dat | - |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | nedostatek dat | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 34 | 91,2 (77,0 až 97,0) | 88,2 (73,4 až 95,3) | 88,2 (73,4 až 95,3) | nedostatek dat | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 30 | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | 96,7 (83,3 až 99,4) | nedostatek dat | - |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 34 | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 29 | 79,3 (61,6 až 90,2) | 79,3 (61,6 až 90,2) | 72,4 (54,3 až 85,3) | nedostatek dat | - |
| c2_udp_custom_port | security | T1095 | command-and-control | 26 | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | 88,5 (71,0 až 96,0) | nedostatek dat | - |
| c2_websocket_long | security | T1071.001 | command-and-control | 25 | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | 92,0 (75,0 až 97,8) | nedostatek dat | - |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 26 | 3,8 (0,7 až 18,9) | 3,8 (0,7 až 18,9) | 0,0 (0,0 až 12,9) | nedostatek dat | - |
| cloud_api_discovery_burst | security | T1580 | discovery | 19 | 10,5 (2,9 až 31,4) | 10,5 (2,9 až 31,4) | 0,0 (0,0 až 16,8) | nedostatek dat | - |
| credential_stuffing | security | - | credential-access | 137 | 93,4 (88,0 až 96,5) | 93,4 (88,0 až 96,5) | 90,5 (84,4 až 94,4) | splněno | - |
| cryptomining | security | - | impact | 94 | 89,4 (81,5 až 94,1) | 89,4 (81,5 až 94,1) | 77,7 (68,2 až 84,9) | pod prahem | c (otevřené) |
| data_destruction_smb_wave | security | T1485 | impact | 31 | 87,1 (71,1 až 94,9) | 87,1 (71,1 až 94,9) | 74,2 (56,8 až 86,3) | nedostatek dat | - |
| data_staging_smb_internal | security | T1039 | collection | 24 | 83,3 (64,1 až 93,3) | 83,3 (64,1 až 93,3) | 75,0 (55,1 až 88,0) | nedostatek dat | - |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 17 | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | 94,1 (73,0 až 99,0) | nedostatek dat | - |
| ddos_dns_amplification | security | T1498.002 | impact | 28 | 64,3 (45,8 až 79,3) | 64,3 (45,8 až 79,3) | 53,6 (35,8 až 70,5) | nedostatek dat | - |
| ddos_ntp_amplification | security | T1498.002 | impact | 34 | 97,1 (85,1 až 99,5) | 97,1 (85,1 až 99,5) | 94,1 (80,9 až 98,4) | nedostatek dat | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 16 | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | nedostatek dat | - |
| ddos_volume | security | - | impact | 55 | 94,5 (85,1 až 98,1) | 94,5 (85,1 až 98,1) | 94,5 (85,1 až 98,1) | splněno | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 32 | 90,6 (75,8 až 96,8) | 90,6 (75,8 až 96,8) | 87,5 (71,9 až 95,0) | nedostatek dat | - |
| dns_tunnel | security | - | command-and-control | 76 | 94,7 (87,2 až 97,9) | 94,7 (87,2 až 97,9) | 77,6 (67,1 až 85,5) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 36 | 22,2 (11,7 až 38,1) | 22,2 (11,7 až 38,1) | 11,1 (4,4 až 25,3) | nedostatek dat | - |
| drive_by_bulk_download | security | T1189 | initial-access | 39 | 12,8 (5,6 až 26,7) | 12,8 (5,6 až 26,7) | 7,7 (2,7 až 20,3) | nedostatek dat | - |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 30 | 10,0 (3,5 až 25,6) | 13,3 (5,3 až 29,7) | 10,0 (3,5 až 25,6) | nedostatek dat | - |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 21 | 42,9 (24,5 až 63,5) | 47,6 (28,3 až 67,6) | 23,8 (10,6 až 45,1) | nedostatek dat | - |
| exfil_dns_slow | security | T1048.003 | exfiltration | 26 | 65,4 (46,2 až 80,6) | 61,5 (42,5 až 77,6) | 42,3 (25,5 až 61,1) | nedostatek dat | - |
| exfil_https_burst | security | T1041 | exfiltration | 23 | 43,5 (25,6 až 63,2) | 43,5 (25,6 až 63,2) | 34,8 (18,8 až 55,1) | nedostatek dat | - |
| exfil_icmp_payload | security | T1048 | exfiltration | 28 | 57,1 (39,1 až 73,5) | 57,1 (39,1 až 73,5) | 7,1 (2,0 až 22,6) | nedostatek dat | - |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 31 | 58,1 (40,8 až 73,6) | 77,4 (60,2 až 88,6) | 67,7 (50,1 až 81,4) | nedostatek dat | - |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 17 | 88,2 (65,7 až 96,7) | 94,1 (73,0 až 99,0) | 88,2 (65,7 až 96,7) | nedostatek dat | - |
| exfiltration | security | - | exfiltration | 135 | 88,1 (81,6 až 92,6) | 88,1 (81,6 až 92,6) | 87,4 (80,8 až 92,0) | pod prahem | c (otevřené) |
| exploit_attempt | security | - | initial-access | 215 | 84,2 (78,7 až 88,5) | 84,2 (78,7 až 88,5) | 44,7 (38,2 až 51,3) | pod prahem | c (otevřené) |
| fleet_beacon | security | - | command-and-control | 42 | 95,2 (84,2 až 98,7) | 95,2 (84,2 až 98,7) | 83,3 (69,4 až 91,7) | nedostatek dat | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 27 | 100,0 (87,5 až 100,0) | 100,0 (87,5 až 100,0) | 96,3 (81,7 až 99,3) | nedostatek dat | - |
| http_slow_connections_dos | security | T1499.002 | impact | 22 | 63,6 (43,0 až 80,3) | 63,6 (43,0 až 80,3) | 54,5 (34,7 až 73,1) | nedostatek dat | - |
| ics_attack | security | - | impact | 6 | 83,3 (43,6 až 97,0) | 83,3 (43,6 až 97,0) | 0,0 (0,0 až 39,0) | nedostatek dat | - |
| ics_dnp3_unsolicited_flood | security | T0814 | impact | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| ics_ethernetip_scan | security | T0846 | discovery | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| ics_opcua_enumeration | security | T0846 | discovery | 1 | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | nedostatek dat | - |
| ics_program_download_slow | security | T0843 | execution | 2 | 0,0 (0,0 až 65,8) | 0,0 (0,0 až 65,8) | 0,0 (0,0 až 65,8) | nedostatek dat | - |
| ics_s7_operating_mode_change | security | T0858 | execution | 1 | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | nedostatek dat | - |
| ics_slow_poll_new_source | security | T0801 | collection | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 0,0 (0,0 až 79,3) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 28 | 92,9 (77,4 až 98,0) | 92,9 (77,4 až 98,0) | 92,9 (77,4 až 98,0) | nedostatek dat | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 27 | 48,1 (30,7 až 66,0) | 48,1 (30,7 až 66,0) | 44,4 (27,6 až 62,7) | nedostatek dat | - |
| insider_hoarding | security | - | exfiltration | 46 | 100,0 (92,3 až 100,0) | 100,0 (92,3 až 100,0) | 100,0 (92,3 až 100,0) | nedostatek dat | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 28 | 89,3 (72,8 až 96,3) | 89,3 (72,8 až 96,3) | 89,3 (72,8 až 96,3) | nedostatek dat | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 24 | 95,8 (79,8 až 99,3) | 95,8 (79,8 až 99,3) | 91,7 (74,2 až 97,7) | nedostatek dat | - |
| lateral_movement | security | - | lateral-movement | 172 | 94,2 (89,6 až 96,8) | 94,2 (89,6 až 96,8) | 83,1 (76,8 až 88,0) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 37 | 89,2 (75,3 až 95,7) | 91,9 (78,7 až 97,2) | 75,7 (59,9 až 86,6) | nedostatek dat | - |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 31 | 100,0 (89,0 až 100,0) | 100,0 (89,0 až 100,0) | 100,0 (89,0 až 100,0) | nedostatek dat | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 35 | 91,4 (77,6 až 97,0) | 91,4 (77,6 až 97,0) | 85,7 (70,6 až 93,7) | nedostatek dat | - |
| lateral_winrm | security | T1021.006 | lateral-movement | 34 | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| lateral_wmi_dcom | security | T1047 | execution | 32 | 93,8 (79,9 až 98,3) | 93,8 (79,9 až 98,3) | 93,8 (79,9 až 98,3) | nedostatek dat | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 35 | 100,0 (90,1 až 100,0) | 100,0 (90,1 až 100,0) | 100,0 (90,1 až 100,0) | nedostatek dat | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 34 | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | nedostatek dat | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 29 | 58,6 (40,7 až 74,5) | 82,8 (65,5 až 92,4) | 79,3 (61,6 až 90,2) | nedostatek dat | - |
| mqtt_probe_ext | security | T1046 | discovery | 27 | 55,6 (37,3 až 72,4) | 55,6 (37,3 až 72,4) | 51,9 (34,0 až 69,3) | nedostatek dat | - |
| mssql_login_failures | security | T1110.001 | credential-access | 35 | 97,1 (85,5 až 99,5) | 97,1 (85,5 až 99,5) | 97,1 (85,5 až 99,5) | nedostatek dat | - |
| mysql_login_failures | security | T1110.001 | credential-access | 29 | 86,2 (69,4 až 94,5) | 86,2 (69,4 až 94,5) | 86,2 (69,4 až 94,5) | nedostatek dat | - |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 90,9 (72,2 až 97,5) | nedostatek dat | - |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 33 | 90,9 (76,4 až 96,9) | 90,9 (76,4 až 96,9) | 90,9 (76,4 až 96,9) | nedostatek dat | - |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 26 | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | 100,0 (87,1 až 100,0) | nedostatek dat | - |
| port_scan_horizontal | security | - | discovery | 147 | 86,4 (79,9 až 91,0) | 87,8 (81,5 až 92,1) | 83,0 (76,1 až 88,2) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 180 | 86,7 (80,9 až 90,9) | 86,7 (80,9 až 90,9) | 85,6 (79,7 až 89,9) | pod prahem | c (otevřené) |
| public_app_probe_trickle | security | T1190 | initial-access | 34 | 76,5 (60,0 až 87,6) | 76,5 (60,0 až 87,6) | 29,4 (16,8 až 46,2) | nedostatek dat | - |
| ransomware | security | - | impact | 50 | 98,0 (89,5 až 99,6) | 98,0 (89,5 až 99,6) | 90,0 (78,6 až 95,7) | detekce ano, typ ne | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 37 | 97,3 (86,2 až 99,5) | 97,3 (86,2 až 99,5) | 94,6 (82,3 až 98,5) | nedostatek dat | - |
| rdp_sweep_ext | security | T1046 | discovery | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | nedostatek dat | - |
| resource_hijack_pool_tls | security | T1496 | impact | 37 | 100,0 (90,6 až 100,0) | 100,0 (90,6 až 100,0) | 100,0 (90,6 až 100,0) | nedostatek dat | - |
| rogue_device | security | - | initial-access | 45 | 100,0 (92,1 až 100,0) | 100,0 (92,1 až 100,0) | 93,3 (82,1 až 97,7) | nedostatek dat | - |
| share_encryption_wave_slow | security | T1486 | impact | 15 | 93,3 (70,2 až 98,8) | 93,3 (70,2 až 98,8) | 93,3 (70,2 až 98,8) | nedostatek dat | - |
| slow_scan | security | - | discovery | 145 | 86,9 (80,4 až 91,4) | 87,6 (81,2 až 92,0) | 81,4 (74,3 až 86,9) | pod prahem | b (zmírněno, zbývá mezera) |
| smb_login_failures | security | T1110 | credential-access | 28 | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | 100,0 (87,9 až 100,0) | nedostatek dat | - |
| smb_share_enum_internal | security | T1135 | discovery | 21 | 85,7 (65,4 až 95,0) | 85,7 (65,4 až 95,0) | 85,7 (65,4 až 95,0) | nedostatek dat | - |
| smb_sweep_ext | security | T1046 | discovery | 32 | 71,9 (54,6 až 84,4) | 71,9 (54,6 až 84,4) | 68,8 (51,4 až 82,0) | nedostatek dat | - |
| smtp_auth_spray | security | T1110.003 | credential-access | 25 | 100,0 (86,7 až 100,0) | 100,0 (86,7 až 100,0) | 100,0 (86,7 až 100,0) | nedostatek dat | - |
| snmp_sweep_ext | security | T1046 | discovery | 27 | 92,6 (76,6 až 97,9) | 92,6 (76,6 až 97,9) | 88,9 (71,9 až 96,1) | nedostatek dat | - |
| snmp_walk_internal | security | T1602.001 | collection | 22 | 95,5 (78,2 až 99,2) | 95,5 (78,2 až 99,2) | 90,9 (72,2 až 97,5) | nedostatek dat | - |
| ssh_bruteforce | security | - | credential-access | 227 | 94,7 (91,0 až 97,0) | 94,7 (91,0 až 97,0) | 89,9 (85,3 až 93,2) | splněno | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 31 | 90,3 (75,1 až 96,7) | 90,3 (75,1 až 96,7) | 80,6 (63,7 až 90,8) | nedostatek dat | - |
| telnet_iot_login | security | T1110.001 | credential-access | 29 | 48,3 (31,4 až 65,6) | 48,3 (31,4 až 65,6) | 44,8 (28,4 až 62,5) | nedostatek dat | - |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 29 | 89,7 (73,6 až 96,4) | 93,1 (78,0 až 98,1) | 82,8 (65,5 až 92,4) | nedostatek dat | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 26 | 30,8 (16,5 až 50,0) | 30,8 (16,5 až 50,0) | 7,7 (2,1 až 24,1) | nedostatek dat | - |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 28 | 82,1 (64,4 až 92,1) | 82,1 (64,4 až 92,1) | 78,6 (60,5 až 89,8) | nedostatek dat | - |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 25 | 40,0 (23,4 až 59,3) | 40,0 (23,4 až 59,3) | 32,0 (17,2 až 51,6) | nedostatek dat | - |
| web_exploit | security | - | initial-access | 119 | 95,8 (90,5 až 98,2) | 95,8 (90,5 až 98,2) | 79,8 (71,7 až 86,1) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 21 | 100,0 (84,5 až 100,0) | 100,0 (84,5 až 100,0) | 100,0 (84,5 až 100,0) | nedostatek dat | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 100 | 60,0 (50,2 až 69,1) | 67,0 (57,3 až 75,4) | 61,0 (51,2 až 70,0) |
| command-and-control | 749 | 87,0 (84,5 až 89,3) | 86,9 (84,3 až 89,1) | 76,5 (73,3 až 79,4) |
| credential-access | 771 | 91,1 (88,8 až 92,9) | 91,1 (88,8 až 92,9) | 88,1 (85,6 až 90,2) |
| discovery | 656 | 83,1 (80,0 až 85,8) | 83,5 (80,5 až 86,2) | 80,0 (76,8 až 82,9) |
| execution | 35 | 85,7 (70,6 až 93,7) | 85,7 (70,6 až 93,7) | 85,7 (70,6 až 93,7) |
| exfiltration | 384 | 69,3 (64,5 až 73,7) | 71,4 (66,6 až 75,6) | 62,8 (57,8 až 67,4) |
| impact | 441 | 89,6 (86,4 až 92,1) | 89,6 (86,4 až 92,1) | 82,5 (78,7 až 85,8) |
| initial-access | 533 | 76,2 (72,4 až 79,6) | 76,4 (72,6 až 79,8) | 51,0 (46,8 až 55,3) |
| lateral-movement | 425 | 93,2 (90,4 až 95,2) | 93,4 (90,6 až 95,4) | 86,4 (82,8 až 89,3) |
| none | 2167 | 67,6 (65,6 až 69,5) | 68,1 (66,1 až 70,0) | 64,2 (62,2 až 66,2) |
| reconnaissance | 116 | 73,3 (64,6 až 80,5) | 73,3 (64,6 až 80,5) | 69,0 (60,1 až 76,7) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 1320 | 64,3 (61,7 až 66,9) | 64,4 (61,8 až 66,9) | 60,3 (57,6 až 62,9) | 0,0 % |
| ops_fault | 847 | 72,6 (69,5 až 75,5) | 73,9 (70,8 až 76,8) | 70,4 (67,2 až 73,3) | 0,0 % |
| security | 4210 | 84,0 (82,9 až 85,1) | 84,5 (83,3 až 85,5) | 75,8 (74,5 až 77,1) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 771 | 91,1 (88,8 až 92,9) | 91,1 (88,8 až 92,9) | 88,1 (85,6 až 90,2) | splněno |
| taktika discovery | 656 | 83,1 (80,0 až 85,8) | 83,5 (80,5 až 86,2) | 80,0 (76,8 až 82,9) | nedosaženo |
| taktika lateral-movement | 425 | 93,2 (90,4 až 95,2) | 93,4 (90,6 až 95,4) | 86,4 (82,8 až 89,3) | splněno |
| rodina c2_slow_long_interval | 29 | 79,3 (61,6 až 90,2) | 79,3 (61,6 až 90,2) | 72,4 (54,3 až 85,3) | nedostatek dat |
| rodina ssh_spray_slow_distributed | 31 | 90,3 (75,1 až 96,7) | 90,3 (75,1 až 96,7) | 80,6 (63,7 až 90,8) | nedostatek dat |
| rodina data_staging_smb_internal | 24 | 83,3 (64,1 až 93,3) | 83,3 (64,1 až 93,3) | 75,0 (55,1 až 88,0) | nedostatek dat |
| rodina kerberos_ticket_request_burst | 28 | 89,3 (72,8 až 96,3) | 89,3 (72,8 až 96,3) | 89,3 (72,8 až 96,3) | nedostatek dat |
| rodina ics_attack | 6 | 83,3 (43,6 až 97,0) | 83,3 (43,6 až 97,0) | 0,0 (0,0 až 39,0) | nedostatek dat |
| rodina cloud_api_discovery_burst | 19 | 10,5 (2,9 až 31,4) | 10,5 (2,9 až 31,4) | 0,0 (0,0 až 16,8) | nedostatek dat |
| rodina rdp_bruteforce | 37 | 97,3 (86,2 až 99,5) | 97,3 (86,2 až 99,5) | 94,6 (82,3 až 98,5) | nedostatek dat |
| rodina ddos_syn_flood_distributed | 16 | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | 93,8 (71,7 až 98,9) | nedostatek dat |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| hn_cdn_update_download (benign_change) | 153 | 6,5 | c (otevřené) |
| hn_mail_newsletter_burst (benign_change) | 146 | 7,5 | c (otevřené) |
| hn_nightly_cloud_backup_upload (benign_change) | 166 | 48,2 | b (zmírněno, zbývá mezera) |
| hn_db_replication_bulk (benign_change) | 157 | 79,0 | c (otevřené) |
| hn_admin_bulk_ssh (benign_change) | 146 | 82,9 | c (otevřené) |
| hn_monitoring_snmp_sweep (benign_change) | 160 | 83,1 | c (otevřené) |
| exploit_attempt (security) | 215 | 84,2 | c (otevřené) |
| c2_beacon (security) | 165 | 84,2 | c (otevřené) |
| port_scan_vertical (security) | 180 | 86,7 | c (otevřené) |
| slow_scan (security) | 145 | 87,6 | b (zmírněno, zbývá mezera) |
| port_scan_horizontal (security) | 147 | 87,8 | b (zmírněno, zbývá mezera) |
| exfiltration (security) | 135 | 88,1 | c (otevřené) |
| cryptomining (security) | 94 | 89,4 | c (otevřené) |

