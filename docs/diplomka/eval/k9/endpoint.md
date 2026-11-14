# Koncová telemetrie: vypnuto (základ) proti zapnuto (kandidát)

Rameno `off` (základ) proti `on` (kandidát), párově po sítích: 120 sítí, 8692 útoků a poruch s toky, 1236 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 82,5 (81,7 až 83,3) | 85,0 (84,2 až 85,7) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 12,12 | 12,64 | poměr 1,043 (1,032 až 1,055); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 150,6 | 155,2 | poměr 1,030 (1,026 až 1,036) |
| útoky s omylem zavřeným nálezem | 76 (0,9 %) | 70 (0,8 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 112922 | 116936 |
| potvrzeno | 11906 | 15167 |
| vyvráceno | 1439 | 958 |
| eskalováno (nerozhodnuto) | 99030 | 100261 |
| vyvráceno omylem (kontrafaktuál) | 35 | 36 |
| podíl případů pravdivého útoku mezi případy žebříku (off) | 46,3 % z 112375 |
| podíl případů pravdivého útoku mezi případy žebříku (on) | 47,2 % z 116386 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 1404 z 1439, kandidát 922 z 958. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 10834 z 11906, kandidát 13706 z 15167. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| planned_maintenance_window | benign_change | - | none | 64 | 96,9 (89,3 až 99,1) | 96,9 (89,3 až 99,1) | 96,9 (89,3 až 99,1) | splněno | - |
| planned_patch_reboot_wave | benign_change | - | none | 50 | 100,0 (92,9 až 100,0) | 100,0 (92,9 až 100,0) | 100,0 (92,9 až 100,0) | splněno | - |
| seasonal_peak_web | benign_change | - | none | 34 | 91,2 (77,0 až 97,0) | 91,2 (77,0 až 97,0) | 88,2 (73,4 až 95,3) | nedostatek dat | - |
| access_point_controller_failure | ops_fault | - | none | 39 | 94,9 (83,1 až 98,6) | 94,9 (83,1 až 98,6) | 92,3 (79,7 až 97,3) | nedostatek dat | - |
| app_server_crash_cascade | ops_fault | - | none | 45 | 100,0 (92,1 až 100,0) | 100,0 (92,1 až 100,0) | 100,0 (92,1 až 100,0) | nedostatek dat | - |
| backup_window_overrun | ops_fault | - | none | 36 | 91,7 (78,2 až 97,1) | 91,7 (78,2 až 97,1) | 80,6 (65,0 až 90,2) | nedostatek dat | - |
| broadcast_storm_loop | ops_fault | - | none | 43 | 37,2 (24,4 až 52,1) | 37,2 (24,4 až 52,1) | 34,9 (22,4 až 49,8) | nedostatek dat | - |
| cert_chain_misconfig_external | ops_fault | - | none | 58 | 93,1 (83,6 až 97,3) | 93,1 (83,6 až 97,3) | 93,1 (83,6 až 97,3) | pod prahem | c (otevřené) |
| cert_expired_internal_service | ops_fault | - | none | 40 | 17,5 (8,7 až 31,9) | 17,5 (8,7 až 31,9) | 10,0 (4,0 až 23,1) | nedostatek dat | - |
| core_router_flapping | ops_fault | - | none | 50 | 98,0 (89,5 až 99,6) | 98,0 (89,5 až 99,6) | 98,0 (89,5 až 99,6) | splněno | - |
| db_overload_degradation | ops_fault | - | none | 32 | 100,0 (89,3 až 100,0) | 100,0 (89,3 až 100,0) | 100,0 (89,3 až 100,0) | nedostatek dat | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 43 | 18,6 (9,7 až 32,6) | 20,9 (11,4 až 35,2) | 16,3 (8,1 až 30,0) | nedostatek dat | - |
| dhcp_server_down | ops_fault | - | none | 57 | 98,2 (90,7 až 99,7) | 98,2 (90,7 až 99,7) | 98,2 (90,7 až 99,7) | splněno | - |
| disk_full_backup_failure | ops_fault | - | none | 27 | 92,6 (76,6 až 97,9) | 92,6 (76,6 až 97,9) | 88,9 (71,9 až 96,1) | nedostatek dat | - |
| dns_partial_failure | ops_fault | - | none | 71 | 74,6 (63,4 až 83,3) | 74,6 (63,4 až 83,3) | 63,4 (51,8 až 73,6) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| dns_slow_resolution | ops_fault | - | none | 65 | 60,0 (47,9 až 71,0) | 60,0 (47,9 až 71,0) | 46,2 (34,6 až 58,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| duplicate_ip_conflict | ops_fault | - | none | 54 | 94,4 (84,9 až 98,1) | 94,4 (84,9 až 98,1) | 94,4 (84,9 až 98,1) | pod prahem | c (otevřené) |
| flapping_service | ops_fault | - | none | 46 | 100,0 (92,3 až 100,0) | 100,0 (92,3 až 100,0) | 100,0 (92,3 až 100,0) | nedostatek dat | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 47 | 91,5 (80,1 až 96,6) | 91,5 (80,1 až 96,6) | 91,5 (80,1 až 96,6) | nedostatek dat | - |
| load_balancer_partial_outage | ops_fault | - | none | 29 | 96,6 (82,8 až 99,4) | 96,6 (82,8 až 99,4) | 93,1 (78,0 až 98,1) | nedostatek dat | - |
| mail_relay_queue_retry | ops_fault | - | none | 55 | 100,0 (93,5 až 100,0) | 100,0 (93,5 až 100,0) | 100,0 (93,5 až 100,0) | splněno | - |
| mdns_ssdp_storm | ops_fault | - | none | 41 | 24,4 (13,8 až 39,3) | 24,4 (13,8 až 39,3) | 22,0 (12,0 až 36,7) | nedostatek dat | - |
| memory_exhaustion_stall | ops_fault | - | none | 49 | 98,0 (89,3 až 99,6) | 98,0 (89,3 až 99,6) | 98,0 (89,3 až 99,6) | nedostatek dat | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 59 | 84,7 (73,5 až 91,8) | 84,7 (73,5 až 91,8) | 83,1 (71,5 až 90,5) | pod prahem | c (otevřené) |
| ntp_clock_drift_host | ops_fault | - | none | 57 | 91,2 (81,1 až 96,2) | 91,2 (81,1 až 96,2) | 86,0 (74,7 až 92,7) | pod prahem | c (otevřené) |
| ntp_unreachable | ops_fault | - | none | 50 | 52,0 (38,5 až 65,2) | 52,0 (38,5 až 65,2) | 34,0 (22,4 až 47,8) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| slow_link_loss_degradation | ops_fault | - | none | 51 | 100,0 (93,0 až 100,0) | 100,0 (93,0 až 100,0) | 100,0 (93,0 až 100,0) | splněno | - |
| switch_outage_subnet | ops_fault | - | none | 41 | 95,1 (83,9 až 98,7) | 95,1 (83,9 až 98,7) | 95,1 (83,9 až 98,7) | nedostatek dat | - |
| uplink_saturation | ops_fault | - | none | 48 | 20,8 (11,7 až 34,3) | 18,8 (10,2 až 31,9) | 8,3 (3,3 až 19,6) | nedostatek dat | - |
| vpn_concentrator_down | ops_fault | - | none | 31 | 87,1 (71,1 až 94,9) | 87,1 (71,1 až 94,9) | 87,1 (71,1 až 94,9) | nedostatek dat | - |
| api_enum_distributed | security | T1595.002 | reconnaissance | 37 | 83,8 (68,9 až 92,3) | 83,8 (68,9 až 92,3) | 83,8 (68,9 až 92,3) | nedostatek dat | - |
| app_layer_flood_api | security | T1499.003 | impact | 40 | 90,0 (76,9 až 96,0) | 90,0 (76,9 až 96,0) | 85,0 (70,9 až 92,9) | nedostatek dat | - |
| apt_chain | security | - | lateral-movement | 70 | 98,6 (92,3 až 99,7) | 98,6 (92,3 až 99,7) | 98,6 (92,3 až 99,7) | splněno | - |
| backup_service_probing | security | T1490 | impact | 31 | 83,9 (67,4 až 92,9) | 83,9 (67,4 až 92,9) | 77,4 (60,2 až 88,6) | nedostatek dat | - |
| bucket_mass_download | security | T1530 | collection | 43 | 27,9 (16,7 až 42,7) | 27,9 (16,7 až 42,7) | 18,6 (9,7 až 32,6) | nedostatek dat | - |
| c2_alt_port_8443 | security | T1571 | command-and-control | 39 | 89,7 (76,4 až 95,9) | 89,7 (76,4 až 95,9) | 87,2 (73,3 až 94,4) | nedostatek dat | - |
| c2_beacon | security | - | command-and-control | 355 | 79,2 (74,6 až 83,1) | 84,8 (80,7 až 88,2) | 63,7 (58,5 až 68,5) | pod prahem | b (zmírněno, zbývá mezera) |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 43 | 79,1 (64,8 až 88,6) | 79,1 (64,8 až 88,6) | 79,1 (64,8 až 88,6) | nedostatek dat | - |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 40 | 65,0 (49,5 až 77,9) | 67,5 (52,0 až 79,9) | 17,5 (8,7 až 31,9) | nedostatek dat | - |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 49 | 55,1 (41,3 až 68,1) | 55,1 (41,3 až 68,1) | 30,6 (19,5 až 44,5) | nedostatek dat | - |
| c2_doh_resolver | security | T1572 | command-and-control | 58 | 89,7 (79,2 až 95,2) | 89,7 (79,2 až 95,2) | 87,9 (77,1 až 94,0) | pod prahem | c (otevřené) |
| c2_high_jitter | security | T1071.001 | command-and-control | 47 | 68,1 (53,8 až 79,6) | 70,2 (56,0 až 81,3) | 59,6 (45,3 až 72,4) | nedostatek dat | - |
| c2_https_legit_service | security | T1102 | command-and-control | 52 | 90,4 (79,4 až 95,8) | 90,4 (79,4 až 95,8) | 86,5 (74,7 až 93,3) | pod prahem | c (otevřené) |
| c2_icmp_tunnel | security | T1095 | command-and-control | 53 | 90,6 (79,7 až 95,9) | 90,6 (79,7 až 95,9) | 90,6 (79,7 až 95,9) | pod prahem | c (otevřené) |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 60 | 96,7 (88,6 až 99,1) | 98,3 (91,1 až 99,7) | 96,7 (88,6 až 99,1) | splněno | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 46 | 97,8 (88,7 až 99,6) | 97,8 (88,7 až 99,6) | 93,5 (82,5 až 97,8) | nedostatek dat | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 61 | 83,6 (72,4 až 90,8) | 85,2 (74,3 až 92,0) | 83,6 (72,4 až 90,8) | pod prahem | b (zmírněno, zbývá mezera) |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 39 | 97,4 (86,8 až 99,5) | 97,4 (86,8 až 99,5) | 97,4 (86,8 až 99,5) | nedostatek dat | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 54 | 90,7 (80,1 až 96,0) | 90,7 (80,1 až 96,0) | 88,9 (77,8 až 94,8) | pod prahem | c (otevřené) |
| c2_udp_custom_port | security | T1095 | command-and-control | 44 | 86,4 (73,3 až 93,6) | 86,4 (73,3 až 93,6) | 86,4 (73,3 až 93,6) | nedostatek dat | - |
| c2_websocket_long | security | T1071.001 | command-and-control | 55 | 89,1 (78,2 až 94,9) | 89,1 (78,2 až 94,9) | 87,3 (76,0 až 93,7) | pod prahem | c (otevřené) |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 48 | 10,4 (4,5 až 22,2) | 12,5 (5,9 až 24,7) | 6,2 (2,1 až 16,8) | nedostatek dat | - |
| cloud_api_discovery_burst | security | T1580 | discovery | 41 | 9,8 (3,9 až 22,5) | 9,8 (3,9 až 22,5) | 4,9 (1,3 až 16,1) | nedostatek dat | - |
| credential_stuffing | security | - | credential-access | 204 | 92,2 (87,6 až 95,1) | 92,6 (88,2 až 95,5) | 90,2 (85,3 až 93,6) | splněno | - |
| cryptomining | security | - | impact | 144 | 86,8 (80,3 až 91,4) | 89,6 (83,5 až 93,6) | 81,9 (74,9 až 87,4) | pod prahem | b (zmírněno, zbývá mezera) |
| data_destruction_smb_wave | security | T1485 | impact | 35 | 85,7 (70,6 až 93,7) | 85,7 (70,6 až 93,7) | 74,3 (57,9 až 85,8) | nedostatek dat | - |
| data_staging_smb_internal | security | T1039 | collection | 39 | 84,6 (70,3 až 92,8) | 84,6 (70,3 až 92,8) | 66,7 (51,0 až 79,4) | nedostatek dat | - |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 34 | 100,0 (89,8 až 100,0) | 100,0 (89,8 až 100,0) | 97,1 (85,1 až 99,5) | nedostatek dat | - |
| ddos_dns_amplification | security | T1498.002 | impact | 47 | 72,3 (58,2 až 83,1) | 72,3 (58,2 až 83,1) | 66,0 (51,7 až 77,8) | nedostatek dat | - |
| ddos_ntp_amplification | security | T1498.002 | impact | 61 | 98,4 (91,3 až 99,7) | 98,4 (91,3 až 99,7) | 95,1 (86,5 až 98,3) | splněno | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 28 | 85,7 (68,5 až 94,3) | 85,7 (68,5 až 94,3) | 85,7 (68,5 až 94,3) | nedostatek dat | - |
| ddos_volume | security | - | impact | 110 | 92,7 (86,3 až 96,3) | 92,7 (86,3 až 96,3) | 88,2 (80,8 až 93,0) | splněno | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 56 | 83,9 (72,2 až 91,3) | 83,9 (72,2 až 91,3) | 78,6 (66,2 až 87,3) | pod prahem | c (otevřené) |
| dns_tunnel | security | - | command-and-control | 175 | 95,4 (91,2 až 97,7) | 96,6 (92,7 až 98,4) | 80,0 (73,5 až 85,3) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 36 | 11,1 (4,4 až 25,3) | 11,1 (4,4 až 25,3) | 8,3 (2,9 až 21,8) | nedostatek dat | - |
| drive_by_bulk_download | security | T1189 | initial-access | 50 | 8,0 (3,2 až 18,8) | 8,0 (3,2 až 18,8) | 2,0 (0,4 až 10,5) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 36 | 19,4 (9,8 až 35,0) | 19,4 (9,8 až 35,0) | 19,4 (9,8 až 35,0) | nedostatek dat | - |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 39 | 41,0 (27,1 až 56,6) | 41,0 (27,1 až 56,6) | 17,9 (9,0 až 32,7) | nedostatek dat | - |
| exfil_dns_slow | security | T1048.003 | exfiltration | 63 | 77,8 (66,1 až 86,3) | 76,2 (64,4 až 85,0) | 57,1 (44,9 až 68,6) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_https_burst | security | T1041 | exfiltration | 49 | 65,3 (51,3 až 77,1) | 65,3 (51,3 až 77,1) | 61,2 (47,2 až 73,6) | nedostatek dat | - |
| exfil_icmp_payload | security | T1048 | exfiltration | 54 | 53,7 (40,6 až 66,3) | 53,7 (40,6 až 66,3) | 9,3 (4,0 až 19,9) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 47 | 78,7 (65,1 až 88,0) | 78,7 (65,1 až 88,0) | 72,3 (58,2 až 83,1) | nedostatek dat | - |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 39 | 92,3 (79,7 až 97,3) | 92,3 (79,7 až 97,3) | 92,3 (79,7 až 97,3) | nedostatek dat | - |
| exfiltration | security | - | exfiltration | 237 | 93,7 (89,8 až 96,1) | 94,5 (90,8 až 96,8) | 92,8 (88,8 až 95,5) | splněno | - |
| exploit_attempt | security | - | initial-access | 387 | 60,7 (55,8 až 65,5) | 89,4 (85,9 až 92,1) | 47,5 (42,6 až 52,5) | pod prahem | b (zmírněno, zbývá mezera) |
| fleet_beacon | security | - | command-and-control | 44 | 90,9 (78,8 až 96,4) | 95,5 (84,9 až 98,7) | 79,5 (65,5 až 88,8) | nedostatek dat | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 50 | 90,0 (78,6 až 95,7) | 90,0 (78,6 až 95,7) | 88,0 (76,2 až 94,4) | pod prahem | c (otevřené) |
| http_slow_connections_dos | security | T1499.002 | impact | 29 | 69,0 (50,8 až 82,7) | 69,0 (50,8 až 82,7) | 58,6 (40,7 až 74,5) | nedostatek dat | - |
| ics_attack | security | - | impact | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat | - |
| ics_slow_poll_new_source | security | T0801 | collection | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 47 | 95,7 (85,8 až 98,8) | 95,7 (85,8 až 98,8) | 95,7 (85,8 až 98,8) | nedostatek dat | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 43 | 51,2 (36,8 až 65,4) | 51,2 (36,8 až 65,4) | 48,8 (34,6 až 63,2) | nedostatek dat | - |
| insider_hoarding | security | - | exfiltration | 60 | 95,0 (86,3 až 98,3) | 96,7 (88,6 až 99,1) | 93,3 (84,1 až 97,4) | splněno | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 39 | 100,0 (91,0 až 100,0) | 100,0 (91,0 až 100,0) | 97,4 (86,8 až 99,5) | nedostatek dat | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 63 | 98,4 (91,5 až 99,7) | 98,4 (91,5 až 99,7) | 92,1 (82,7 až 96,6) | splněno | - |
| lateral_movement | security | - | lateral-movement | 347 | 89,6 (86,0 až 92,4) | 98,3 (96,3 až 99,2) | 79,0 (74,4 až 82,9) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 59 | 88,1 (77,5 až 94,1) | 88,1 (77,5 až 94,1) | 71,2 (58,6 až 81,2) | pod prahem | c (otevřené) |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 46 | 91,3 (79,7 až 96,6) | 91,3 (79,7 až 96,6) | 91,3 (79,7 až 96,6) | nedostatek dat | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 50 | 84,0 (71,5 až 91,7) | 88,0 (76,2 až 94,4) | 84,0 (71,5 až 91,7) | pod prahem | b (zmírněno, zbývá mezera) |
| lateral_winrm | security | T1021.006 | lateral-movement | 45 | 97,8 (88,4 až 99,6) | 97,8 (88,4 až 99,6) | 95,6 (85,2 až 98,8) | nedostatek dat | - |
| lateral_wmi_dcom | security | T1047 | execution | 43 | 95,3 (84,5 až 98,7) | 95,3 (84,5 až 98,7) | 95,3 (84,5 až 98,7) | nedostatek dat | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 41 | 97,6 (87,4 až 99,6) | 97,6 (87,4 až 99,6) | 95,1 (83,9 až 98,7) | nedostatek dat | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 40 | 97,5 (87,1 až 99,6) | 97,5 (87,1 až 99,6) | 95,0 (83,5 až 98,6) | nedostatek dat | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 45 | 68,9 (54,3 až 80,5) | 71,1 (56,6 až 82,3) | 68,9 (54,3 až 80,5) | nedostatek dat | - |
| mqtt_probe_ext | security | T1046 | discovery | 48 | 68,8 (54,7 až 80,1) | 70,8 (56,8 až 81,8) | 64,6 (50,4 až 76,6) | nedostatek dat | - |
| mssql_login_failures | security | T1110.001 | credential-access | 44 | 88,6 (76,0 až 95,0) | 88,6 (76,0 až 95,0) | 88,6 (76,0 až 95,0) | nedostatek dat | - |
| mysql_login_failures | security | T1110.001 | credential-access | 49 | 85,7 (73,3 až 92,9) | 85,7 (73,3 až 92,9) | 83,7 (71,0 až 91,5) | nedostatek dat | - |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 42 | 81,0 (66,7 až 90,0) | 85,7 (72,2 až 93,3) | 83,3 (69,4 až 91,7) | nedostatek dat | - |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 47 | 89,4 (77,4 až 95,4) | 89,4 (77,4 až 95,4) | 89,4 (77,4 až 95,4) | nedostatek dat | - |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 48 | 87,5 (75,3 až 94,1) | 87,5 (75,3 až 94,1) | 87,5 (75,3 až 94,1) | nedostatek dat | - |
| port_scan_horizontal | security | - | discovery | 273 | 85,0 (80,3 až 88,7) | 85,7 (81,1 až 89,4) | 81,3 (76,3 až 85,5) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 331 | 89,7 (86,0 až 92,6) | 89,7 (86,0 až 92,6) | 87,9 (84,0 až 91,0) | pod prahem | c (otevřené) |
| public_app_probe_trickle | security | T1190 | initial-access | 31 | 83,9 (67,4 až 92,9) | 83,9 (67,4 až 92,9) | 45,2 (29,2 až 62,2) | nedostatek dat | - |
| ransomware | security | - | impact | 122 | 96,7 (91,9 až 98,7) | 99,2 (95,5 až 99,9) | 96,7 (91,9 až 98,7) | splněno | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 42 | 100,0 (91,6 až 100,0) | 100,0 (91,6 až 100,0) | 100,0 (91,6 až 100,0) | nedostatek dat | - |
| rdp_sweep_ext | security | T1046 | discovery | 42 | 85,7 (72,2 až 93,3) | 85,7 (72,2 až 93,3) | 73,8 (58,9 až 84,7) | nedostatek dat | - |
| resource_hijack_pool_tls | security | T1496 | impact | 49 | 93,9 (83,5 až 97,9) | 95,9 (86,3 až 98,9) | 95,9 (86,3 až 98,9) | nedostatek dat | - |
| rogue_device | security | - | initial-access | 73 | 93,2 (84,9 až 97,0) | 91,8 (83,2 až 96,2) | 86,3 (76,6 až 92,4) | pod prahem | c (otevřené) |
| share_encryption_wave_slow | security | T1486 | impact | 36 | 91,7 (78,2 až 97,1) | 91,7 (78,2 až 97,1) | 77,8 (61,9 až 88,3) | nedostatek dat | - |
| slow_scan | security | - | discovery | 266 | 93,6 (90,0 až 96,0) | 93,6 (90,0 až 96,0) | 88,3 (83,9 až 91,7) | splněno | - |
| smb_login_failures | security | T1110 | credential-access | 56 | 98,2 (90,6 až 99,7) | 98,2 (90,6 až 99,7) | 96,4 (87,9 až 99,0) | splněno | - |
| smb_share_enum_internal | security | T1135 | discovery | 30 | 73,3 (55,6 až 85,8) | 76,7 (59,1 až 88,2) | 70,0 (52,1 až 83,3) | nedostatek dat | - |
| smb_sweep_ext | security | T1046 | discovery | 35 | 77,1 (61,0 až 87,9) | 74,3 (57,9 až 85,8) | 74,3 (57,9 až 85,8) | nedostatek dat | - |
| smtp_auth_spray | security | T1110.003 | credential-access | 37 | 89,2 (75,3 až 95,7) | 89,2 (75,3 až 95,7) | 89,2 (75,3 až 95,7) | nedostatek dat | - |
| snmp_sweep_ext | security | T1046 | discovery | 47 | 85,1 (72,3 až 92,6) | 87,2 (74,8 až 94,0) | 80,9 (67,5 až 89,6) | nedostatek dat | - |
| snmp_walk_internal | security | T1602.001 | collection | 37 | 100,0 (90,6 až 100,0) | 100,0 (90,6 až 100,0) | 97,3 (86,2 až 99,5) | nedostatek dat | - |
| ssh_bruteforce | security | - | credential-access | 456 | 93,9 (91,3 až 95,7) | 94,3 (91,8 až 96,1) | 83,6 (79,9 až 86,7) | detekce ano, typ ne | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 64 | 81,2 (70,0 až 88,9) | 81,2 (70,0 až 88,9) | 76,6 (64,9 až 85,3) | pod prahem | c (otevřené) |
| telnet_iot_login | security | T1110.001 | credential-access | 39 | 41,0 (27,1 až 56,6) | 43,6 (29,3 až 59,0) | 30,8 (18,6 až 46,4) | nedostatek dat | - |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 38 | 100,0 (90,8 až 100,0) | 100,0 (90,8 až 100,0) | 100,0 (90,8 až 100,0) | nedostatek dat | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 40 | 37,5 (24,2 až 53,0) | 40,0 (26,3 až 55,4) | 5,0 (1,4 až 16,5) | nedostatek dat | - |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 55 | 65,5 (52,3 až 76,6) | 65,5 (52,3 až 76,6) | 61,8 (48,6 až 73,5) | pod prahem | c (otevřené) |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 31 | 41,9 (26,4 až 59,2) | 41,9 (26,4 až 59,2) | 25,8 (13,7 až 43,2) | nedostatek dat | - |
| web_exploit | security | - | initial-access | 262 | 87,0 (82,4 až 90,6) | 95,4 (92,2 až 97,4) | 74,0 (68,4 až 79,0) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 40 | 95,0 (83,5 až 98,6) | 95,0 (83,5 až 98,6) | 75,0 (59,8 až 85,8) | nedostatek dat | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 165 | 69,1 (61,7 až 75,6) | 69,7 (62,3 až 76,2) | 61,8 (54,2 až 68,9) |
| command-and-control | 1362 | 85,1 (83,1 až 86,9) | 87,2 (85,3 až 88,8) | 75,6 (73,2 až 77,8) |
| credential-access | 1280 | 90,1 (88,3 až 91,6) | 90,4 (88,7 až 91,9) | 84,7 (82,6 až 86,6) |
| discovery | 1153 | 84,9 (82,7 až 86,9) | 85,3 (83,1 až 87,2) | 81,1 (78,7 až 83,2) |
| execution | 43 | 95,3 (84,5 až 98,7) | 95,3 (84,5 až 98,7) | 95,3 (84,5 až 98,7) |
| exfiltration | 667 | 76,0 (72,6 až 79,1) | 76,3 (72,9 až 79,4) | 67,8 (64,1 až 71,2) |
| impact | 735 | 89,3 (86,8 až 91,3) | 90,3 (88,0 až 92,3) | 84,8 (82,0 až 87,2) |
| initial-access | 929 | 66,6 (63,5 až 69,6) | 81,1 (78,4 až 83,4) | 53,7 (50,5 až 56,9) |
| lateral-movement | 777 | 89,1 (86,7 až 91,1) | 93,4 (91,5 až 95,0) | 82,2 (79,4 až 84,8) |
| none | 1412 | 80,2 (78,1 až 82,2) | 80,2 (78,1 až 82,2) | 76,7 (74,4 až 78,8) |
| reconnaissance | 169 | 71,0 (63,8 až 77,3) | 71,0 (63,8 až 77,3) | 63,9 (56,4 až 70,8) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 148 | 96,6 (92,3 až 98,5) | 96,6 (92,3 až 98,5) | 95,9 (91,4 až 98,1) | 0,0 % |
| ops_fault | 1264 | 78,3 (76,0 až 80,5) | 78,3 (76,0 až 80,5) | 74,4 (72,0 až 76,8) | 0,0 % |
| security | 7280 | 83,0 (82,1 až 83,8) | 85,9 (85,1 až 86,7) | 75,7 (74,7 až 76,7) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 1280 | 90,1 (88,3 až 91,6) | 90,4 (88,7 až 91,9) | 84,7 (82,6 až 86,6) | splněno |
| taktika discovery | 1153 | 84,9 (82,7 až 86,9) | 85,3 (83,1 až 87,2) | 81,1 (78,7 až 83,2) | nedosaženo |
| taktika lateral-movement | 777 | 89,1 (86,7 až 91,1) | 93,4 (91,5 až 95,0) | 82,2 (79,4 až 84,8) | splněno |
| rodina c2_slow_long_interval | 54 | 90,7 (80,1 až 96,0) | 90,7 (80,1 až 96,0) | 88,9 (77,8 až 94,8) | nedosaženo |
| rodina ssh_spray_slow_distributed | 64 | 81,2 (70,0 až 88,9) | 81,2 (70,0 až 88,9) | 76,6 (64,9 až 85,3) | nedosaženo |
| rodina data_staging_smb_internal | 39 | 84,6 (70,3 až 92,8) | 84,6 (70,3 až 92,8) | 66,7 (51,0 až 79,4) | nedostatek dat |
| rodina kerberos_ticket_request_burst | 39 | 100,0 (91,0 až 100,0) | 100,0 (91,0 až 100,0) | 97,4 (86,8 až 99,5) | nedostatek dat |
| rodina ics_attack | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat |
| rodina cloud_api_discovery_burst | 41 | 9,8 (3,9 až 22,5) | 9,8 (3,9 až 22,5) | 4,9 (1,3 až 16,1) | nedostatek dat |
| rodina rdp_bruteforce | 42 | 100,0 (91,6 až 100,0) | 100,0 (91,6 až 100,0) | 100,0 (91,6 až 100,0) | nedostatek dat |
| rodina ddos_syn_flood_distributed | 28 | 85,7 (68,5 až 94,3) | 85,7 (68,5 až 94,3) | 85,7 (68,5 až 94,3) | nedostatek dat |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| drive_by_bulk_download (security) | 50 | 8,0 | c (obsahový rozdíl neviditelný v tocích) |
| ntp_unreachable (ops_fault) | 50 | 52,0 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_icmp_payload (security) | 54 | 53,7 | c (obsahový rozdíl neviditelný v tocích) |
| dns_slow_resolution (ops_fault) | 65 | 60,0 | c (obsahový rozdíl neviditelný v tocích) |
| vnc_probe_ext (security) | 55 | 65,5 | c (otevřené) |
| dns_partial_failure (ops_fault) | 71 | 74,6 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_dns_slow (security) | 63 | 76,2 | c (obsahový rozdíl neviditelný v tocích) |
| ssh_spray_slow_distributed (security) | 64 | 81,2 | c (otevřené) |
| distributed_low_port_probe (security) | 56 | 83,9 | c (otevřené) |
| monitoring_agent_misconfig_poll (ops_fault) | 59 | 84,7 | c (otevřené) |
| c2_beacon (security) | 355 | 84,8 | b (zmírněno, zbývá mezera) |
| c2_irc_style_channel (security) | 61 | 85,2 | b (zmírněno, zbývá mezera) |
| port_scan_horizontal (security) | 273 | 85,7 | b (zmírněno, zbývá mezera) |
| lateral_ssh_hop (security) | 50 | 88,0 | b (zmírněno, zbývá mezera) |
| lateral_rdp_hop (security) | 59 | 88,1 | c (otevřené) |
| c2_websocket_long (security) | 55 | 89,1 | c (otevřené) |
| exploit_attempt (security) | 387 | 89,4 | b (zmírněno, zbývá mezera) |
| cryptomining (security) | 144 | 89,6 | b (zmírněno, zbývá mezera) |
| c2_doh_resolver (security) | 58 | 89,7 | c (otevřené) |
| port_scan_vertical (security) | 331 | 89,7 | c (otevřené) |
| ftp_bruteforce (security) | 50 | 90,0 | c (otevřené) |
| c2_https_legit_service (security) | 52 | 90,4 | c (otevřené) |
| c2_icmp_tunnel (security) | 53 | 90,6 | c (otevřené) |
| c2_slow_long_interval (security) | 54 | 90,7 | c (otevřené) |
| ntp_clock_drift_host (ops_fault) | 57 | 91,2 | c (otevřené) |
| rogue_device (security) | 73 | 91,8 | c (otevřené) |
| cert_chain_misconfig_external (ops_fault) | 58 | 93,1 | c (otevřené) |
| duplicate_ip_conflict (ops_fault) | 54 | 94,4 | c (otevřené) |

