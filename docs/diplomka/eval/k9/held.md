# Výsledky kroku 9, držené seedy (jednou)

Rameno `base` (základ) proti `cand` (kandidát), párově po sítích: 240 sítí, 17268 útoků a poruch s toky, 2256 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 83,4 (82,9 až 84,0) | 84,0 (83,5 až 84,5) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 20,38 | 21,58 | poměr 1,059 (1,042 až 1,083); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 194,0 | 199,2 | poměr 1,027 (1,021 až 1,033) |
| útoky s omylem zavřeným nálezem | 76 (0,4 %) | 91 (0,5 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 253945 | 265730 |
| potvrzeno | 40290 | 42220 |
| vyvráceno | 3705 | 4149 |
| eskalováno (nerozhodnuto) | 209059 | 218382 |
| vyvráceno omylem (kontrafaktuál) | 52 | 65 |
| podíl případů pravdivého útoku mezi případy žebříku (base) | 46,4 % z 253054 |
| podíl případů pravdivého útoku mezi případy žebříku (cand) | 44,7 % z 264751 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 3653 z 3705, kandidát 4084 z 4149. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 36357 z 40290, kandidát 37546 z 42220. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| planned_maintenance_window | benign_change | - | none | 83 | 95,2 (88,3 až 98,1) | 95,2 (88,3 až 98,1) | 95,2 (88,3 až 98,1) | splněno | - |
| planned_patch_reboot_wave | benign_change | - | none | 99 | 97,0 (91,5 až 99,0) | 97,0 (91,5 až 99,0) | 97,0 (91,5 až 99,0) | splněno | - |
| seasonal_peak_web | benign_change | - | none | 61 | 80,3 (68,7 až 88,4) | 80,3 (68,7 až 88,4) | 77,0 (65,1 až 85,8) | pod prahem | c (otevřené) |
| access_point_controller_failure | ops_fault | - | none | 89 | 96,6 (90,6 až 98,8) | 96,6 (90,6 až 98,8) | 95,5 (89,0 až 98,2) | splněno | - |
| app_server_crash_cascade | ops_fault | - | none | 116 | 99,1 (95,3 až 99,8) | 99,1 (95,3 až 99,8) | 99,1 (95,3 až 99,8) | splněno | - |
| backup_window_overrun | ops_fault | - | none | 64 | 92,2 (83,0 až 96,6) | 92,2 (83,0 až 96,6) | 85,9 (75,4 až 92,4) | pod prahem | c (otevřené) |
| broadcast_storm_loop | ops_fault | - | none | 80 | 8,8 (4,3 až 17,0) | 23,8 (15,8 až 34,1) | 22,5 (14,7 až 32,8) | pod prahem | b (zmírněno, zbývá mezera) |
| cert_chain_misconfig_external | ops_fault | - | none | 98 | 95,9 (90,0 až 98,4) | 95,9 (90,0 až 98,4) | 95,9 (90,0 až 98,4) | splněno | - |
| cert_expired_internal_service | ops_fault | - | none | 71 | 29,6 (20,2 až 41,0) | 29,6 (20,2 až 41,0) | 19,7 (12,1 až 30,4) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| core_router_flapping | ops_fault | - | none | 99 | 99,0 (94,5 až 99,8) | 99,0 (94,5 až 99,8) | 98,0 (92,9 až 99,4) | splněno | - |
| db_overload_degradation | ops_fault | - | none | 77 | 100,0 (95,2 až 100,0) | 98,7 (93,0 až 99,8) | 98,7 (93,0 až 99,8) | splněno | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 99 | 12,1 (7,1 až 20,0) | 25,3 (17,7 až 34,6) | 21,2 (14,3 až 30,3) | pod prahem | b (zmírněno, zbývá mezera) |
| dhcp_server_down | ops_fault | - | none | 102 | 97,1 (91,7 až 99,0) | 97,1 (91,7 až 99,0) | 96,1 (90,3 až 98,5) | splněno | - |
| disk_full_backup_failure | ops_fault | - | none | 76 | 81,6 (71,4 až 88,7) | 81,6 (71,4 až 88,7) | 76,3 (65,6 až 84,5) | pod prahem | c (otevřené) |
| dns_partial_failure | ops_fault | - | none | 92 | 65,2 (55,1 až 74,2) | 65,2 (55,1 až 74,2) | 54,3 (44,2 až 64,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| dns_slow_resolution | ops_fault | - | none | 118 | 62,7 (53,7 až 70,9) | 62,7 (53,7 až 70,9) | 51,7 (42,8 až 60,5) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| duplicate_ip_conflict | ops_fault | - | none | 89 | 98,9 (93,9 až 99,8) | 98,9 (93,9 až 99,8) | 97,8 (92,2 až 99,4) | splněno | - |
| flapping_service | ops_fault | - | none | 114 | 98,2 (93,8 až 99,5) | 98,2 (93,8 až 99,5) | 97,4 (92,5 až 99,1) | splněno | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 96 | 91,7 (84,4 až 95,7) | 91,7 (84,4 až 95,7) | 91,7 (84,4 až 95,7) | pod prahem | c (otevřené) |
| load_balancer_partial_outage | ops_fault | - | none | 76 | 98,7 (92,9 až 99,8) | 98,7 (92,9 až 99,8) | 97,4 (90,9 až 99,3) | splněno | - |
| mail_relay_queue_retry | ops_fault | - | none | 93 | 100,0 (96,0 až 100,0) | 100,0 (96,0 až 100,0) | 100,0 (96,0 až 100,0) | splněno | - |
| mdns_ssdp_storm | ops_fault | - | none | 101 | 10,9 (6,2 až 18,5) | 27,7 (19,9 až 37,1) | 21,8 (14,8 až 30,8) | pod prahem | b (zmírněno, zbývá mezera) |
| memory_exhaustion_stall | ops_fault | - | none | 104 | 100,0 (96,4 až 100,0) | 100,0 (96,4 až 100,0) | 99,0 (94,8 až 99,8) | splněno | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 106 | 79,2 (70,6 až 85,9) | 79,2 (70,6 až 85,9) | 75,5 (66,5 až 82,7) | pod prahem | c (otevřené) |
| ntp_clock_drift_host | ops_fault | - | none | 99 | 87,9 (80,0 až 92,9) | 87,9 (80,0 až 92,9) | 78,8 (69,7 až 85,7) | pod prahem | c (otevřené) |
| ntp_unreachable | ops_fault | - | none | 110 | 60,9 (51,6 až 69,5) | 60,9 (51,6 až 69,5) | 45,5 (36,5 až 54,8) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| slow_link_loss_degradation | ops_fault | - | none | 86 | 100,0 (95,7 až 100,0) | 100,0 (95,7 až 100,0) | 100,0 (95,7 až 100,0) | splněno | - |
| switch_outage_subnet | ops_fault | - | none | 98 | 96,9 (91,4 až 99,0) | 96,9 (91,4 až 99,0) | 95,9 (90,0 až 98,4) | splněno | - |
| uplink_saturation | ops_fault | - | none | 104 | 31,7 (23,6 až 41,2) | 31,7 (23,6 až 41,2) | 13,5 (8,2 až 21,3) | pod prahem | c (otevřené) |
| vpn_concentrator_down | ops_fault | - | none | 74 | 91,9 (83,4 až 96,2) | 91,9 (83,4 až 96,2) | 89,2 (80,1 až 94,4) | pod prahem | c (otevřené) |
| api_enum_distributed | security | T1595.002 | reconnaissance | 74 | 90,5 (81,7 až 95,3) | 90,5 (81,7 až 95,3) | 89,2 (80,1 až 94,4) | pod prahem | c (otevřené) |
| app_layer_flood_api | security | T1499.003 | impact | 73 | 91,8 (83,2 až 96,2) | 91,8 (83,2 až 96,2) | 91,8 (83,2 až 96,2) | pod prahem | c (otevřené) |
| apt_chain | security | - | lateral-movement | 163 | 98,2 (94,7 až 99,4) | 98,2 (94,7 až 99,4) | 95,7 (91,4 až 97,9) | splněno | - |
| backup_service_probing | security | T1490 | impact | 88 | 76,1 (66,3 až 83,8) | 76,1 (66,3 až 83,8) | 56,8 (46,4 až 66,7) | pod prahem | c (otevřené) |
| bucket_mass_download | security | T1530 | collection | 94 | 11,7 (6,7 až 19,8) | 11,7 (6,7 až 19,8) | 2,1 (0,6 až 7,4) | pod prahem | c (otevřené) |
| c2_alt_port_8443 | security | T1571 | command-and-control | 105 | 89,5 (82,2 až 94,0) | 89,5 (82,2 až 94,0) | 89,5 (82,2 až 94,0) | pod prahem | c (otevřené) |
| c2_beacon | security | - | command-and-control | 687 | 84,4 (81,5 až 86,9) | 85,0 (82,1 až 87,5) | 64,0 (60,4 až 67,5) | pod prahem | b (zmírněno, zbývá mezera) |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 92 | 89,1 (81,1 až 94,0) | 89,1 (81,1 až 94,0) | 89,1 (81,1 až 94,0) | pod prahem | c (otevřené) |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 92 | 57,6 (47,4 až 67,2) | 57,6 (47,4 až 67,2) | 7,6 (3,7 až 14,9) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 79 | 45,6 (35,0 až 56,5) | 48,1 (37,4 až 58,9) | 20,3 (12,9 až 30,4) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| c2_doh_resolver | security | T1572 | command-and-control | 76 | 93,4 (85,5 až 97,2) | 93,4 (85,5 až 97,2) | 93,4 (85,5 až 97,2) | splněno | - |
| c2_high_jitter | security | T1071.001 | command-and-control | 87 | 70,1 (59,8 až 78,7) | 71,3 (61,0 až 79,7) | 66,7 (56,2 až 75,7) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| c2_https_legit_service | security | T1102 | command-and-control | 92 | 91,3 (83,8 až 95,5) | 91,3 (83,8 až 95,5) | 91,3 (83,8 až 95,5) | pod prahem | c (otevřené) |
| c2_icmp_tunnel | security | T1095 | command-and-control | 91 | 94,5 (87,8 až 97,6) | 94,5 (87,8 až 97,6) | 94,5 (87,8 až 97,6) | splněno | - |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 91 | 94,5 (87,8 až 97,6) | 94,5 (87,8 až 97,6) | 86,8 (78,4 až 92,3) | detekce ano, typ ne | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 71 | 91,5 (82,8 až 96,1) | 91,5 (82,8 až 96,1) | 90,1 (81,0 až 95,1) | pod prahem | c (otevřené) |
| c2_irc_style_channel | security | T1071 | command-and-control | 71 | 94,4 (86,4 až 97,8) | 94,4 (86,4 až 97,8) | 93,0 (84,6 až 97,0) | splněno | - |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 91 | 87,9 (79,6 až 93,1) | 87,9 (79,6 až 93,1) | 87,9 (79,6 až 93,1) | pod prahem | c (otevřené) |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 92 | 87,0 (78,6 až 92,4) | 87,0 (78,6 až 92,4) | 84,8 (76,1 až 90,7) | pod prahem | c (otevřené) |
| c2_udp_custom_port | security | T1095 | command-and-control | 77 | 84,4 (74,7 až 90,9) | 84,4 (74,7 až 90,9) | 83,1 (73,2 až 89,9) | pod prahem | c (otevřené) |
| c2_websocket_long | security | T1071.001 | command-and-control | 82 | 89,0 (80,4 až 94,1) | 89,0 (80,4 až 94,1) | 89,0 (80,4 až 94,1) | pod prahem | c (otevřené) |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 100 | 13,0 (7,8 až 21,0) | 13,0 (7,8 až 21,0) | 6,0 (2,8 až 12,5) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| cloud_api_discovery_burst | security | T1580 | discovery | 98 | 9,2 (4,9 až 16,5) | 9,2 (4,9 až 16,5) | 4,1 (1,6 až 10,0) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| credential_stuffing | security | - | credential-access | 492 | 90,2 (87,3 až 92,6) | 90,2 (87,3 až 92,6) | 87,2 (84,0 až 89,9) | splněno | - |
| cryptomining | security | - | impact | 346 | 93,1 (89,9 až 95,3) | 93,6 (90,6 až 95,8) | 82,9 (78,6 až 86,5) | detekce ano, typ ne | - |
| data_destruction_smb_wave | security | T1485 | impact | 71 | 85,9 (76,0 až 92,2) | 85,9 (76,0 až 92,2) | 84,5 (74,3 až 91,1) | pod prahem | c (otevřené) |
| data_staging_smb_internal | security | T1039 | collection | 85 | 82,4 (72,9 až 89,0) | 82,4 (72,9 až 89,0) | 72,9 (62,7 až 81,2) | pod prahem | c (otevřené) |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 87 | 95,4 (88,8 až 98,2) | 95,4 (88,8 až 98,2) | 80,5 (70,9 až 87,4) | detekce ano, typ ne | - |
| ddos_dns_amplification | security | T1498.002 | impact | 98 | 51,0 (41,3 až 60,7) | 52,0 (42,3 až 61,7) | 46,9 (37,4 až 56,7) | pod prahem | b (zmírněno, zbývá mezera) |
| ddos_ntp_amplification | security | T1498.002 | impact | 76 | 93,4 (85,5 až 97,2) | 93,4 (85,5 až 97,2) | 93,4 (85,5 až 97,2) | splněno | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 81 | 91,4 (83,2 až 95,8) | 91,4 (83,2 až 95,8) | 90,1 (81,7 až 94,9) | pod prahem | c (otevřené) |
| ddos_volume | security | - | impact | 205 | 88,3 (83,2 až 92,0) | 88,3 (83,2 až 92,0) | 85,4 (79,9 až 89,6) | pod prahem | c (otevřené) |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 94 | 93,6 (86,8 až 97,0) | 93,6 (86,8 až 97,0) | 93,6 (86,8 až 97,0) | splněno | - |
| dns_tunnel | security | - | command-and-control | 334 | 92,5 (89,2 až 94,9) | 92,2 (88,8 až 94,6) | 74,9 (69,9 až 79,2) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 91 | 11,0 (6,1 až 19,1) | 11,0 (6,1 až 19,1) | 5,5 (2,4 až 12,2) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| drive_by_bulk_download | security | T1189 | initial-access | 89 | 9,0 (4,6 až 16,7) | 9,0 (4,6 až 16,7) | 2,2 (0,6 až 7,8) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 84 | 15,5 (9,3 až 24,7) | 16,7 (10,2 až 26,1) | 7,1 (3,3 až 14,7) | pod prahem | b (zmírněno, zbývá mezera) |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 87 | 32,2 (23,3 až 42,6) | 37,9 (28,5 až 48,4) | 24,1 (16,4 až 34,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_dns_slow | security | T1048.003 | exfiltration | 86 | 76,7 (66,8 až 84,4) | 76,7 (66,8 až 84,4) | 59,3 (48,7 až 69,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_https_burst | security | T1041 | exfiltration | 85 | 50,6 (40,2 až 61,0) | 50,6 (40,2 až 61,0) | 50,6 (40,2 až 61,0) | pod prahem | c (otevřené) |
| exfil_icmp_payload | security | T1048 | exfiltration | 71 | 67,6 (56,1 až 77,3) | 67,6 (56,1 až 77,3) | 16,9 (9,9 až 27,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 114 | 71,1 (62,1 až 78,6) | 82,5 (74,4 až 88,3) | 73,7 (64,9 až 80,9) | pod prahem | b (zmírněno, zbývá mezera) |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 91 | 85,7 (77,1 až 91,5) | 87,9 (79,6 až 93,1) | 85,7 (77,1 až 91,5) | pod prahem | b (zmírněno, zbývá mezera) |
| exfiltration | security | - | exfiltration | 543 | 89,3 (86,4 až 91,6) | 89,3 (86,4 až 91,6) | 88,0 (85,0 až 90,5) | pod prahem | c (otevřené) |
| exploit_attempt | security | - | initial-access | 753 | 85,9 (83,3 až 88,2) | 85,9 (83,3 až 88,2) | 38,4 (35,0 až 41,9) | pod prahem | c (otevřené) |
| fleet_beacon | security | - | command-and-control | 122 | 90,2 (83,6 až 94,3) | 91,0 (84,6 až 94,9) | 70,5 (61,9 až 77,9) | pod prahem | b (zmírněno, zbývá mezera) |
| ftp_bruteforce | security | T1110.001 | credential-access | 89 | 94,4 (87,5 až 97,6) | 94,4 (87,5 až 97,6) | 93,3 (86,1 až 96,9) | splněno | - |
| http_slow_connections_dos | security | T1499.002 | impact | 63 | 69,8 (57,6 až 79,8) | 69,8 (57,6 až 79,8) | 61,9 (49,6 až 72,9) | pod prahem | c (otevřené) |
| ics_attack | security | - | impact | 14 | 85,7 (60,1 až 96,0) | 85,7 (60,1 až 96,0) | 57,1 (32,6 až 78,6) | nedostatek dat | - |
| ics_bacnet_enumeration | security | T0846 | discovery | 2 | 50,0 (9,5 až 90,5) | 50,0 (9,5 až 90,5) | 50,0 (9,5 až 90,5) | nedostatek dat | - |
| ics_dnp3_unsolicited_flood | security | T0814 | impact | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | nedostatek dat | - |
| ics_ethernetip_scan | security | T0846 | discovery | 2 | 100,0 (34,2 až 100,0) | 100,0 (34,2 až 100,0) | 50,0 (9,5 až 90,5) | nedostatek dat | - |
| ics_modbus_write_burst | security | T0836 | impact | 4 | 100,0 (51,0 až 100,0) | 100,0 (51,0 až 100,0) | 100,0 (51,0 až 100,0) | nedostatek dat | - |
| ics_opcua_enumeration | security | T0846 | discovery | 2 | 50,0 (9,5 až 90,5) | 50,0 (9,5 až 90,5) | 0,0 (0,0 až 65,8) | nedostatek dat | - |
| ics_program_download_slow | security | T0843 | execution | 5 | 40,0 (11,8 až 76,9) | 40,0 (11,8 až 76,9) | 0,0 (0,0 až 43,4) | nedostatek dat | - |
| ics_s7_operating_mode_change | security | T0858 | execution | 1 | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | nedostatek dat | - |
| ics_slow_poll_new_source | security | T0801 | collection | 3 | 66,7 (20,8 až 93,9) | 66,7 (20,8 až 93,9) | 33,3 (6,1 až 79,2) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 97 | 88,7 (80,8 až 93,5) | 88,7 (80,8 až 93,5) | 86,6 (78,4 až 92,0) | pod prahem | c (otevřené) |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 94 | 40,4 (31,1 až 50,5) | 40,4 (31,1 až 50,5) | 37,2 (28,1 až 47,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| insider_hoarding | security | - | exfiltration | 128 | 93,8 (88,2 až 96,8) | 93,8 (88,2 až 96,8) | 92,2 (86,2 až 95,7) | splněno | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 87 | 98,9 (93,8 až 99,8) | 98,9 (93,8 až 99,8) | 97,7 (92,0 až 99,4) | splněno | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 90 | 98,9 (94,0 až 99,8) | 98,9 (94,0 až 99,8) | 93,3 (86,2 až 96,9) | splněno | - |
| lateral_movement | security | - | lateral-movement | 664 | 98,0 (96,7 až 98,9) | 98,0 (96,7 až 98,9) | 85,4 (82,5 až 87,9) | splněno | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 91 | 94,5 (87,8 až 97,6) | 94,5 (87,8 až 97,6) | 81,3 (72,1 až 88,0) | detekce ano, typ ne | - |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 91 | 98,9 (94,0 až 99,8) | 98,9 (94,0 až 99,8) | 98,9 (94,0 až 99,8) | splněno | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 98 | 87,8 (79,8 až 92,9) | 87,8 (79,8 až 92,9) | 84,7 (76,3 až 90,5) | pod prahem | c (otevřené) |
| lateral_winrm | security | T1021.006 | lateral-movement | 90 | 94,4 (87,6 až 97,6) | 94,4 (87,6 až 97,6) | 93,3 (86,2 až 96,9) | splněno | - |
| lateral_wmi_dcom | security | T1047 | execution | 90 | 94,4 (87,6 až 97,6) | 94,4 (87,6 až 97,6) | 93,3 (86,2 až 96,9) | splněno | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 86 | 97,7 (91,9 až 99,4) | 97,7 (91,9 až 99,4) | 93,0 (85,6 až 96,8) | splněno | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 77 | 93,5 (85,7 až 97,2) | 93,5 (85,7 až 97,2) | 93,5 (85,7 až 97,2) | splněno | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 104 | 65,4 (55,8 až 73,8) | 86,5 (78,7 až 91,8) | 85,6 (77,6 až 91,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| mqtt_probe_ext | security | T1046 | discovery | 76 | 65,8 (54,6 až 75,5) | 69,7 (58,7 až 78,9) | 57,9 (46,7 až 68,4) | pod prahem | b (zmírněno, zbývá mezera) |
| mssql_login_failures | security | T1110.001 | credential-access | 99 | 94,9 (88,7 až 97,8) | 94,9 (88,7 až 97,8) | 94,9 (88,7 až 97,8) | splněno | - |
| mysql_login_failures | security | T1110.001 | credential-access | 91 | 84,6 (75,8 až 90,6) | 84,6 (75,8 až 90,6) | 80,2 (70,9 až 87,1) | pod prahem | c (otevřené) |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 75 | 82,7 (72,6 až 89,6) | 81,3 (71,1 až 88,5) | 73,3 (62,4 až 82,0) | pod prahem | c (otevřené) |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 95 | 90,5 (83,0 až 94,9) | 90,5 (83,0 až 94,9) | 90,5 (83,0 až 94,9) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 82 | 84,1 (74,7 až 90,5) | 84,1 (74,7 až 90,5) | 82,9 (73,4 až 89,5) | pod prahem | c (otevřené) |
| port_scan_horizontal | security | - | discovery | 593 | 83,8 (80,6 až 86,6) | 84,7 (81,5 až 87,3) | 79,6 (76,2 až 82,6) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 665 | 87,7 (85,0 až 90,0) | 87,8 (85,1 až 90,1) | 85,9 (83,0 až 88,3) | pod prahem | b (zmírněno, zbývá mezera) |
| public_app_probe_trickle | security | T1190 | initial-access | 80 | 86,2 (77,0 až 92,1) | 86,2 (77,0 až 92,1) | 37,5 (27,7 až 48,5) | pod prahem | c (otevřené) |
| ransomware | security | - | impact | 216 | 98,1 (95,3 až 99,3) | 98,1 (95,3 až 99,3) | 95,4 (91,7 až 97,5) | splněno | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 83 | 98,8 (93,5 až 99,8) | 98,8 (93,5 až 99,8) | 98,8 (93,5 až 99,8) | splněno | - |
| rdp_sweep_ext | security | T1046 | discovery | 88 | 87,5 (79,0 až 92,9) | 87,5 (79,0 až 92,9) | 85,2 (76,3 až 91,2) | pod prahem | c (otevřené) |
| resource_hijack_pool_tls | security | T1496 | impact | 67 | 95,5 (87,6 až 98,5) | 95,5 (87,6 až 98,5) | 95,5 (87,6 až 98,5) | splněno | - |
| rogue_device | security | - | initial-access | 145 | 94,5 (89,5 až 97,2) | 95,2 (90,4 až 97,6) | 90,3 (84,4 až 94,2) | splněno | - |
| share_encryption_wave_slow | security | T1486 | impact | 76 | 90,8 (82,2 až 95,5) | 90,8 (82,2 až 95,5) | 72,4 (61,4 až 81,2) | pod prahem | c (otevřené) |
| slow_scan | security | - | discovery | 541 | 91,5 (88,8 až 93,6) | 91,7 (89,1 až 93,7) | 85,4 (82,2 až 88,1) | splněno | - |
| smb_login_failures | security | T1110 | credential-access | 83 | 96,4 (89,9 až 98,8) | 96,4 (89,9 až 98,8) | 95,2 (88,3 až 98,1) | splněno | - |
| smb_share_enum_internal | security | T1135 | discovery | 73 | 87,7 (78,2 až 93,4) | 87,7 (78,2 až 93,4) | 82,2 (71,9 až 89,3) | pod prahem | c (otevřené) |
| smb_sweep_ext | security | T1046 | discovery | 103 | 69,9 (60,5 až 77,9) | 68,9 (59,5 až 77,1) | 66,0 (56,4 až 74,4) | pod prahem | c (otevřené) |
| smtp_auth_spray | security | T1110.003 | credential-access | 82 | 91,5 (83,4 až 95,8) | 91,5 (83,4 až 95,8) | 89,0 (80,4 až 94,1) | pod prahem | c (otevřené) |
| snmp_sweep_ext | security | T1046 | discovery | 88 | 88,6 (80,3 až 93,7) | 88,6 (80,3 až 93,7) | 85,2 (76,3 až 91,2) | pod prahem | c (otevřené) |
| snmp_walk_internal | security | T1602.001 | collection | 90 | 97,8 (92,3 až 99,4) | 97,8 (92,3 až 99,4) | 97,8 (92,3 až 99,4) | splněno | - |
| ssh_bruteforce | security | - | credential-access | 908 | 94,1 (92,3 až 95,4) | 94,1 (92,3 až 95,4) | 86,5 (84,1 až 88,5) | splněno | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 76 | 85,5 (75,9 až 91,7) | 85,5 (75,9 až 91,7) | 82,9 (72,9 až 89,7) | pod prahem | c (otevřené) |
| telnet_iot_login | security | T1110.001 | credential-access | 82 | 51,2 (40,6 až 61,7) | 51,2 (40,6 až 61,7) | 46,3 (36,0 až 57,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 107 | 90,7 (83,6 až 94,8) | 89,7 (82,5 až 94,2) | 84,1 (76,0 až 89,8) | pod prahem | c (otevřené) |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 78 | 43,6 (33,1 až 54,6) | 43,6 (33,1 až 54,6) | 12,8 (7,1 až 22,0) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 68 | 72,1 (60,4 až 81,3) | 72,1 (60,4 až 81,3) | 63,2 (51,4 až 73,7) | pod prahem | c (otevřené) |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 60 | 46,7 (34,6 až 59,1) | 46,7 (34,6 až 59,1) | 41,7 (30,1 až 54,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| web_exploit | security | - | initial-access | 513 | 95,3 (93,1 až 96,8) | 95,3 (93,1 až 96,8) | 73,9 (69,9 až 77,5) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 85 | 94,1 (87,0 až 97,5) | 94,1 (87,0 až 97,5) | 87,1 (78,3 až 92,6) | detekce ano, typ ne | - |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 376 | 63,6 (58,6 až 68,3) | 69,4 (64,6 až 73,9) | 64,4 (59,4 až 69,0) |
| command-and-control | 2514 | 85,6 (84,1 až 86,9) | 85,8 (84,4 až 87,1) | 73,4 (71,7 až 75,1) |
| credential-access | 2597 | 90,5 (89,3 až 91,6) | 90,5 (89,3 až 91,6) | 85,8 (84,4 až 87,1) |
| discovery | 2408 | 83,1 (81,5 až 84,5) | 83,5 (81,9 až 84,9) | 79,1 (77,4 až 80,7) |
| execution | 96 | 90,6 (83,1 až 95,0) | 90,6 (83,1 až 95,0) | 87,5 (79,4 až 92,7) |
| exfiltration | 1383 | 72,3 (69,9 až 74,6) | 73,8 (71,4 až 76,1) | 67,0 (64,4 až 69,4) |
| impact | 1481 | 87,8 (86,0 až 89,3) | 88,0 (86,2 až 89,5) | 81,5 (79,4 až 83,4) |
| initial-access | 1865 | 80,1 (78,2 až 81,9) | 80,1 (78,2 až 81,9) | 50,2 (48,0 až 52,5) |
| lateral-movement | 1430 | 95,0 (93,7 až 96,0) | 94,9 (93,6 až 95,9) | 86,4 (84,6 až 88,1) |
| none | 2774 | 78,6 (77,0 až 80,0) | 80,0 (78,5 až 81,5) | 76,1 (74,4 až 77,6) |
| reconnaissance | 344 | 71,2 (66,2 až 75,8) | 71,2 (66,2 až 75,8) | 67,7 (62,6 až 72,5) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 243 | 92,2 (88,1 až 94,9) | 92,2 (88,1 až 94,9) | 91,4 (87,2 až 94,3) | 0,0 % |
| ops_fault | 2531 | 77,2 (75,6 až 78,8) | 78,9 (77,2 až 80,4) | 74,6 (72,9 až 76,3) | 0,0 % |
| security | 14494 | 84,3 (83,7 až 84,9) | 84,8 (84,2 až 85,3) | 74,8 (74,1 až 75,5) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 2597 | 90,5 (89,3 až 91,6) | 90,5 (89,3 až 91,6) | 85,8 (84,4 až 87,1) | splněno |
| taktika discovery | 2408 | 83,1 (81,5 až 84,5) | 83,5 (81,9 až 84,9) | 79,1 (77,4 až 80,7) | nedosaženo |
| taktika lateral-movement | 1430 | 95,0 (93,7 až 96,0) | 94,9 (93,6 až 95,9) | 86,4 (84,6 až 88,1) | splněno |
| rodina c2_slow_long_interval | 92 | 87,0 (78,6 až 92,4) | 87,0 (78,6 až 92,4) | 84,8 (76,1 až 90,7) | nedosaženo |
| rodina ssh_spray_slow_distributed | 76 | 85,5 (75,9 až 91,7) | 85,5 (75,9 až 91,7) | 82,9 (72,9 až 89,7) | nedosaženo |
| rodina data_staging_smb_internal | 85 | 82,4 (72,9 až 89,0) | 82,4 (72,9 až 89,0) | 72,9 (62,7 až 81,2) | nedosaženo |
| rodina kerberos_ticket_request_burst | 87 | 98,9 (93,8 až 99,8) | 98,9 (93,8 až 99,8) | 97,7 (92,0 až 99,4) | splněno |
| rodina ics_attack | 14 | 85,7 (60,1 až 96,0) | 85,7 (60,1 až 96,0) | 57,1 (32,6 až 78,6) | nedostatek dat |
| rodina cloud_api_discovery_burst | 98 | 9,2 (4,9 až 16,5) | 9,2 (4,9 až 16,5) | 4,1 (1,6 až 10,0) | nedosaženo |
| rodina rdp_bruteforce | 83 | 98,8 (93,5 až 99,8) | 98,8 (93,5 až 99,8) | 98,8 (93,5 až 99,8) | splněno |
| rodina ddos_syn_flood_distributed | 81 | 91,4 (83,2 až 95,8) | 91,4 (83,2 až 95,8) | 90,1 (81,7 až 94,9) | nedosaženo |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| drive_by_bulk_download (security) | 89 | 9,0 | c (obsahový rozdíl neviditelný v tocích) |
| cloud_api_discovery_burst (security) | 98 | 9,2 | c (obsahový rozdíl neviditelný v tocích) |
| dns_zone_enum_burst (security) | 91 | 11,0 | c (obsahový rozdíl neviditelný v tocích) |
| bucket_mass_download (security) | 94 | 11,7 | c (otevřené) |
| clicks_to_rare_destination (security) | 100 | 13,0 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_alt_protocol_ftp (security) | 84 | 16,7 | b (zmírněno, zbývá mezera) |
| broadcast_storm_loop (ops_fault) | 80 | 23,8 | b (zmírněno, zbývá mezera) |
| dhcp_pool_exhaustion (ops_fault) | 99 | 25,3 | b (zmírněno, zbývá mezera) |
| mdns_ssdp_storm (ops_fault) | 101 | 27,7 | b (zmírněno, zbývá mezera) |
| cert_expired_internal_service (ops_fault) | 71 | 29,6 | c (obsahový rozdíl neviditelný v tocích) |
| uplink_saturation (ops_fault) | 104 | 31,7 | c (otevřené) |
| exfil_cloud_storage_upload (security) | 87 | 37,9 | c (obsahový rozdíl neviditelný v tocích) |
| insider_after_hours_cloud_sync (security) | 94 | 40,4 | c (obsahový rozdíl neviditelný v tocích) |
| vendor_remote_access_odd_hours (security) | 78 | 43,6 | c (obsahový rozdíl neviditelný v tocích) |
| vpn_password_spray_slow (security) | 60 | 46,7 | c (obsahový rozdíl neviditelný v tocích) |
| c2_dns_txt_beacon (security) | 79 | 48,1 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_https_burst (security) | 85 | 50,6 | c (otevřené) |
| telnet_iot_login (security) | 82 | 51,2 | c (obsahový rozdíl neviditelný v tocích) |
| ddos_dns_amplification (security) | 98 | 52,0 | b (zmírněno, zbývá mezera) |
| c2_cloud_storage_dead_drop (security) | 92 | 57,6 | c (obsahový rozdíl neviditelný v tocích) |
| ntp_unreachable (ops_fault) | 110 | 60,9 | c (obsahový rozdíl neviditelný v tocích) |
| dns_slow_resolution (ops_fault) | 118 | 62,7 | c (obsahový rozdíl neviditelný v tocích) |
| dns_partial_failure (ops_fault) | 92 | 65,2 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_icmp_payload (security) | 71 | 67,6 | c (obsahový rozdíl neviditelný v tocích) |
| smb_sweep_ext (security) | 103 | 68,9 | c (otevřené) |
| mqtt_probe_ext (security) | 76 | 69,7 | b (zmírněno, zbývá mezera) |
| http_slow_connections_dos (security) | 63 | 69,8 | c (otevřené) |
| c2_high_jitter (security) | 87 | 71,3 | c (obsahový rozdíl neviditelný v tocích) |
| vnc_probe_ext (security) | 68 | 72,1 | c (otevřené) |
| backup_service_probing (security) | 88 | 76,1 | c (otevřené) |
| exfil_dns_slow (security) | 86 | 76,7 | c (obsahový rozdíl neviditelný v tocích) |
| monitoring_agent_misconfig_poll (ops_fault) | 106 | 79,2 | c (otevřené) |
| seasonal_peak_web (benign_change) | 61 | 80,3 | c (otevřené) |
| ntlm_relay_style_fanout (security) | 75 | 81,3 | c (otevřené) |
| disk_full_backup_failure (ops_fault) | 76 | 81,6 | c (otevřené) |
| data_staging_smb_internal (security) | 85 | 82,4 | c (otevřené) |
| exfil_over_c2_trickle (security) | 114 | 82,5 | b (zmírněno, zbývá mezera) |
| onion_style_circuit_egress (security) | 82 | 84,1 | c (otevřené) |
| c2_udp_custom_port (security) | 77 | 84,4 | c (otevřené) |
| mysql_login_failures (security) | 91 | 84,6 | c (otevřené) |
| port_scan_horizontal (security) | 593 | 84,7 | b (zmírněno, zbývá mezera) |
| c2_beacon (security) | 687 | 85,0 | b (zmírněno, zbývá mezera) |
| ssh_spray_slow_distributed (security) | 76 | 85,5 | c (otevřené) |
| data_destruction_smb_wave (security) | 71 | 85,9 | c (otevřené) |
| exploit_attempt (security) | 753 | 85,9 | c (otevřené) |
| public_app_probe_trickle (security) | 80 | 86,2 | c (otevřené) |
| mail_forward_smtp_exfil (security) | 104 | 86,5 | c (obsahový rozdíl neviditelný v tocích) |
| c2_slow_long_interval (security) | 92 | 87,0 | c (otevřené) |
| rdp_sweep_ext (security) | 88 | 87,5 | c (otevřené) |
| smb_share_enum_internal (security) | 73 | 87,7 | c (otevřené) |
| lateral_ssh_hop (security) | 98 | 87,8 | c (otevřené) |
| port_scan_vertical (security) | 665 | 87,8 | b (zmírněno, zbývá mezera) |
| ntp_clock_drift_host (ops_fault) | 99 | 87,9 | c (otevřené) |
| c2_ntp_port_misuse (security) | 91 | 87,9 | c (otevřené) |
| exfil_scheduled_chunks (security) | 91 | 87,9 | b (zmírněno, zbývá mezera) |
| ddos_volume (security) | 205 | 88,3 | c (otevřené) |
| snmp_sweep_ext (security) | 88 | 88,6 | c (otevřené) |
| imap_spray (security) | 97 | 88,7 | c (otevřené) |
| c2_websocket_long (security) | 82 | 89,0 | c (otevřené) |
| c2_cdn_fronted (security) | 92 | 89,1 | c (otevřené) |
| exfiltration (security) | 543 | 89,3 | c (otevřené) |
| c2_alt_port_8443 (security) | 105 | 89,5 | c (otevřené) |
| update_channel_compromise_fleet (security) | 107 | 89,7 | c (otevřené) |
| oauth_token_abuse_periodic (security) | 95 | 90,5 | c (obsahový rozdíl neviditelný v tocích) |
| api_enum_distributed (security) | 74 | 90,5 | c (otevřené) |
| share_encryption_wave_slow (security) | 76 | 90,8 | c (otevřené) |
| fleet_beacon (security) | 122 | 91,0 | b (zmírněno, zbývá mezera) |
| c2_https_legit_service (security) | 92 | 91,3 | c (otevřené) |
| ddos_syn_flood_distributed (security) | 81 | 91,4 | c (otevřené) |
| smtp_auth_spray (security) | 82 | 91,5 | c (otevřené) |
| c2_iot_mqtt_cloud (security) | 71 | 91,5 | c (otevřené) |
| iot_firmware_chatter_loop (ops_fault) | 96 | 91,7 | c (otevřené) |
| app_layer_flood_api (security) | 73 | 91,8 | c (otevřené) |
| vpn_concentrator_down (ops_fault) | 74 | 91,9 | c (otevřené) |
| backup_window_overrun (ops_fault) | 64 | 92,2 | c (otevřené) |

