# Výsledky kroku 9, ladicí seedy

Rameno `base` (základ) proti `cand` (kandidát), párově po sítích: 200 sítí, 14455 útoků a poruch s toky, 2035 virtuálních síť-dnů. Intervaly: Wilson 95 % pro podíly, bootstrap po sítích (B = 2000) pro poměry.

## Souhrn

| ukazatel | základ | kandidát | poznámka |
|---|---|---|---|
| detekce útoků | 84,2 (83,6 až 84,8) | 84,7 (84,2 až 85,3) | kontrafaktuální zobrazená detekce |
| zobrazené FP na síť-den | 11,17 | 11,72 | poměr 1,050 (1,031 až 1,072); práh K9-3 ≤ 1,15 |
| všechny zobrazené položky na síť-den | 153,0 | 155,9 | poměr 1,019 (1,014 až 1,025) |
| útoky s omylem zavřeným nálezem | 123 (0,9 %) | 137 (0,9 %) | práh K9-4 ≤ 2,2 % |
| chráněná automatická zavření | 0 | 0 | práh K9-5 = 0 |
| paniky / porušené invarianty | 0 / 0 | 0 / 0 | práh K9-7 = 0 |

## Žebřík ověřování: potvrzeno, vyvráceno, nerozhodnuto

Případ žebříku končí jako potvrzeno (podezření prokázáno nezávislými kontrolami), vyvráceno (neškodný důkaz z více nezávislých zdrojů, nikdy u chráněného případu) nebo eskalováno k člověku (nerozhodnuto). Nerozhodnuté případy se nezavírají (V1).

| ukazatel | základ | kandidát |
|---|---|---|
| případů | 182784 | 188679 |
| potvrzeno | 23410 | 24032 |
| vyvráceno | 2164 | 1886 |
| eskalováno (nerozhodnuto) | 156416 | 161929 |
| vyvráceno omylem (kontrafaktuál) | 55 | 66 |
| podíl případů pravdivého útoku mezi případy žebříku (base) | 50,1 % z 181990 |
| podíl případů pravdivého útoku mezi případy žebříku (cand) | 48,8 % z 187847 |

Přesnost „vyvráceno“ je podíl vyvrácených případů, které nebyly omyl (kontrafaktuál): základ 2109 z 2164, kandidát 1820 z 1886. Přesnost „potvrzeno“ je podíl potvrzených případů, které patří pravdivému útoku: základ 21370 z 23410, kandidát 21609 z 24032. Kalibrace posteriorů (V3, ECE) se z záznamů běhu neodvozuje, protože běh posterior případu neukládá; ECE není změřeno (kategorie c, viz impl-krok9.md, E).

## Tabulka po rodinách a variantách (před a po)

Stav: splněno = detekce ≥ 90 % a dolní mez ≥ 85 % a správný typ ≥ 85 % s dolní mezí ≥ 80 %; n < 50 = nedostatek dat (nepočítá se jako splněno ani nesplněno), ale detekce je uvedena.

| rodina | kategorie | ATT&CK | taktika | n | detekce před | detekce po | správný typ po | stav (n ≥ 50) | kategorie slepého místa |
|---|---|---|---|---:|---|---|---|---|---|
| planned_maintenance_window | benign_change | - | none | 93 | 93,5 (86,6 až 97,0) | 93,5 (86,6 až 97,0) | 93,5 (86,6 až 97,0) | splněno | - |
| planned_patch_reboot_wave | benign_change | - | none | 80 | 100,0 (95,4 až 100,0) | 100,0 (95,4 až 100,0) | 100,0 (95,4 až 100,0) | splněno | - |
| seasonal_peak_web | benign_change | - | none | 62 | 93,5 (84,6 až 97,5) | 93,5 (84,6 až 97,5) | 88,7 (78,5 až 94,4) | pod prahem | c (otevřené) |
| access_point_controller_failure | ops_fault | - | none | 66 | 92,4 (83,5 až 96,7) | 92,4 (83,5 až 96,7) | 90,9 (81,6 až 95,8) | pod prahem | c (otevřené) |
| app_server_crash_cascade | ops_fault | - | none | 80 | 100,0 (95,4 až 100,0) | 100,0 (95,4 až 100,0) | 100,0 (95,4 až 100,0) | splněno | - |
| backup_window_overrun | ops_fault | - | none | 60 | 93,3 (84,1 až 97,4) | 93,3 (84,1 až 97,4) | 83,3 (72,0 až 90,7) | pod prahem | c (otevřené) |
| broadcast_storm_loop | ops_fault | - | none | 93 | 10,8 (5,9 až 18,7) | 32,3 (23,6 až 42,3) | 28,0 (19,9 až 37,8) | pod prahem | b (zmírněno, zbývá mezera) |
| cert_chain_misconfig_external | ops_fault | - | none | 88 | 93,2 (85,9 až 96,8) | 93,2 (85,9 až 96,8) | 93,2 (85,9 až 96,8) | splněno | - |
| cert_expired_internal_service | ops_fault | - | none | 66 | 21,2 (13,1 až 32,5) | 21,2 (13,1 až 32,5) | 12,1 (6,3 až 22,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| core_router_flapping | ops_fault | - | none | 79 | 97,5 (91,2 až 99,3) | 97,5 (91,2 až 99,3) | 96,2 (89,4 až 98,7) | splněno | - |
| db_overload_degradation | ops_fault | - | none | 55 | 100,0 (93,5 až 100,0) | 100,0 (93,5 až 100,0) | 100,0 (93,5 až 100,0) | splněno | - |
| dhcp_pool_exhaustion | ops_fault | - | none | 84 | 16,7 (10,2 až 26,1) | 25,0 (17,0 až 35,2) | 16,7 (10,2 až 26,1) | pod prahem | b (zmírněno, zbývá mezera) |
| dhcp_server_down | ops_fault | - | none | 84 | 98,8 (93,6 až 99,8) | 98,8 (93,6 až 99,8) | 97,6 (91,7 až 99,3) | splněno | - |
| disk_full_backup_failure | ops_fault | - | none | 50 | 86,0 (73,8 až 93,0) | 86,0 (73,8 až 93,0) | 82,0 (69,2 až 90,2) | pod prahem | c (otevřené) |
| dns_partial_failure | ops_fault | - | none | 108 | 71,3 (62,1 až 79,0) | 71,3 (62,1 až 79,0) | 60,2 (50,8 až 68,9) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| dns_slow_resolution | ops_fault | - | none | 92 | 63,0 (52,8 až 72,2) | 62,0 (51,7 až 71,2) | 50,0 (40,0 až 60,0) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| duplicate_ip_conflict | ops_fault | - | none | 91 | 96,7 (90,8 až 98,9) | 96,7 (90,8 až 98,9) | 95,6 (89,2 až 98,3) | splněno | - |
| flapping_service | ops_fault | - | none | 81 | 97,5 (91,4 až 99,3) | 97,5 (91,4 až 99,3) | 97,5 (91,4 až 99,3) | splněno | - |
| iot_firmware_chatter_loop | ops_fault | - | none | 79 | 92,4 (84,4 až 96,5) | 92,4 (84,4 až 96,5) | 91,1 (82,8 až 95,6) | pod prahem | c (otevřené) |
| load_balancer_partial_outage | ops_fault | - | none | 63 | 98,4 (91,5 až 99,7) | 98,4 (91,5 až 99,7) | 96,8 (89,1 až 99,1) | splněno | - |
| mail_relay_queue_retry | ops_fault | - | none | 101 | 100,0 (96,3 až 100,0) | 100,0 (96,3 až 100,0) | 100,0 (96,3 až 100,0) | splněno | - |
| mdns_ssdp_storm | ops_fault | - | none | 69 | 7,2 (3,1 až 15,9) | 23,2 (14,8 až 34,4) | 21,7 (13,6 až 32,8) | pod prahem | b (zmírněno, zbývá mezera) |
| memory_exhaustion_stall | ops_fault | - | none | 74 | 97,3 (90,7 až 99,3) | 97,3 (90,7 až 99,3) | 95,9 (88,7 až 98,6) | splněno | - |
| monitoring_agent_misconfig_poll | ops_fault | - | none | 87 | 87,4 (78,8 až 92,8) | 87,4 (78,8 až 92,8) | 83,9 (74,8 až 90,2) | pod prahem | c (otevřené) |
| ntp_clock_drift_host | ops_fault | - | none | 95 | 88,4 (80,4 až 93,4) | 88,4 (80,4 až 93,4) | 80,0 (70,9 až 86,8) | pod prahem | c (otevřené) |
| ntp_unreachable | ops_fault | - | none | 88 | 55,7 (45,3 až 65,6) | 54,5 (44,2 až 64,5) | 35,2 (26,1 až 45,6) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| slow_link_loss_degradation | ops_fault | - | none | 81 | 100,0 (95,5 až 100,0) | 100,0 (95,5 až 100,0) | 100,0 (95,5 až 100,0) | splněno | - |
| switch_outage_subnet | ops_fault | - | none | 80 | 92,5 (84,6 až 96,5) | 92,5 (84,6 až 96,5) | 92,5 (84,6 až 96,5) | pod prahem | c (otevřené) |
| uplink_saturation | ops_fault | - | none | 78 | 21,8 (14,1 až 32,2) | 20,5 (13,0 až 30,8) | 10,3 (5,3 až 19,0) | pod prahem | c (otevřené) |
| vpn_concentrator_down | ops_fault | - | none | 56 | 91,1 (80,7 až 96,1) | 91,1 (80,7 až 96,1) | 91,1 (80,7 až 96,1) | pod prahem | c (otevřené) |
| api_enum_distributed | security | T1595.002 | reconnaissance | 60 | 83,3 (72,0 až 90,7) | 83,3 (72,0 až 90,7) | 83,3 (72,0 až 90,7) | pod prahem | c (otevřené) |
| app_layer_flood_api | security | T1499.003 | impact | 62 | 93,5 (84,6 až 97,5) | 93,5 (84,6 až 97,5) | 88,7 (78,5 až 94,4) | pod prahem | c (otevřené) |
| apt_chain | security | - | lateral-movement | 131 | 99,2 (95,8 až 99,9) | 99,2 (95,8 až 99,9) | 99,2 (95,8 až 99,9) | splněno | - |
| backup_service_probing | security | T1490 | impact | 65 | 81,5 (70,4 až 89,1) | 81,5 (70,4 až 89,1) | 64,6 (52,5 až 75,1) | pod prahem | c (otevřené) |
| bucket_mass_download | security | T1530 | collection | 72 | 11,1 (5,7 až 20,4) | 11,1 (5,7 až 20,4) | 2,8 (0,8 až 9,6) | pod prahem | c (otevřené) |
| c2_alt_port_8443 | security | T1571 | command-and-control | 58 | 93,1 (83,6 až 97,3) | 93,1 (83,6 až 97,3) | 91,4 (81,4 až 96,3) | pod prahem | c (otevřené) |
| c2_beacon | security | - | command-and-control | 596 | 84,2 (81,1 až 86,9) | 83,9 (80,7 až 86,6) | 61,9 (57,9 až 65,7) | pod prahem | c (otevřené) |
| c2_cdn_fronted | security | T1090.004 | command-and-control | 77 | 88,3 (79,3 až 93,7) | 88,3 (79,3 až 93,7) | 88,3 (79,3 až 93,7) | pod prahem | c (otevřené) |
| c2_cloud_storage_dead_drop | security | T1102.002 | command-and-control | 76 | 67,1 (55,9 až 76,6) | 67,1 (55,9 až 76,6) | 11,8 (6,4 až 21,0) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| c2_dns_txt_beacon | security | T1071.004 | command-and-control | 77 | 55,8 (44,7 až 66,4) | 58,4 (47,3 až 68,8) | 33,8 (24,2 až 44,9) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| c2_doh_resolver | security | T1572 | command-and-control | 89 | 91,0 (83,3 až 95,4) | 91,0 (83,3 až 95,4) | 91,0 (83,3 až 95,4) | pod prahem | c (otevřené) |
| c2_high_jitter | security | T1071.001 | command-and-control | 72 | 65,3 (53,8 až 75,2) | 66,7 (55,2 až 76,5) | 58,3 (46,8 až 69,0) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| c2_https_legit_service | security | T1102 | command-and-control | 84 | 90,5 (82,3 až 95,1) | 90,5 (82,3 až 95,1) | 88,1 (79,5 až 93,4) | pod prahem | c (otevřené) |
| c2_icmp_tunnel | security | T1095 | command-and-control | 82 | 91,5 (83,4 až 95,8) | 91,5 (83,4 až 95,8) | 91,5 (83,4 až 95,8) | pod prahem | c (otevřené) |
| c2_internal_proxy_chain | security | T1090.001 | command-and-control | 83 | 98,8 (93,5 až 99,8) | 98,8 (93,5 až 99,8) | 94,0 (86,7 až 97,4) | splněno | - |
| c2_iot_mqtt_cloud | security | T1071 | command-and-control | 80 | 95,0 (87,8 až 98,0) | 96,2 (89,5 až 98,7) | 92,5 (84,6 až 96,5) | splněno | - |
| c2_irc_style_channel | security | T1071 | command-and-control | 89 | 87,6 (79,2 až 93,0) | 87,6 (79,2 až 93,0) | 86,5 (77,9 až 92,1) | pod prahem | c (otevřené) |
| c2_ntp_port_misuse | security | T1095 | command-and-control | 74 | 95,9 (88,7 až 98,6) | 95,9 (88,7 až 98,6) | 95,9 (88,7 až 98,6) | splněno | - |
| c2_slow_long_interval | security | T1071.001 | command-and-control | 89 | 92,1 (84,6 až 96,1) | 92,1 (84,6 až 96,1) | 89,9 (81,9 až 94,6) | pod prahem | c (otevřené) |
| c2_udp_custom_port | security | T1095 | command-and-control | 68 | 89,7 (80,2 až 94,9) | 89,7 (80,2 až 94,9) | 89,7 (80,2 až 94,9) | pod prahem | c (otevřené) |
| c2_websocket_long | security | T1071.001 | command-and-control | 80 | 91,2 (83,0 až 95,7) | 92,5 (84,6 až 96,5) | 90,0 (81,5 až 94,8) | pod prahem | b (zmírněno, zbývá mezera) |
| clicks_to_rare_destination | security | T1566.002 | initial-access | 83 | 10,8 (5,8 až 19,3) | 10,8 (5,8 až 19,3) | 6,0 (2,6 až 13,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| cloud_api_discovery_burst | security | T1580 | discovery | 65 | 10,8 (5,3 až 20,6) | 10,8 (5,3 až 20,6) | 3,1 (0,8 až 10,5) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| credential_stuffing | security | - | credential-access | 347 | 91,6 (88,3 až 94,1) | 91,6 (88,3 až 94,1) | 89,0 (85,3 až 91,9) | splněno | - |
| cryptomining | security | - | impact | 259 | 88,8 (84,4 až 92,1) | 88,8 (84,4 až 92,1) | 76,8 (71,3 až 81,6) | pod prahem | c (otevřené) |
| data_destruction_smb_wave | security | T1485 | impact | 62 | 75,8 (63,8 až 84,8) | 75,8 (63,8 až 84,8) | 67,7 (55,4 až 78,0) | pod prahem | c (otevřené) |
| data_staging_smb_internal | security | T1039 | collection | 68 | 82,4 (71,6 až 89,6) | 82,4 (71,6 až 89,6) | 63,2 (51,4 až 73,7) | pod prahem | c (otevřené) |
| dc_replication_from_workstation | security | T1003.006 | credential-access | 67 | 98,5 (92,0 až 99,7) | 98,5 (92,0 až 99,7) | 92,5 (83,7 až 96,8) | splněno | - |
| ddos_dns_amplification | security | T1498.002 | impact | 78 | 59,0 (47,9 až 69,2) | 59,0 (47,9 až 69,2) | 56,4 (45,4 až 66,9) | pod prahem | c (otevřené) |
| ddos_ntp_amplification | security | T1498.002 | impact | 98 | 98,0 (92,9 až 99,4) | 98,0 (92,9 až 99,4) | 94,9 (88,6 až 97,8) | splněno | - |
| ddos_syn_flood_distributed | security | T1498.001 | impact | 59 | 89,8 (79,5 až 95,3) | 89,8 (79,5 až 95,3) | 89,8 (79,5 až 95,3) | pod prahem | c (otevřené) |
| ddos_volume | security | - | impact | 167 | 94,0 (89,3 až 96,7) | 94,0 (89,3 až 96,7) | 91,0 (85,7 až 94,5) | splněno | - |
| distributed_low_port_probe | security | T1595.001 | reconnaissance | 76 | 88,2 (79,0 až 93,6) | 88,2 (79,0 až 93,6) | 84,2 (74,4 až 90,7) | pod prahem | c (otevřené) |
| dns_tunnel | security | - | command-and-control | 277 | 97,1 (94,4 až 98,5) | 96,8 (93,9 až 98,3) | 78,3 (73,1 až 82,8) | detekce ano, typ ne | - |
| dns_zone_enum_burst | security | T1590.002 | reconnaissance | 71 | 12,7 (6,8 až 22,4) | 12,7 (6,8 až 22,4) | 8,5 (3,9 až 17,2) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| drive_by_bulk_download | security | T1189 | initial-access | 73 | 8,2 (3,8 až 16,8) | 8,2 (3,8 až 16,8) | 2,7 (0,8 až 9,5) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_alt_protocol_ftp | security | T1048.003 | exfiltration | 66 | 16,7 (9,6 až 27,4) | 16,7 (9,6 až 27,4) | 15,2 (8,4 až 25,7) | pod prahem | c (otevřené) |
| exfil_cloud_storage_upload | security | T1567.002 | exfiltration | 62 | 33,9 (23,3 až 46,3) | 40,3 (29,0 až 52,7) | 19,4 (11,4 až 30,9) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_dns_slow | security | T1048.003 | exfiltration | 92 | 70,7 (60,7 až 79,0) | 70,7 (60,7 až 79,0) | 52,2 (42,1 až 62,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_https_burst | security | T1041 | exfiltration | 70 | 60,0 (48,3 až 70,7) | 60,0 (48,3 až 70,7) | 57,1 (45,5 až 68,1) | pod prahem | c (otevřené) |
| exfil_icmp_payload | security | T1048 | exfiltration | 79 | 58,2 (47,2 až 68,5) | 58,2 (47,2 až 68,5) | 11,4 (6,1 až 20,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| exfil_over_c2_trickle | security | T1041 | exfiltration | 75 | 62,7 (51,4 až 72,7) | 80,0 (69,6 až 87,5) | 73,3 (62,4 až 82,0) | pod prahem | b (zmírněno, zbývá mezera) |
| exfil_scheduled_chunks | security | T1029 | exfiltration | 64 | 89,1 (79,1 až 94,6) | 90,6 (81,0 až 95,6) | 85,9 (75,4 až 92,4) | pod prahem | b (zmírněno, zbývá mezera) |
| exfiltration | security | - | exfiltration | 408 | 93,4 (90,5 až 95,4) | 93,4 (90,5 až 95,4) | 91,7 (88,6 až 94,0) | splněno | - |
| exploit_attempt | security | - | initial-access | 635 | 88,3 (85,6 až 90,6) | 88,3 (85,6 až 90,6) | 48,8 (44,9 až 52,7) | pod prahem | c (otevřené) |
| fleet_beacon | security | - | command-and-control | 79 | 93,7 (86,0 až 97,3) | 93,7 (86,0 až 97,3) | 77,2 (66,8 až 85,1) | detekce ano, typ ne | - |
| ftp_bruteforce | security | T1110.001 | credential-access | 76 | 92,1 (83,8 až 96,3) | 92,1 (83,8 až 96,3) | 90,8 (82,2 až 95,5) | pod prahem | c (otevřené) |
| http_slow_connections_dos | security | T1499.002 | impact | 54 | 68,5 (55,3 až 79,3) | 68,5 (55,3 až 79,3) | 50,0 (37,1 až 62,9) | pod prahem | c (otevřené) |
| ics_attack | security | - | impact | 5 | 60,0 (23,1 až 88,2) | 60,0 (23,1 až 88,2) | 40,0 (11,8 až 76,9) | nedostatek dat | - |
| ics_bacnet_enumeration | security | T0846 | discovery | 1 | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | nedostatek dat | - |
| ics_ethernetip_scan | security | T0846 | discovery | 1 | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | 0,0 (0,0 až 79,3) | nedostatek dat | - |
| ics_modbus_write_burst | security | T0836 | impact | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| ics_slow_poll_new_source | security | T0801 | collection | 1 | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | 100,0 (20,7 až 100,0) | nedostatek dat | - |
| imap_spray | security | T1110.003 | credential-access | 78 | 94,9 (87,5 až 98,0) | 94,9 (87,5 až 98,0) | 93,6 (85,9 až 97,2) | splněno | - |
| insider_after_hours_cloud_sync | security | T1567.002 | exfiltration | 70 | 48,6 (37,2 až 60,0) | 48,6 (37,2 až 60,0) | 47,1 (35,9 až 58,7) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| insider_hoarding | security | - | exfiltration | 116 | 95,7 (90,3 až 98,1) | 95,7 (90,3 až 98,1) | 93,1 (87,0 až 96,5) | splněno | - |
| kerberos_ticket_request_burst | security | T1558.003 | credential-access | 73 | 98,6 (92,6 až 99,8) | 98,6 (92,6 až 99,8) | 94,5 (86,7 až 97,8) | splněno | - |
| lateral_cautious_one_target | security | T1021.002 | lateral-movement | 89 | 96,6 (90,6 až 98,8) | 96,6 (90,6 až 98,8) | 92,1 (84,6 až 96,1) | splněno | - |
| lateral_movement | security | - | lateral-movement | 575 | 98,3 (96,8 až 99,1) | 98,4 (97,1 až 99,2) | 81,2 (77,8 až 84,2) | detekce ano, typ ne | - |
| lateral_rdp_hop | security | T1021.001 | lateral-movement | 92 | 88,0 (79,8 až 93,2) | 89,1 (81,1 až 94,0) | 75,0 (65,3 až 82,7) | pod prahem | b (zmírněno, zbývá mezera) |
| lateral_smb_admin_shares | security | T1021.002 | lateral-movement | 80 | 93,8 (86,2 až 97,3) | 93,8 (86,2 až 97,3) | 93,8 (86,2 až 97,3) | splněno | - |
| lateral_ssh_hop | security | T1021.004 | lateral-movement | 79 | 82,3 (72,4 až 89,1) | 82,3 (72,4 až 89,1) | 75,9 (65,5 až 84,0) | pod prahem | c (otevřené) |
| lateral_winrm | security | T1021.006 | lateral-movement | 76 | 98,7 (92,9 až 99,8) | 98,7 (92,9 až 99,8) | 96,1 (89,0 až 98,6) | splněno | - |
| lateral_wmi_dcom | security | T1047 | execution | 84 | 96,4 (90,0 až 98,8) | 96,4 (90,0 až 98,8) | 96,4 (90,0 až 98,8) | splněno | - |
| ldap_bind_spray | security | T1110.003 | credential-access | 72 | 98,6 (92,5 až 99,8) | 98,6 (92,5 až 99,8) | 94,4 (86,6 až 97,8) | splněno | - |
| ldap_directory_enum_bulk | security | T1087.002 | discovery | 71 | 95,8 (88,3 až 98,6) | 95,8 (88,3 až 98,6) | 90,1 (81,0 až 95,1) | splněno | - |
| mail_forward_smtp_exfil | security | T1114 | collection | 79 | 62,0 (51,0 až 71,9) | 75,9 (65,5 až 84,0) | 70,9 (60,1 až 79,7) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| mqtt_probe_ext | security | T1046 | discovery | 71 | 71,8 (60,5 až 81,0) | 71,8 (60,5 až 81,0) | 66,2 (54,6 až 76,1) | pod prahem | c (otevřené) |
| mssql_login_failures | security | T1110.001 | credential-access | 73 | 90,4 (81,5 až 95,3) | 90,4 (81,5 až 95,3) | 89,0 (79,8 až 94,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| mysql_login_failures | security | T1110.001 | credential-access | 80 | 87,5 (78,5 až 93,1) | 86,2 (77,0 až 92,1) | 83,8 (74,2 až 90,3) | pod prahem | c (otevřené) |
| ntlm_relay_style_fanout | security | T1550.002 | lateral-movement | 75 | 82,7 (72,6 až 89,6) | 84,0 (74,1 až 90,6) | 81,3 (71,1 až 88,5) | pod prahem | b (zmírněno, zbývá mezera) |
| oauth_token_abuse_periodic | security | T1528 | credential-access | 71 | 91,5 (82,8 až 96,1) | 91,5 (82,8 až 96,1) | 91,5 (82,8 až 96,1) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| onion_style_circuit_egress | security | T1090.003 | command-and-control | 69 | 89,9 (80,5 až 95,0) | 89,9 (80,5 až 95,0) | 89,9 (80,5 až 95,0) | pod prahem | c (otevřené) |
| port_scan_horizontal | security | - | discovery | 450 | 85,6 (82,0 až 88,5) | 86,2 (82,7 až 89,1) | 81,3 (77,5 až 84,7) | pod prahem | b (zmírněno, zbývá mezera) |
| port_scan_vertical | security | - | discovery | 561 | 90,7 (88,0 až 92,9) | 90,7 (88,0 až 92,9) | 89,3 (86,5 až 91,6) | splněno | - |
| public_app_probe_trickle | security | T1190 | initial-access | 64 | 82,8 (71,8 až 90,1) | 82,8 (71,8 až 90,1) | 45,3 (33,7 až 57,4) | pod prahem | c (otevřené) |
| ransomware | security | - | impact | 193 | 99,5 (97,1 až 99,9) | 99,5 (97,1 až 99,9) | 97,4 (94,1 až 98,9) | splněno | - |
| rdp_bruteforce | security | T1110.001 | credential-access | 69 | 100,0 (94,7 až 100,0) | 100,0 (94,7 až 100,0) | 97,1 (90,0 až 99,2) | splněno | - |
| rdp_sweep_ext | security | T1046 | discovery | 78 | 84,6 (75,0 až 91,0) | 85,9 (76,5 až 91,9) | 79,5 (69,2 až 87,0) | pod prahem | b (zmírněno, zbývá mezera) |
| resource_hijack_pool_tls | security | T1496 | impact | 74 | 97,3 (90,7 až 99,3) | 97,3 (90,7 až 99,3) | 97,3 (90,7 až 99,3) | splněno | - |
| rogue_device | security | - | initial-access | 130 | 93,1 (87,4 až 96,3) | 92,3 (86,4 až 95,8) | 86,9 (80,1 až 91,7) | splněno | - |
| share_encryption_wave_slow | security | T1486 | impact | 61 | 91,8 (82,2 až 96,4) | 93,4 (84,3 až 97,4) | 72,1 (59,8 až 81,8) | pod prahem | b (zmírněno, zbývá mezera) |
| slow_scan | security | - | discovery | 446 | 92,8 (90,0 až 94,9) | 93,3 (90,6 až 95,2) | 87,4 (84,0 až 90,2) | splněno | - |
| smb_login_failures | security | T1110 | credential-access | 101 | 96,0 (90,3 až 98,4) | 96,0 (90,3 až 98,4) | 92,1 (85,1 až 95,9) | splněno | - |
| smb_share_enum_internal | security | T1135 | discovery | 57 | 78,9 (66,7 až 87,5) | 78,9 (66,7 až 87,5) | 75,4 (62,9 až 84,8) | pod prahem | c (otevřené) |
| smb_sweep_ext | security | T1046 | discovery | 70 | 81,4 (70,8 až 88,8) | 81,4 (70,8 až 88,8) | 75,7 (64,5 až 84,2) | pod prahem | c (otevřené) |
| smtp_auth_spray | security | T1110.003 | credential-access | 72 | 93,1 (84,8 až 97,0) | 93,1 (84,8 až 97,0) | 93,1 (84,8 až 97,0) | pod prahem | c (otevřené) |
| snmp_sweep_ext | security | T1046 | discovery | 93 | 82,8 (73,9 až 89,1) | 83,9 (75,1 až 90,0) | 78,5 (69,1 až 85,6) | pod prahem | b (zmírněno, zbývá mezera) |
| snmp_walk_internal | security | T1602.001 | collection | 72 | 98,6 (92,5 až 99,8) | 98,6 (92,5 až 99,8) | 97,2 (90,4 až 99,2) | splněno | - |
| ssh_bruteforce | security | - | credential-access | 730 | 93,4 (91,4 až 95,0) | 93,4 (91,4 až 95,0) | 83,7 (80,8 až 86,2) | detekce ano, typ ne | - |
| ssh_spray_slow_distributed | security | T1110.003 | credential-access | 87 | 79,3 (69,6 až 86,5) | 79,3 (69,6 až 86,5) | 71,3 (61,0 až 79,7) | pod prahem | c (otevřené) |
| telnet_iot_login | security | T1110.001 | credential-access | 58 | 50,0 (37,5 až 62,5) | 50,0 (37,5 až 62,5) | 41,4 (29,6 až 54,2) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| update_channel_compromise_fleet | security | T1195.002 | initial-access | 67 | 98,5 (92,0 až 99,7) | 98,5 (92,0 až 99,7) | 94,0 (85,6 až 97,7) | splněno | - |
| vendor_remote_access_odd_hours | security | T1199 | initial-access | 61 | 44,3 (32,5 až 56,7) | 44,3 (32,5 až 56,7) | 4,9 (1,7 až 13,5) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| vnc_probe_ext | security | T1021.005 | lateral-movement | 82 | 67,1 (56,3 až 76,3) | 68,3 (57,6 až 77,4) | 61,0 (50,2 až 70,8) | pod prahem | b (zmírněno, zbývá mezera) |
| vpn_password_spray_slow | security | T1110.003 | credential-access | 63 | 38,1 (27,1 až 50,4) | 38,1 (27,1 až 50,4) | 25,4 (16,3 až 37,3) | pod prahem | c (obsahový rozdíl neviditelný v tocích) |
| web_exploit | security | - | initial-access | 439 | 94,5 (92,0 až 96,3) | 94,5 (92,0 až 96,3) | 73,3 (69,0 až 77,3) | detekce ano, typ ne | - |
| web_scanner_404_storm | security | T1595.003 | reconnaissance | 58 | 93,1 (83,6 až 97,3) | 93,1 (83,6 až 97,3) | 77,6 (65,3 až 86,4) | pod prahem | c (otevřené) |

## Souhrn po taktikách (kandidát)

| taktika | n | detekce před | detekce po | správný typ po |
|---|---:|---|---|---|
| collection | 292 | 63,4 (57,7 až 68,7) | 67,1 (61,5 až 72,3) | 58,9 (53,2 až 64,4) |
| command-and-control | 2199 | 87,5 (86,1 až 88,9) | 87,6 (86,2 až 88,9) | 75,0 (73,2 až 76,8) |
| credential-access | 2117 | 90,2 (88,8 až 91,4) | 90,1 (88,8 až 91,3) | 84,4 (82,8 až 85,9) |
| discovery | 1964 | 85,5 (83,9 až 87,0) | 85,8 (84,2 až 87,3) | 81,5 (79,7 až 83,2) |
| execution | 84 | 96,4 (90,0 až 98,8) | 96,4 (90,0 až 98,8) | 96,4 (90,0 až 98,8) |
| exfiltration | 1102 | 74,0 (71,3 až 76,5) | 75,6 (73,0 až 78,0) | 67,5 (64,7 až 70,2) |
| impact | 1238 | 88,9 (87,1 až 90,6) | 89,0 (87,2 až 90,6) | 81,9 (79,7 až 84,0) |
| initial-access | 1552 | 81,1 (79,0 až 82,9) | 81,0 (79,0 až 82,9) | 54,6 (52,1 až 57,0) |
| lateral-movement | 1279 | 93,4 (91,9 až 94,6) | 93,7 (92,2 až 94,9) | 83,4 (81,3 až 85,4) |
| none | 2363 | 78,2 (76,5 až 79,8) | 79,6 (78,0 až 81,2) | 75,6 (73,9 až 77,3) |
| reconnaissance | 265 | 67,9 (62,1 až 73,3) | 67,9 (62,1 až 73,3) | 62,3 (56,3 až 67,9) |

## Souhrn po kategoriích (kandidát)

Pro `benign_change` je „detekce“ podíl neškodných změn, které se zobrazily (nežádoucí; nižší je lepší).

| kategorie | n | detekce před | detekce po | správný typ po | zobrazeno ve frontě provoz |
|---|---:|---|---|---|---|
| benign_change | 235 | 95,7 (92,3 až 97,7) | 95,7 (92,3 až 97,7) | 94,5 (90,8 až 96,7) | 0,0 % |
| ops_fault | 2128 | 76,2 (74,4 až 78,0) | 77,9 (76,1 až 79,6) | 73,5 (71,6 až 75,4) | 0,0 % |
| security | 12092 | 85,4 (84,8 až 86,0) | 85,7 (85,1 až 86,4) | 75,5 (74,7 až 76,2) | 0,0 % |

## Neviděné taktiky a rodiny (protokol z `impl-krok10.md`, C)

Foldy byly stanoveny před měřením a při ladění detektorů se nepoužily. Práh K10-1: detekce ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %.

| fold | n | detekce před | detekce po | správný typ po | K10-1 |
|---|---:|---|---|---|---|
| taktika credential-access | 2117 | 90,2 (88,8 až 91,4) | 90,1 (88,8 až 91,3) | 84,4 (82,8 až 85,9) | splněno |
| taktika discovery | 1964 | 85,5 (83,9 až 87,0) | 85,8 (84,2 až 87,3) | 81,5 (79,7 až 83,2) | nedosaženo |
| taktika lateral-movement | 1279 | 93,4 (91,9 až 94,6) | 93,7 (92,2 až 94,9) | 83,4 (81,3 až 85,4) | splněno |
| rodina c2_slow_long_interval | 89 | 92,1 (84,6 až 96,1) | 92,1 (84,6 až 96,1) | 89,9 (81,9 až 94,6) | nedosaženo |
| rodina ssh_spray_slow_distributed | 87 | 79,3 (69,6 až 86,5) | 79,3 (69,6 až 86,5) | 71,3 (61,0 až 79,7) | nedosaženo |
| rodina data_staging_smb_internal | 68 | 82,4 (71,6 až 89,6) | 82,4 (71,6 až 89,6) | 63,2 (51,4 až 73,7) | nedosaženo |
| rodina kerberos_ticket_request_burst | 73 | 98,6 (92,6 až 99,8) | 98,6 (92,6 až 99,8) | 94,5 (86,7 až 97,8) | splněno |
| rodina ics_attack | 5 | 60,0 (23,1 až 88,2) | 60,0 (23,1 až 88,2) | 40,0 (11,8 až 76,9) | nedostatek dat |
| rodina cloud_api_discovery_burst | 65 | 10,8 (5,3 až 20,6) | 10,8 (5,3 až 20,6) | 3,1 (0,8 až 10,5) | nedosaženo |
| rodina rdp_bruteforce | 69 | 100,0 (94,7 až 100,0) | 100,0 (94,7 až 100,0) | 97,1 (90,0 až 99,2) | splněno |
| rodina ddos_syn_flood_distributed | 59 | 89,8 (79,5 až 95,3) | 89,8 (79,5 až 95,3) | 89,8 (79,5 až 95,3) | nedosaženo |

## Rodiny pod prahem (n ≥ 50; detekce < 90 % nebo dolní mez < 85 %)

| rodina | n | detekce % | kategorie slepého místa |
|---|---:|---:|---|
| drive_by_bulk_download (security) | 73 | 8,2 | c (obsahový rozdíl neviditelný v tocích) |
| cloud_api_discovery_burst (security) | 65 | 10,8 | c (obsahový rozdíl neviditelný v tocích) |
| clicks_to_rare_destination (security) | 83 | 10,8 | c (obsahový rozdíl neviditelný v tocích) |
| bucket_mass_download (security) | 72 | 11,1 | c (otevřené) |
| dns_zone_enum_burst (security) | 71 | 12,7 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_alt_protocol_ftp (security) | 66 | 16,7 | c (otevřené) |
| uplink_saturation (ops_fault) | 78 | 20,5 | c (otevřené) |
| cert_expired_internal_service (ops_fault) | 66 | 21,2 | c (obsahový rozdíl neviditelný v tocích) |
| mdns_ssdp_storm (ops_fault) | 69 | 23,2 | b (zmírněno, zbývá mezera) |
| dhcp_pool_exhaustion (ops_fault) | 84 | 25,0 | b (zmírněno, zbývá mezera) |
| broadcast_storm_loop (ops_fault) | 93 | 32,3 | b (zmírněno, zbývá mezera) |
| vpn_password_spray_slow (security) | 63 | 38,1 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_cloud_storage_upload (security) | 62 | 40,3 | c (obsahový rozdíl neviditelný v tocích) |
| vendor_remote_access_odd_hours (security) | 61 | 44,3 | c (obsahový rozdíl neviditelný v tocích) |
| insider_after_hours_cloud_sync (security) | 70 | 48,6 | c (obsahový rozdíl neviditelný v tocích) |
| telnet_iot_login (security) | 58 | 50,0 | c (obsahový rozdíl neviditelný v tocích) |
| ntp_unreachable (ops_fault) | 88 | 54,5 | c (obsahový rozdíl neviditelný v tocích) |
| exfil_icmp_payload (security) | 79 | 58,2 | c (obsahový rozdíl neviditelný v tocích) |
| c2_dns_txt_beacon (security) | 77 | 58,4 | c (obsahový rozdíl neviditelný v tocích) |
| ddos_dns_amplification (security) | 78 | 59,0 | c (otevřené) |
| exfil_https_burst (security) | 70 | 60,0 | c (otevřené) |
| dns_slow_resolution (ops_fault) | 92 | 62,0 | c (obsahový rozdíl neviditelný v tocích) |
| c2_high_jitter (security) | 72 | 66,7 | c (obsahový rozdíl neviditelný v tocích) |
| c2_cloud_storage_dead_drop (security) | 76 | 67,1 | c (obsahový rozdíl neviditelný v tocích) |
| vnc_probe_ext (security) | 82 | 68,3 | b (zmírněno, zbývá mezera) |
| http_slow_connections_dos (security) | 54 | 68,5 | c (otevřené) |
| exfil_dns_slow (security) | 92 | 70,7 | c (obsahový rozdíl neviditelný v tocích) |
| dns_partial_failure (ops_fault) | 108 | 71,3 | c (obsahový rozdíl neviditelný v tocích) |
| mqtt_probe_ext (security) | 71 | 71,8 | c (otevřené) |
| data_destruction_smb_wave (security) | 62 | 75,8 | c (otevřené) |
| mail_forward_smtp_exfil (security) | 79 | 75,9 | c (obsahový rozdíl neviditelný v tocích) |
| smb_share_enum_internal (security) | 57 | 78,9 | c (otevřené) |
| ssh_spray_slow_distributed (security) | 87 | 79,3 | c (otevřené) |
| exfil_over_c2_trickle (security) | 75 | 80,0 | b (zmírněno, zbývá mezera) |
| smb_sweep_ext (security) | 70 | 81,4 | c (otevřené) |
| backup_service_probing (security) | 65 | 81,5 | c (otevřené) |
| lateral_ssh_hop (security) | 79 | 82,3 | c (otevřené) |
| data_staging_smb_internal (security) | 68 | 82,4 | c (otevřené) |
| public_app_probe_trickle (security) | 64 | 82,8 | c (otevřené) |
| api_enum_distributed (security) | 60 | 83,3 | c (otevřené) |
| snmp_sweep_ext (security) | 93 | 83,9 | b (zmírněno, zbývá mezera) |
| c2_beacon (security) | 596 | 83,9 | c (otevřené) |
| ntlm_relay_style_fanout (security) | 75 | 84,0 | b (zmírněno, zbývá mezera) |
| rdp_sweep_ext (security) | 78 | 85,9 | b (zmírněno, zbývá mezera) |
| disk_full_backup_failure (ops_fault) | 50 | 86,0 | c (otevřené) |
| port_scan_horizontal (security) | 450 | 86,2 | b (zmírněno, zbývá mezera) |
| mysql_login_failures (security) | 80 | 86,2 | c (otevřené) |
| monitoring_agent_misconfig_poll (ops_fault) | 87 | 87,4 | c (otevřené) |
| c2_irc_style_channel (security) | 89 | 87,6 | c (otevřené) |
| distributed_low_port_probe (security) | 76 | 88,2 | c (otevřené) |
| c2_cdn_fronted (security) | 77 | 88,3 | c (otevřené) |
| exploit_attempt (security) | 635 | 88,3 | c (otevřené) |
| ntp_clock_drift_host (ops_fault) | 95 | 88,4 | c (otevřené) |
| cryptomining (security) | 259 | 88,8 | c (otevřené) |
| lateral_rdp_hop (security) | 92 | 89,1 | b (zmírněno, zbývá mezera) |
| c2_udp_custom_port (security) | 68 | 89,7 | c (otevřené) |
| ddos_syn_flood_distributed (security) | 59 | 89,8 | c (otevřené) |
| onion_style_circuit_egress (security) | 69 | 89,9 | c (otevřené) |
| mssql_login_failures (security) | 73 | 90,4 | c (obsahový rozdíl neviditelný v tocích) |
| c2_https_legit_service (security) | 84 | 90,5 | c (otevřené) |
| exfil_scheduled_chunks (security) | 64 | 90,6 | b (zmírněno, zbývá mezera) |
| c2_doh_resolver (security) | 89 | 91,0 | c (otevřené) |
| vpn_concentrator_down (ops_fault) | 56 | 91,1 | c (otevřené) |
| c2_icmp_tunnel (security) | 82 | 91,5 | c (otevřené) |
| oauth_token_abuse_periodic (security) | 71 | 91,5 | c (obsahový rozdíl neviditelný v tocích) |
| ftp_bruteforce (security) | 76 | 92,1 | c (otevřené) |
| c2_slow_long_interval (security) | 89 | 92,1 | c (otevřené) |
| iot_firmware_chatter_loop (ops_fault) | 79 | 92,4 | c (otevřené) |
| access_point_controller_failure (ops_fault) | 66 | 92,4 | c (otevřené) |
| switch_outage_subnet (ops_fault) | 80 | 92,5 | c (otevřené) |
| c2_websocket_long (security) | 80 | 92,5 | b (zmírněno, zbývá mezera) |
| smtp_auth_spray (security) | 72 | 93,1 | c (otevřené) |
| c2_alt_port_8443 (security) | 58 | 93,1 | c (otevřené) |
| web_scanner_404_storm (security) | 58 | 93,1 | c (otevřené) |
| backup_window_overrun (ops_fault) | 60 | 93,3 | c (otevřené) |
| share_encryption_wave_slow (security) | 61 | 93,4 | b (zmírněno, zbývá mezera) |
| seasonal_peak_web (benign_change) | 62 | 93,5 | c (otevřené) |
| app_layer_flood_api (security) | 62 | 93,5 | c (otevřené) |

