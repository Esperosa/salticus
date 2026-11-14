| technika | taktika | rodina nebo varianta | kategorie | n | detektor (nejčastější typ nálezu) | detekce % (Wilson) | stav |
|---|---|---|---|---:|---|---|---|
| - | none | hn_admin_bulk_ssh | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_authorized_internal_scan | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_cdn_update_download | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_db_replication_bulk | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_mail_newsletter_burst | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_monitoring_snmp_sweep | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_nightly_cloud_backup_upload | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | hn_password_sync_periodic | benign_change | 0 | - | - | nepokryto v běhu |
| - | none | planned_maintenance_window | benign_change | 93 | service_unreachable (79), connection_timeout_burst (14) | 93,5 (86,6 až 97,0) | splněno |
| - | none | planned_patch_reboot_wave | benign_change | 80 | service_unreachable (73), connection_timeout_burst (47) | 100,0 (95,4 až 100,0) | splněno |
| - | none | seasonal_peak_web | benign_change | 62 | inductive_volume_anomaly (53), packet_rate_spike (43) | 93,5 (84,6 až 97,5) | pod prahem |
| - | none | access_point_controller_failure | ops_fault | 66 | service_unreachable (57), scan_attempts (7) | 92,4 (83,5 až 96,7) | pod prahem |
| - | none | app_server_crash_cascade | ops_fault | 80 | service_unreachable (76), scan_attempts (44) | 100,0 (95,4 až 100,0) | splněno |
| - | none | backup_window_overrun | ops_fault | 60 | inductive_volume_anomaly (35), packet_rate_spike (35) | 93,3 (84,1 až 97,4) | pod prahem |
| - | none | broadcast_storm_loop | ops_fault | 93 | broadcast_storm (23), unexpected_traffic (4) | 32,3 (23,6 až 42,3) | pod prahem |
| - | none | cert_chain_misconfig_external | ops_fault | 88 | service_unreachable (80), connection_timeout_burst (24) | 93,2 (85,9 až 96,8) | splněno |
| - | none | cert_expired_internal_service | ops_fault | 66 | unexpected_traffic (5), novel_fanout (4) | 21,2 (13,1 až 32,5) | pod prahem |
| - | none | core_router_flapping | ops_fault | 79 | service_unreachable (70), connection_timeout_burst (38) | 97,5 (91,2 až 99,3) | splněno |
| - | none | db_overload_degradation | ops_fault | 55 | service_unreachable (55), unexpected_traffic (54) | 100,0 (93,5 až 100,0) | splněno |
| - | none | dhcp_pool_exhaustion | ops_fault | 84 | broadcast_storm (9), packet_rate_spike (4) | 25,0 (17,0 až 35,2) | pod prahem |
| - | none | dhcp_server_down | ops_fault | 84 | service_unreachable (78), scan_attempts (8) | 98,8 (93,6 až 99,8) | splněno |
| - | none | disk_full_backup_failure | ops_fault | 50 | service_unreachable (36), unmapped_passive_event (4) | 86,0 (73,8 až 93,0) | pod prahem |
| - | none | dns_partial_failure | ops_fault | 108 | packet_rate_spike (47), service_unreachable (25) | 71,3 (62,1 až 79,0) | pod prahem |
| - | none | dns_slow_resolution | ops_fault | 92 | packet_rate_spike (34), service_unreachable (16) | 62,0 (51,7 až 71,2) | pod prahem |
| - | none | duplicate_ip_conflict | ops_fault | 91 | service_unreachable (71), connection_timeout_burst (32) | 96,7 (90,8 až 98,9) | splněno |
| - | none | flapping_service | ops_fault | 81 | service_unreachable (73), unexpected_traffic (15) | 97,5 (91,4 až 99,3) | splněno |
| - | none | iot_firmware_chatter_loop | ops_fault | 79 | beacon_periodic (71), novel_persistent_peer (48) | 92,4 (84,4 až 96,5) | pod prahem |
| - | none | load_balancer_partial_outage | ops_fault | 63 | service_unreachable (58), pivot_chain (31) | 98,4 (91,5 až 99,7) | splněno |
| - | none | mail_relay_queue_retry | ops_fault | 101 | service_unreachable (98), scan_attempts (23) | 100,0 (96,3 až 100,0) | splněno |
| - | none | mdns_ssdp_storm | ops_fault | 69 | broadcast_storm (14), unexpected_traffic (2) | 23,2 (14,8 až 34,4) | pod prahem |
| - | none | memory_exhaustion_stall | ops_fault | 74 | service_unreachable (65), unexpected_traffic (60) | 97,3 (90,7 až 99,3) | splněno |
| - | none | monitoring_agent_misconfig_poll | ops_fault | 87 | scan_attempts (64), multi_target_pattern (45) | 87,4 (78,8 až 92,8) | pod prahem |
| - | none | ntp_clock_drift_host | ops_fault | 95 | unexpected_traffic (63), pivot_chain (32) | 88,4 (80,4 až 93,4) | pod prahem |
| - | none | ntp_unreachable | ops_fault | 88 | service_unreachable (18), scan_attempts (11) | 54,5 (44,2 až 64,5) | pod prahem |
| - | none | slow_link_loss_degradation | ops_fault | 81 | service_unreachable (77), connection_timeout_burst (58) | 100,0 (95,5 až 100,0) | splněno |
| - | none | switch_outage_subnet | ops_fault | 80 | service_unreachable (71), connection_timeout_burst (28) | 92,5 (84,6 až 96,5) | pod prahem |
| - | none | uplink_saturation | ops_fault | 78 | unexpected_traffic (8), service_unreachable (6) | 20,5 (13,0 až 30,8) | pod prahem |
| - | none | vpn_concentrator_down | ops_fault | 56 | service_unreachable (48), connection_timeout_burst (11) | 91,1 (80,7 až 96,1) | pod prahem |
| T0801 | collection | ics_slow_poll_new_source | security | 1 | connection_timeout_burst (1), novel_fanout (1) | 100,0 (20,7 až 100,0) | nedostatek dat |
| T0814 | impact | ics_dnp3_unsolicited_flood | security | 0 | - | - | nepokryto v běhu |
| T0836 | impact | ics_modbus_write_burst | security | 1 | unexpected_traffic (1) | 100,0 (20,7 až 100,0) | nedostatek dat |
| T0843 | execution | ics_program_download_slow | security | 0 | - | - | nepokryto v běhu |
| T0846 | discovery | ics_bacnet_enumeration | security | 1 | - | 0,0 (0,0 až 79,3) | nedostatek dat |
| T0846 | discovery | ics_ethernetip_scan | security | 1 | - | 0,0 (0,0 až 79,3) | nedostatek dat |
| T0846 | discovery | ics_opcua_enumeration | security | 0 | - | - | nepokryto v běhu |
| T0858 | execution | ics_s7_operating_mode_change | security | 0 | - | - | nepokryto v běhu |
| T1003.006 | credential-access | dc_replication_from_workstation | security | 67 | unexpected_traffic (56), multi_target_pattern (34) | 98,5 (92,0 až 99,7) | splněno |
| T1021.001 | lateral-movement | lateral_rdp_hop | security | 92 | multi_target_pattern (49), packet_rate_spike (48) | 89,1 (81,1 až 94,0) | pod prahem |
| T1021.002 | lateral-movement | lateral_cautious_one_target | security | 89 | unexpected_traffic (77), inductive_volume_anomaly (64) | 96,6 (90,6 až 98,8) | splněno |
| T1021.002 | lateral-movement | lateral_smb_admin_shares | security | 80 | unexpected_traffic (71), suricata_alert (43) | 93,8 (86,2 až 97,3) | splněno |
| T1021.004 | lateral-movement | lateral_ssh_hop | security | 79 | multi_target_pattern (32), unexpected_traffic (32) | 82,3 (72,4 až 89,1) | pod prahem |
| T1021.005 | lateral-movement | vnc_probe_ext | security | 82 | scan_attempts (45), unexpected_traffic (12) | 68,3 (57,6 až 77,4) | pod prahem |
| T1021.006 | lateral-movement | lateral_winrm | security | 76 | unexpected_traffic (69), multi_target_pattern (38) | 98,7 (92,9 až 99,8) | splněno |
| T1029 | exfiltration | exfil_scheduled_chunks | security | 64 | beacon_periodic (53), slow_egress (50) | 90,6 (81,0 až 95,6) | pod prahem |
| T1039 | collection | data_staging_smb_internal | security | 68 | inductive_volume_anomaly (33), packet_rate_spike (31) | 82,4 (71,6 až 89,6) | pod prahem |
| T1041 | exfiltration | exfil_https_burst | security | 70 | egress_volume_anomaly (39), pivot_chain (2) | 60,0 (48,3 až 70,7) | pod prahem |
| T1041 | exfiltration | exfil_over_c2_trickle | security | 75 | slow_egress (47), novel_persistent_peer (37) | 80,0 (69,6 až 87,5) | pod prahem |
| T1046 | discovery | mqtt_probe_ext | security | 71 | scan_attempts (43), pivot_chain (13) | 71,8 (60,5 až 81,0) | pod prahem |
| T1046 | discovery | rdp_sweep_ext | security | 78 | scan_attempts (52), suricata_alert (35) | 85,9 (76,5 až 91,9) | pod prahem |
| T1046 | discovery | smb_sweep_ext | security | 70 | scan_attempts (46), novel_fanout (12) | 81,4 (70,8 až 88,8) | pod prahem |
| T1046 | discovery | snmp_sweep_ext | security | 93 | scan_attempts (56), suricata_alert (52) | 83,9 (75,1 až 90,0) | pod prahem |
| T1047 | execution | lateral_wmi_dcom | security | 84 | unexpected_traffic (77), multi_target_pattern (50) | 96,4 (90,0 až 98,8) | splněno |
| T1048 | exfiltration | exfil_icmp_payload | security | 79 | novel_persistent_peer (42), pivot_chain (6) | 58,2 (47,2 až 68,5) | pod prahem |
| T1048.003 | exfiltration | exfil_alt_protocol_ftp | security | 66 | unexpected_traffic (6), egress_volume_anomaly (2) | 16,7 (9,6 až 27,4) | pod prahem |
| T1048.003 | exfiltration | exfil_dns_slow | security | 92 | unexpected_traffic (29), novel_fanout (19) | 70,7 (60,7 až 79,0) | pod prahem |
| T1071 | command-and-control | c2_iot_mqtt_cloud | security | 80 | beacon_periodic (74), novel_persistent_peer (46) | 96,2 (89,5 až 98,7) | splněno |
| T1071 | command-and-control | c2_irc_style_channel | security | 89 | beacon_periodic (77), novel_persistent_peer (44) | 87,6 (79,2 až 93,0) | pod prahem |
| T1071.001 | command-and-control | c2_high_jitter | security | 72 | novel_persistent_peer (34), beacon_periodic (11) | 66,7 (55,2 až 76,5) | pod prahem |
| T1071.001 | command-and-control | c2_slow_long_interval | security | 89 | beacon_periodic (73), novel_persistent_peer (48) | 92,1 (84,6 až 96,1) | pod prahem |
| T1071.001 | command-and-control | c2_websocket_long | security | 80 | long_lived_tunnel (68), beacon_periodic (57) | 92,5 (84,6 až 96,5) | pod prahem |
| T1071.004 | command-and-control | c2_dns_txt_beacon | security | 77 | unexpected_traffic (21), inductive_volume_anomaly (13) | 58,4 (47,3 až 68,8) | pod prahem |
| T1087.002 | discovery | ldap_directory_enum_bulk | security | 71 | unexpected_traffic (60), novel_fanout (18) | 95,8 (88,3 až 98,6) | splněno |
| T1090.001 | command-and-control | c2_internal_proxy_chain | security | 83 | unexpected_traffic (77), service_unreachable (29) | 98,8 (93,5 až 99,8) | splněno |
| T1090.003 | command-and-control | onion_style_circuit_egress | security | 69 | long_lived_tunnel (62), beacon_periodic (33) | 89,9 (80,5 až 95,0) | pod prahem |
| T1090.004 | command-and-control | c2_cdn_fronted | security | 77 | beacon_periodic (68), novel_persistent_peer (36) | 88,3 (79,3 až 93,7) | pod prahem |
| T1095 | command-and-control | c2_icmp_tunnel | security | 82 | beacon_periodic (73), novel_persistent_peer (47) | 91,5 (83,4 až 95,8) | pod prahem |
| T1095 | command-and-control | c2_ntp_port_misuse | security | 74 | beacon_periodic (70), novel_persistent_peer (47) | 95,9 (88,7 až 98,6) | splněno |
| T1095 | command-and-control | c2_udp_custom_port | security | 68 | beacon_periodic (61), novel_persistent_peer (33) | 89,7 (80,2 až 94,9) | pod prahem |
| T1102 | command-and-control | c2_https_legit_service | security | 84 | beacon_periodic (73), novel_persistent_peer (47) | 90,5 (82,3 až 95,1) | pod prahem |
| T1102.002 | command-and-control | c2_cloud_storage_dead_drop | security | 76 | novel_persistent_peer (41), beacon_periodic (11) | 67,1 (55,9 až 76,6) | pod prahem |
| T1110 | credential-access | smb_login_failures | security | 101 | unexpected_traffic (90), inductive_volume_anomaly (58) | 96,0 (90,3 až 98,4) | splněno |
| T1110.001 | credential-access | ftp_bruteforce | security | 76 | unexpected_traffic (69), inductive_volume_anomaly (9) | 92,1 (83,8 až 96,3) | pod prahem |
| T1110.001 | credential-access | mssql_login_failures | security | 73 | unexpected_traffic (65), scan_attempts (3) | 90,4 (81,5 až 95,3) | pod prahem |
| T1110.001 | credential-access | mysql_login_failures | security | 80 | unexpected_traffic (64), inductive_volume_anomaly (6) | 86,2 (77,0 až 92,1) | pod prahem |
| T1110.001 | credential-access | rdp_bruteforce | security | 69 | unexpected_traffic (63), suricata_alert (41) | 100,0 (94,7 až 100,0) | splněno |
| T1110.001 | credential-access | telnet_iot_login | security | 58 | unexpected_traffic (23), unmapped_passive_event (5) | 50,0 (37,5 až 62,5) | pod prahem |
| T1110.003 | credential-access | imap_spray | security | 78 | unexpected_traffic (69), inductive_volume_anomaly (11) | 94,9 (87,5 až 98,0) | splněno |
| T1110.003 | credential-access | ldap_bind_spray | security | 72 | unexpected_traffic (66), inductive_volume_anomaly (21) | 98,6 (92,5 až 99,8) | splněno |
| T1110.003 | credential-access | smtp_auth_spray | security | 72 | unexpected_traffic (67), connection_timeout_burst (5) | 93,1 (84,8 až 97,0) | pod prahem |
| T1110.003 | credential-access | ssh_spray_slow_distributed | security | 87 | unexpected_traffic (56), packet_rate_spike (15) | 79,3 (69,6 až 86,5) | pod prahem |
| T1110.003 | credential-access | vpn_password_spray_slow | security | 63 | unexpected_traffic (10), novel_fanout (6) | 38,1 (27,1 až 50,4) | pod prahem |
| T1114 | collection | mail_forward_smtp_exfil | security | 79 | slow_egress (54), novel_persistent_peer (44) | 75,9 (65,5 až 84,0) | pod prahem |
| T1135 | discovery | smb_share_enum_internal | security | 57 | scan_attempts (36), multi_target_pattern (30) | 78,9 (66,7 až 87,5) | pod prahem |
| T1189 | initial-access | drive_by_bulk_download | security | 73 | pivot_chain (2), unexpected_traffic (2) | 8,2 (3,8 až 16,8) | pod prahem |
| T1190 | initial-access | public_app_probe_trickle | security | 64 | suricata_alert (36), unexpected_traffic (25) | 82,8 (71,8 až 90,1) | pod prahem |
| T1195.002 | initial-access | update_channel_compromise_fleet | security | 67 | beacon_periodic (57), unexpected_traffic (40) | 98,5 (92,0 až 99,7) | splněno |
| T1199 | initial-access | vendor_remote_access_odd_hours | security | 61 | packet_rate_spike (16), pivot_chain (3) | 44,3 (32,5 až 56,7) | pod prahem |
| T1485 | impact | data_destruction_smb_wave | security | 62 | unexpected_traffic (28), multi_target_pattern (27) | 75,8 (63,8 až 84,8) | pod prahem |
| T1486 | impact | share_encryption_wave_slow | security | 61 | packet_rate_spike (50), unexpected_traffic (31) | 93,4 (84,3 až 97,4) | pod prahem |
| T1490 | impact | backup_service_probing | security | 65 | unexpected_traffic (33), novel_fanout (22) | 81,5 (70,4 až 89,1) | pod prahem |
| T1496 | impact | resource_hijack_pool_tls | security | 74 | long_lived_tunnel (70), beacon_periodic (62) | 97,3 (90,7 až 99,3) | splněno |
| T1498.001 | impact | ddos_syn_flood_distributed | security | 59 | connection_timeout_burst (53), inductive_volume_anomaly (49) | 89,8 (79,5 až 95,3) | pod prahem |
| T1498.002 | impact | ddos_dns_amplification | security | 78 | connection_timeout_burst (35), service_overload_risk (28) | 59,0 (47,9 až 69,2) | pod prahem |
| T1498.002 | impact | ddos_ntp_amplification | security | 98 | connection_timeout_burst (92), unexpected_traffic (86) | 98,0 (92,9 až 99,4) | splněno |
| T1499.002 | impact | http_slow_connections_dos | security | 54 | inductive_volume_anomaly (27), unexpected_traffic (17) | 68,5 (55,3 až 79,3) | pod prahem |
| T1499.003 | impact | app_layer_flood_api | security | 62 | connection_timeout_burst (54), inductive_volume_anomaly (45) | 93,5 (84,6 až 97,5) | pod prahem |
| T1528 | credential-access | oauth_token_abuse_periodic | security | 71 | beacon_periodic (65), novel_persistent_peer (41) | 91,5 (82,8 až 96,1) | pod prahem |
| T1530 | collection | bucket_mass_download | security | 72 | pivot_chain (2), packet_rate_spike (1) | 11,1 (5,7 až 20,4) | pod prahem |
| T1550.002 | lateral-movement | ntlm_relay_style_fanout | security | 75 | multi_target_pattern (40), unexpected_traffic (37) | 84,0 (74,1 až 90,6) | pod prahem |
| T1558.003 | credential-access | kerberos_ticket_request_burst | security | 73 | unexpected_traffic (69), novel_fanout (19) | 98,6 (92,6 až 99,8) | splněno |
| T1566.002 | initial-access | clicks_to_rare_destination | security | 83 | unexpected_traffic (5), novel_persistent_peer (1) | 10,8 (5,8 až 19,3) | pod prahem |
| T1567.002 | exfiltration | exfil_cloud_storage_upload | security | 62 | novel_persistent_peer (16), slow_egress (9) | 40,3 (29,0 až 52,7) | pod prahem |
| T1567.002 | exfiltration | insider_after_hours_cloud_sync | security | 70 | egress_volume_anomaly (29), novel_persistent_peer (6) | 48,6 (37,2 až 60,0) | pod prahem |
| T1571 | command-and-control | c2_alt_port_8443 | security | 58 | beacon_periodic (53), novel_persistent_peer (30) | 93,1 (83,6 až 97,3) | pod prahem |
| T1572 | command-and-control | c2_doh_resolver | security | 89 | beacon_periodic (77), novel_persistent_peer (44) | 91,0 (83,3 až 95,4) | pod prahem |
| T1580 | discovery | cloud_api_discovery_burst | security | 65 | pivot_chain (4), novel_fanout (3) | 10,8 (5,3 až 20,6) | pod prahem |
| T1590.002 | reconnaissance | dns_zone_enum_burst | security | 71 | unexpected_traffic (5), inductive_volume_anomaly (3) | 12,7 (6,8 až 22,4) | pod prahem |
| T1595.001 | reconnaissance | distributed_low_port_probe | security | 76 | scan_attempts (63), unexpected_traffic (9) | 88,2 (79,0 až 93,6) | pod prahem |
| T1595.002 | reconnaissance | api_enum_distributed | security | 60 | connection_timeout_burst (48), inductive_volume_anomaly (29) | 83,3 (72,0 až 90,7) | pod prahem |
| T1595.003 | reconnaissance | web_scanner_404_storm | security | 58 | suricata_alert (35), source_volume_outlier (34) | 93,1 (83,6 až 97,3) | pod prahem |
| T1602.001 | collection | snmp_walk_internal | security | 72 | unexpected_traffic (70), pivot_chain (18) | 98,6 (92,5 až 99,8) | splněno |
| - | lateral-movement | apt_chain | security | 131 | scan_attempts (119), novel_persistent_peer (103) | 99,2 (95,8 až 99,9) | splněno |
| - | command-and-control | c2_beacon | security | 596 | endpoint_alert (334), beacon_periodic (263) | 83,9 (80,7 až 86,6) | pod prahem |
| - | credential-access | credential_stuffing | security | 347 | inductive_volume_anomaly (267), suricata_alert (167) | 91,6 (88,3 až 94,1) | splněno |
| - | impact | cryptomining | security | 259 | endpoint_alert (165), beacon_periodic (114) | 88,8 (84,4 až 92,1) | pod prahem |
| - | impact | ddos_volume | security | 167 | connection_timeout_burst (151), inductive_volume_anomaly (126) | 94,0 (89,3 až 96,7) | splněno |
| - | command-and-control | dns_tunnel | security | 277 | source_volume_outlier (144), endpoint_alert (136) | 96,8 (93,9 až 98,3) | detekce ano, typ ne |
| - | exfiltration | exfiltration | security | 408 | egress_volume_anomaly (372), unexpected_traffic (49) | 93,4 (90,5 až 95,4) | splněno |
| - | initial-access | exploit_attempt | security | 635 | endpoint_alert (431), suricata_alert (310) | 88,3 (85,6 až 90,6) | pod prahem |
| - | command-and-control | fleet_beacon | security | 79 | endpoint_alert (55), pivot_chain (55) | 93,7 (86,0 až 97,3) | detekce ano, typ ne |
| - | impact | ics_attack | security | 5 | novel_fanout (2), pivot_chain (2) | 60,0 (23,1 až 88,2) | nedostatek dat |
| - | exfiltration | insider_hoarding | security | 116 | inductive_volume_anomaly (88), packet_rate_spike (88) | 95,7 (90,3 až 98,1) | splněno |
| - | lateral-movement | lateral_movement | security | 575 | endpoint_alert (440), pivot_chain (304) | 98,4 (97,1 až 99,2) | detekce ano, typ ne |
| - | discovery | port_scan_horizontal | security | 450 | scan_attempts (258), connection_timeout_burst (154) | 86,2 (82,7 až 89,1) | pod prahem |
| - | discovery | port_scan_vertical | security | 561 | scan_attempts (481), suricata_alert (173) | 90,7 (88,0 až 92,9) | splněno |
| - | impact | ransomware | security | 193 | inductive_volume_anomaly (170), packet_rate_spike (167) | 99,5 (97,1 až 99,9) | splněno |
| - | initial-access | rogue_device | security | 130 | scan_attempts (108), unmapped_passive_event (66) | 92,3 (86,4 až 95,8) | splněno |
| - | discovery | slow_scan | security | 446 | scan_attempts (276), connection_timeout_burst (214) | 93,3 (90,6 až 95,2) | splněno |
| - | credential-access | ssh_bruteforce | security | 730 | inductive_volume_anomaly (524), unexpected_traffic (402) | 93,4 (91,4 až 95,0) | detekce ano, typ ne |
| - | initial-access | web_exploit | security | 439 | endpoint_alert (289), inductive_volume_anomaly (270) | 94,5 (92,0 až 96,3) | detekce ano, typ ne |
