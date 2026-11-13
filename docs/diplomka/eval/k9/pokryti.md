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
| - | none | planned_maintenance_window | benign_change | 64 | service_unreachable (57), connection_timeout_burst (10) | 96,9 (89,3 až 99,1) | splněno |
| - | none | planned_patch_reboot_wave | benign_change | 50 | service_unreachable (47), connection_timeout_burst (30) | 100,0 (92,9 až 100,0) | splněno |
| - | none | seasonal_peak_web | benign_change | 34 | inductive_volume_anomaly (28), packet_rate_spike (24) | 91,2 (77,0 až 97,0) | nedostatek dat |
| - | none | access_point_controller_failure | ops_fault | 39 | service_unreachable (33), connection_timeout_burst (5) | 94,9 (83,1 až 98,6) | nedostatek dat |
| - | none | app_server_crash_cascade | ops_fault | 45 | service_unreachable (41), scan_attempts (24) | 100,0 (92,1 až 100,0) | nedostatek dat |
| - | none | backup_window_overrun | ops_fault | 36 | packet_rate_spike (21), unexpected_traffic (20) | 91,7 (78,2 až 97,1) | nedostatek dat |
| - | none | broadcast_storm_loop | ops_fault | 43 | broadcast_storm (12), unexpected_traffic (3) | 37,2 (24,4 až 52,1) | nedostatek dat |
| - | none | cert_chain_misconfig_external | ops_fault | 58 | service_unreachable (52), connection_timeout_burst (18) | 93,1 (83,6 až 97,3) | pod prahem |
| - | none | cert_expired_internal_service | ops_fault | 40 | novel_fanout (3), unexpected_traffic (3) | 17,5 (8,7 až 31,9) | nedostatek dat |
| - | none | core_router_flapping | ops_fault | 50 | service_unreachable (43), connection_timeout_burst (25) | 98,0 (89,5 až 99,6) | splněno |
| - | none | db_overload_degradation | ops_fault | 32 | service_unreachable (32), unexpected_traffic (31) | 100,0 (89,3 až 100,0) | nedostatek dat |
| - | none | dhcp_pool_exhaustion | ops_fault | 43 | broadcast_storm (5), packet_rate_spike (3) | 20,9 (11,4 až 35,2) | nedostatek dat |
| - | none | dhcp_server_down | ops_fault | 57 | service_unreachable (53), connection_timeout_burst (5) | 98,2 (90,7 až 99,7) | splněno |
| - | none | disk_full_backup_failure | ops_fault | 27 | service_unreachable (20), unmapped_passive_event (3) | 92,6 (76,6 až 97,9) | nedostatek dat |
| - | none | dns_partial_failure | ops_fault | 71 | packet_rate_spike (30), service_unreachable (17) | 73,2 (61,9 až 82,1) | pod prahem |
| - | none | dns_slow_resolution | ops_fault | 65 | packet_rate_spike (19), service_unreachable (13) | 58,5 (46,3 až 69,6) | pod prahem |
| - | none | duplicate_ip_conflict | ops_fault | 54 | service_unreachable (42), connection_timeout_burst (18) | 94,4 (84,9 až 98,1) | pod prahem |
| - | none | flapping_service | ops_fault | 46 | service_unreachable (42), scan_attempts (10) | 100,0 (92,3 až 100,0) | nedostatek dat |
| - | none | iot_firmware_chatter_loop | ops_fault | 47 | beacon_periodic (42), novel_persistent_peer (30) | 91,5 (80,1 až 96,6) | nedostatek dat |
| - | none | load_balancer_partial_outage | ops_fault | 29 | service_unreachable (25), pivot_chain (13) | 96,6 (82,8 až 99,4) | nedostatek dat |
| - | none | mail_relay_queue_retry | ops_fault | 55 | service_unreachable (52), scan_attempts (13) | 100,0 (93,5 až 100,0) | splněno |
| - | none | mdns_ssdp_storm | ops_fault | 41 | broadcast_storm (11), beacon_periodic (1) | 29,3 (17,6 až 44,5) | nedostatek dat |
| - | none | memory_exhaustion_stall | ops_fault | 49 | service_unreachable (43), unexpected_traffic (40) | 98,0 (89,3 až 99,6) | nedostatek dat |
| - | none | monitoring_agent_misconfig_poll | ops_fault | 59 | scan_attempts (40), multi_target_pattern (29) | 84,7 (73,5 až 91,8) | pod prahem |
| - | none | ntp_clock_drift_host | ops_fault | 57 | unexpected_traffic (41), packet_rate_spike (24) | 91,2 (81,1 až 96,2) | pod prahem |
| - | none | ntp_unreachable | ops_fault | 50 | service_unreachable (11), connection_timeout_burst (7) | 52,0 (38,5 až 65,2) | pod prahem |
| - | none | slow_link_loss_degradation | ops_fault | 51 | service_unreachable (47), connection_timeout_burst (38) | 100,0 (93,0 až 100,0) | splněno |
| - | none | switch_outage_subnet | ops_fault | 41 | service_unreachable (37), connection_timeout_burst (18) | 95,1 (83,9 až 98,7) | nedostatek dat |
| - | none | uplink_saturation | ops_fault | 48 | unexpected_traffic (4), service_unreachable (4) | 18,8 (10,2 až 31,9) | nedostatek dat |
| - | none | vpn_concentrator_down | ops_fault | 31 | service_unreachable (24), scan_attempts (5) | 87,1 (71,1 až 94,9) | nedostatek dat |
| T0801 | collection | ics_slow_poll_new_source | security | 1 | connection_timeout_burst (1), novel_fanout (1) | 100,0 (20,7 až 100,0) | nedostatek dat |
| T0814 | impact | ics_dnp3_unsolicited_flood | security | 0 | - | - | nepokryto v běhu |
| T0836 | impact | ics_modbus_write_burst | security | 0 | - | - | nepokryto v běhu |
| T0843 | execution | ics_program_download_slow | security | 0 | - | - | nepokryto v běhu |
| T0846 | discovery | ics_bacnet_enumeration | security | 0 | - | - | nepokryto v běhu |
| T0846 | discovery | ics_ethernetip_scan | security | 0 | - | - | nepokryto v běhu |
| T0846 | discovery | ics_opcua_enumeration | security | 0 | - | - | nepokryto v běhu |
| T0858 | execution | ics_s7_operating_mode_change | security | 0 | - | - | nepokryto v běhu |
| T1003.006 | credential-access | dc_replication_from_workstation | security | 34 | unexpected_traffic (30), multi_target_pattern (12) | 100,0 (89,8 až 100,0) | nedostatek dat |
| T1021.001 | lateral-movement | lateral_rdp_hop | security | 59 | packet_rate_spike (31), multi_target_pattern (28) | 88,1 (77,5 až 94,1) | pod prahem |
| T1021.002 | lateral-movement | lateral_cautious_one_target | security | 63 | unexpected_traffic (55), inductive_volume_anomaly (45) | 98,4 (91,5 až 99,7) | splněno |
| T1021.002 | lateral-movement | lateral_smb_admin_shares | security | 46 | unexpected_traffic (41), suricata_alert (28) | 91,3 (79,7 až 96,6) | nedostatek dat |
| T1021.004 | lateral-movement | lateral_ssh_hop | security | 50 | unexpected_traffic (25), multi_target_pattern (20) | 88,0 (76,2 až 94,4) | pod prahem |
| T1021.005 | lateral-movement | vnc_probe_ext | security | 55 | scan_attempts (30), pivot_chain (9) | 67,3 (54,1 až 78,2) | pod prahem |
| T1021.006 | lateral-movement | lateral_winrm | security | 45 | unexpected_traffic (41), multi_target_pattern (18) | 97,8 (88,4 až 99,6) | nedostatek dat |
| T1029 | exfiltration | exfil_scheduled_chunks | security | 39 | beacon_periodic (34), slow_egress (31) | 92,3 (79,7 až 97,3) | nedostatek dat |
| T1039 | collection | data_staging_smb_internal | security | 39 | inductive_volume_anomaly (20), packet_rate_spike (17) | 84,6 (70,3 až 92,8) | nedostatek dat |
| T1041 | exfiltration | exfil_https_burst | security | 49 | egress_volume_anomaly (29), pivot_chain (2) | 65,3 (51,3 až 77,1) | nedostatek dat |
| T1041 | exfiltration | exfil_over_c2_trickle | security | 47 | slow_egress (28), novel_persistent_peer (22) | 78,7 (65,1 až 88,0) | nedostatek dat |
| T1046 | discovery | mqtt_probe_ext | security | 48 | scan_attempts (27), pivot_chain (8) | 70,8 (56,8 až 81,8) | nedostatek dat |
| T1046 | discovery | rdp_sweep_ext | security | 42 | scan_attempts (27), suricata_alert (16) | 85,7 (72,2 až 93,3) | nedostatek dat |
| T1046 | discovery | smb_sweep_ext | security | 35 | scan_attempts (25), novel_fanout (8) | 74,3 (57,9 až 85,8) | nedostatek dat |
| T1046 | discovery | snmp_sweep_ext | security | 47 | scan_attempts (28), suricata_alert (23) | 87,2 (74,8 až 94,0) | nedostatek dat |
| T1047 | execution | lateral_wmi_dcom | security | 43 | unexpected_traffic (38), multi_target_pattern (21) | 95,3 (84,5 až 98,7) | nedostatek dat |
| T1048 | exfiltration | exfil_icmp_payload | security | 54 | novel_persistent_peer (25), pivot_chain (5) | 51,9 (38,9 až 64,6) | pod prahem |
| T1048.003 | exfiltration | exfil_alt_protocol_ftp | security | 36 | unexpected_traffic (4), egress_volume_anomaly (2) | 19,4 (9,8 až 35,0) | nedostatek dat |
| T1048.003 | exfiltration | exfil_dns_slow | security | 63 | unexpected_traffic (21), packet_rate_spike (11) | 71,4 (59,3 až 81,1) | pod prahem |
| T1071 | command-and-control | c2_iot_mqtt_cloud | security | 46 | beacon_periodic (43), novel_persistent_peer (25) | 97,8 (88,7 až 99,6) | nedostatek dat |
| T1071 | command-and-control | c2_irc_style_channel | security | 61 | beacon_periodic (51), novel_persistent_peer (28) | 85,2 (74,3 až 92,0) | pod prahem |
| T1071.001 | command-and-control | c2_high_jitter | security | 47 | novel_persistent_peer (22), unexpected_traffic (10) | 68,1 (53,8 až 79,6) | nedostatek dat |
| T1071.001 | command-and-control | c2_slow_long_interval | security | 54 | beacon_periodic (44), novel_persistent_peer (31) | 90,7 (80,1 až 96,0) | pod prahem |
| T1071.001 | command-and-control | c2_websocket_long | security | 55 | long_lived_tunnel (45), beacon_periodic (38) | 89,1 (78,2 až 94,9) | pod prahem |
| T1071.004 | command-and-control | c2_dns_txt_beacon | security | 49 | unexpected_traffic (9), inductive_volume_anomaly (8) | 53,1 (39,4 až 66,3) | nedostatek dat |
| T1087.002 | discovery | ldap_directory_enum_bulk | security | 40 | unexpected_traffic (35), packet_rate_spike (9) | 97,5 (87,1 až 99,6) | nedostatek dat |
| T1090.001 | command-and-control | c2_internal_proxy_chain | security | 60 | unexpected_traffic (56), service_unreachable (20) | 98,3 (91,1 až 99,7) | splněno |
| T1090.003 | command-and-control | onion_style_circuit_egress | security | 48 | long_lived_tunnel (42), beacon_periodic (24) | 87,5 (75,3 až 94,1) | nedostatek dat |
| T1090.004 | command-and-control | c2_cdn_fronted | security | 43 | beacon_periodic (34), novel_persistent_peer (18) | 79,1 (64,8 až 88,6) | nedostatek dat |
| T1095 | command-and-control | c2_icmp_tunnel | security | 53 | beacon_periodic (46), novel_persistent_peer (27) | 90,6 (79,7 až 95,9) | pod prahem |
| T1095 | command-and-control | c2_ntp_port_misuse | security | 39 | beacon_periodic (37), novel_persistent_peer (26) | 97,4 (86,8 až 99,5) | nedostatek dat |
| T1095 | command-and-control | c2_udp_custom_port | security | 44 | beacon_periodic (38), novel_persistent_peer (23) | 86,4 (73,3 až 93,6) | nedostatek dat |
| T1102 | command-and-control | c2_https_legit_service | security | 52 | beacon_periodic (44), novel_persistent_peer (28) | 90,4 (79,4 až 95,8) | pod prahem |
| T1102.002 | command-and-control | c2_cloud_storage_dead_drop | security | 40 | novel_persistent_peer (20), beacon_periodic (5) | 65,0 (49,5 až 77,9) | nedostatek dat |
| T1110 | credential-access | smb_login_failures | security | 56 | unexpected_traffic (52), inductive_volume_anomaly (34) | 98,2 (90,6 až 99,7) | splněno |
| T1110.001 | credential-access | ftp_bruteforce | security | 50 | unexpected_traffic (44), inductive_volume_anomaly (4) | 90,0 (78,6 až 95,7) | pod prahem |
| T1110.001 | credential-access | mssql_login_failures | security | 44 | unexpected_traffic (39), scan_attempts (3) | 88,6 (76,0 až 95,0) | nedostatek dat |
| T1110.001 | credential-access | mysql_login_failures | security | 49 | unexpected_traffic (38), inductive_volume_anomaly (4) | 85,7 (73,3 až 92,9) | nedostatek dat |
| T1110.001 | credential-access | rdp_bruteforce | security | 42 | unexpected_traffic (40), suricata_alert (23) | 100,0 (91,6 až 100,0) | nedostatek dat |
| T1110.001 | credential-access | telnet_iot_login | security | 39 | unexpected_traffic (11), unmapped_passive_event (4) | 43,6 (29,3 až 59,0) | nedostatek dat |
| T1110.003 | credential-access | imap_spray | security | 47 | unexpected_traffic (43), inductive_volume_anomaly (7) | 95,7 (85,8 až 98,8) | nedostatek dat |
| T1110.003 | credential-access | ldap_bind_spray | security | 41 | unexpected_traffic (37), inductive_volume_anomaly (15) | 97,6 (87,4 až 99,6) | nedostatek dat |
| T1110.003 | credential-access | smtp_auth_spray | security | 37 | unexpected_traffic (33), connection_timeout_burst (3) | 89,2 (75,3 až 95,7) | nedostatek dat |
| T1110.003 | credential-access | ssh_spray_slow_distributed | security | 64 | unexpected_traffic (43), packet_rate_spike (14) | 81,2 (70,0 až 88,9) | pod prahem |
| T1110.003 | credential-access | vpn_password_spray_slow | security | 31 | novel_fanout (4), unexpected_traffic (4) | 41,9 (26,4 až 59,2) | nedostatek dat |
| T1114 | collection | mail_forward_smtp_exfil | security | 45 | slow_egress (29), novel_persistent_peer (24) | 71,1 (56,6 až 82,3) | nedostatek dat |
| T1135 | discovery | smb_share_enum_internal | security | 30 | scan_attempts (17), multi_target_pattern (12) | 76,7 (59,1 až 88,2) | nedostatek dat |
| T1189 | initial-access | drive_by_bulk_download | security | 50 | pivot_chain (2), beacon_periodic (1) | 8,0 (3,2 až 18,8) | pod prahem |
| T1190 | initial-access | public_app_probe_trickle | security | 31 | suricata_alert (16), unexpected_traffic (12) | 83,9 (67,4 až 92,9) | nedostatek dat |
| T1195.002 | initial-access | update_channel_compromise_fleet | security | 38 | beacon_periodic (34), unexpected_traffic (24) | 100,0 (90,8 až 100,0) | nedostatek dat |
| T1199 | initial-access | vendor_remote_access_odd_hours | security | 40 | packet_rate_spike (8), unmapped_passive_event (2) | 40,0 (26,3 až 55,4) | nedostatek dat |
| T1485 | impact | data_destruction_smb_wave | security | 35 | unexpected_traffic (19), multi_target_pattern (17) | 80,0 (64,1 až 90,0) | nedostatek dat |
| T1486 | impact | share_encryption_wave_slow | security | 36 | packet_rate_spike (27), unexpected_traffic (20) | 91,7 (78,2 až 97,1) | nedostatek dat |
| T1490 | impact | backup_service_probing | security | 31 | unexpected_traffic (21), novel_fanout (10) | 83,9 (67,4 až 92,9) | nedostatek dat |
| T1496 | impact | resource_hijack_pool_tls | security | 49 | long_lived_tunnel (45), beacon_periodic (44) | 95,9 (86,3 až 98,9) | nedostatek dat |
| T1498.001 | impact | ddos_syn_flood_distributed | security | 28 | connection_timeout_burst (24), inductive_volume_anomaly (23) | 85,7 (68,5 až 94,3) | nedostatek dat |
| T1498.002 | impact | ddos_dns_amplification | security | 47 | connection_timeout_burst (25), inductive_volume_anomaly (17) | 70,2 (56,0 až 81,3) | nedostatek dat |
| T1498.002 | impact | ddos_ntp_amplification | security | 61 | connection_timeout_burst (57), unexpected_traffic (54) | 98,4 (91,3 až 99,7) | splněno |
| T1499.002 | impact | http_slow_connections_dos | security | 29 | inductive_volume_anomaly (17), unexpected_traffic (7) | 69,0 (50,8 až 82,7) | nedostatek dat |
| T1499.003 | impact | app_layer_flood_api | security | 40 | connection_timeout_burst (33), inductive_volume_anomaly (28) | 90,0 (76,9 až 96,0) | nedostatek dat |
| T1528 | credential-access | oauth_token_abuse_periodic | security | 47 | beacon_periodic (42), novel_persistent_peer (31) | 89,4 (77,4 až 95,4) | nedostatek dat |
| T1530 | collection | bucket_mass_download | security | 43 | packet_rate_spike (1), unexpected_traffic (1) | 14,0 (6,6 až 27,3) | nedostatek dat |
| T1550.002 | lateral-movement | ntlm_relay_style_fanout | security | 42 | multi_target_pattern (22), unexpected_traffic (20) | 85,7 (72,2 až 93,3) | nedostatek dat |
| T1558.003 | credential-access | kerberos_ticket_request_burst | security | 39 | unexpected_traffic (38), novel_fanout (12) | 100,0 (91,0 až 100,0) | nedostatek dat |
| T1566.002 | initial-access | clicks_to_rare_destination | security | 48 | unexpected_traffic (3), novel_persistent_peer (1) | 12,5 (5,9 až 24,7) | nedostatek dat |
| T1567.002 | exfiltration | exfil_cloud_storage_upload | security | 39 | novel_persistent_peer (10), slow_egress (6) | 41,0 (27,1 až 56,6) | nedostatek dat |
| T1567.002 | exfiltration | insider_after_hours_cloud_sync | security | 43 | egress_volume_anomaly (19), novel_persistent_peer (3) | 51,2 (36,8 až 65,4) | nedostatek dat |
| T1571 | command-and-control | c2_alt_port_8443 | security | 39 | beacon_periodic (34), novel_persistent_peer (20) | 89,7 (76,4 až 95,9) | nedostatek dat |
| T1572 | command-and-control | c2_doh_resolver | security | 58 | beacon_periodic (48), novel_persistent_peer (29) | 87,9 (77,1 až 94,0) | pod prahem |
| T1580 | discovery | cloud_api_discovery_burst | security | 41 | novel_fanout (2), pivot_chain (2) | 9,8 (3,9 až 22,5) | nedostatek dat |
| T1590.002 | reconnaissance | dns_zone_enum_burst | security | 36 | scan_attempts (1), inductive_volume_anomaly (1) | 5,6 (1,5 až 18,1) | nedostatek dat |
| T1595.001 | reconnaissance | distributed_low_port_probe | security | 56 | scan_attempts (43), unexpected_traffic (6) | 83,9 (72,2 až 91,3) | pod prahem |
| T1595.002 | reconnaissance | api_enum_distributed | security | 37 | connection_timeout_burst (29), inductive_volume_anomaly (16) | 83,8 (68,9 až 92,3) | nedostatek dat |
| T1595.003 | reconnaissance | web_scanner_404_storm | security | 40 | suricata_alert (23), source_volume_outlier (23) | 92,5 (80,1 až 97,4) | nedostatek dat |
| T1602.001 | collection | snmp_walk_internal | security | 37 | unexpected_traffic (36), pivot_chain (8) | 100,0 (90,6 až 100,0) | nedostatek dat |
| - | lateral-movement | apt_chain | security | 70 | scan_attempts (64), pivot_chain (57) | 98,6 (92,3 až 99,7) | splněno |
| - | command-and-control | c2_beacon | security | 355 | endpoint_alert (202), beacon_periodic (157) | 84,5 (80,4 až 87,9) | pod prahem |
| - | credential-access | credential_stuffing | security | 204 | inductive_volume_anomaly (160), suricata_alert (98) | 92,2 (87,6 až 95,1) | splněno |
| - | impact | cryptomining | security | 144 | endpoint_alert (91), long_lived_tunnel (72) | 89,6 (83,5 až 93,6) | pod prahem |
| - | impact | ddos_volume | security | 110 | connection_timeout_burst (96), inductive_volume_anomaly (79) | 92,7 (86,3 až 96,3) | splněno |
| - | command-and-control | dns_tunnel | security | 175 | source_volume_outlier (89), endpoint_alert (78) | 96,6 (92,7 až 98,4) | detekce ano, typ ne |
| - | exfiltration | exfiltration | security | 237 | egress_volume_anomaly (219), unexpected_traffic (27) | 94,1 (90,3 až 96,4) | splněno |
| - | initial-access | exploit_attempt | security | 387 | endpoint_alert (270), suricata_alert (184) | 89,4 (85,9 až 92,1) | pod prahem |
| - | command-and-control | fleet_beacon | security | 44 | pivot_chain (36), unexpected_traffic (31) | 95,5 (84,9 až 98,7) | nedostatek dat |
| - | impact | ics_attack | security | 3 | novel_fanout (2), pivot_chain (2) | 66,7 (20,8 až 93,9) | nedostatek dat |
| - | exfiltration | insider_hoarding | security | 60 | inductive_volume_anomaly (51), packet_rate_spike (50) | 96,7 (88,6 až 99,1) | splněno |
| - | lateral-movement | lateral_movement | security | 347 | endpoint_alert (270), unexpected_traffic (181) | 98,3 (96,3 až 99,2) | detekce ano, typ ne |
| - | discovery | port_scan_horizontal | security | 273 | scan_attempts (155), connection_timeout_burst (102) | 85,3 (80,7 až 89,1) | pod prahem |
| - | discovery | port_scan_vertical | security | 331 | scan_attempts (278), suricata_alert (97) | 89,7 (86,0 až 92,6) | pod prahem |
| - | impact | ransomware | security | 122 | inductive_volume_anomaly (108), packet_rate_spike (108) | 99,2 (95,5 až 99,9) | splněno |
| - | initial-access | rogue_device | security | 73 | scan_attempts (60), unmapped_passive_event (37) | 91,8 (83,2 až 96,2) | pod prahem |
| - | discovery | slow_scan | security | 266 | scan_attempts (170), connection_timeout_burst (138) | 93,6 (90,0 až 96,0) | splněno |
| - | credential-access | ssh_bruteforce | security | 456 | inductive_volume_anomaly (330), unexpected_traffic (248) | 94,3 (91,8 až 96,1) | detekce ano, typ ne |
| - | initial-access | web_exploit | security | 262 | endpoint_alert (174), inductive_volume_anomaly (167) | 95,4 (92,2 až 97,4) | detekce ano, typ ne |
