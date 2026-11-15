#!/usr/bin/env python3
"""Krok 14 (C2): doplní do data/incident-catalog.json pole `ops_signals` (klíč signálu, váha 1 až 3).

Váha: 3 = specifický signál typu, 2 = typický, 1 = slabý nebo sdílený. Klíče jsou slovník
`src/ops_telemetry/mod.rs` (`KEYS`). Tabulka je odvozená z popisů signálů v katalogu (pole
`signals`) a z RFC/MIB názvů veličin; nezávislé ověření proti primárním zdrojům je v
docs/diplomka/studie/14-provozni-telemetrie.md. Spuštění: python -I tools/k14_catalog_signals.py
"""
import json, sys

T = {
 "OPS-001": "if_oper_down3 snmp_timeout3 sys_link_down2 power_fail2 arp_absent2 dhcp_discover_absent1 dns_queries_absent1",
 "OPS-002": "if_flap3 route_adj_change3 sys_link_down2",
 "OPS-003": "dhcp_pool_high3 dhcp_no_free3",
 "OPS-004": "dhcp_service_down3 dhcp_no_offer3",
 "OPS-005": "dns_servfail3 probe_dns_fail2 dns_latency1",
 "OPS-006": "dns_latency3 cpu_high2",
 "OPS-007": "ntp_unreach3",
 "OPS-008": "ntp_offset3 sys_krb_skew2",
 "OPS-009": "probe_tls_expired3 sys_cert_expired3",
 "OPS-010": "probe_tls_chain3 sys_cert_chain2",
 "OPS-011": "if_util_high3 if_out_discards3 qos_drop1",
 "OPS-012": "backup_running_long3 if_util_high1",
 "OPS-013": "bcast_pps3 stp_tc2 mac_flap3 cpu_high2",
 "OPS-014": "mcast_pps3 bcast_pps1",
 "OPS-015": "sys_dup_addr3 arp_conflict3",
 "OPS-016": "sys_proc_crash3 probe_http_fail2 sys_health_fail2",
 "OPS-017": "io_wait_high3 sys_slow_query3 cpu_high2 conn_count_high2",
 "OPS-018": "lb_backend_down3 sys_health_fail2 probe_http_fail1",
 "OPS-019": "sys_service_restart3 sys_proc_crash2",
 "OPS-020": "if_in_errors3 if_crc3",
 "OPS-021": "disk_high3 sys_disk_full3 sys_backup_fail3",
 "OPS-022": "mem_high3 sys_oom3",
 "OPS-023": "vpn_tunnel_down3 sys_ike_fail3",
 "OPS-024": "sys_ap_lost_ctrl3",
 "OPS-025": "sys_mail_deferred3",
 "OPS-026": "uptime_reset1 sys_firmware_poll2",
 "OPS-027": "snmp_poll_load3 snmp_timeout1",
 "CHG-001": "conn_count_high1 if_util_high1 probe_http_ok2",
 "CHG-002": "sys_change_ticket3 uptime_reset2",
 "CHG-003": "sys_update_installed3 uptime_reset2 sys_pending_reboot1",
 "CHG-004": "sys_backup_job3",
 "CHG-005": "sys_update_job3",
 "CHG-006": "snmp_poll_load3 sys_scanner_job1",
 "CHG-007": "sys_dir_sync3",
 "CHG-008": "sys_sshd_key_accept3",
 "CHG-009": "sys_repl_stream3 repl_lag1",
 "CHG-010": "sys_mail_queue_bulk3",
 "CHG-011": "sys_scanner_job3",
 "OPS-028": "dns_queries_wrong_server3",
 "OPS-029": "dns_stale_record3",
 "OPS-030": "dns_split_horizon3",
 "OPS-031": "dns_nxdomain3",
 "OPS-032": "dns_ttl_anom3",
 "OPS-033": "sys_native_vlan_mismatch3",
 "OPS-034": "sys_native_vlan_mismatch2 vlan_double_tag2",
 "OPS-035": "sys_icmp_frag_blocked3",
 "OPS-036": "sys_dhcp_snoop_viol3 dhcp_rogue_offer3",
 "OPS-037": "dhcp_bad_lease3",
 "OPS-038": "dhcp_relay_missing3 dhcp_discover_absent1",
 "CHG-012": "cert_new_issuer3 sys_change_ticket1",
 "OPS-040": "sys_route_null03",
 "OPS-041": "sys_oos_drop3",
 "OPS-042": "route_default_changed3",
 "OPS-043": "conntrack_high3 sys_conntrack_full3",
 "OPS-044": "if_late_collision3 if_duplex_mismatch3 if_in_errors2",
 "OPS-045": "if_crc3 if_in_errors2",
 "OPS-046": "qos_drop3",
 "CHG-013": "arp_new_mac3 sys_change_ticket1",
 "OPS-048": "sys_port_sec_viol3 arp_new_mac2",
 "OPS-049": "uptime_reset3 sys_boot3",
 "OPS-050": "sys_update_failed3",
 "CHG-014": "sys_pending_reboot3",
 "OPS-052": "repl_lag3",
 "OPS-053": "sys_license_expired3",
 "OPS-054": "sys_health_fail3 probe_http_fail2",
 "OPS-055": "vpn_tunnel_flap3 sys_ike_fail2",
 "OPS-056": "sys_waf_block3",
 "OPS-057": "probe_cloud_status3 probe_http_fail2",
 "CHG-015": "sys_change_ticket3",
 "OPS-059": "if_util_high2 conn_count_high2 probe_http_ok1",
 "OPS-060": "sys_http_5xx3",
 "OPS-061": "sys_icmp_deny3 probe_icmp_fail2",
 "OPS-062": "stp_tc3 mac_flap2",
 "OPS-063": "sys_krb_dc_error3 sys_krb_skew1",
 "OPS-064": "sys_fd_limit3 conn_count_high2",
}

def main():
    p = "data/incident-catalog.json"
    c = json.load(open(p, encoding="utf-8"))
    ids = {e["id"] for e in c["incidents"]}
    assert ids == set(T), (ids ^ set(T))
    for e in c["incidents"]:
        sig = []
        for tok in T[e["id"]].split():
            key, w = tok[:-1], int(tok[-1])
            sig.append([key, w])
        e["ops_signals"] = sig
    c["catalog_version"] = "1.1.0"
    json.dump(c, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("ok", len(c["incidents"]), len({k for e in c["incidents"] for k, _ in e["ops_signals"]}), "klíčů")

main()
