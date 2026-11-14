# Společné příčiny chyb (14455 útoků a poruch, 3673 záznamů chyb)

Základní podíl chyb: 25,4 %. Lift = podíl chyb u hodnoty rysu / základní podíl.

| rys | hodnota | n | chyb | podíl % (Wilson) | lift |
|---|---|---:|---:|---|---:|
| tempo | trickle | 389 | 192 | 49,4 (44,4 až 54,3) | 1.94 |
| proto | icmp | 161 | 77 | 47,8 (40,3 až 55,5) | 1.88 |
| port_class | none | 161 | 77 | 47,8 (40,3 až 55,5) | 1.88 |
| tactic | initial-access | 1552 | 711 | 45,8 (43,3 až 48,3) | 1.80 |
| port_class | dns | 795 | 359 | 45,2 (41,7 až 48,6) | 1.78 |
| proto | udp | 1408 | 586 | 41,6 (39,1 až 44,2) | 1.64 |
| tactic | collection | 292 | 121 | 41,4 (35,9 až 47,2) | 1.63 |
| volume | medium | 726 | 274 | 37,7 (34,3 až 41,3) | 1.49 |
| tactic | reconnaissance | 265 | 100 | 37,7 (32,1 až 43,7) | 1.49 |
| volume | large | 640 | 211 | 33,0 (29,4 až 36,7) | 1.30 |
| tactic | exfiltration | 1102 | 362 | 32,8 (30,1 až 35,7) | 1.29 |
| port_class | web | 5477 | 1747 | 31,9 (30,7 až 33,1) | 1.26 |
| ids | no_ids | 12243 | 3480 | 28,4 (27,6 až 29,2) | 1.12 |
| topology | one_to_one | 10173 | 2866 | 28,2 (27,3 až 29,1) | 1.11 |
| tempo | sustained | 1143 | 319 | 27,9 (25,4 až 30,6) | 1.10 |
| sources | 1 | 12357 | 3310 | 26,8 (26,0 až 27,6) | 1.05 |
| volume | tiny | 6530 | 1706 | 26,1 (25,1 až 27,2) | 1.03 |
| tempo | burst | 5846 | 1518 | 26,0 (24,9 až 27,1) | 1.02 |
| tactic | command-and-control | 2199 | 571 | 26,0 (24,2 až 27,8) | 1.02 |
| tactic | none | 2363 | 587 | 24,8 (23,1 až 26,6) | 0.98 |
| tempo | periodic_fast | 1688 | 417 | 24,7 (22,7 až 26,8) | 0.97 |
| volume | small | 6035 | 1436 | 23,8 (22,7 až 24,9) | 0.94 |
| tempo | instant | 5098 | 1196 | 23,5 (22,3 až 24,6) | 0.92 |
| proto | tcp | 12886 | 3010 | 23,4 (22,6 až 24,1) | 0.92 |
| port_class | other | 1709 | 377 | 22,1 (20,2 až 24,1) | 0.87 |

## Shluky podle kombinace rysů (n ≥ 10)

| taktika | tempo | objem | topologie | zdroje | třída portu | IDS | n | chyb | podíl % |
|---|---|---|---|---|---|---|---:|---:|---|
| initial-access | sustained | medium | one_to_one | 1 | web | no_ids | 61 | 60 | 98,4 |
| collection | burst | large | one_to_one | 1 | web | no_ids | 72 | 70 | 97,2 |
| discovery | burst | small | one_to_one | 1 | web | no_ids | 65 | 63 | 96,9 |
| initial-access | burst | small | one_to_one | 1 | web | no_ids | 156 | 149 | 95,5 |
| reconnaissance | burst | tiny | one_to_one | 1 | dns | no_ids | 71 | 65 | 91,5 |
| none | sustained | large | one_to_one | 1 | web | no_ids | 78 | 70 | 89,7 |
| exfiltration | trickle | tiny | one_to_one | 1 | none | no_ids | 79 | 70 | 88,6 |
| command-and-control | burst | small | one_to_one | 1 | web | no_ids | 76 | 67 | 88,2 |
| exfiltration | burst | medium | one_to_one | 1 | file_share | no_ids | 66 | 56 | 84,8 |
| none | burst | small | one_to_one | 1 | high | no_ids | 69 | 54 | 78,3 |
| none | burst | small | one_to_one | 1 | other | no_ids | 177 | 137 | 77,4 |
| initial-access | instant | tiny | one_to_one | 1 | web | no_ids | 518 | 399 | 77,0 |
| credential-access | instant | tiny | many_to_one | many | web | no_ids | 63 | 47 | 74,6 |
| command-and-control | periodic_fast | tiny | one_to_one | 1 | dns | no_ids | 77 | 54 | 70,1 |
| exfiltration | burst | medium | one_to_one | 1 | web | no_ids | 132 | 87 | 65,9 |
| initial-access | trickle | tiny | one_to_one | 1 | web | ids | 36 | 20 | 55,6 |
| reconnaissance | burst | small | one_to_one | 1 | web | no_ids | 22 | 12 | 54,5 |
| initial-access | trickle | tiny | one_to_one | 1 | web | no_ids | 28 | 15 | 53,6 |
| none | instant | tiny | one_to_one | 1 | dns | no_ids | 92 | 47 | 51,1 |
| impact | sustained | tiny | many_to_one | few | web | no_ids | 54 | 27 | 50,0 |
| exfiltration | trickle | tiny | one_to_one | 1 | dns | no_ids | 92 | 44 | 47,8 |
| impact | burst | small | many_to_one | many | dns | no_ids | 78 | 34 | 43,6 |
| discovery | instant | tiny | one_to_many | 1 | other | no_ids | 37 | 16 | 43,2 |
| exfiltration | burst | large | one_to_one | 1 | web | no_ids | 70 | 30 | 42,9 |
| credential-access | instant | small | one_to_one | 1 | remote_admin | no_ids | 86 | 36 | 41,9 |
