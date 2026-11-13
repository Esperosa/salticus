# Společné příčiny chyb (8692 útoků a poruch, 2189 záznamů chyb)

Základní podíl chyb: 25,2 %. Lift = podíl chyb u hodnoty rysu / základní podíl.

| rys | hodnota | n | chyb | podíl % (Wilson) | lift |
|---|---|---:|---:|---|---:|
| proto | icmp | 107 | 54 | 50,5 (41,1 až 59,8) | 2.00 |
| port_class | none | 107 | 54 | 50,5 (41,1 až 59,8) | 2.00 |
| tempo | trickle | 240 | 120 | 50,0 (43,7 až 56,3) | 1.99 |
| tactic | initial-access | 929 | 433 | 46,6 (43,4 až 49,8) | 1.85 |
| port_class | dns | 506 | 224 | 44,3 (40,0 až 48,6) | 1.76 |
| tactic | collection | 165 | 70 | 42,4 (35,1 až 50,1) | 1.68 |
| proto | udp | 832 | 333 | 40,0 (36,7 až 43,4) | 1.59 |
| tactic | reconnaissance | 169 | 63 | 37,3 (30,3 až 44,8) | 1.48 |
| volume | medium | 439 | 158 | 36,0 (31,6 až 40,6) | 1.43 |
| volume | large | 408 | 134 | 32,8 (28,5 až 37,5) | 1.30 |
| tactic | exfiltration | 667 | 218 | 32,7 (29,2 až 36,3) | 1.30 |
| port_class | web | 3306 | 1045 | 31,6 (30,0 až 33,2) | 1.26 |
| ids | no_ids | 7402 | 2075 | 28,0 (27,0 až 29,1) | 1.11 |
| topology | one_to_one | 6142 | 1720 | 28,0 (26,9 až 29,1) | 1.11 |
| tempo | sustained | 694 | 188 | 27,1 (23,9 až 30,5) | 1.08 |
| sources | 1 | 7407 | 1975 | 26,7 (25,7 až 27,7) | 1.06 |
| volume | tiny | 3925 | 1024 | 26,1 (24,7 až 27,5) | 1.04 |
| tactic | command-and-control | 1362 | 353 | 25,9 (23,7 až 28,3) | 1.03 |
| tempo | burst | 3468 | 879 | 25,3 (23,9 až 26,8) | 1.01 |
| tempo | periodic_fast | 1038 | 260 | 25,0 (22,5 až 27,8) | 0.99 |
| tactic | none | 1412 | 334 | 23,7 (21,5 až 25,9) | 0.94 |
| tempo | instant | 3074 | 726 | 23,6 (22,1 až 25,2) | 0.94 |
| volume | small | 3623 | 849 | 23,4 (22,1 až 24,8) | 0.93 |
| proto | tcp | 7753 | 1802 | 23,2 (22,3 až 24,2) | 0.92 |
| port_class | other | 976 | 201 | 20,6 (18,2 až 23,2) | 0.82 |

## Shluky podle kombinace rysů (n ≥ 10)

| taktika | tempo | objem | topologie | zdroje | třída portu | IDS | n | chyb | podíl % |
|---|---|---|---|---|---|---|---:|---:|---|
| reconnaissance | burst | tiny | one_to_one | 1 | dns | no_ids | 36 | 35 | 97,2 |
| initial-access | burst | small | one_to_one | 1 | web | no_ids | 98 | 94 | 95,9 |
| collection | burst | large | one_to_one | 1 | web | no_ids | 43 | 41 | 95,3 |
| discovery | burst | small | one_to_one | 1 | web | no_ids | 41 | 39 | 95,1 |
| initial-access | sustained | medium | one_to_one | 1 | web | no_ids | 40 | 38 | 95,0 |
| none | sustained | large | one_to_one | 1 | web | no_ids | 48 | 44 | 91,7 |
| exfiltration | trickle | tiny | one_to_one | 1 | none | no_ids | 54 | 49 | 90,7 |
| command-and-control | burst | small | one_to_one | 1 | web | no_ids | 40 | 34 | 85,0 |
| exfiltration | burst | medium | one_to_one | 1 | file_share | no_ids | 36 | 29 | 80,6 |
| command-and-control | periodic_fast | tiny | one_to_one | 1 | dns | no_ids | 49 | 38 | 77,6 |
| initial-access | instant | tiny | one_to_one | 1 | web | no_ids | 320 | 246 | 76,9 |
| none | burst | small | one_to_one | 1 | other | no_ids | 86 | 64 | 74,4 |
| credential-access | instant | tiny | many_to_one | many | web | no_ids | 31 | 23 | 74,2 |
| none | burst | small | one_to_one | 1 | high | no_ids | 41 | 30 | 73,2 |
| exfiltration | burst | medium | one_to_one | 1 | web | no_ids | 82 | 54 | 65,9 |
| initial-access | trickle | tiny | one_to_one | 1 | web | ids | 16 | 10 | 62,5 |
| reconnaissance | burst | small | one_to_one | 1 | web | no_ids | 16 | 9 | 56,2 |
| none | instant | tiny | one_to_one | 1 | dns | no_ids | 65 | 36 | 55,4 |
| initial-access | trickle | tiny | one_to_one | 1 | web | no_ids | 15 | 7 | 46,7 |
| credential-access | instant | small | one_to_one | 1 | remote_admin | no_ids | 58 | 27 | 46,6 |
| exfiltration | trickle | tiny | one_to_one | 1 | dns | no_ids | 63 | 27 | 42,9 |
| impact | sustained | tiny | many_to_one | few | web | no_ids | 29 | 12 | 41,4 |
| discovery | instant | tiny | one_to_many | 1 | iot_messaging | no_ids | 48 | 19 | 39,6 |
| none | instant | small | one_to_one | 1 | dns | no_ids | 71 | 28 | 39,4 |
| exfiltration | burst | large | one_to_one | 1 | web | no_ids | 49 | 19 | 38,8 |
