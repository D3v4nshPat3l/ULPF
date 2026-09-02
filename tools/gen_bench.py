#!/usr/bin/env python3
"""Generate a synthetic perimeter-device corpus for benchmarking.

The mix matches what a mid-size enterprise perimeter actually emits: mostly
firewall session logs, a substantial minority of NGFW positional CSV, and a
tail of CEF from assorted appliances.

Line shapes follow the vendor documentation the packs were written against, so
a coverage number measured here means something. It is still synthetic: real
device logs are messier, and coverage on them will be lower.

    python tools/gen_bench.py 200000 > testdata/bench.log
"""

import random
import sys

PORTS = [80, 443, 53, 22]
ACTIONS = ["accept", "deny", "close"]


def fortigate(i: int) -> str:
    """FortiOS traffic log: key=value body, no 3164 timestamp or hostname."""
    return (
        f'<134>date=2026-08-31 time=10:23:45 devname="FGT-DEL-{i % 4:02}" '
        f'devid="FG100F123456789{i % 4}" type="traffic" subtype="forward" '
        f'level="notice" eventtime={1756636800 + i % 86400} '
        f'srcip=10.2.{i % 256}.{(i // 256) % 256} srcport={40000 + i % 20000} '
        f'srcintf="port1" dstip=8.8.{i % 256}.8 '
        f'dstport={random.choice(PORTS)} dstintf="wan1" proto=6 '
        f'action="{random.choice(ACTIONS)}" policyid={i % 64} sessionid={i} '
        f'duration={i % 300} sentbyte={i % 9000} rcvdbyte={i % 7000}'
    )


def panos(i: int) -> str:
    """PAN-OS traffic log: positional CSV behind a 3164 syslog header."""
    return (
        f'<14>Aug 31 10:23:46 PA-3220 1,2026/08/31 10:23:46,'
        f'00180123456{i % 8},TRAFFIC,end,2049,2026/08/31 10:23:45,'
        f'10.2.{i % 256}.9,1.1.1.1,203.0.113.9,1.1.1.1,allow-dns,,,dns,'
        f'vsys1,trust,untrust,ethernet1/1,ethernet1/2,log-forwarding,,'
        f'{i},1,{40000 + i % 20000},53,41235,53,0x400053,udp,allow,'
        f'{i % 9000},64,448,4,2026/08/31 10:23:40,0,dns'
    )


def cef(i: int) -> str:
    """CEF, with a msg value containing spaces to exercise extension parsing."""
    return (
        f'CEF:0|CheckPoint|VPN-1|R81|100|Connection allowed|3|'
        f'msg=connection allowed by policy src=192.0.2.{i % 256} '
        f'dst=198.51.100.5 spt={40000 + i % 20000} dpt=80 act=allow '
        f'rt=1756636800000'
    )


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    random.seed(7)  # reproducible: the same corpus on every run
    write = sys.stdout.write
    for i in range(n):
        bucket = i % 10
        if bucket < 6:
            write(fortigate(i) + "\n")
        elif bucket < 9:
            write(panos(i) + "\n")
        else:
            write(cef(i) + "\n")


if __name__ == "__main__":
    main()
