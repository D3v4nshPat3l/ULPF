#!/usr/bin/env python3
"""
Synthetic log generator for ULPF testing and benchmarking.

Generates realistic multi-vendor log traffic at configurable rates.
Supports all 11 installed source packs and outputs to stdout, file, or
direct HTTP POST to the ULPF server.

Usage:
    python generate_traffic.py --rate 100 --duration 60 --output stdout
    python generate_traffic.py --rate 500 --duration 300 --output file --file test.log
    python generate_traffic.py --rate 50 --duration 0 --output http --url http://127.0.0.1:8787
"""

import argparse
import json
import random
import sys
import time
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Sample data pools
# ---------------------------------------------------------------------------
INTERNAL_IPS = [
    "10.0.0.{}".format(i) for i in range(1, 51)
] + [
    "192.168.1.{}".format(i) for i in range(1, 51)
] + [
    "172.16.0.{}".format(i) for i in range(1, 21)
]

EXTERNAL_IPS = [
    "203.0.113.{}".format(i) for i in range(1, 101)
] + [
    "198.51.100.{}".format(i) for i in range(1, 51)
] + [
    "93.184.216.{}".format(i) for i in range(1, 20)
] + [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9",
]

HOSTNAMES = [
    "fw-dc-01", "fw-dc-02", "fw-branch-01", "fw-edge-01",
    "proxy-01", "proxy-02", "web-01", "web-02", "web-03",
    "ids-01", "ids-02", "srx-gw-01", "srx-gw-02",
    "FGT-DEL-01", "FGT-MUM-01", "PA-3220", "fwv-lon-01",
    "bridge", "bastion",
]

DOMAINS = [
    "example.com", "test.org", "internal.local", "cdn.example.net",
    "api.service.io", "storage.cloud.example.com", "mail.example.com",
]

SNORT_RULES = [
    (2003, 8, "MS-SQL Worm propagation attempt", "Misc Attack", 2),
    (483, 5, "ICMP PING CyberKit 2.2 Windows", "Misc activity", 3),
    (2001219, 19, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
    (2013926, 5, "ET POLICY DNS Query to .bit TLD", "Potentially Bad Traffic", 3),
    (1000001, 1, "NIDS: Possible SYN flood", "Denial of Service", 1),
]

MODSEC_RULES = [
    ("941100", "XSS Attack Detected via libinjection", "CRITICAL"),
    ("942100", "SQL Injection Attack Detected via libinjection", "CRITICAL"),
    ("949110", "Inbound Anomaly Score Exceeded", "CRITICAL"),
    ("932100", "Remote Command Execution: Unix Command Injection", "ERROR"),
    ("920350", "Missing Host Header", "WARNING"),
]

SURICATA_SIGS = [
    (2001219, 19, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
    (2013926, 5, "ET POLICY DNS Query to .bit TLD", "Potentially Bad Traffic", 3),
    (2100498, 7, "GPL ATTACK_RESPONSE id check returned root", "Potentially Bad Traffic", 1),
]


def rfc3164_ts():
    now = datetime.now(timezone.utc)
    return now.strftime("%b %d %H:%M:%S").replace("  ", " ")


def epoch_s():
    return str(int(time.time()))


def iso_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def src_ip():
    return random.choice(INTERNAL_IPS)


def dst_ip():
    return random.choice(EXTERNAL_IPS)


def ext_ip():
    return random.choice(EXTERNAL_IPS)


def hostname():
    return random.choice(HOSTNAMES)


def high_port():
    return random.randint(1024, 65535)


def service_port():
    return random.choice([22, 53, 80, 443, 3389, 8080, 8443, 3306, 5432, 6379])


# ---------------------------------------------------------------------------
# Generators — one per pack format
# ---------------------------------------------------------------------------

def gen_fortigate():
    action = random.choice(["accept", "deny", "close"])
    proto = random.choice([6, 17])
    s_ip, d_ip = src_ip(), dst_ip()
    s_port, d_port = high_port(), service_port()
    level = "notice" if action == "accept" else "warning"
    pri = 134 if action == "accept" else 131
    return (
        f'<{pri}>date={datetime.now(timezone.utc).strftime("%Y-%m-%d")} '
        f'time={datetime.now(timezone.utc).strftime("%H:%M:%S")} '
        f'devname="{random.choice(["FGT-DEL-01", "FGT-MUM-01"])}" '
        f'devid="FG100F{random.randint(1000000000, 9999999999)}" '
        f'logid="0000000013" type="traffic" subtype="forward" level="{level}" '
        f'vd="root" eventtime={epoch_s()} srcip={s_ip} srcport={s_port} '
        f'srcintf="port1" dstip={d_ip} dstport={d_port} dstintf="wan1" '
        f'proto={proto} action="{action}" policyid={random.randint(1, 100)} '
        f'sessionid={random.randint(10000, 99999)} duration={random.randint(1, 300)} '
        f'sentbyte={random.randint(100, 50000)} rcvdbyte={random.randint(100, 50000)}'
    )


def gen_panos():
    action = random.choice(["allow", "deny", "drop"])
    s_ip, d_ip = src_ip(), dst_ip()
    s_port, d_port = high_port(), service_port()
    proto = random.choice(["tcp", "udp"])
    app = random.choice(["dns", "ssl", "web-browsing", "ssh", "smtp"])
    now = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    serial = f"00180{random.randint(1000000, 9999999)}"
    sid = random.randint(10000, 99999)
    byt = random.randint(100, 50000)
    return (
        f'<14>{rfc3164_ts()} PA-3220 1,{now},{serial},TRAFFIC,end,2049,{now},'
        f'{s_ip},{d_ip},{s_ip},{d_ip},{action}-rule,,,{app},vsys1,trust,untrust,'
        f'ethernet1/1,ethernet1/2,log-forwarding,,{sid},1,{s_port},{d_port},'
        f'{s_port},{d_port},0x400053,{proto},{action},{byt},{byt // 2},{byt // 2},'
        f'4,{now},0,{app}'
    )


def gen_cisco_asa():
    is_build = random.choice([True, False])
    proto = random.choice(["TCP", "UDP"])
    direction = random.choice(["inbound", "outbound"])
    s_ip, d_ip = src_ip(), dst_ip()
    s_port, d_port = high_port(), service_port()
    session = random.randint(100000, 99999999)
    hn = random.choice(["fwv-lon-01", "fwv-nyc-01", "fwv-sin-01"])
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S").replace("  ", " ")

    if is_build:
        msg_id = "302013" if proto == "TCP" else "302015"
        return (
            f'<166>{ts} {hn} : %ASA-6-{msg_id}: Built {direction} {proto} '
            f'connection {session} for outside:{s_ip}/{s_port} '
            f'to inside:{d_ip}/{d_port}'
        )
    else:
        msg_id = "302014" if proto == "TCP" else "302016"
        dur = f"0:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
        byt = random.randint(100, 50000)
        return (
            f'<166>{ts} {hn} : %ASA-6-{msg_id}: Teardown {proto} '
            f'connection {session} for outside:{s_ip}/{s_port} '
            f'to inside:{d_ip}/{d_port} duration {dur} bytes {byt}'
        )


def gen_iptables():
    verdict = random.choice([
        "INBOUND TCP", "INBOUND UDP", "INBOUND ICMP",
        "OUTG CONN TCP", "OUTG CONN UDP", "INBLOCK",
    ])
    s_ip, d_ip = ext_ip(), src_ip()
    proto = random.choice(["TCP", "UDP", "ICMP"])
    ttl = random.randint(32, 128)
    pkt_id = random.randint(1, 65535)
    line = (
        f'{rfc3164_ts()} bridge kernel: {verdict}: IN=br0 PHYSIN=eth0 OUT=br0 '
        f'PHYSOUT=eth1 SRC={s_ip} DST={d_ip} LEN={random.randint(40, 1500)} '
        f'TOS=0x00 PREC=0x00 TTL={ttl} ID={pkt_id} PROTO={proto}'
    )
    if proto in ("TCP", "UDP"):
        line += f' SPT={high_port()} DPT={service_port()}'
    if proto == "TCP":
        line += f' WINDOW={random.randint(1024, 65535)} RES=0x00 SYN URGP=0'
    return line


def gen_cef():
    vendors = [
        ("Security", "threatmanager", "1.0"),
        ("Zscaler", "NSS", "6.1"),
        ("TrendMicro", "DeepSecurity", "20.0"),
    ]
    vendor, product, version = random.choice(vendors)
    action = random.choice(["allow", "block", "permit", "deny"])
    sev = random.randint(1, 10)
    s_ip, d_ip = src_ip(), dst_ip()
    return (
        f'CEF:0|{vendor}|{product}|{version}|100|Network Event|{sev}|'
        f'src={s_ip} dst={d_ip} spt={high_port()} dpt={service_port()} '
        f'act={action} rt={int(time.time() * 1000)} '
        f'proto={random.choice(["TCP", "UDP"])}'
    )


def gen_snort():
    sid, rev, name, classification, priority = random.choice(SNORT_RULES)
    proto = random.choice(["TCP", "UDP", "ICMP"])
    s_ip, d_ip = ext_ip(), src_ip()
    ports = ""
    if proto != "ICMP":
        ports = f":{high_port()} -> {d_ip}:{service_port()}"
    else:
        ports = f" -> {d_ip}"
    return (
        f'{rfc3164_ts()} bastion snort: [1:{sid}:{rev}] {name} '
        f'[Classification: {classification}] [Priority: {priority}]: '
        f'{{{proto}}} {s_ip}{ports}'
    )


def gen_squid():
    method = random.choice(["GET", "POST", "CONNECT", "HEAD", "PUT"])
    result = random.choice(["TCP_MISS", "TCP_HIT", "TCP_TUNNEL", "TCP_DENIED"])
    status = random.choice([200, 301, 302, 403, 404, 500])
    url = f"http://{random.choice(DOMAINS)}/{random.choice(['page', 'api/data', 'images/logo.png', 'index.html'])}"
    user = random.choice(["user1", "user2", "admin", "-"])
    peer = random.choice(EXTERNAL_IPS)
    return (
        f'{time.time():.3f}    {random.randint(10, 5000)} {src_ip()} '
        f'{result}/{status} {random.randint(100, 50000)} {method} {url} '
        f'{user} DIRECT/{peer} '
        f'{random.choice(["text/html", "application/json", "image/png", "-"])}'
    )


def gen_juniper_srx():
    action = random.choice(["CREATE", "CLOSE", "DENY"])
    s_ip, d_ip = src_ip(), dst_ip()
    proto = random.choice([6, 17])
    return (
        f'{rfc3164_ts()} srx-gw-01 RT_FLOW - RT_FLOW_SESSION_{action} '
        f'[junos@2636.1.1.1.2.129 source-address="{s_ip}" '
        f'source-port="{high_port()}" destination-address="{d_ip}" '
        f'destination-port="{service_port()}" protocol-id="{proto}"]'
    )


def gen_checkpoint():
    action = random.choice(["Accept", "Drop", "Reject"])
    sev = random.choice([3, 5, 7])
    s_ip, d_ip = src_ip(), dst_ip()
    return (
        f'CEF:0|Check Point|VPN-1|R81.20|{random.randint(100, 999)}|'
        f'Connection {action}ed|{sev}|src={s_ip} dst={d_ip} '
        f'spt={high_port()} dpt={service_port()} proto=TCP act={action} '
        f'rt={int(time.time() * 1000)} '
        f'out={random.randint(100, 5000)} in={random.randint(100, 10000)}'
    )


def gen_suricata():
    sid, rev, name, category, severity = random.choice(SURICATA_SIGS)
    s_ip, d_ip = ext_ip(), src_ip()
    proto = random.choice(["TCP", "UDP"])
    return json.dumps({
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "flow_id": random.randint(100000000, 999999999),
        "event_type": "alert",
        "src_ip": s_ip,
        "src_port": high_port(),
        "dest_ip": d_ip,
        "dest_port": service_port(),
        "proto": proto,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": sid,
            "rev": rev,
            "signature": name,
            "category": category,
            "severity": severity,
        },
    })


def gen_modsecurity():
    rule_id, msg, severity = random.choice(MODSEC_RULES)
    client = ext_ip()
    attack_types = [
        'Pattern match "<script" at REQUEST_URI',
        'Matched "Operator `Rx\'\' with parameter" at REQUEST_BODY',
        'Matched phrase "select" at ARGS:id',
    ]
    return (
        f'{rfc3164_ts()} web-01 ModSecurity: Access denied with code 403 (phase 2). '
        f'{random.choice(attack_types)}. '
        f'[file "/etc/modsecurity/crs/rules/REQUEST.conf"] [line "93"] '
        f'[id "{rule_id}"] [msg "{msg}"] '
        f'[severity "{severity}"] [client {client}]'
    )


def gen_unknown():
    """Generate an unknown format that no pack should match."""
    templates = [
        f'[{datetime.now(timezone.utc).isoformat()}] app=myservice level=info msg="request handled" latency={random.randint(1, 500)}ms',
        f'{datetime.now(timezone.utc).isoformat()} DEBUG myapp.worker - Processing batch {random.randint(1, 1000)} items={random.randint(10, 500)}',
        f'custom_log ts={int(time.time())} host={hostname()} metric=cpu_usage value={random.uniform(0.1, 99.9):.1f}',
    ]
    return random.choice(templates)


# Weight table: higher weight = more frequent
GENERATORS = [
    (gen_fortigate, 20),
    (gen_panos, 15),
    (gen_cisco_asa, 15),
    (gen_iptables, 12),
    (gen_cef, 8),
    (gen_snort, 5),
    (gen_squid, 8),
    (gen_juniper_srx, 5),
    (gen_checkpoint, 5),
    (gen_suricata, 3),
    (gen_modsecurity, 2),
    (gen_unknown, 2),
]


def weighted_choice():
    total = sum(w for _, w in GENERATORS)
    r = random.random() * total
    for gen, w in GENERATORS:
        r -= w
        if r <= 0:
            return gen
    return GENERATORS[0][0]


def main():
    parser = argparse.ArgumentParser(description="ULPF Synthetic Log Generator")
    parser.add_argument("--rate", type=float, default=10, help="Events per second (0 = max speed)")
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0 = infinite)")
    parser.add_argument("--output", choices=["stdout", "file", "http"], default="stdout")
    parser.add_argument("--file", type=str, default="synthetic.log", help="Output file path")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8787", help="ULPF server URL")
    parser.add_argument("--batch", type=int, default=50, help="Batch size for HTTP mode")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    start = time.time()
    count = 0
    batch = []

    out_file = None
    if args.output == "file":
        out_file = open(args.file, "w", encoding="utf-8")

    try:
        while True:
            if args.duration > 0 and (time.time() - start) >= args.duration:
                break

            gen = weighted_choice()
            line = gen()
            count += 1

            if args.output == "stdout":
                print(line, flush=(count % 100 == 0))
            elif args.output == "file":
                out_file.write(line + "\n")
                if count % 1000 == 0:
                    out_file.flush()
            elif args.output == "http":
                batch.append(line)
                if len(batch) >= args.batch:
                    payload = json.dumps({"lines": "\n".join(batch)}).encode()
                    req = urllib.request.Request(
                        f"{args.url}/api/ingest",
                        data=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    try:
                        urllib.request.urlopen(req, timeout=10)
                    except Exception as e:
                        print(f"[ERROR] POST failed: {e}", file=sys.stderr)
                    batch.clear()

            if args.rate > 0:
                expected = count / args.rate
                elapsed = time.time() - start
                if expected > elapsed:
                    time.sleep(expected - elapsed)

            if count % 1000 == 0:
                elapsed = time.time() - start
                eps = count / elapsed if elapsed > 0 else 0
                print(
                    f"[INFO] {count} events generated in {elapsed:.1f}s ({eps:.0f} EPS)",
                    file=sys.stderr,
                )

    except KeyboardInterrupt:
        pass
    finally:
        # Flush remaining HTTP batch
        if args.output == "http" and batch:
            payload = json.dumps({"lines": "\n".join(batch)}).encode()
            req = urllib.request.Request(
                f"{args.url}/api/ingest",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            try:
                urllib.request.urlopen(req, timeout=10)
            except Exception:
                pass

        if out_file:
            out_file.close()

        elapsed = time.time() - start
        eps = count / elapsed if elapsed > 0 else 0
        print(
            f"\n[DONE] {count} events in {elapsed:.1f}s ({eps:.0f} EPS)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
