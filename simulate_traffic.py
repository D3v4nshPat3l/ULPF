import time
import random
import urllib.request
import urllib.error

# Sample known logs that will parse successfully
KNOWN_LOGS = [
    # FortiGate
    'date=2024-03-15 time=10:30:01 devname="FG-100F" devid="FG100F12345678" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.10 srcport=54321 srcintf="port1" dstip=8.8.8.8 dstport=53 dstintf="port2" poluuid="a1b2c3d4-e5f6-7890" sessionid=123456 proto=17 action="accept" policyid=1',
    # Palo Alto PAN-OS
    '1,2024/03/15 10:30:01,001234567890,TRAFFIC,start,2304,2024/03/15 10:30:01,192.168.1.10,8.8.8.8,0.0.0.0,0.0.0.0,Rule1,,,udp,vsys1,trust,untrust,ethernet1/1,ethernet1/2,syslog,54321,53,0,0,0,0x400000,udp,allow,123456,64,64,128,1,2024/03/15 10:30:01,0,any,0,1234567890,0x0,10.0.0.0-10.255.255.255,US,0,1,0,0,0,0',
    # iptables
    'Mar 15 10:30:01 server1 kernel: [12345.67890] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=192.168.1.10 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0',
]

# Sample unknown logs that will NOT parse (will go to "Needs a pack" for the AI generator)
UNKNOWN_LOGS = [
    # Custom Application A
    '[INFO] [AppServer] User login successful - UserID: 1045, IP: 192.168.1.55, SessionDuration: 3600',
    '[WARN] [AppServer] Database connection timeout - Retry 3/5, DB_Host: db.internal.local',
    # Custom Web Server B
    '192.168.1.100 - - [15/Mar/2024:10:30:01 +0000] "GET /api/v1/users HTTP/1.1" 200 1024 "-" "MyAppClient/1.0"',
    '10.0.0.5 - - [15/Mar/2024:10:30:02 +0000] "POST /api/v1/login HTTP/1.1" 401 512 "-" "MyAppClient/1.0"',
]

URL = 'http://127.0.0.1:8787/api/ingest'

print("Starting live traffic simulation for ULPF...")
while True:
    # 80% chance for a known log, 20% for unknown
    if random.random() < 0.8:
        log = random.choice(KNOWN_LOGS)
    else:
        log = random.choice(UNKNOWN_LOGS)
    
    req = urllib.request.Request(URL, data=log.encode('utf-8'), headers={'Content-Type': 'text/plain'}, method='POST')
    
    try:
        urllib.request.urlopen(req)
        print(".", end="", flush=True)
    except urllib.error.URLError as e:
        print("x", end="", flush=True)
        
    time.sleep(random.uniform(0.1, 0.5))
