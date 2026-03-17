# 🔍 PCAP Analyser — Network Forensics & Threat Detection Tool

A Python CLI tool that ingests `.pcap` network capture files, runs 6 independent
analysis modules, generates a professional dark-themed HTML report, and delivers
it automatically via email.

Built as a security research project demonstrating NDR (Network Detection & Response)
concepts, MITRE ATT&CK mapping, and threat intelligence integration.

> ⚠️ For authorised security research and educational purposes only.
> Only analyse traffic on networks you own or have explicit permission to monitor.

---

## 📸 Report Preview

The generated HTML report covers:

| Section | What It Shows |
|---|---|
| 🔑 Plaintext Credentials | Decoded FTP/HTTP/Telnet/SMTP credentials |
| 🔎 Port Scan Detections | Scan type, source IP, ports hit, MITRE tag |
| 🌐 DNS Analysis | Tunnelling suspects, DGA activity, top domains |
| 📊 Protocol Breakdown | Traffic % per protocol, insecure/OT flags |
| ⚠️ Threat Intelligence | AbuseIPDB IOC results with confidence scores |
| 🔗 Top Sessions | Heaviest conversations by data volume |

---

## 🗂 Project Structure
```
pcap-analyser/
├── main.py                  ← CLI entry point
├── .env                     ← your secrets (never committed)
├── .env.example             ← template for others
├── .gitignore
├── requirements.txt
├── analyser/
│   ├── sessions.py          ← TCP/UDP session reconstruction
│   ├── credentials.py       ← plaintext credential extractor
│   ├── portscan.py          ← port scan detector
│   ├── dns.py               ← DNS anomaly detection
│   ├── protocols.py         ← protocol breakdown
│   └── ioc.py               ← AbuseIPDB threat intel
├── reporter/
│   ├── html_report.py       ← HTML report generator
│   └── mailer.py            ← Gmail SMTP email delivery
├── reports/                 ← generated reports saved here
└── samples/                 ← put your .pcap files here
```

---

## 🧠 How Each Module Works

### `sessions.py` — Session Reconstruction
Reads every packet and groups them into conversations by
`(src_ip, src_port, dst_ip, dst_port, protocol)`.
Sorts by data volume — unusually large transfers can signal exfiltration.

### `credentials.py` — Plaintext Credential Extractor
Extracts TCP payload bytes directly and scans for credentials
sent in cleartext across 5 protocols:

| Protocol | Port | What it captures |
|---|---|---|
| FTP | 21 | USER and PASS commands |
| HTTP Basic Auth | 80, 8080 | base64 decoded username:password |
| HTTP POST | 80, 8080 | login form fields |
| Telnet | 23 | login/password prompts |
| SMTP AUTH | 25 | base64 decoded credentials |

MITRE ATT&CK: **T1040 — Network Sniffing**

### `portscan.py` — Port Scan Detector
Analyses TCP flag combinations per source IP and flags anyone
hitting more than the threshold number of ports:

| Scan Type | Flags (hex) | Threshold | Notes |
|---|---|---|---|
| SYN Scan | 0x02 | 5 ports | nmap default, stealthy |
| NULL Scan | 0x00 | 5 ports | evades stateless firewalls |
| FIN Scan | 0x01 | 5 ports | bypasses some firewalls |
| XMAS Scan | 0x29 | 5 ports | FIN+PSH+URG |
| Connect Scan | full handshake | 10 ports | noisy, fully logged |
| UDP Scan | UDP probes | 5 ports | finds DNS/SNMP/TFTP |

MITRE ATT&CK: **T1046 — Network Service Discovery**

### `dns.py` — DNS Anomaly Detection
DNS (port 53) is almost never blocked, making it a favourite
channel for C2 and data exfiltration. Detects:

| Detection | Signal | MITRE |
|---|---|---|
| DNS Tunnelling | subdomain > 40 chars | T1048.003 |
| DGA Activity | high NXDOMAIN rate (10+) | T1568.002 |
| High Query Volume | 50+ queries from one host | T1048.003 |
| Suspicious TLD | .tk .pw .xyz .top .onion etc. | T1071.004 |
| Non-standard port | DNS not on port 53 | T1071.004 |

### `protocols.py` — Protocol Breakdown
Maps ports to protocol names and counts packets/bytes per protocol.
Flags two categories:
- **Insecure** — FTP, Telnet, HTTP, HTTP-Alt, SMTP, POP3, SNMP, LDAP
- **OT/ICS** — Modbus (502), DNP3 (20000), BACnet (47808)

### `ioc.py` — Threat Intelligence (AbuseIPDB)
Filters out private IPs (192.168.x.x, 10.x.x.x, 127.x.x.x),
then queries AbuseIPDB for every public IP found in the PCAP.

| Score | Verdict |
|---|---|
| 0–24% | Clean |
| 25–74% | Suspicious |
| 75–100% | Malicious |

---

## ⚙️ Prerequisites

| Requirement | Purpose |
|---|---|
| Linux (Arch/Ubuntu/Debian) | Tested environments |
| Python 3.10+ | Runtime |
| tcpdump | Live traffic capture |
| AbuseIPDB account (free) | IOC checking API key |
| Gmail + App Password | Email delivery |

---

## 🚀 Setup From Scratch

### Step 1 — Clone the repo
```bash
git clone https://github.com/Fyiss/pcap-analyser.git
cd pcap-analyser
```

### Step 2 — Install dependencies

**Arch Linux:**
```bash
pip install scapy requests python-dotenv --break-system-packages
```

**Ubuntu / Debian:**
```bash
pip install scapy requests python-dotenv
```

### Step 3 — Get an AbuseIPDB API key

1. Register at [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register)
2. After login go to [https://www.abuseipdb.com/account/api](https://www.abuseipdb.com/account/api)
3. Click **Create Key** → copy it

### Step 4 — Get a Gmail App Password

1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Security → 2-Step Verification → turn **ON**
3. Security → App Passwords → Select app: **Mail** → Device: **Other** → name it `pcap-analyser`
4. Copy the 16-character password shown

### Step 5 — Create your `.env` file
```bash
cp .env.example .env
nano .env
```

Fill in:
```
ABUSEIPDB_API_KEY=your_key_here
EMAIL_SENDER=yourmail@gmail.com
EMAIL_PASSWORD=your_16char_app_password
EMAIL_RECIPIENT=recipient@gmail.com
```

> ⚠️ `.env` is in `.gitignore` — it will never be committed to GitHub.

---

## 📡 Capturing Traffic

### Option A — Live network capture (60 seconds)

Find your interface:
```bash
ip link show
# wlan0 = WiFi   eth0 = ethernet   lo = loopback
```

Capture:
```bash
sudo tcpdump -i wlan0 -w samples/live_capture.pcap -G 60 -W 1
```
Browse some websites while it runs. Stops automatically after 60 seconds.

---

### Option B — FTP plaintext credentials

Tests the FTP credential extractor using a local FTP server.

**Install:**
```bash
# Arch Linux
sudo pacman -S vsftpd inetutils

# Ubuntu / Debian
sudo apt install vsftpd ftp
```

**Configure vsftpd:**
```bash
sudo nano /etc/vsftpd.conf
```
Replace contents with:
```
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
xferlog_enable=YES
connect_from_port_20=YES
ssl_enable=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40010
```

**Terminal 1 — Start FTP server:**
```bash
sudo systemctl start vsftpd
sudo systemctl status vsftpd   # should show active (running)
```

**Terminal 1 — Start capture:**
```bash
sudo tcpdump -i lo -w samples/ftp_creds.pcap port 21
```

**Terminal 2 — Connect via FTP:**
```bash
ftp 127.0.0.1
```
Enter your Linux username and password when prompted, then:
```
ls
pwd
quit
```

**Terminal 1 — Stop capture:**
```
Ctrl+C
```

---

### Option C — HTTP Basic Auth plaintext credentials

Tests the HTTP credential extractor using a local Python server.

**Save the test server:**
```bash
nano http_server.py
```
Paste:
```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Basic '):
            decoded = base64.b64decode(auth[6:]).decode()
            print(f'CAPTURED CREDENTIALS: {decoded}')
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Login successful')
        else:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="SecureArea"')
            self.end_headers()
            self.wfile.write(b'Unauthorized')
    def log_message(self, *args): pass

HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
```

**Terminal 1 — Start capture:**
```bash
sudo tcpdump -i lo -w samples/http_creds.pcap port 8080
```

**Terminal 2 — Start server:**
```bash
python3 http_server.py
```

**Terminal 3 — Send credentials:**
```bash
curl -u testuser:testpassword123 http://127.0.0.1:8080/
```

**Stop:** `Ctrl+C` Terminal 2, then `Ctrl+C` Terminal 1.

---

## ▶️ Running the Analyser
```bash
sudo python3 main.py --file samples/live_capture.pcap --email you@gmail.com
```

**Expected output:**
```
[*] Loading PCAP: samples/live_capture.pcap
[*] Starting analysis...
[+] Loaded 2645 packets

[*] Reconstructing sessions...
[*] Extracting credentials...
[*] Detecting port scans...
[*] Analysing DNS traffic...
[*] Breaking down protocols...
[*] Checking IPs against AbuseIPDB...
    [*] Checking 7 public IPs against AbuseIPDB...
    [1/7] Checking 34.107.243.93... ⚠ MALICIOUS (79%)
    [2/7] Checking 142.250.186.66... ✓ clean (0%)

[*] Generating report...
[+] Report saved: reports/pcap_report_20260317_161750.html
[*] Sending report to you@gmail.com...
[+] Email sent successfully
[+] Done! Report delivered to you@gmail.com
```

The full HTML report is emailed and saved in `reports/`.

---

## 🔬 MITRE ATT&CK Coverage

| Module | Tactic | Technique | ID |
|---|---|---|---|
| credentials.py | Collection | Network Sniffing | T1040 |
| portscan.py | Discovery | Network Service Discovery | T1046 |
| dns.py | C2 | Application Layer Protocol: DNS | T1071.004 |
| dns.py | Exfiltration | Exfiltration Over Alternative Protocol | T1048.003 |
| dns.py | C2 | Dynamic Resolution: DGA | T1568.002 |

---

## 🛡️ Defensive Relevance

| Role | How this applies |
|---|---|
| NDR Analyst | Demonstrates detection rule logic and false positive tuning |
| SOC Analyst | Full triage workflow — ingest, analyse, report, deliver |
| OT Security | Modbus, DNP3, BACnet protocol awareness built in |
| Threat Intel | AbuseIPDB IOC enrichment on every public IP |

---

## 📋 Dependencies
```
scapy
requests
python-dotenv
```

---

## 👤 Author

**Darshith Thalipady Nagesh**
Security Research · Python · Network Forensics · Arch Linux

[GitHub](https://github.com/Fyiss) · [LinkedIn](https://www.linkedin.com/in/darshith-t-n-71467b253/)

---

*All research and testing conducted on personal hardware.
Never deploy on any network without explicit owner consent.*
