"""
dns.py — DNS traffic analyser

What is DNS?
DNS = Domain Name System. It's the internet's phone book.
When you type "google.com", your computer asks a DNS server
"what is the IP address of google.com?" and it replies "142.250.1.1"

Every single domain lookup = one DNS query in the PCAP.

Why do attackers abuse DNS?
Because DNS traffic is almost NEVER blocked by firewalls.
Companies block port 80, 443, block IPs — but DNS (port 53)
is always open because without it, nothing works.

Attackers use this to:

1. DNS Tunnelling — hide data INSIDE dns queries
   normal query : "what is google.com?"
   tunnel query : "what is aGVsbG8gd29ybGQ=.evil.com?"
                   ↑ that's base64 encoded stolen data

2. C2 over DNS — malware contacts its command server via DNS
   malware asks : "what is cmd-get-instructions.evil.com?"
   C2 server replies with an IP that actually encodes a command

3. DGA — Domain Generation Algorithm
   Malware generates hundreds of random domains daily
   trying to find its C2 server
   signs: lots of NXDOMAIN (domain not found) responses

What we detect:
- High query volume from single host (tunnelling/DGA)
- Long subdomain names (data encoded in DNS)
- High NXDOMAIN rate (DGA activity)
- Suspicious TLDs (.tk, .pw, .xyz, .top etc)
- DNS over non-standard ports
- Most queried domains

MITRE ATT&CK:
- T1071.004 — Application Layer Protocol: DNS (C2 over DNS)
- T1048.003 — Exfiltration Over DNS
"""

from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from collections import defaultdict
import re

# Suspicious TLDs commonly used in malware/phishing
SUSPICIOUS_TLDS = {
    ".tk", ".pw", ".xyz", ".top", ".club", ".online",
    ".site", ".gq", ".ml", ".ga", ".cf", ".bit",
    ".onion", ".zip", ".mov"
}

# Legitimate high-volume DNS resolvers
KNOWN_DNS_SERVERS = {
    "8.8.8.8", "8.8.4.4",       # Google
    "1.1.1.1", "1.0.0.1",       # Cloudflare
    "9.9.9.9",                   # Quad9
    "208.67.222.222",            # OpenDNS
}

# Thresholds
HIGH_QUERY_THRESHOLD  = 50   # queries from one host = suspicious
LONG_SUBDOMAIN_LENGTH = 40   # subdomain longer than this = possible tunnelling
NXDOMAIN_THRESHOLD    = 10   # NXDOMAIN responses = possible DGA

def analyse_dns(packets):
    """
    Analyse DNS traffic for anomalies and attacks.
    """

    # Per-host query counts
    query_counts     = defaultdict(int)       # src_ip → total queries
    queried_domains  = defaultdict(set)       # src_ip → set of domains queried
    nxdomain_counts  = defaultdict(int)       # src_ip → NXDOMAIN count
    domain_frequency = defaultdict(int)       # domain → how many times queried

    # Findings
    alerts           = []
    all_queries      = []

    for pkt in packets:
        # DNS runs on UDP port 53 (mostly) and TCP port 53 (large responses)
        if not pkt.haslayer(DNS):
            continue

        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dns    = pkt[DNS]

        # --- DNS Queries (qr=0 means it's a question) ---
        if dns.qr == 0 and dns.qd:
            try:
                # Extract the queried domain name
                domain = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                continue

            query_counts[src_ip]    += 1
            queried_domains[src_ip].add(domain)
            domain_frequency[domain] += 1

            all_queries.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "domain": domain,
            })

            # --- Check 1: Long subdomain (possible DNS tunnelling) ---
            # Split domain into parts: "aGVsbG8.evil.com" → ["aGVsbG8", "evil", "com"]
            parts = domain.split(".")
            if parts:
                subdomain = parts[0]
                if len(subdomain) > LONG_SUBDOMAIN_LENGTH:
                    alerts.append({
                        "type":        "DNS Tunnelling Suspect",
                        "src_ip":      src_ip,
                        "domain":      domain,
                        "detail":      f"Subdomain length {len(subdomain)} chars — possible encoded data",
                        "severity":    "HIGH",
                        "mitre":       "T1048.003",
                    })

            # --- Check 2: Suspicious TLD ---
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    alerts.append({
                        "type":     "Suspicious TLD",
                        "src_ip":   src_ip,
                        "domain":   domain,
                        "detail":   f"Domain uses suspicious TLD: {tld}",
                        "severity": "MEDIUM",
                        "mitre":    "T1071.004",
                    })
                    break

            # --- Check 3: DNS to non-standard port ---
            if pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                if dport != 53 and sport != 53:
                    alerts.append({
                        "type":     "DNS on Non-Standard Port",
                        "src_ip":   src_ip,
                        "domain":   domain,
                        "detail":   f"DNS query sent to port {dport} instead of 53",
                        "severity": "HIGH",
                        "mitre":    "T1071.004",
                    })

        # --- DNS Responses (qr=1 means it's an answer) ---
        elif dns.qr == 1:

            # --- Check 4: NXDOMAIN response (domain not found) ---
            # rcode 3 = NXDOMAIN
            if dns.rcode == 3 and dns.qd:
                try:
                    domain = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    nxdomain_counts[src_ip] += 1
                except Exception:
                    pass

    # --- Post-loop checks ---

    # Check 5: High query volume per host (tunnelling / DGA)
    for src_ip, count in query_counts.items():
        if count >= HIGH_QUERY_THRESHOLD:
            alerts.append({
                "type":     "High DNS Query Volume",
                "src_ip":   src_ip,
                "domain":   f"{len(queried_domains[src_ip])} unique domains",
                "detail":   f"{count} DNS queries from single host — possible tunnelling or DGA",
                "severity": "HIGH",
                "mitre":    "T1048.003",
            })

    # Check 6: High NXDOMAIN rate (DGA — malware trying random domains)
    for src_ip, count in nxdomain_counts.items():
        if count >= NXDOMAIN_THRESHOLD:
            alerts.append({
                "type":     "High NXDOMAIN Rate (Possible DGA)",
                "src_ip":   src_ip,
                "domain":   "Multiple non-existent domains",
                "detail":   f"{count} NXDOMAIN responses — malware may be cycling through generated domains",
                "severity": "CRITICAL",
                "mitre":    "T1568.002",
            })

    # Top 10 most queried domains
    top_domains = sorted(
        domain_frequency.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    return {
        "alerts":          alerts,
        "total_queries":   sum(query_counts.values()),
        "unique_domains":  len(domain_frequency),
        "top_domains":     [{"domain": d, "count": c} for d, c in top_domains],
        "nxdomain_counts": dict(nxdomain_counts),
        "query_counts":    dict(query_counts),
        "total_alerts":    len(alerts),
    }
