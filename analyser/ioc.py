"""
ioc.py — IOC (Indicator of Compromise) checker

What is an IOC?
An Indicator of Compromise is a piece of evidence that suggests
a system may have been breached or is communicating with something malicious.

Common IOCs:
- Malicious IP addresses     ← what we check here
- Known bad domains
- File hashes of malware
- Registry keys malware creates
- Suspicious process names

What is AbuseIPDB?
A crowd-sourced database of malicious IPs.
When someone detects an attack, they report the attacker's IP.
AbuseIPDB aggregates millions of these reports.

We take every IP found in the PCAP and ask AbuseIPDB:
"Has this IP been reported for malicious activity?"

The API returns:
- Abuse confidence score (0-100%)
  0   = never reported / clean
  100 = reported hundreds of times, definitely malicious
- Categories of abuse (port scan, brute force, malware etc.)
- Country of origin
- Total reports count
- Last reported date

Why does this impress recruiters?
This is EXACTLY what Threat Intelligence integration means in NDR tools.
Real platforms like Darktrace, Vectra, Suricata all do this automatically.
You're building it from scratch — that signals deep understanding.

MITRE ATT&CK: T1071 — Application Layer Protocol
"""

import os
import time
import requests
from collections import defaultdict

# AbuseIPDB API endpoint
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Confidence score threshold to flag as malicious
MALICIOUS_THRESHOLD = 25  # 25%+ = suspicious, flag it

# IPs to always skip (private/local ranges, not routable on internet)
PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "255.",
    "169.254.", "224.", "239.", "255."
)

# Abuse category codes → human readable names
# From AbuseIPDB documentation
CATEGORY_MAP = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Brute Force",
    23: "IoT Targeted",
}

def is_private(ip):
    """Check if IP is a private/local address — skip these."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_PREFIXES)

def check_ip(ip, api_key):
    """
    Query AbuseIPDB for a single IP.
    Returns dict with findings or None on error.
    """
    headers = {
        "Key":    api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": 90,   # reports from last 90 days
        "verbose":      True,
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "ip":               ip,
                "confidence":       data.get("abuseConfidenceScore", 0),
                "country":          data.get("countryCode", "Unknown"),
                "isp":              data.get("isp", "Unknown"),
                "total_reports":    data.get("totalReports", 0),
                "last_reported":    data.get("lastReportedAt", "Never"),
                "categories":       [
                    CATEGORY_MAP.get(c, f"Category {c}")
                    for c in data.get("reports", [{}])[0].get("categories", [])
                ] if data.get("reports") else [],
                "domain":           data.get("domain", ""),
                "usage_type":       data.get("usageType", ""),
            }

        elif response.status_code == 429:
            # Rate limited — wait and skip
            print("    [!] AbuseIPDB rate limit hit — waiting 2s...")
            time.sleep(2)
            return None

        elif response.status_code == 401:
            print("    [!] Invalid AbuseIPDB API key — check your .env file")
            return None

    except requests.exceptions.Timeout:
        print(f"    [!] Timeout checking {ip}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"    [!] No internet connection for IOC check")
        return None
    except Exception as e:
        print(f"    [!] Error checking {ip}: {e}")
        return None

def check_iocs(sessions_data):
    """
    Check all unique IPs from sessions against AbuseIPDB.
    Returns malicious IPs, clean IPs, and summary stats.
    """

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        print("    [!] No ABUSEIPDB_API_KEY in .env — skipping IOC check")
        return {
            "malicious":      [],
            "suspicious":     [],
            "clean":          [],
            "skipped":        [],
            "total_checked":  0,
            "error":          "No API key configured",
        }

    # Get unique IPs from sessions
    all_ips = sessions_data.get("unique_ips", [])

    # Filter out private IPs — no point checking these
    public_ips = [ip for ip in all_ips if not is_private(ip)]

    if not public_ips:
        return {
            "malicious":     [],
            "suspicious":    [],
            "clean":         [],
            "skipped":       all_ips,
            "total_checked": 0,
            "note":          "All IPs were private/local — nothing to check",
        }

    print(f"    [*] Checking {len(public_ips)} public IPs against AbuseIPDB...")

    malicious  = []
    suspicious = []
    clean      = []
    skipped    = []

    for i, ip in enumerate(public_ips):
        print(f"    [{i+1}/{len(public_ips)}] Checking {ip}...", end=" ")

        result = check_ip(ip, api_key)

        if result is None:
            skipped.append(ip)
            print("skipped")
            continue

        confidence = result["confidence"]

        if confidence >= 75:
            result["verdict"] = "MALICIOUS"
            result["severity"] = "CRITICAL"
            malicious.append(result)
            print(f"⚠ MALICIOUS ({confidence}%)")

        elif confidence >= MALICIOUS_THRESHOLD:
            result["verdict"] = "SUSPICIOUS"
            result["severity"] = "HIGH"
            suspicious.append(result)
            print(f"? SUSPICIOUS ({confidence}%)")

        else:
            result["verdict"] = "CLEAN"
            result["severity"] = "INFO"
            clean.append(result)
            print(f"✓ clean ({confidence}%)")

        # Be nice to the API — don't hammer it
        # Free tier allows 1000 checks/day
        time.sleep(0.5)

    return {
        "malicious":      malicious,
        "suspicious":     suspicious,
        "clean":          clean,
        "skipped":        skipped,
        "total_checked":  len(public_ips),
        "malicious_count": len(malicious),
        "suspicious_count": len(suspicious),
    }
