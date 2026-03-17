#!/usr/bin/env python3
"""
PCAP Analyser — main entry point
Usage: sudo python3 main.py --file samples/test.pcap --email you@gmail.com
"""

import argparse
import sys
import os
from dotenv import load_dotenv

# Load .env file (your API keys, email credentials)
load_dotenv()

# Import all analyser modules
from analyser.sessions     import analyse_sessions
from analyser.credentials  import extract_credentials
from analyser.portscan     import detect_portscans
from analyser.dns          import analyse_dns
from analyser.protocols    import analyse_protocols
from analyser.ioc          import check_iocs

# Import reporter modules
from reporter.html_report  import generate_report
from reporter.mailer       import send_report

def parse_args():
    parser = argparse.ArgumentParser(
        description="PCAP Analyser — Network forensics & threat detection tool"
    )
    parser.add_argument("--file",  required=True, help="Path to .pcap file")
    parser.add_argument("--email", required=True, help="Email address to send report to")
    return parser.parse_args()

def main():
    args = parse_args()

    # Check the file exists
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    print(f"\n[*] Loading PCAP: {args.file}")
    print("[*] Starting analysis...\n")

    # --- Parse packets once, pass to all modules ---
    # Scapy reads the entire pcap into memory as a list of packets
    from scapy.all import rdpcap
    packets = rdpcap(args.file)
    print(f"[+] Loaded {len(packets)} packets\n")

    # --- Run all analysers ---
    # Each one returns a dict of findings
    print("[*] Reconstructing sessions...")
    sessions    = analyse_sessions(packets)

    print("[*] Extracting credentials...")
    credentials = extract_credentials(packets)

    print("[*] Detecting port scans...")
    portscans   = detect_portscans(packets)

    print("[*] Analysing DNS traffic...")
    dns         = analyse_dns(packets)

    print("[*] Breaking down protocols...")
    protocols   = analyse_protocols(packets)

    print("[*] Checking IPs against AbuseIPDB...")
    iocs        = check_iocs(sessions)

    # --- Bundle everything into one results dict ---
    results = {
        "file":        args.file,
        "total_packets": len(packets),
        "sessions":    sessions,
        "credentials": credentials,
        "portscans":   portscans,
        "dns":         dns,
        "protocols":   protocols,
        "iocs":        iocs,
    }

    # --- Generate HTML report ---
    print("\n[*] Generating report...")
    report_path = generate_report(results)
    print(f"[+] Report saved: {report_path}")

    # --- Email it ---
    print(f"[*] Sending report to {args.email}...")
    send_report(report_path, args.email)
    print(f"[+] Done! Report delivered to {args.email}\n")

if __name__ == "__main__":
    main()
