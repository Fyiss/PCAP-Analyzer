"""
credentials.py — Plaintext credential extractor

What are plaintext credentials?
Some old/insecure protocols send usernames and passwords
over the network with ZERO encryption. Anyone recording
the traffic can just read them directly.

Protocols we target:
- FTP  (port 21)  — file transfer, sends USER and PASS in plaintext
- HTTP (port 80)  — web traffic, Basic Auth sends base64 encoded creds
- Telnet (port 23) — old remote shell, everything plaintext
- SMTP (port 25)  — email sending, AUTH LOGIN sends base64 creds

Why does this matter?
This is exactly what an attacker on your network would do.
It's also what a security analyst does to prove a protocol is insecure.
MITRE ATT&CK T1040 — Network Sniffing
"""

import base64
import re
from scapy.all import IP, TCP

# Ports we care about
FTP_PORT    = 21
HTTP_ALT_PORT = 8080
HTTP_PORT   = 80
TELNET_PORT = 23
SMTP_PORT   = 25

def extract_credentials(packets):
    """
    Scan all packets for plaintext credentials.
    Returns list of findings with protocol, IPs, and credentials.
    """

    findings = []

    for pkt in packets:
        # Must have IP + TCP + Raw payload
        # Raw = the actual data/content of the packet
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue

        src_ip   = pkt[IP].src
        dst_ip   = pkt[IP].dst
        dst_port = pkt[TCP].dport
        src_port = pkt[TCP].sport

        # Raw payload — extract directly from TCP payload
        # Scapy sometimes parses HTTP internally so Raw layer
        # may not exist — we grab bytes directly from TCP payload
        try:
            tcp_payload = bytes(pkt[TCP].payload)
            if not tcp_payload:
                continue
            payload = tcp_payload.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # --- FTP ---
        # FTP sends commands like:
        # USER darshith
        # PASS mysecretpassword
        if dst_port in (HTTP_PORT, HTTP_ALT_PORT) or src_port in (HTTP_PORT, HTTP_ALT_PORT):
            if payload.startswith("USER "):
                username = payload.strip().split(" ", 1)[1]
                findings.append({
                    "protocol": "FTP",
                    "type":     "USERNAME",
                    "value":    username,
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "severity": "HIGH",
                })

            elif payload.startswith("PASS "):
                password = payload.strip().split(" ", 1)[1]
                findings.append({
                    "protocol": "FTP",
                    "type":     "PASSWORD",
                    "value":    password,
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "severity": "CRITICAL",
                })

        # --- HTTP Basic Auth ---
        # HTTP Basic Auth encodes creds as base64 in the header:
        # Authorization: Basic ZGFyc2hpdGg6cGFzc3dvcmQ=
        # That base64 decodes to "darshith:password"
        if dst_port in (HTTP_PORT, HTTP_ALT_PORT) or src_port in (HTTP_PORT, HTTP_ALT_PORT):
            auth_match = re.search(
                r"Authorization: Basic ([A-Za-z0-9+/=]+)", payload
            )
            if auth_match:
                encoded = auth_match.group(1)
                try:
                    decoded = base64.b64decode(encoded).decode("utf-8")
                    if ":" in decoded:
                        user, pwd = decoded.split(":", 1)
                        findings.append({
                            "protocol": "HTTP Basic Auth",
                            "type":     "USERNAME:PASSWORD",
                            "value":    f"{user} : {pwd}",
                            "src_ip":   src_ip,
                            "dst_ip":   dst_ip,
                            "severity": "CRITICAL",
                        })
                except Exception:
                    pass

            # Also catch HTTP POST login forms
            # Many login pages POST: username=darshith&password=secret
            if "POST" in payload:
                post_match = re.search(
                    r"(username|user|login|email)[=:]([^&\s]+).*?"
                    r"(password|pass|pwd)[=:]([^&\s]+)",
                    payload, re.IGNORECASE
                )
                if post_match:
                    findings.append({
                        "protocol": "HTTP POST Form",
                        "type":     "USERNAME:PASSWORD",
                        "value":    f"{post_match.group(2)} : {post_match.group(4)}",
                        "src_ip":   src_ip,
                        "dst_ip":   dst_ip,
                        "severity": "CRITICAL",
                    })

        # --- Telnet ---
        # Telnet sends every single keystroke as a separate packet
        # We look for login/password prompts followed by input
        if dst_port == TELNET_PORT or src_port == TELNET_PORT:
            if re.search(r"login:|Username:", payload, re.IGNORECASE):
                findings.append({
                    "protocol": "Telnet",
                    "type":     "LOGIN PROMPT",
                    "value":    payload.strip(),
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "severity": "HIGH",
                })
            elif re.search(r"Password:", payload, re.IGNORECASE):
                findings.append({
                    "protocol": "Telnet",
                    "type":     "PASSWORD PROMPT",
                    "value":    payload.strip(),
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "severity": "CRITICAL",
                })

        # --- SMTP AUTH ---
        # SMTP sends auth as base64:
        # AUTH LOGIN
        # base64(username)
        # base64(password)
        if dst_port == SMTP_PORT or src_port == SMTP_PORT:
            if re.search(r"AUTH LOGIN", payload, re.IGNORECASE):
                findings.append({
                    "protocol": "SMTP",
                    "type":     "AUTH ATTEMPT",
                    "value":    "AUTH LOGIN detected",
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "severity": "MEDIUM",
                })

            # Base64 blobs after AUTH LOGIN are username/password
            b64_match = re.match(r"^([A-Za-z0-9+/]{4,}={0,2})\r\n$", payload)
            if b64_match:
                try:
                    decoded = base64.b64decode(b64_match.group(1)).decode("utf-8")
                    if decoded.isprintable() and len(decoded) > 2:
                        findings.append({
                            "protocol": "SMTP",
                            "type":     "CREDENTIAL (base64)",
                            "value":    decoded,
                            "src_ip":   src_ip,
                            "dst_ip":   dst_ip,
                            "severity": "CRITICAL",
                        })
                except Exception:
                    pass

    return {
        "findings":       findings,
        "total_found":    len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
    }
