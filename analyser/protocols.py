"""
protocols.py — Protocol breakdown analyser

What does this do?
Gives a high-level picture of WHAT kind of traffic
exists in the PCAP — broken down by protocol.

Why does this matter to an analyst?
The protocol breakdown is always the FIRST thing an analyst
looks at. It immediately tells you:

- Is this normal traffic? (mostly HTTPS, DNS, NTP)
- Is something weird? (huge amount of ICMP, raw TCP, unknown protocols)
- Are insecure protocols in use? (HTTP, FTP, Telnet — should not exist in 2026)
- Is there OT/ICS traffic? (Modbus port 502, DNP3 port 20000)

In OT/production networks (exactly the job you're applying for)
seeing Modbus or DNP3 is normal. Seeing it suddenly spike, or
seeing it mixed with internet traffic, is a red flag.

Protocol → Port mapping we track:
Layer 4 (Transport): TCP, UDP, ICMP
Layer 7 (Application — by port):
  HTTP    80      FTP     21      SSH     22
  HTTPS   443     DNS     53      SMTP    25
  Telnet  23      RDP     3389    SMB     445
  SNMP    161     NTP     123     IMAP    143
  POP3    110     LDAP    389     Kerberos 88
  Modbus  502     DNP3    20000   BACnet  47808
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP
from collections import defaultdict

# Port → protocol name mapping
PORT_MAP = {
    20:    "FTP-Data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP",
    80:    "HTTP",
    88:    "Kerberos",
    110:   "POP3",
    123:   "NTP",
    143:   "IMAP",
    161:   "SNMP",
    162:   "SNMP-Trap",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB",
    502:   "Modbus",        # OT/ICS protocol
    3389:  "RDP",
    5060:  "SIP",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    20000: "DNP3",          # OT/ICS protocol
    47808: "BACnet",        # Building automation
}

# Protocols considered insecure — flag these
INSECURE_PROTOCOLS = {"FTP", "Telnet", "HTTP", "HTTP-Alt", "SMTP", "POP3", "SNMP", "LDAP"}

# OT/ICS protocols — flag presence for awareness
OT_PROTOCOLS = {"Modbus", "DNP3", "BACnet"}

def analyse_protocols(packets):
    """
    Break down all traffic by protocol and flag anomalies.
    """

    # Counters
    protocol_counts  = defaultdict(int)   # protocol → packet count
    protocol_bytes   = defaultdict(int)   # protocol → byte count
    insecure_found   = set()              # insecure protocols seen
    ot_found         = set()              # OT protocols seen
    total_packets    = len(packets)
    total_bytes      = 0

    for pkt in packets:
        size = len(pkt)
        total_bytes += size

        # --- Layer 3 non-IP ---
        if pkt.haslayer(ARP):
            protocol_counts["ARP"] += 1
            protocol_bytes["ARP"]  += size
            continue

        if not pkt.haslayer(IP):
            protocol_counts["Other"] += 1
            protocol_bytes["Other"]  += size
            continue

        # --- ICMP ---
        if pkt.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
            protocol_bytes["ICMP"]  += size
            continue

        # --- TCP ---
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            # Identify by destination port first, then source port
            proto = PORT_MAP.get(dport) or PORT_MAP.get(sport) or "TCP-Other"

            protocol_counts[proto] += 1
            protocol_bytes[proto]  += size

            if proto in INSECURE_PROTOCOLS:
                insecure_found.add(proto)
            if proto in OT_PROTOCOLS:
                ot_found.add(proto)
            continue

        # --- UDP ---
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport

            proto = PORT_MAP.get(dport) or PORT_MAP.get(sport) or "UDP-Other"

            protocol_counts[proto] += 1
            protocol_bytes[proto]  += size

            if proto in INSECURE_PROTOCOLS:
                insecure_found.add(proto)
            if proto in OT_PROTOCOLS:
                ot_found.add(proto)
            continue

        # --- Everything else ---
        protocol_counts["Other"] += 1
        protocol_bytes["Other"]  += size

    # Build sorted breakdown (most packets first)
    breakdown = []
    for proto, count in sorted(protocol_counts.items(),
                                key=lambda x: x[1], reverse=True):
        pct = round((count / total_packets) * 100, 1) if total_packets else 0
        breakdown.append({
            "protocol":   proto,
            "packets":    count,
            "bytes":      protocol_bytes[proto],
            "percentage": pct,
            "insecure":   proto in INSECURE_PROTOCOLS,
            "ot":         proto in OT_PROTOCOLS,
        })

    # Alerts
    alerts = []
    for proto in insecure_found:
        alerts.append({
            "type":     "Insecure Protocol Detected",
            "protocol": proto,
            "detail":   f"{proto} transmits data in plaintext — should be replaced with encrypted alternative",
            "severity": "HIGH",
        })
    for proto in ot_found:
        alerts.append({
            "type":     "OT/ICS Protocol Detected",
            "protocol": proto,
            "detail":   f"{proto} is an industrial control protocol — verify this is expected in this network segment",
            "severity": "MEDIUM",
        })

    return {
        "breakdown":       breakdown,
        "total_packets":   total_packets,
        "total_bytes":     total_bytes,
        "insecure_protos": list(insecure_found),
        "ot_protos":       list(ot_found),
        "alerts":          alerts,
        "unique_protocols": len(protocol_counts),
    }
