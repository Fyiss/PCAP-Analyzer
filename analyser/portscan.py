"""
portscan.py — Port scan detector

What is a port scan?
Before an attacker attacks, they reconnaissance — they probe
your machine to find which ports are open (which services
are running). This is called a port scan.

Like a burglar trying every door and window of a building
to see which ones are unlocked.

Types we detect:
- SYN Scan    — most common, sends SYN, never completes handshake
                (nmap default, stealthy, also called "half-open scan")
- NULL Scan   — sends packet with no flags set
- FIN Scan    — sends FIN flag on a non-existing connection
- XMAS Scan   — sends FIN+PSH+URG flags (lights up like a christmas tree)
- UDP Scan    — probes UDP ports, gets ICMP unreachable if closed
- Connect Scan — completes full TCP handshake (noisy, easy to detect)

Why does this matter?
Port scans are almost always the first step in an attack.
Detecting them early = stopping the attack before it starts.
MITRE ATT&CK T1046 — Network Service Discovery
"""

from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict

# Thresholds — how many ports hit before we call it a scan
SYN_THRESHOLD     = 5   # 5+ SYN packets to different ports = scan
CONNECT_THRESHOLD = 10  # 10+ completed connections to different ports
UDP_THRESHOLD     = 5   # 5+ UDP probes to different ports

def detect_portscans(packets):
    """
    Analyse packets and detect port scanning activity.
    Returns list of detected scanners with technique and targets.
    """

    # Track per source IP:
    # syn_targets[src_ip] = set of (dst_ip, dst_port) they sent SYN to
    syn_targets     = defaultdict(set)
    fin_targets     = defaultdict(set)
    null_targets    = defaultdict(set)
    xmas_targets    = defaultdict(set)
    connect_targets = defaultdict(set)
    udp_targets     = defaultdict(set)

    # Track SYN-ACK responses to identify completed connections
    # syn_ack_seen[dst_ip] = set of ports that responded
    syn_ack_seen = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # --- TCP flag analysis ---
        if pkt.haslayer(TCP):
            tcp   = pkt[TCP]
            flags = tcp.flags
            dport = tcp.dport
            sport = tcp.sport

            # TCP flags as integers:
            # SYN = 0x02, ACK = 0x10, FIN = 0x01
            # RST = 0x04, PSH = 0x08, URG = 0x20

            # SYN scan — SYN flag only (0x02), no ACK
            if flags == 0x02:
                syn_targets[src_ip].add((dst_ip, dport))

            # SYN-ACK response — server is saying "port is open"
            # We track this to identify connect scans
            elif flags == 0x12:  # SYN + ACK
                syn_ack_seen[dst_ip].add(sport)

            # Connect scan — ACK after SYN-ACK = full handshake completed
            elif flags == 0x10:  # ACK only
                if dport in syn_ack_seen[dst_ip]:
                    connect_targets[src_ip].add((dst_ip, dport))

            # NULL scan — no flags set at all (0x00)
            elif flags == 0x00:
                null_targets[src_ip].add((dst_ip, dport))

            # FIN scan — only FIN flag (0x01)
            elif flags == 0x01:
                fin_targets[src_ip].add((dst_ip, dport))

            # XMAS scan — FIN + PSH + URG (0x29)
            elif flags == 0x29:
                xmas_targets[src_ip].add((dst_ip, dport))

        # --- UDP scan detection ---
        # Attacker sends UDP to closed port
        # Target replies with ICMP "port unreachable"
        if pkt.haslayer(UDP):
            udp_targets[src_ip].add((dst_ip, pkt[UDP].dport))

    # --- Now evaluate who crossed the threshold ---
    detections = []

    def evaluate(tracker, scan_type, threshold):
        for src_ip, targets in tracker.items():
            if len(targets) >= threshold:
                # Group targets by destination IP
                dst_ips = list(set(t[0] for t in targets))
                ports   = sorted(set(t[1] for t in targets))

                detections.append({
                    "src_ip":      src_ip,
                    "scan_type":   scan_type,
                    "ports_hit":   len(targets),
                    "target_ips":  dst_ips,
                    "ports":       ports[:20],  # show first 20 ports
                    "severity":    get_severity(scan_type),
                    "mitre":       "T1046",
                    "description": get_description(scan_type),
                })

    evaluate(syn_targets,     "SYN Scan",     SYN_THRESHOLD)
    evaluate(null_targets,    "NULL Scan",    SYN_THRESHOLD)
    evaluate(fin_targets,     "FIN Scan",     SYN_THRESHOLD)
    evaluate(xmas_targets,    "XMAS Scan",    SYN_THRESHOLD)
    evaluate(connect_targets, "Connect Scan", CONNECT_THRESHOLD)
    evaluate(udp_targets,     "UDP Scan",     UDP_THRESHOLD)

    # Sort by most ports hit — most aggressive scanner first
    detections.sort(key=lambda x: x["ports_hit"], reverse=True)

    return {
        "detections":    detections,
        "total_scanners": len(set(d["src_ip"] for d in detections)),
        "total_detected": len(detections),
    }

def get_severity(scan_type):
    severity_map = {
        "SYN Scan":     "HIGH",
        "NULL Scan":    "HIGH",
        "FIN Scan":     "HIGH",
        "XMAS Scan":    "HIGH",
        "Connect Scan": "MEDIUM",
        "UDP Scan":     "MEDIUM",
    }
    return severity_map.get(scan_type, "MEDIUM")

def get_description(scan_type):
    desc_map = {
        "SYN Scan":     "Half-open scan — sends SYN, never completes handshake. Stealthy, evades basic logging.",
        "NULL Scan":    "No flags set — used to evade stateless firewalls and identify OS type.",
        "FIN Scan":     "FIN on non-existing connection — bypasses some firewalls, OS fingerprinting.",
        "XMAS Scan":    "FIN+PSH+URG flags set — named for lighting up like a christmas tree.",
        "Connect Scan": "Full TCP handshake completed — noisy but reliable, logged by most systems.",
        "UDP Scan":     "UDP probe sweep — slower, detects UDP services like DNS, SNMP, TFTP.",
    }
    return desc_map.get(scan_type, "Unknown scan type.")
