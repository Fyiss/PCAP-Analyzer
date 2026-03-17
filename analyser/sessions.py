"""
sessions.py — TCP/UDP session reconstruction

What is a session?
A session is a conversation between two machines.
Example: Your browser (192.168.1.5:54231) talks to Google (142.250.1.1:443)
That entire back-and-forth is one session.

We extract:
- Source IP + port
- Destination IP + port
- Protocol (TCP/UDP)
- How many packets exchanged
- How much data transferred
"""

from scapy.all import IP, TCP, UDP
from collections import defaultdict

def analyse_sessions(packets):
    """
    Reconstruct all sessions from packets.
    Returns a dict of sessions + summary stats.
    """

    # We'll store sessions in a dict
    # Key   = (src_ip, src_port, dst_ip, dst_port, protocol)
    # Value = {packets: count, bytes: total}
    sessions = defaultdict(lambda: {"packets": 0, "bytes": 0})

    for pkt in packets:
        # Only process packets that have an IP layer
        # Some packets are ARP, ICMP etc — skip those for now
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        size   = len(pkt)  # packet size in bytes

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto    = "TCP"

        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto    = "UDP"

        else:
            # ICMP or other — no ports, still track it
            src_port = 0
            dst_port = 0
            proto    = pkt[IP].proto  # raw protocol number

        # Build session key
        # We sort src/dst so A→B and B→A count as the same session
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)

        sessions[key]["packets"] += 1
        sessions[key]["bytes"]   += size

    # Convert to a clean list of dicts for the reporter
    session_list = []
    for key, stats in sessions.items():
        (a_ip, a_port), (b_ip, b_port) = key[0], key[1]
        proto = key[2]

        session_list.append({
            "src_ip":   a_ip,
            "src_port": a_port,
            "dst_ip":   b_ip,
            "dst_port": b_port,
            "protocol": proto,
            "packets":  stats["packets"],
            "bytes":    stats["bytes"],
        })

    # Sort by most traffic first
    session_list.sort(key=lambda x: x["bytes"], reverse=True)

    # Extract all unique IPs for IOC checking later
    all_ips = set()
    for s in session_list:
        all_ips.add(s["src_ip"])
        all_ips.add(s["dst_ip"])

    return {
        "sessions":      session_list,
        "total_sessions": len(session_list),
        "unique_ips":    list(all_ips),
        "top_talkers":   session_list[:10],  # top 10 by data volume
    }
