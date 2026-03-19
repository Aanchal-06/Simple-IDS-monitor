from scapy.all import sniff, IP, TCP
from collections import defaultdict
from utils import alert
import time

port_scan_tracker = defaultdict(set)
last_alert_time = {}

THRESHOLD = 10        # ports accessed
COOLDOWN = 10        # seconds


def detect_network(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) > THRESHOLD:
            now = time.time()

            # prevent alert spam
            if src_ip not in last_alert_time or (now - last_alert_time[src_ip]) > COOLDOWN:
                alert(f"[NIDS] Port scan detected from {src_ip}")
                last_alert_time[src_ip] = now

            port_scan_tracker[src_ip].clear()


def start_nids():
    print("🌐 NIDS Started...")
    sniff(prn=detect_network, store=False, iface="lo")