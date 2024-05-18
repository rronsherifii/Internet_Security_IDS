from collections import defaultdict
from datetime import time
import time

import psutil
import pyshark


icmp_count = defaultdict(int)


def is_icmp_suspicious(interface):
    global icmp_count
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="icmp")
    print("Sniffing ICMP packets on interface:", interface)

    start_time = time.time()

    for packet in capture.sniff_continuously():
        if "IP" in packet and "ICMP" in packet:
            src_ip = packet.ip.src

            # Increment the count for the source IP
            icmp_count[src_ip] += 1
            print(f"ICMP count from {src_ip}: {icmp_count[src_ip]}")

            # Check if 10 packets are from the same source IP
            if icmp_count[src_ip] >= 10:
                return True, src_ip

        # Check if 10 seconds have passed
        if time.time() - start_time >= 10:
            # Reset counts for all source IPs
            icmp_count.clear()
            start_time = time.time()

    return False, None


if __name__ == "__main__":
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:", interfaces)

    if interfaces:
        interface = 'Wi-Fi'
        print("Sniffing on interface:", interface)
        if(is_icmp_suspicious(interface)):
                print("Attack ICMP Flood Detected!!")

