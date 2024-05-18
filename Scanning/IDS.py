import asyncio
import sqlite3
from collections import defaultdict
import psutil
import pyshark
import time
import psutil
import threading

icmp_count = defaultdict(int)
http_requests = defaultdict(int)
syn_count = defaultdict(int)

threshold = 20  # Duhet me kshyr qfar limiti me i lan
time_window = 7  # Duhet me kshyr poashtu per limitin -- vlera testuese

SYN_COUNT_THRESHOLD = 10
TIME_WINDOW = 10
last_reset_time = time.time()
sniffing_status = False
attacker_ip = None


def create_database():
    conn = sqlite3.connect('icmp_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS suspicious_icmp
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 attack_type TEXT,
                 timestamp TEXT,
                 attacker_ip TEXT,
                 interface TEXT)''')
    conn.commit()
    conn.close()


def save_to_database(attack_type, timestamp, attacker_ip, interface):
    conn = sqlite3.connect('icmp_data.db')
    c = conn.cursor()
    c.execute("INSERT INTO suspicious_icmp (attack_type, timestamp, attacker_ip, interface) VALUES (?, ?, ?, ?)",
              (attack_type, timestamp, attacker_ip, interface))
    conn.commit()
    conn.close()


def print_database():
    conn = sqlite3.connect('icmp_data.db')
    c = conn.cursor()
    c.execute("SELECT * FROM suspicious_icmp")
    rows = c.fetchall()
    # print("Attack Type\tTimestamp\t\tAttacker IP\t\tInterface")
    # for row in rows:
    #     print(f"{row[1]}\t{row[2]}\t{row[3]}\t{row[4]}")
    conn.close()
    return rows


def detect_icmp_flood(interface):
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
                timestamp = int(time.time())
                save_to_database("Possible ICMP Flood Attack", timestamp, src_ip, interface)
                return True, src_ip

        # Check if 10 seconds have passed
        if time.time() - start_time >= 10:
            # Reset counts for all source IPs
            icmp_count.clear()
            start_time = time.time()

    return False, None


def detect_http_flood(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter="http")  # Filter for HTTP packets (port 80)
    print("Sniffing HTTP packets on interface:", interface)

    start_time = time.time()
    for packet in capture.sniff_continuously():
        if "HTTP" in packet:
            src_ip = packet.ip.src
            http_requests[src_ip] += 1
            http_requests[time.time()] += 1

            # Calculate the rate of HTTP requests within the time window
            current_time = time.time()
            request_count = sum(
                http_requests[timestamp] for timestamp in http_requests if timestamp >= current_time - time_window)
            if icmp_count[src_ip] >= 10 and request_count > threshold:
                timestamp = int(time.time())
                save_to_database("Possible HTTP Flood Attack", timestamp, src_ip, interface)
                # print("Alert: HTTP Flood Detected! Rate:", request_count, "requests/second")
    if time.time() - start_time >= 10:
        # Reset counts for all source IPs
        http_requests.clear()
        start_time = time.time()


def detect_syn_flood(interface):
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter=f'tcp.flags.syn==1 && tcp.flags.ack==0'
    )
    print(f"Sniffing TCP SYN packets on interface {interface}")

    start_time = time.time()
    for packet in capture.sniff_continuously():
        if 'IP' in packet and 'TCP' in packet:
            ip_src = packet.ip.src
            tcp_flags = packet.tcp.flags

            if tcp_flags == '0x0002':
                syn_count[ip_src] += 1

                if syn_count[ip_src] > SYN_COUNT_THRESHOLD:
                    timestamp = int(time.time())
                    save_to_database("Possible SYN Flood Attack", timestamp, ip_src, interface)
                    attacker_ip = ip_src
    if time.time() - start_time >= 10:
        # Reset counts for all source IPs
        syn_count.clear()
        start_time = time.time()

def icmp_detection_wrapper(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    detect_icmp_flood(interface)


def http_detection_wrapper(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    detect_http_flood(interface)


def syn_detection_wrapper(interface):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    detect_syn_flood(interface)




