import sqlite3
from collections import defaultdict
import psutil
import pyshark
import time


icmp_count = defaultdict(int)

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
                timestamp = int(time.time())
                save_to_database("Possible ICMP Flood Attack", timestamp, src_ip, interface)
                return True, src_ip

        # Check if 10 seconds have passed
        if time.time() - start_time >= 10:
            # Reset counts for all source IPs
            icmp_count.clear()
            start_time = time.time()

    return False, None

def print_database():
    conn = sqlite3.connect('icmp_data.db')
    c = conn.cursor()
    c.execute("SELECT * FROM suspicious_icmp")
    rows = c.fetchall()
    print("Attack Type\tTimestamp\t\tAttacker IP\t\tInterface")
    for row in rows:
        print(f"{row[1]}\t{row[2]}\t{row[3]}\t{row[4]}")
    conn.close()
    return rows






if __name__ == "__main__":
    create_database()
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:", interfaces)

    if interfaces:
        interface = 'Wi-Fi'
        print("Sniffing on interface:", interface)
        if is_icmp_suspicious(interface):
            print("Attack ICMP Flood Detected!!")

