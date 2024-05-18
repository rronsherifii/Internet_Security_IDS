
import time
import pyshark
from scapy.all import *
import psutil
import ping3
import threading



def get_wifi_ip():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        if interface.startswith('Wi-Fi') or interface.startswith('wlan'):
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.address
    return None


def send_icmp_packets(destination_ip, duration):
    start_time = time.time()
    end_time = start_time + duration

    my_ip_address = get_wifi_ip()
    print("My ip address is " + my_ip_address)

    while time.time() < end_time:
        # Send ICMP echo request
        ping3.ping(destination_ip)

        # Wait for a short interval between packets
        time.sleep(0.5)




# Sending attack
destination_ip = input("Enter destination ip:")
send_icmp_packets(destination_ip,20)
