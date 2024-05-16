import pyshark
from collections import defaultdict
import time
import psutil

# Global variables
http_requests = defaultdict(int)
threshold = 20
time_window = 7

def detect_http_flood(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter="http")  # Filter for HTTP packets (port 80)
    print("Sniffing HTTP packets on interface:", interface)

    start_time = time.time()
    for packet in capture.sniff_continuously():
        print(packet)
        if "HTTP" in packet:
            http_requests[time.time()] += 1

        # Calculate the rate of HTTP requests within the time window
        current_time = time.time()
        request_count = sum(http_requests[timestamp] for timestamp in http_requests if timestamp >= current_time - time_window)

        if request_count > threshold:
            print("Alert: HTTP Flood Detected! Rate:", request_count, "requests/second")

if __name__ == "__main__":
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:", interfaces)

    if interfaces:
        interface = input("Enter the interface name you want to use: ")
        detect_http_flood(interface)
    else:
        print("No interfaces found.")
