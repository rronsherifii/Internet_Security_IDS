import pyshark
from collections import defaultdict
import time
import psutil

# Global variables
http_requests = defaultdict(int)
threshold = 20  # Example threshold for rate limit
time_window = 7  # Time window for detection in seconds

def detect_http_flood(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter="http")  # Filter for HTTP packets (port 80)
    print("Sniffing HTTP packets on interface:", interface)

    for packet in capture.sniff_continuously():
        try:
            current_time = time.time()
            packet_time = float(packet.sniff_time.timestamp())  # Extract packet timestamp

            if "HTTP" in packet:
                http_requests[packet_time] += 1

            # Clean up old requests outside the time window
            old_timestamps = [timestamp for timestamp in http_requests if timestamp < current_time - time_window]
            for timestamp in old_timestamps:
                del http_requests[timestamp]

            # Calculate the rate of HTTP requests within the time window
            request_count = sum(http_requests[timestamp] for timestamp in http_requests if timestamp >= current_time - time_window)

            if request_count > threshold:
                print("Alert: HTTP Flood Detected! Rate:", request_count, "requests/second")

        except Exception as e:
            print(f"Error processing packet: {e}")

if __name__ == "__main__":
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:", interfaces)

    if interfaces:
        interface = input("Enter the interface name you want to use: ")
        detect_http_flood(interface)
    else:
        print("No interfaces found.")
