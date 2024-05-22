import socket
import threading
from datetime import datetime

def scan_ports(target, start_port, end_port, num_threads=100):
    # Print a banner with information on the target
    print("_" * 50)
    print("Scanning Target: " + target)
    print("Scanning started at: " + str(datetime.now()))
    print("_" * 50)

    # Function to scan a single port
    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print("[*] Port {} is open".format(port))
            s.close()
        except socket.error:
            print(f"Error scanning port {port}")
        except Exception as e:
            print(f"Unexpected error scanning port {port}: {e}")

    # Function to handle threading for port scanning
    def threader(ports):
        for port in ports:
            scan_port(port)

    # Splitting the range of ports into chunks for threading
    def split_ports(range_start, range_end, num_chunks):
        ports = list(range(range_start, range_end + 1))
        chunk_size = len(ports) // num_chunks
        return [ports[i * chunk_size:(i + 1) * chunk_size] for i in range(num_chunks)]

    # Split ports into chunks
    ports_chunks = split_ports(start_port, end_port, num_threads)

    # Creating threads
    threads = []
    for chunk in ports_chunks:
        thread = threading.Thread(target=threader, args=(chunk,))
        threads.append(thread)
        thread.start()

    # Joining threads
    for thread in threads:
        thread.join()

    print("Scanning completed at: " + str(datetime.now()))

# Example usage:
if __name__ == "__main__":
    target = input("Target IP: ")
    scan_ports(target, 1, 65535)

