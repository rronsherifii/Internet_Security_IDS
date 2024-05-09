import pyshark
import psutil



def sniff_icmp_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="icmp")
    print("Sniffing ICMP packets on interface:", interface)
    for packet in capture.sniff_continuously():
        if "ICMP" in packet:
            print(packet)


if __name__ == "__main__":
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:", interfaces)

    if interfaces:
        interface = 'Wi-Fi' #next(iter(interfaces))  # Choose the first interface
        print("Sniffing on interface:", interface)

        packets = sniff_icmp_packets(interface)
        print("Sniffed", len(packets), "packets:")
        for i, packet in enumerate(packets, 1):
            print("Packet", i, ":", packet)
    else:
        print("No interfaces found.")
