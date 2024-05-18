import pyshark
import psutil
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import asyncio
import time

SYN_COUNT_THRESHOLD = 10
TIME_WINDOW = 10
syn_count = 0
last_reset_time = time.time()
sniffing_status = False
attacker_ip = None

def sniff_packets(interface, ip_address, packet_list, status_label):
    global syn_count, last_reset_time, sniffing_status, attacker_ip

    print(f"Sniffing TCP SYN packets on interface {interface} for IP address {ip_address}")

    def packet_handler(packet):
        global syn_count, last_reset_time, attacker_ip

        if 'IP' in packet and 'TCP' in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            tcp_flags = packet.tcp.flags
            tcp_src_port = packet.tcp.srcport
            tcp_dst_port = packet.tcp.dstport

            if tcp_flags == '0x0002':
                syn_count += 1

                if syn_count > SYN_COUNT_THRESHOLD:
                    attacker_ip = ip_src

            packet_info = (
                f"Source IP: {ip_src}\n"
                f"Destination IP: {ip_dst}\n"
                f"TCP Flags: {tcp_flags}\n"
                f"Source Port: {tcp_src_port}\n"
                f"Destination Port: {tcp_dst_port}\n"
            )

            print(packet_info)

            packet_list.insert(tk.END, packet_info)

            current_time = time.time()
            if current_time - last_reset_time > TIME_WINDOW:
                check_syn_count(status_label)  # Pass status_label to the function
                syn_count = 0
                last_reset_time = current_time

    try:
        sniffing_status = True

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=f'tcp.flags.syn==1 && tcp.flags.ack==0 && ip.addr=={ip_address}'
        )

        for pkt in capture.sniff_continuously():
            if not sniffing_status:
                break
            packet_handler(pkt)

        capture.close()

        status_label.config(text="Packet sniffing stopped")

    except Exception as e:
        print("Error occurred while capturing packets:", e)
        status_label.config(text=f"Error: {e}")

    finally:
        loop.close()

def check_syn_count(status_label):  # Pass status_label as parameter
    global syn_count

    if syn_count > SYN_COUNT_THRESHOLD:
        messagebox.showwarning("Possible SYN Flood", "SYN Flood Detected!")
        status_label.config(text="Possible SYN Flood Detected!")  # Update status_label

def start_sniffing(interface_var, ip_entry, packet_list, status_label):
    global sniffing_status

    interface = interface_var.get()
    ip_address = ip_entry.get()

    if not interface:
        messagebox.showerror("Error", "Please select a network interface")
        return
    if not ip_address:
        messagebox.showerror("Error", "Please enter an IP address to monitor")
        return

    packet_list.delete(0, tk.END)

    sniffing_status = True

    sniff_thread = threading.Thread(
        target=sniff_packets, args=(interface, ip_address, packet_list, status_label)
    )
    sniff_thread.start()

    status_label.config(text="Packet sniffing in progress...")

def stop_sniffing():
    global sniffing_status

    sniffing_status = False

    # No need to update status_label here as sniffing is already stopped

def update_syn_count_label(syn_count_label):
    global syn_count
    syn_count_label.config(text=f"SYN Count: {syn_count}")
    syn_count_label.after(1000, lambda: update_syn_count_label(syn_count_label))  # Update every second
