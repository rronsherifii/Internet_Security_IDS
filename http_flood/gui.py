import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from threading import Thread
import requests
import time
import pyshark
from collections import defaultdict
import psutil
import asyncio


# Global variables
http_requests = defaultdict(int)
threshold = 20
time_window = 7
stop_detection = False

def detect_http_flood(interface):
    global stop_detection
    asyncio.set_event_loop(asyncio.new_event_loop())  # Create a new event loop for this thread
    capture = pyshark.LiveCapture(interface=interface, display_filter="http")  # Filter for HTTP packets (port 80)
    print("Sniffing HTTP packets on interface:", interface)

    start_time = time.time()
    for packet in capture.sniff_continuously():
        if stop_detection:
            break
        if "HTTP" in packet:
            http_requests[time.time()] += 1

        # Calculate the rate of HTTP requests within the time window
        current_time = time.time()
        request_count = sum(http_requests[timestamp] for timestamp in http_requests if timestamp >= current_time - time_window)

        if request_count > threshold:
            messagebox.showwarning("HTTP Flood Detected", f"HTTP Flood Detected! Rate: {request_count} requests/second")

def send_http_requests(server_url, interval):
    while True:
        try:
            response = requests.get(server_url)
            print("HTTP request sent to", server_url, "Status code:", response.status_code)
        except Exception as e:
            print("Error:", e)
        time.sleep(interval)

def start_detection(interface):
    global stop_detection
    stop_detection = False
    Thread(target=detect_http_flood, args=(interface,)).start()

def stop_detection():
    global stop_detection
    stop_detection = True

def start_sending_requests(server_url, interval):
    Thread(target=send_http_requests, args=(server_url, interval)).start()

def create_gui():
    root = tk.Tk()
    root.title("HTTP Flood Detection")

    tab_control = ttk.Notebook(root)

    detection_tab = ttk.Frame(tab_control)
    request_tab = ttk.Frame(tab_control)

    tab_control.add(detection_tab, text="Detection")
    tab_control.add(request_tab, text="Request Sending")

    tab_control.pack(expand=1, fill="both")

    # Detection Tab
    detection_frame = ttk.Frame(detection_tab)
    detection_frame.pack(padx=20, pady=20)

    lbl_interface = ttk.Label(detection_frame, text="Interface:")
    lbl_interface.grid(row=0, column=0, padx=5, pady=5)

    interface_var = tk.StringVar()
    entry_interface = ttk.Entry(detection_frame, textvariable=interface_var)
    entry_interface.grid(row=0, column=1, padx=5, pady=5)

    btn_start_detection = ttk.Button(detection_frame, text="Start Detection", command=lambda: start_detection(interface_var.get()))
    btn_start_detection.grid(row=1, column=0, padx=5, pady=5)

    btn_stop_detection = ttk.Button(detection_frame, text="Stop Detection", command=stop_detection)
    btn_stop_detection.grid(row=1, column=1, padx=5, pady=5)

    # Request Sending Tab
    request_frame = ttk.Frame(request_tab)
    request_frame.pack(padx=20, pady=20)

    lbl_server_url = ttk.Label(request_frame, text="Server URL:")
    lbl_server_url.grid(row=0, column=0, padx=5, pady=5)

    server_url_var = tk.StringVar()
    entry_server_url = ttk.Entry(request_frame, textvariable=server_url_var)
    entry_server_url.grid(row=0, column=1, padx=5, pady=5)

    lbl_interval = ttk.Label(request_frame, text="Interval (s):")
    lbl_interval.grid(row=1, column=0, padx=5, pady=5)

    interval_var = tk.DoubleVar()
    entry_interval = ttk.Entry(request_frame, textvariable=interval_var)
    entry_interval.grid(row=1, column=1, padx=5, pady=5)

    btn_start_sending = ttk.Button(request_frame, text="Start Sending", command=lambda: start_sending_requests(server_url_var.get(), interval_var.get()))
    btn_start_sending.grid(row=2, column=0, padx=5, pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
