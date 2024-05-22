import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk
from IDS import *


def format_timestamp(timestamp):
    timestamp = int(timestamp)
    # Convert timestamp to datetime object
    dt_object = datetime.fromtimestamp(timestamp)
    # Format datetime to desired format (without year)
    formatted_timestamp = dt_object.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_timestamp


def refresh_table():
    tree.delete(*tree.get_children())
    rows = print_database()
    if rows is not None:
        for row in rows:
            row = list(row)  # Convert tuple to list for modification
            row[2] = format_timestamp(row[2])  # Index 1 is the timestamp column
            tree.insert("", "end", values=row)
    root.after(3500, refresh_table)


def create_gui():
    global tree, root
    root = tk.Tk()
    root.title("Host Based Intrusion Detection System")

    tree = ttk.Treeview(root)
    tree["columns"] = ("ID", "Attack Type", "Timestamp", "Attacker IP", "Interface")
    tree.heading("ID", text="ID", anchor=tk.CENTER)
    tree.column("ID", minwidth=20, width=20)
    tree.heading("Attack Type", text="Attack Type", anchor=tk.CENTER)
    tree.column("Attack Type", minwidth=350, width=350)
    tree.heading("Timestamp", text="Timestamp", anchor=tk.CENTER)
    tree.column("Timestamp", minwidth=350, width=350)
    tree.heading("Attacker IP", text="Attacker IP", anchor=tk.CENTER)
    tree.column("Attacker IP", minwidth=350, width=350)
    tree.heading("Interface", text="Interface", anchor=tk.CENTER)
    tree.column("Interface", minwidth=150, width=150)
    tree.pack(expand=True, fill="both")

    refresh_table()

    root.mainloop()


def gui_thread_wrapper():
    create_gui()


if __name__ == "__main__":
    create_database()
    interfaces = psutil.net_if_addrs().keys()
    print("Available interfaces:", interfaces)

    if interfaces:
        interface = 'WiFi'
        print("Sniffing on interface:", interface)

        # Create and start threads for each detection function
        icmp_thread = threading.Thread(target=icmp_detection_wrapper, args=(interface,))
        http_thread = threading.Thread(target=http_detection_wrapper, args=(interface,))
        syn_thread = threading.Thread(target=syn_detection_wrapper, args=(interface,))
        port_thread = threading.Thread(target=port_detection_wrapper, args=(interface,))
        gui_thread = threading.Thread(target=gui_thread_wrapper)

        icmp_thread.start()
        http_thread.start()
        syn_thread.start()
        port_thread.start()
        gui_thread.start()

        # Join threads to wait for them to complete
        icmp_thread.join()
        http_thread.join()
        syn_thread.join()
        port_thread.join()
        gui_thread.join()

        print("Detection complete.")
