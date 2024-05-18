import tkinter as tk
from datetime import datetime
from tkinter import ttk

from Scanning.IDS import print_database

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
    tree["columns"] = ("ID","Attack Type", "Timestamp", "Attacker IP", "Interface")
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

create_gui()
