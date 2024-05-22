from Scanning.syn_detection import *
import subprocess
import Attack.icmp_attack
import Attack.syn_attack
import Attack.http_flood_attack
import Attack.port_attack


def main():
    root = tk.Tk()
    root.title("Attacker ")

    # Create a notebook (tabbed interface)
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)

    # Attack tab
    attack_tab = ttk.Frame(notebook)
    notebook.add(attack_tab, text='Syn Attack')

    attack_label = ttk.Label(attack_tab, text="Enter Target IP Address:")
    attack_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

    attack_ip_entry = ttk.Entry(attack_tab)
    attack_ip_entry.grid(row=0, column=1, padx=5, pady=5)

    attack_button = ttk.Button(attack_tab, text="Launch Attack", command=lambda:
    Attack.syn_attack.launch_attack(attack_ip_entry.get()))
    attack_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

    # HTTP Attack
    http_tab = ttk.Frame(notebook)
    notebook.add(http_tab, text='HTTP Attack')

    http_label = ttk.Label(http_tab, text="Enter Target IP Address:")
    http_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

    http_ip_entry = ttk.Entry(http_tab)
    http_ip_entry.grid(row=0, column=1, padx=5, pady=5)

    http_button = ttk.Button(http_tab, text="Launch Attack", command=lambda:
            Attack.http_flood_attack.send_http_requests(http_ip_entry.get(),0.5))
    http_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

    # ICMP Attack
    icmp_tab = ttk.Frame(notebook)
    notebook.add(icmp_tab, text='ICMP Attack')

    icmp_label = ttk.Label(icmp_tab, text="Enter Target IP Address:")
    icmp_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

    icmp_ip_entry = ttk.Entry(icmp_tab)
    icmp_ip_entry.grid(row=0, column=1, padx=5, pady=5)

    icmp_button = ttk.Button(icmp_tab, text="Launch Attack", command=lambda:
    Attack.icmp_attack.send_icmp_packets(icmp_ip_entry.get(),20))
    icmp_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

    # Port Attack
    attack_tab=ttk.Frame(notebook)
    notebook.add(attack_tab,text="Port Attack")
    attack_label = ttk.Label(attack_tab, text="Enter Target IP Address:")
    attack_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

    attack_ip_entry = ttk.Entry(attack_tab)
    attack_ip_entry.grid(row=0, column=1, padx=5, pady=5)

    port_label = ttk.Label(attack_tab, text="Enter Target Port:")
    port_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")

    port_entry = ttk.Entry(attack_tab)
    port_entry.grid(row=1, column=1, padx=5, pady=5)

    attack_button = ttk.Button(attack_tab, text="Launch Attack", command=lambda:
    Attack.port_attack.launch_attack(
        attack_ip_entry.get(),
        int(port_entry.get())
    )
                               )
    attack_button.grid(row=4, column=0, columnspan=2, padx=5, pady=10)
    root.mainloop()


if __name__ == "__main__":
    main()
