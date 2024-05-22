import subprocess

def launch_attack(target_ip, target_port):
    try:
        subprocess.run([
            "nping", "--tcp", "--flags", "ACK", "-p", str(target_port), "--count", "100", target_ip
        ], check=True)
    except subprocess.CalledProcessError as e:
        print("Error occurred:", e)

if __name__ == "main":
    target_ip = input("Enter target IP: ")
    target_port = int(input("Enter target port: "))

    launch_attack(target_ip, target_port)