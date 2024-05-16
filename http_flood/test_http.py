import requests
import time

def send_http_requests(server_url, interval):
    while True:
        try:
            response = requests.get(server_url)
            print("HTTP request sent to", server_url, "Status code:", response.status_code)
        except Exception as e:
            print("Error:", e)
        time.sleep(interval)

if __name__ == "__main__":
    server_url = "http://localhost:8000" #EC2 aws-instance public ip address
    interval = 0.1  # Interval between each HTTP request in seconds

    send_http_requests(server_url, interval)


