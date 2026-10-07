#from phone to pc


import requests
import time

PC_IP = "172.16.12.190"
#TARGET_IP = "192.168.43.31"

PORT = 8080

URL = f"http://{PC_IP}:{PORT}/login"

ATTEMPTS = 30
DELAY = 0.15

print("======================================")
print(" AI-NIDS Controlled Brute Force Test")
print("======================================")
print(f"Target: {URL}")
print(f"Attempts: {ATTEMPTS}")
print()

for i in range(1, ATTEMPTS + 1):

    username = f"testuser{i}"
    password = f"wrongpassword{i}"

    try:
        response = requests.post(
            URL,
            json={
                "username": username,
                "password": password
            },
            timeout=2
        )

        print(
            f"[{i:02d}/{ATTEMPTS}] "
            f"HTTP {response.status_code}"
        )

    except requests.RequestException as e:
        print(f"[{i:02d}/{ATTEMPTS}] Connection error: {e}")

    time.sleep(DELAY)

print()
print("Test completed.")