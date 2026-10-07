import requests
import time

# Target IP (Matches PC_IP / test server)
TARGET_IP = "172.16.12.190"
PORT = 8080
URL = f"http://{TARGET_IP}:{PORT}/"

# Burst parameters to exceed HTTP_DOS_THRESHOLD (25 requests)
REQUEST_COUNT = 40
DELAY = 0.05

print("=" * 70)
print("AI-NIDS CONTROLLED HTTP DoS TEST")
print("=" * 70)
print(f"Target: {URL}")
print(f"Requests: {REQUEST_COUNT}")
print("Press CTRL+C to stop.")
print("=" * 70)

sent = 0
try:
    for i in range(1, REQUEST_COUNT + 1):
        try:
            resp = requests.get(URL, timeout=1.5)
            print(f"[{i:02d}/{REQUEST_COUNT}] HTTP {resp.status_code}")
            sent += 1
        except requests.RequestException as e:
            print(f"[{i:02d}/{REQUEST_COUNT}] Sent request ({e})")
            sent += 1

        time.sleep(DELAY)

except KeyboardInterrupt:
    print("\nTest stopped by user.")

print()
print("=" * 70)
print("HTTP DoS TEST COMPLETE")
print("=" * 70)
print(f"Total requests sent: {sent}")
print("=" * 70)
