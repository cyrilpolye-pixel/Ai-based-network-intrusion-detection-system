import socket
import time

TARGET_IP = "172.16.12.190"
PORT = 8080

# Exceeds TCP_SYN_FLOOD_THRESHOLD (30 SYNs within 5 seconds)
SYN_COUNT = 45
DELAY = 0.03

print("=" * 70)
print("AI-NIDS CONTROLLED TCP CONNECTION FLOOD TEST")
print("=" * 70)
print(f"Target: {TARGET_IP}:{PORT}")
print(f"Packets to send: {SYN_COUNT}")
print("Press CTRL+C to stop.")
print("=" * 70)

sent = 0
try:
    for i in range(1, SYN_COUNT + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            sock.connect_ex((TARGET_IP, PORT))
            sent += 1
            print(f"[{i:02d}/{SYN_COUNT}] Sent TCP connection packet to port {PORT}")
        except Exception as e:
            print(f"[{i:02d}/{SYN_COUNT}] Error: {e}")
        finally:
            sock.close()

        time.sleep(DELAY)

except KeyboardInterrupt:
    print("\nTest stopped by user.")

print()
print("=" * 70)
print("TCP CONNECTION FLOOD TEST COMPLETE")
print("=" * 70)
print(f"Total connections initiated: {sent}")
print("=" * 70)
