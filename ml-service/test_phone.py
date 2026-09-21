import socket
import time

# YOUR PC on the phone hotspot
TARGET_IP = "192.168.43.31"

# Controlled test range
START_PORT = 1
END_PORT = 200

DELAY = 0.05

print("=" * 70)
print("AI-NIDS CONTROLLED PORTSCAN TEST")
print("=" * 70)
print(f"Target: {TARGET_IP}")
print(f"Ports : {START_PORT} - {END_PORT}")
print()
print("This test targets only your own PC.")
print("Press CTRL+C to stop.")
print("=" * 70)

scanned = 0
open_ports = []

try:
    for port in range(START_PORT, END_PORT + 1):

        scanned += 1

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)

        try:
            result = sock.connect_ex((TARGET_IP, port))

            if result == 0:
                open_ports.append(port)
                print(f"[OPEN]  Port {port}")

            else:
                print(f"[SCAN]  Port {port}")

        except Exception as e:
            print(f"[ERROR] Port {port}: {e}")

        finally:
            sock.close()

        time.sleep(DELAY)

except KeyboardInterrupt:
    print("\nTest stopped by user.")

print()
print("=" * 70)
print("PORTSCAN TEST COMPLETE")
print("=" * 70)
print(f"Ports scanned: {scanned}")
print(f"Open ports   : {open_ports}")
print("=" * 70)


