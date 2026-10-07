import socket
import time

TARGET_IP = "172.16.12.190"
PORT = 9999

# Exceeds UDP_FLOOD_THRESHOLD (35 UDP datagrams within 5 seconds)
PACKET_COUNT = 50
DELAY = 0.02
PAYLOAD = b"AI-NIDS_CONTROLLED_UDP_TEST_PAYLOAD" * 2

print("=" * 70)
print("AI-NIDS CONTROLLED UDP FLOOD TEST")
print("=" * 70)
print(f"Target: {TARGET_IP}:{PORT}")
print(f"Packets to send: {PACKET_COUNT}")
print("Press CTRL+C to stop.")
print("=" * 70)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent = 0

try:
    for i in range(1, PACKET_COUNT + 1):
        try:
            sock.sendto(PAYLOAD, (TARGET_IP, PORT))
            sent += 1
            print(f"[{i:02d}/{PACKET_COUNT}] Sent UDP packet to port {PORT}")
        except Exception as e:
            print(f"[{i:02d}/{PACKET_COUNT}] Send error: {e}")

        time.sleep(DELAY)

except KeyboardInterrupt:
    print("\nTest stopped by user.")
finally:
    sock.close()

print()
print("=" * 70)
print("UDP FLOOD TEST COMPLETE")
print("=" * 70)
print(f"Total UDP packets sent: {sent}")
print("=" * 70)
