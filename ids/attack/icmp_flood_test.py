import subprocess
import time
import platform

TARGET_IP = "172.16.12.190"

# Exceeds ICMP_FLOOD_THRESHOLD (20 packets within 5 seconds)
PING_COUNT = 30

print("=" * 70)
print("AI-NIDS CONTROLLED ICMP PING FLOOD TEST")
print("=" * 70)
print(f"Target: {TARGET_IP}")
print(f"Pings to send: {PING_COUNT}")
print("Press CTRL+C to stop.")
print("=" * 70)

is_windows = platform.system().lower() == "windows"

sent = 0
try:
    if is_windows:
        # On Windows, ping -n sends the specified number of echo requests
        cmd = ["ping", "-n", str(PING_COUNT), "-w", "500", TARGET_IP]
        print(f"Executing: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in process.stdout:
            line_str = line.strip()
            if line_str:
                print(f"[ICMP] {line_str}")
        process.wait()
    else:
        # On Linux/Unix, ping -c with fast interval -i 0.1
        cmd = ["ping", "-c", str(PING_COUNT), "-i", "0.1", TARGET_IP]
        print(f"Executing: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in process.stdout:
            line_str = line.strip()
            if line_str:
                print(f"[ICMP] {line_str}")
        process.wait()

except KeyboardInterrupt:
    print("\nTest stopped by user.")

print()
print("=" * 70)
print("ICMP FLOOD TEST COMPLETE")
print("=" * 70)
