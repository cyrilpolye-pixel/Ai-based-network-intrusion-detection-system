# ============================================================
# AI-NIDS CAPTURE CONFIGURATION
# ============================================================

import socket


# ============================================================
# AUTOMATIC LOCAL IP DETECTION
# ============================================================

def get_local_ip():
    """
    Automatically determine the local IPv4 address used by
    this computer's active network connection.

    Works with normal Ethernet/LAN, Wi-Fi, and mobile
    hotspot connections.

    No actual network connection is made.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        # This causes Windows to select the IP address
        # associated with the active route.
        #
        # No data is actually sent to this address.
        sock.connect(
            ("8.8.8.8", 80)
        )

        local_ip = sock.getsockname()[0]

    except Exception:

        # Fallback if route detection fails.
        local_ip = socket.gethostbyname(
            socket.gethostname()
        )

    finally:

        sock.close()

    return local_ip


# Automatically detect the IP of this computer.
PC_IP = get_local_ip()


# ============================================================
# MONITORING MODE
# ============================================================

# True  = controlled PortScan testing
# False = normal application/network monitoring

PORTSCAN_TEST_MODE = True


# ============================================================
# IGNORED PORTS
# ============================================================

# Traffic involving these ports will NOT be processed
# as monitored network flows.

IGNORED_PORTS = {
    53,        # DNS
    5001,      # AI-NIDS ML service
}


# ============================================================
# NORMAL APPLICATION MONITORING
# ============================================================

# Used when PORTSCAN_TEST_MODE = False.
#
# Example:
#
# MONITORED_PORTS = {3000, 5000}
#
# Keep empty during PortScan testing.

MONITORED_PORTS = set()


# ============================================================
# ML SERVICE
# ============================================================

ML_API_URL = "http://127.0.0.1:5001/predict"


# ============================================================
# FLOW SETTINGS
# ============================================================

# A flow is processed after no new packet is seen
# for this number of seconds.

FLOW_TIMEOUT = 3.0


# ============================================================
# BEHAVIORAL ATTACK DETECTION THRESHOLDS
# ============================================================

# 1. PortScan
PORTSCAN_PORT_THRESHOLD = 10
PORTSCAN_WINDOW = 5.0

# 2. BruteForce (rapid attempts to authentication or service ports)
BRUTEFORCE_THRESHOLD = 8
BRUTEFORCE_WINDOW = 10.0
AUTH_SERVICE_PORTS = {8080, 80, 443, 21, 22, 23, 3389, 25, 110, 143}

# 3. HTTP DoS (high-frequency HTTP request bursts)
HTTP_DOS_THRESHOLD = 25
HTTP_DOS_WINDOW = 5.0
HTTP_PORTS = {80, 443, 8080, 5000, 3000, 8000}

# 4. TCP Connection Flood (SYN Flood targeting single port)
TCP_SYN_FLOOD_THRESHOLD = 30
TCP_SYN_FLOOD_WINDOW = 3.0

# 5. UDP Flood (high volumetric datagram flood)
UDP_FLOOD_THRESHOLD = 35
UDP_FLOOD_WINDOW = 3.0

# 6. ICMP Flood (Ping of death / echo request flood)
ICMP_FLOOD_THRESHOLD = 20
ICMP_FLOOD_WINDOW = 3.0


# ============================================================
# OUTPUT
# ============================================================

OUTPUT_FILE = "flow_output.txt"


# ============================================================
# STARTUP INFORMATION
# ============================================================

print(
    f"[AI-NIDS] Automatically detected local IP: {PC_IP}"
)












