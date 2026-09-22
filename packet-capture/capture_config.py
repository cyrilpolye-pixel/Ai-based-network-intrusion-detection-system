# ============================================================
# AI-NIDS CAPTURE CONFIGURATION
# ============================================================

# IP address of this computer
PC_IP = "172.16.12.190"
#PC_IP = "192.168.43.31"



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
# OUTPUT
# ============================================================

OUTPUT_FILE = "flow_output.txt"
