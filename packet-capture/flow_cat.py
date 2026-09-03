# ============================================================
# AI-NIDS LIVE NETWORK CAPTURE
# PART 1 OF 2
# ============================================================

import threading
import time
from datetime import datetime

import requests

from scapy.all import sniff, IP, TCP, UDP

from feat import FEATURE_NAMES, calculate_features


# ============================================================
# CONFIGURATION
# ============================================================

# IP address of this computer
PC_IP = "192.168.43.31"


# ------------------------------------------------------------
# MONITORING MODE
# ------------------------------------------------------------
#
# We are currently testing controlled PortScan traffic.
#
# The old configuration was:
#
#     MONITORED_PORTS = {8000}
#
# That would only capture traffic involving port 8000.
#
# For PortScan testing, we need to capture multiple TCP
# destination ports.
#
# Therefore we monitor TCP traffic involving the PC and
# allow the packet filter below to decide what is useful.
#
# ------------------------------------------------------------

PORTSCAN_TEST_MODE = True


# Ports belonging to services that should NOT become
# monitored application flows.
IGNORED_PORTS = {
    5001,       # ML service
}


# Optional: keep this set empty during PortScan testing.
#
# If later you want to monitor only specific application
# ports, you can put them here.
#
# Example:
#
# MONITORED_PORTS = {3000, 5000}
#
MONITORED_PORTS = set()


# ML service
ML_API_URL = "http://127.0.0.1:5001/predict"


# Flow timeout
FLOW_TIMEOUT = 3.0


# Output file
OUTPUT_FILE = "flow_output.txt"


# ============================================================
# GLOBAL DATA
# ============================================================

flows = {}

stop_event = threading.Event()

lock = threading.Lock()


# ============================================================
# OUTPUT
# ============================================================

def clear_output_file():

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "AI-NIDS LIVE NETWORK CAPTURE\n"
        )

        f.write(
            "=" * 70 + "\n"
        )

        f.write(
            f"Started: {datetime.now()}\n"
        )

        f.write(
            f"PC IP: {PC_IP}\n"
        )

        if PORTSCAN_TEST_MODE:

            f.write(
                "Mode: CONTROLLED PORTSCAN TEST\n"
            )

        else:

            f.write(
                f"Monitored Ports: "
                f"{sorted(MONITORED_PORTS)}\n"
            )

        f.write(
            f"Ignored Ports: "
            f"{sorted(IGNORED_PORTS)}\n"
        )

        f.write(
            f"ML API: {ML_API_URL}\n"
        )

        f.write(
            "=" * 70 + "\n\n"
        )


def write_output(text):

    with open(
        OUTPUT_FILE,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(text)

        f.flush()


# ============================================================
# PACKET FILTERING
# ============================================================

def packet_is_useful(packet):

    # We only process IPv4 packets.
    if not packet.haslayer(IP):

        return False


    ip = packet[IP]


    # --------------------------------------------------------
    # Only traffic involving our PC
    # --------------------------------------------------------

    if (
        ip.src != PC_IP
        and
        ip.dst != PC_IP
    ):

        return False


    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        sport = int(packet[TCP].sport)

        dport = int(packet[TCP].dport)


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        sport = int(packet[UDP].sport)

        dport = int(packet[UDP].dport)


    else:

        return False


    # --------------------------------------------------------
    # Ignore internal service ports
    # --------------------------------------------------------

    if (
        sport in IGNORED_PORTS
        or
        dport in IGNORED_PORTS
    ):

        return False


    # --------------------------------------------------------
    # PortScan testing
    # --------------------------------------------------------

    if PORTSCAN_TEST_MODE:

        # For the controlled PortScan test we need to see
        # traffic involving many destination ports.
        #
        # We therefore do NOT restrict traffic to port 8000.

        return True


    # --------------------------------------------------------
    # Normal application monitoring mode
    # --------------------------------------------------------

    if (
        sport not in MONITORED_PORTS
        and
        dport not in MONITORED_PORTS
    ):

        return False


    return True


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_information(packet):

    ip = packet[IP]


    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        sport = int(packet[TCP].sport)

        dport = int(packet[TCP].dport)


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        sport = int(packet[UDP].sport)

        dport = int(packet[UDP].dport)


    else:

        return None


    src = ip.src

    dst = ip.dst


    # --------------------------------------------------------
    # Canonical bidirectional flow key
    # --------------------------------------------------------

    endpoint1 = (
        src,
        sport
    )

    endpoint2 = (
        dst,
        dport
    )


    if endpoint1 <= endpoint2:

        key = (
            src,
            sport,
            dst,
            dport,
            protocol
        )

    else:

        key = (
            dst,
            dport,
            src,
            sport,
            protocol
        )


    return {
        "key": key,

        "src_ip": src,

        "src_port": sport,

        "dst_ip": dst,

        "dst_port": dport,

        "protocol": protocol,
    }


# ============================================================
# ML PREDICTION
# ============================================================

def send_to_ml(features):

    payload = {
        "features": features
    }


    try:

        response = requests.post(
            ML_API_URL,
            json=payload,
            timeout=10
        )


        response.raise_for_status()


        return response.json()


    except Exception as e:

        return {
            "error": str(e)
        }


# ============================================================
# PROCESS FLOW
# ============================================================

def process_flow(flow):

    try:

        features = calculate_features(flow)


    except Exception as e:

        print(
            f"[ERROR] Feature extraction failed: {e}"
        )


        write_output(
            f"[ERROR] Feature extraction failed: {e}\n\n"
        )


        return


    # --------------------------------------------------------
    # Verify that exactly 78 features were generated
    # --------------------------------------------------------

    if len(features) != 78:

        error_message = (
            f"Feature count error: "
            f"expected 78, got {len(features)}"
        )


        print(
            f"[ERROR] {error_message}"
        )


        write_output(
            f"[ERROR] {error_message}\n\n"
        )


        return


    # --------------------------------------------------------
    # Send to ML service
    # --------------------------------------------------------

    prediction = send_to_ml(features)


    # --------------------------------------------------------
    # Console output
    # --------------------------------------------------------

    print(
        "\n"
        + "=" * 70
    )


    print(
        f"FLOW: "
        f"{flow['src_ip']}:{flow['src_port']} "
        f"<-> "
        f"{flow['dst_ip']}:{flow['dst_port']} "
        f"| {flow['protocol']}"
    )


    print(
        f"Packets: {len(flow['packets'])}"
    )


    print(
        f"Prediction: {prediction}"
    )


    print(
        "=" * 70
    )


    # --------------------------------------------------------
    # TEXT FILE
    # --------------------------------------------------------

    output = []


    output.append(
        "\n"
        + "=" * 70
        + "\n"
    )


    output.append(
        "FLOW\n"
    )


    output.append(
        f"{flow['src_ip']}:{flow['src_port']} "
        f"<-> "
        f"{flow['dst_ip']}:{flow['dst_port']} "
        f"| {flow['protocol']}\n"
    )


    output.append(
        f"Packets: {len(flow['packets'])}\n"
    )


    output.append(
        f"Start Time: {flow['first_time']}\n"
    )


    output.append(
        f"End Time: {flow['last_time']}\n"
    )


    output.append(
        "\n78 ML FEATURES\n"
    )


    output.append(
        "-" * 70
        + "\n"
    )


    for i, (
        name,
        value
    ) in enumerate(
        zip(
            FEATURE_NAMES,
            features
        ),
        start=1
    ):

        output.append(
            f"{i:02d}. {name}: {value}\n"
        )


    output.append(
        "\nML PREDICTION\n"
    )


    output.append(
        "-" * 70
        + "\n"
    )


    output.append(
        f"{prediction}\n"
    )


    output.append(
        "=" * 70
        + "\n"
    )


    write_output(
        "".join(output)
    )
# ============================================================
# AI-NIDS LIVE NETWORK CAPTURE
# PART 2 OF 2
# ============================================================


# ============================================================
# FLOW TIMEOUT
# ============================================================

def flow_expiration_worker():

    while not stop_event.is_set():

        time.sleep(1)

        now = time.time()

        expired = []


        with lock:

            for key, flow in list(
                flows.items()
            ):

                if (
                    now - flow["last_seen"]
                    >= FLOW_TIMEOUT
                ):

                    expired.append(
                        (key, flow)
                    )

                    del flows[key]


        # Process expired flows outside the lock
        for key, flow in expired:

            process_flow(flow)


# ============================================================
# PACKET HANDLER
# ============================================================

def handle_packet(packet):

    # --------------------------------------------------------
    # Ignore packets that aren't relevant
    # --------------------------------------------------------

    if not packet_is_useful(packet):

        return


    # --------------------------------------------------------
    # Extract flow information
    # --------------------------------------------------------

    info = get_flow_information(packet)


    if info is None:

        return


    key = info["key"]

    now = time.time()


    # --------------------------------------------------------
    # Add packet to flow
    # --------------------------------------------------------

    with lock:

        if key not in flows:

            flows[key] = {

                "src_ip":
                    info["src_ip"],

                "src_port":
                    info["src_port"],

                "dst_ip":
                    info["dst_ip"],

                "dst_port":
                    info["dst_port"],

                "protocol":
                    info["protocol"],

                "packets":
                    [],

                "first_time":
                    now,

                "last_time":
                    now,

                "last_seen":
                    now,
            }


        flow = flows[key]


        flow["packets"].append(
            packet
        )


        flow["last_time"] = now

        flow["last_seen"] = now


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Prepare output file
    # --------------------------------------------------------

    clear_output_file()


    # --------------------------------------------------------
    # Console header
    # --------------------------------------------------------

    print(
        "\nAI-NIDS LIVE PACKET CAPTURE"
    )


    print(
        "=" * 70
    )


    print(
        f"PC IP           : {PC_IP}"
    )


    if PORTSCAN_TEST_MODE:

        print(
            "Mode            : "
            "CONTROLLED PORTSCAN TEST"
        )

        print(
            "Port filtering  : "
            "DISABLED FOR TEST"
        )

    else:

        print(
            f"Monitored Ports : "
            f"{sorted(MONITORED_PORTS)}"
        )


    print(
        f"Ignored Ports   : "
        f"{sorted(IGNORED_PORTS)}"
    )


    print(
        f"ML API          : {ML_API_URL}"
    )


    print(
        f"Output File     : {OUTPUT_FILE}"
    )


    print(
        "\nStarting packet capture..."
    )


    print(
        "Press CTRL+C to stop.\n"
    )


    # --------------------------------------------------------
    # Start flow expiration worker
    # --------------------------------------------------------

    worker = threading.Thread(
        target=flow_expiration_worker,
        daemon=True
    )


    worker.start()


    # --------------------------------------------------------
    # Start Scapy capture
    # --------------------------------------------------------

    try:

        sniff(

            # Only capture IPv4 traffic.
            #
            # packet_is_useful() performs the more detailed
            # filtering afterward.

            filter="ip",

            prn=handle_packet,

            store=False,

            stop_filter=lambda _: (
                stop_event.is_set()
            )
        )


    except KeyboardInterrupt:

        print(
            "\nStopping capture..."
        )


    finally:

        stop_event.set()


        # ----------------------------------------------------
        # Process flows still in memory
        # ----------------------------------------------------

        remaining = []


        with lock:

            for key, flow in flows.items():

                remaining.append(
                    flow
                )


            flows.clear()


        # ----------------------------------------------------
        # Send remaining flows to ML
        # ----------------------------------------------------

        for flow in remaining:

            process_flow(flow)


        print(
            "\nCapture stopped."
        )


        print(
            f"Results saved to "
            f"{OUTPUT_FILE}"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()