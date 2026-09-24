# ============================================================
# AI-NIDS LIVE NETWORK CAPTURE
# ============================================================

import threading
import time
from datetime import datetime

import requests

from scapy.all import sniff, IP, TCP, UDP

from feat import FEATURE_NAMES, calculate_features

from capture_config import (
    PC_IP,
    PORTSCAN_TEST_MODE,
    IGNORED_PORTS,
    MONITORED_PORTS,
    ML_API_URL,
    FLOW_TIMEOUT,
    OUTPUT_FILE,
)


# ============================================================
# GLOBAL DATA
# ============================================================

flows = {}

stop_event = threading.Event()

lock = threading.Lock()


# ============================================================
# PORTSCAN DETECTION CONFIGURATION
# ============================================================

# Number of DIFFERENT destination ports contacted by the
# same source against the same target within PORTSCAN_WINDOW
# before declaring a PortScan.
#
# Example:
#
# PC2 -> PC1:1
# PC2 -> PC1:2
# PC2 -> PC1:3
# ...
# PC2 -> PC1:10
#
# => PortScan
#
PORTSCAN_PORT_THRESHOLD = 10


# Time period in which the distinct ports are counted.
#
# 5 seconds is suitable for the current controlled test.
#
PORTSCAN_WINDOW = 5.0


# ============================================================
# PORTSCAN TRACKING
# ============================================================

# Structure:
#
# portscan_tracker = {
#
#     source_ip: {
#
#         target_ip: {
#
#             destination_port: timestamp,
#             ...
#
#         }
#     }
# }
#
portscan_tracker = {}


# Stores currently detected scans.
#
# Structure:
#
# {
#     (source_ip, target_ip): {
#         "detected_at": timestamp,
#         "ports": set(...)
#     }
# }
#
active_portscans = {}


portscan_lock = threading.Lock()


# ============================================================
# PORTSCAN DETECTION
# ============================================================

def detect_portscan(packet):
    """
    Detect TCP SYN-based PortScan behavior.

    A PortScan is detected when one source sends TCP SYN
    packets to many different destination ports on our PC
    within a short time window.

    This is a behavioral detector.

    It complements the CNN rather than modifying it.
    """

    # --------------------------------------------------------
    # Must be IPv4
    # --------------------------------------------------------

    if not packet.haslayer(IP):

        return None


    # --------------------------------------------------------
    # Current PortScan detector uses TCP SYN traffic
    # --------------------------------------------------------

    if not packet.haslayer(TCP):

        return None


    ip = packet[IP]

    tcp = packet[TCP]


    # --------------------------------------------------------
    # Traffic must be targeting our PC
    # --------------------------------------------------------

    if ip.dst != PC_IP:

        return None


    # --------------------------------------------------------
    # Do not treat our own PC as attacker
    # --------------------------------------------------------

    if ip.src == PC_IP:

        return None


    # --------------------------------------------------------
    # TCP flags
    #
    # SYN = 0x02
    # ACK = 0x10
    #
    # We want initial SYN packets:
    #
    # SYN = 1
    # ACK = 0
    # --------------------------------------------------------

    flags = int(tcp.flags)

    syn_flag = bool(flags & 0x02)

    ack_flag = bool(flags & 0x10)


    if not syn_flag:

        return None


    if ack_flag:

        return None


    # --------------------------------------------------------
    # Source / target
    # --------------------------------------------------------

    source_ip = ip.src

    target_ip = ip.dst


    destination_port = int(
        tcp.dport
    )


    # --------------------------------------------------------
    # Ignore configured service ports
    # --------------------------------------------------------

    if destination_port in IGNORED_PORTS:

        return None


    now = time.time()


    with portscan_lock:

        # ----------------------------------------------------
        # Create source entry
        # ----------------------------------------------------

        if source_ip not in portscan_tracker:

            portscan_tracker[source_ip] = {}


        # ----------------------------------------------------
        # Create target entry
        # ----------------------------------------------------

        if target_ip not in portscan_tracker[source_ip]:

            portscan_tracker[source_ip][target_ip] = {}


        port_data = (
            portscan_tracker[source_ip][target_ip]
        )


        # ----------------------------------------------------
        # Remove ports outside detection window
        # ----------------------------------------------------

        expired_ports = []

        for port, timestamp in port_data.items():

            if (
                now - timestamp
                > PORTSCAN_WINDOW
            ):

                expired_ports.append(
                    port
                )


        for port in expired_ports:

            del port_data[port]


        # ----------------------------------------------------
        # Record this destination port
        # ----------------------------------------------------

        port_data[destination_port] = now


        # ----------------------------------------------------
        # Count distinct destination ports
        # ----------------------------------------------------

        distinct_ports = len(
            port_data
        )


        # ----------------------------------------------------
        # Check PortScan threshold
        # ----------------------------------------------------

        if (
            distinct_ports
            >= PORTSCAN_PORT_THRESHOLD
        ):

            scan_key = (
                source_ip,
                target_ip
            )


            # ------------------------------------------------
            # New PortScan
            # ------------------------------------------------

            if scan_key not in active_portscans:

                active_portscans[scan_key] = {

                    "detected_at":
                        now,

                    "ports":
                        set(
                            port_data.keys()
                        ),
                }


                return {

                    "source_ip":
                        source_ip,

                    "target_ip":
                        target_ip,

                    "port_count":
                        distinct_ports,

                    "ports":
                        sorted(
                            port_data.keys()
                        ),

                    "timestamp":
                        datetime.now(),
                }


            # ------------------------------------------------
            # Existing scan
            #
            # Update the known port set, but do not create
            # another alert every packet.
            # ------------------------------------------------

            active_portscans[scan_key][
                "ports"
            ].update(
                port_data.keys()
            )


    return None


# ============================================================
# PORTSCAN CLEANUP
# ============================================================

def cleanup_portscan_tracker():

    """
    Remove old PortScan tracking information.

    This prevents the dictionaries from growing forever
    during long-running monitoring.
    """

    while not stop_event.is_set():

        time.sleep(1)


        now = time.time()


        with portscan_lock:

            # ------------------------------------------------
            # Clean individual tracked ports
            # ------------------------------------------------

            for source_ip in list(
                portscan_tracker.keys()
            ):

                targets = (
                    portscan_tracker[
                        source_ip
                    ]
                )


                for target_ip in list(
                    targets.keys()
                ):

                    port_data = (
                        targets[
                            target_ip
                        ]
                    )


                    expired_ports = []

                    for port, timestamp in (
                        list(
                            port_data.items()
                        )
                    ):

                        if (
                            now - timestamp
                            > PORTSCAN_WINDOW
                        ):

                            expired_ports.append(
                                port
                            )


                    for port in expired_ports:

                        del port_data[port]


                    if not port_data:

                        del targets[
                            target_ip
                        ]


                if not targets:

                    del portscan_tracker[
                        source_ip
                    ]


            # ------------------------------------------------
            # Clean active scan states
            # ------------------------------------------------

            expired_scans = []

            for scan_key, scan_data in (
                active_portscans.items()
            ):

                if (
                    now
                    - scan_data[
                        "detected_at"
                    ]
                    > PORTSCAN_WINDOW
                ):

                    expired_scans.append(
                        scan_key
                    )


            for scan_key in expired_scans:

                del active_portscans[
                    scan_key
                ]


# ============================================================
# PORTSCAN ACTIVE CHECK
# ============================================================

def get_active_portscan(
    source_ip,
    target_ip
):
    """
    Check whether the source/target pair is currently
    involved in a detected PortScan.
    """

    scan_key = (
        source_ip,
        target_ip
    )


    now = time.time()


    with portscan_lock:

        scan = active_portscans.get(
            scan_key
        )


        if scan is None:

            return None


        # ----------------------------------------------------
        # Check expiration
        # ----------------------------------------------------

        if (
            now
            - scan["detected_at"]
            > PORTSCAN_WINDOW
        ):

            del active_portscans[
                scan_key
            ]

            return None


        return {

            "source_ip":
                source_ip,

            "target_ip":
                target_ip,

            "ports":
                sorted(
                    scan["ports"]
                ),

            "port_count":
                len(
                    scan["ports"]
                ),
        }


# ============================================================
# MARK ACTIVE FLOWS AS PORTSCAN
# ============================================================

def mark_active_flows_as_portscan(
    source_ip,
    target_ip
):
    """
    Once a PortScan has been detected, mark all currently
    stored flows belonging to that source/target pair.

    This prevents the earlier individual scan flows from
    remaining completely disconnected from the PortScan
    detection.
    """

    with lock:

        for flow in flows.values():

            # ------------------------------------------------
            # Only traffic from attacker -> defender
            # ------------------------------------------------

            if (
                flow["src_ip"]
                == source_ip
                and
                flow["dst_ip"]
                == target_ip
            ):

                flow[
                    "behavioral_detection"
                ] = "PortScan"


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
            "=" * 70
            + "\n"
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
            f"PortScan Threshold: "
            f"{PORTSCAN_PORT_THRESHOLD} ports\n"
        )

        f.write(
            f"PortScan Window: "
            f"{PORTSCAN_WINDOW} seconds\n"
        )

        f.write(
            "=" * 70
            + "\n\n"
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

    # --------------------------------------------------------
    # Only IPv4 packets
    # --------------------------------------------------------

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

        sport = int(
            packet[TCP].sport
        )

        dport = int(
            packet[TCP].dport
        )


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        sport = int(
            packet[UDP].sport
        )

        dport = int(
            packet[UDP].dport
        )


    else:

        return False


    # --------------------------------------------------------
    # Ignore unwanted service ports
    # --------------------------------------------------------

    if (
        sport in IGNORED_PORTS
        or
        dport in IGNORED_PORTS
    ):

        return False


    # --------------------------------------------------------
    # Controlled PortScan testing
    #
    # This means:
    #
    # capture all non-ignored ports
    #
    # It is NOT the PortScan detector itself.
    # --------------------------------------------------------

    if PORTSCAN_TEST_MODE:

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
# FLOW INFORMATION
# ============================================================

def get_flow_information(packet):

    ip = packet[IP]


    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        sport = int(
            packet[TCP].sport
        )

        dport = int(
            packet[TCP].dport
        )


    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        sport = int(
            packet[UDP].sport
        )

        dport = int(
            packet[UDP].dport
        )


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

        "key":
            key,

        "src_ip":
            src,

        "src_port":
            sport,

        "dst_ip":
            dst,

        "dst_port":
            dport,

        "protocol":
            protocol,
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

        features = calculate_features(
            flow
        )


    except Exception as e:

        print(
            f"[ERROR] "
            f"Feature extraction failed: {e}"
        )


        write_output(
            f"[ERROR] "
            f"Feature extraction failed: "
            f"{e}\n\n"
        )


        return


    # --------------------------------------------------------
    # Verify exactly 78 features
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
            f"[ERROR] "
            f"{error_message}\n\n"
        )


        return


    # --------------------------------------------------------
    # Send features to CNN
    # --------------------------------------------------------

    print(
        "\nLIVE FLOW FEATURE CHECK"
    )

    print(
        "-" * 70
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

        print(
            f"{i:02d}. "
            f"{name:<35} = {value}"
        )


    print(
        "-" * 70
    )


    prediction = send_to_ml(
        features
    )


    # --------------------------------------------------------
    # Check behavioral PortScan detection
    # --------------------------------------------------------

    behavioral_detection = (
        flow.get(
            "behavioral_detection"
        )
    )


    if behavioral_detection is None:

        active_scan = (
            get_active_portscan(
                flow["src_ip"],
                flow["dst_ip"]
            )
        )


        if active_scan is not None:

            behavioral_detection = (
                "PortScan"
            )


    # --------------------------------------------------------
    # Final detection result
    # --------------------------------------------------------

    if behavioral_detection == "PortScan":

        final_detection = {

            "binary_prediction":
                "ATTACK",

            "attack_type":
                "PortScan",

            "detection_method":
                "Behavioral PortScan Detection",

            "port_count":
                (
                    len(
                        get_active_portscan(
                            flow["src_ip"],
                            flow["dst_ip"]
                        )["ports"]
                    )
                    if get_active_portscan(
                        flow["src_ip"],
                        flow["dst_ip"]
                    )
                    else None
                ),

            "cnn_prediction":
                prediction,
        }


    else:

        final_detection = prediction


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
        f"Packets: "
        f"{len(flow['packets'])}"
    )


    print(
        f"CNN Prediction: "
        f"{prediction}"
    )


    if behavioral_detection == "PortScan":

        print(
            "BEHAVIORAL DETECTION: "
            "PortScan"
        )


    print(
        f"FINAL DETECTION: "
        f"{final_detection}"
    )


    print(
        "=" * 70
    )


    # --------------------------------------------------------
    # TEXT FILE OUTPUT
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
        f"Packets: "
        f"{len(flow['packets'])}\n"
    )


    output.append(
        f"Start Time: "
        f"{flow['first_time']}\n"
    )


    output.append(
        f"End Time: "
        f"{flow['last_time']}\n"
    )


    # --------------------------------------------------------
    # Behavioral detection
    # --------------------------------------------------------

    output.append(
        "\nBEHAVIORAL DETECTION\n"
    )


    output.append(
        "-" * 70
        + "\n"
    )


    if behavioral_detection == "PortScan":

        output.append(
            "PortScan\n"
        )

        output.append(
            "Detection Method: "
            "Multi-flow TCP SYN analysis\n"
        )

    else:

        output.append(
            "None\n"
        )


    # --------------------------------------------------------
    # 78 ML features
    # --------------------------------------------------------

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
            f"{i:02d}. "
            f"{name}: {value}\n"
        )


    # --------------------------------------------------------
    # CNN prediction
    # --------------------------------------------------------

    output.append(
        "\nCNN ML PREDICTION\n"
    )


    output.append(
        "-" * 70
        + "\n"
    )


    output.append(
        f"{prediction}\n"
    )


    # --------------------------------------------------------
    # Final detection
    # --------------------------------------------------------

    output.append(
        "\nFINAL NIDS DETECTION\n"
    )


    output.append(
        "-" * 70
        + "\n"
    )


    output.append(
        f"{final_detection}\n"
    )


    output.append(
        "=" * 70
        + "\n"
    )


    write_output(
        "".join(output)
    )


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
                    now
                    - flow["last_seen"]
                    >= FLOW_TIMEOUT
                ):

                    expired.append(
                        (key, flow)
                    )

                    del flows[key]


        # ----------------------------------------------------
        # Process expired flows outside the lock
        # ----------------------------------------------------

        for key, flow in expired:

            process_flow(flow)


# ============================================================
# PACKET HANDLER
# ============================================================

def handle_packet(packet):

    # --------------------------------------------------------
    # Ignore irrelevant packets
    # --------------------------------------------------------

    if not packet_is_useful(
        packet
    ):

        return


    # --------------------------------------------------------
    # PortScan behavioral detection
    # --------------------------------------------------------

    portscan_alert = (
        detect_portscan(
            packet
        )
    )


    if portscan_alert is not None:

        source_ip = (
            portscan_alert[
                "source_ip"
            ]
        )

        target_ip = (
            portscan_alert[
                "target_ip"
            ]
        )


        # ----------------------------------------------------
        # Mark already-active scan flows
        # ----------------------------------------------------

        mark_active_flows_as_portscan(
            source_ip,
            target_ip
        )


        # ----------------------------------------------------
        # Create alert
        # ----------------------------------------------------

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "PORTSCAN DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : "
            f"{source_ip}\n"
            + f"Target IP       : "
            f"{target_ip}\n"
            + f"Ports detected  : "
            f"{portscan_alert['port_count']}\n"
            + f"Port list       : "
            f"{portscan_alert['ports']}\n"
            + f"Detected at     : "
            f"{portscan_alert['timestamp']}\n"
            + f"Detection method: "
            f"Multi-flow TCP SYN analysis\n"
            + "!" * 70
            + "\n"
        )


        print(
            message
        )


        write_output(
            message
        )


    # --------------------------------------------------------
    # Get flow information
    # --------------------------------------------------------

    info = get_flow_information(
        packet
    )


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

                "behavioral_detection":
                    None,
            }


        flow = flows[key]


        flow["packets"].append(
            packet
        )


        flow["last_time"] = now

        flow["last_seen"] = now


        # ----------------------------------------------------
        # If this source/target is already a detected scan,
        # mark this flow as PortScan immediately.
        # ----------------------------------------------------

        active_scan = (
            get_active_portscan(
                info["src_ip"],
                info["dst_ip"]
            )
        )


        if active_scan is not None:

            flow[
                "behavioral_detection"
            ] = "PortScan"


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
        f"ML API          : "
        f"{ML_API_URL}"
    )


    print(
        f"Output File     : "
        f"{OUTPUT_FILE}"
    )


    print(
        f"PortScan threshold: "
        f"{PORTSCAN_PORT_THRESHOLD} "
        f"distinct ports"
    )


    print(
        f"PortScan window : "
        f"{PORTSCAN_WINDOW} seconds"
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
    # Start PortScan cleanup worker
    # --------------------------------------------------------

    portscan_worker = threading.Thread(
        target=cleanup_portscan_tracker,
        daemon=True
    )


    portscan_worker.start()


    # --------------------------------------------------------
    # Start Scapy capture
    # --------------------------------------------------------

    try:

        sniff(

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


    except Exception as e:

        print(
            f"\n[ERROR] "
            f"Packet capture failed: {e}"
        )


        write_output(
            f"\n[ERROR] "
            f"Packet capture failed: "
            f"{e}\n"
        )


    finally:

        stop_event.set()


        # ----------------------------------------------------
        # Process remaining flows
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

            process_flow(
                flow
            )


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