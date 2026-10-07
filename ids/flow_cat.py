# ============================================================
# AI-NIDS LIVE NETWORK CAPTURE
# ============================================================

import os
import sys
import threading
import time
from datetime import datetime
import signal
import csv
from pathlib import Path
import requests

from scapy.all import (
    AsyncSniffer,
    IP,
    TCP,
    UDP,
    ICMP,
    Raw,
    get_if_list,
    get_if_addr,
)

from feat import FEATURE_NAMES, calculate_features

from capture_config import (
    PC_IP,
    PORTSCAN_TEST_MODE,
    IGNORED_PORTS,
    MONITORED_PORTS,
    ML_API_URL,
    FLOW_TIMEOUT,
    OUTPUT_FILE,
    PORTSCAN_PORT_THRESHOLD,
    PORTSCAN_WINDOW,
    BRUTEFORCE_THRESHOLD,
    BRUTEFORCE_WINDOW,
    AUTH_SERVICE_PORTS,
    HTTP_DOS_THRESHOLD,
    HTTP_DOS_WINDOW,
    HTTP_PORTS,
    TCP_SYN_FLOOD_THRESHOLD,
    TCP_SYN_FLOOD_WINDOW,
    UDP_FLOOD_THRESHOLD,
    UDP_FLOOD_WINDOW,
    ICMP_FLOOD_THRESHOLD,
    ICMP_FLOOD_WINDOW,
)

BACKEND_ATTACK_URL = "http://127.0.0.1:5000/api/detections/attack"
BACKEND_DETECTION_URL = "http://127.0.0.1:5000/api/detections/portscan"
BACKEND_FLOW_URL = "http://127.0.0.1:5000/api/detections/live-flow"



# --------------------------------------------------------
# CSV FLOW OUTPUT
# --------------------------------------------------------

OUTPUT_DIR = Path("Outputs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CSV_METADATA_FIELDS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

CSV_RESULT_FIELDS = [
    "prediction",
    "attack_type",
    "confidence",
    "detection_method",
]

CSV_FIELDS = (
    CSV_METADATA_FIELDS
    + FEATURE_NAMES
    + CSV_RESULT_FIELDS
)

csv_lock = threading.Lock()


def get_csv_file():
    """
    Return today's CSV file.

    Example:
        Outputs/output-30-09-26.csv
    """

    date_string = datetime.now().strftime("%d-%m-%y")

    return (
        OUTPUT_DIR
        / f"output-{date_string}.csv"
    )



# ============================================================
# GLOBAL DATA
# ============================================================

flows = {}

stop_event = threading.Event()

lock = threading.Lock()


# ============================================================
# BEHAVIORAL ATTACK TRACKING & DETECTION
# ============================================================

# 1. PortScan Tracking
portscan_tracker = {}
active_portscans = {}
portscan_lock = threading.Lock()

# 2. BruteForce Tracking
bruteforce_tracker = {}
active_bruteforce = {}
bruteforce_lock = threading.Lock()

# 3. HTTP DoS Tracking
http_dos_tracker = {}
active_http_dos = {}
http_dos_lock = threading.Lock()

# 4. TCP Connection Flood Tracking
tcp_flood_tracker = {}
active_tcp_floods = {}
tcp_flood_lock = threading.Lock()

# 5. UDP Flood Tracking
udp_flood_tracker = {}
active_udp_floods = {}
udp_flood_lock = threading.Lock()

# 6. ICMP Flood Tracking
icmp_flood_tracker = {}
active_icmp_floods = {}
icmp_flood_lock = threading.Lock()


# ------------------------------------------------------------
# 1. PORTSCAN DETECTION (Multi-port SYN scanning)
# ------------------------------------------------------------
def detect_portscan(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    ip = packet[IP]
    tcp = packet[TCP]

    if ip.dst != PC_IP or ip.src == PC_IP:
        return None

    flags = int(tcp.flags)
    syn_flag = bool(flags & 0x02)
    ack_flag = bool(flags & 0x10)

    if not syn_flag or ack_flag:
        return None

    source_ip = ip.src
    target_ip = ip.dst
    destination_port = int(tcp.dport)

    if destination_port in IGNORED_PORTS:
        return None

    now = time.time()

    with portscan_lock:
        if source_ip not in portscan_tracker:
            portscan_tracker[source_ip] = {}
        if target_ip not in portscan_tracker[source_ip]:
            portscan_tracker[source_ip][target_ip] = {}

        port_data = portscan_tracker[source_ip][target_ip]

        # Evict expired
        expired = [p for p, ts in port_data.items() if now - ts > PORTSCAN_WINDOW]
        for p in expired:
            del port_data[p]

        port_data[destination_port] = now
        distinct_ports = len(port_data)

        if distinct_ports >= PORTSCAN_PORT_THRESHOLD:
            scan_key = (source_ip, target_ip)
            if scan_key not in active_portscans:
                active_portscans[scan_key] = {
                    "detected_at": now,
                    "ports": set(port_data.keys()),
                }
                return {
                    "source_ip": source_ip,
                    "target_ip": target_ip,
                    "target_port": destination_port,
                    "port_count": distinct_ports,
                    "ports": sorted(port_data.keys()),
                    "attack_type": "PortScan",
                    "timestamp": datetime.now(),
                }
            else:
                active_portscans[scan_key]["ports"].update(port_data.keys())

    return None


# ------------------------------------------------------------
# 2. BRUTEFORCE DETECTION (Authentication & service hammering)
# ------------------------------------------------------------
def detect_bruteforce(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    ip = packet[IP]
    tcp = packet[TCP]

    if ip.dst != PC_IP or ip.src == PC_IP:
        return None

    dport = int(tcp.dport)
    is_auth_port = dport in AUTH_SERVICE_PORTS
    has_login_payload = False

    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load).lower()
            if b"post " in payload or b"/login" in payload or b"password" in payload or b"auth" in payload:
                has_login_payload = True
        except Exception:
            pass

    flags = int(tcp.flags)
    is_syn = bool(flags & 0x02) and not bool(flags & 0x10)

    # Must be either SYN to auth port or HTTP payload with auth keywords
    if not (is_auth_port and is_syn) and not has_login_payload:
        return None

    now = time.time()
    source_ip = ip.src
    key = (source_ip, dport)

    with bruteforce_lock:
        if key not in bruteforce_tracker:
            bruteforce_tracker[key] = []

        # Evict expired
        bruteforce_tracker[key] = [t for t in bruteforce_tracker[key] if now - t <= BRUTEFORCE_WINDOW]
        bruteforce_tracker[key].append(now)
        attempts = len(bruteforce_tracker[key])

        if attempts >= BRUTEFORCE_THRESHOLD:
            if key not in active_bruteforce or (now - active_bruteforce[key]["detected_at"] > BRUTEFORCE_WINDOW):
                active_bruteforce[key] = {
                    "detected_at": now,
                    "attempts": attempts,
                }
                return {
                    "source_ip": source_ip,
                    "target_ip": ip.dst,
                    "target_port": dport,
                    "protocol": "TCP",
                    "attempt_count": attempts,
                    "attack_type": "BruteForce",
                    "details": f"High frequency authentication attempts targeting port {dport} ({attempts} attempts in {BRUTEFORCE_WINDOW}s)",
                    "timestamp": datetime.now(),
                }
            else:
                active_bruteforce[key]["attempts"] = attempts

    return None


# ------------------------------------------------------------
# 3. HTTP DoS DETECTION (Hulk / Slowloris / HTTP Flood)
# ------------------------------------------------------------
def detect_http_dos(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    ip = packet[IP]
    tcp = packet[TCP]

    if ip.dst != PC_IP or ip.src == PC_IP:
        return None

    dport = int(tcp.dport)
    if dport not in HTTP_PORTS and dport not in {80, 443, 8080, 5000, 3000}:
        return None

    has_http_req = False
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load)
            if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HEAD "):
                has_http_req = True
        except Exception:
            pass

    flags = int(tcp.flags)
    is_syn = bool(flags & 0x02) and not bool(flags & 0x10)

    if not has_http_req and not is_syn:
        return None

    now = time.time()
    source_ip = ip.src

    with http_dos_lock:
        if source_ip not in http_dos_tracker:
            http_dos_tracker[source_ip] = []

        http_dos_tracker[source_ip] = [t for t in http_dos_tracker[source_ip] if now - t <= HTTP_DOS_WINDOW]
        http_dos_tracker[source_ip].append(now)
        req_count = len(http_dos_tracker[source_ip])

        if req_count >= HTTP_DOS_THRESHOLD:
            if source_ip not in active_http_dos or (now - active_http_dos[source_ip]["detected_at"] > HTTP_DOS_WINDOW):
                active_http_dos[source_ip] = {
                    "detected_at": now,
                    "count": req_count,
                }
                return {
                    "source_ip": source_ip,
                    "target_ip": ip.dst,
                    "target_port": dport,
                    "protocol": "TCP",
                    "request_count": req_count,
                    "attack_type": "HTTP DoS",
                    "details": f"High volume HTTP request burst targeting port {dport} ({req_count} requests in {HTTP_DOS_WINDOW}s)",
                    "timestamp": datetime.now(),
                }
            else:
                active_http_dos[source_ip]["count"] = req_count

    return None


# ------------------------------------------------------------
# 4. TCP CONNECTION FLOOD (SYN flood targeting single port)
# ------------------------------------------------------------
def detect_tcp_flood(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    ip = packet[IP]
    tcp = packet[TCP]

    if ip.dst != PC_IP or ip.src == PC_IP:
        return None

    flags = int(tcp.flags)
    syn_flag = bool(flags & 0x02)
    ack_flag = bool(flags & 0x10)

    if not syn_flag or ack_flag:
        return None

    dport = int(tcp.dport)
    now = time.time()
    key = (ip.src, dport)

    with tcp_flood_lock:
        if key not in tcp_flood_tracker:
            tcp_flood_tracker[key] = []

        tcp_flood_tracker[key] = [t for t in tcp_flood_tracker[key] if now - t <= TCP_SYN_FLOOD_WINDOW]
        tcp_flood_tracker[key].append(now)
        syn_count = len(tcp_flood_tracker[key])

        if syn_count >= TCP_SYN_FLOOD_THRESHOLD:
            if key not in active_tcp_floods or (now - active_tcp_floods[key]["detected_at"] > TCP_SYN_FLOOD_WINDOW):
                active_tcp_floods[key] = {
                    "detected_at": now,
                    "count": syn_count,
                }
                return {
                    "source_ip": ip.src,
                    "target_ip": ip.dst,
                    "target_port": dport,
                    "protocol": "TCP",
                    "packet_count": syn_count,
                    "attack_type": "TCP Connection Flood",
                    "details": f"Volumetric TCP SYN flood targeting port {dport} ({syn_count} SYNs in {TCP_SYN_FLOOD_WINDOW}s)",
                    "timestamp": datetime.now(),
                }
            else:
                active_tcp_floods[key]["count"] = syn_count

    return None


# ------------------------------------------------------------
# 5. UDP FLOOD DETECTION
# ------------------------------------------------------------
def detect_udp_flood(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return None

    ip = packet[IP]
    if ip.dst != PC_IP or ip.src == PC_IP:
        return None

    now = time.time()
    source_ip = ip.src
    dport = int(packet[UDP].dport)

    with udp_flood_lock:
        if source_ip not in udp_flood_tracker:
            udp_flood_tracker[source_ip] = []

        udp_flood_tracker[source_ip] = [t for t in udp_flood_tracker[source_ip] if now - t <= UDP_FLOOD_WINDOW]
        udp_flood_tracker[source_ip].append(now)
        udp_count = len(udp_flood_tracker[source_ip])

        if udp_count >= UDP_FLOOD_THRESHOLD:
            if source_ip not in active_udp_floods or (now - active_udp_floods[source_ip]["detected_at"] > UDP_FLOOD_WINDOW):
                active_udp_floods[source_ip] = {
                    "detected_at": now,
                    "count": udp_count,
                }
                return {
                    "source_ip": source_ip,
                    "target_ip": ip.dst,
                    "target_port": dport,
                    "protocol": "UDP",
                    "packet_count": udp_count,
                    "attack_type": "UDP Flood",
                    "details": f"Volumetric UDP packet flood ({udp_count} datagrams in {UDP_FLOOD_WINDOW}s)",
                    "timestamp": datetime.now(),
                }
            else:
                active_udp_floods[source_ip]["count"] = udp_count

    return None


# ------------------------------------------------------------
# 6. ICMP FLOOD DETECTION (Ping Flood)
# ------------------------------------------------------------
def detect_icmp_flood(packet):
    if not packet.haslayer(IP) or not packet.haslayer(ICMP):
        return None

    ip = packet[IP]
    icmp = packet[ICMP]

    if ip.dst != PC_IP or ip.src == PC_IP:
        return None

    # Echo Request is type 8
    if int(icmp.type) != 8:
        return None

    now = time.time()
    source_ip = ip.src

    with icmp_flood_lock:
        if source_ip not in icmp_flood_tracker:
            icmp_flood_tracker[source_ip] = []

        icmp_flood_tracker[source_ip] = [t for t in icmp_flood_tracker[source_ip] if now - t <= ICMP_FLOOD_WINDOW]
        icmp_flood_tracker[source_ip].append(now)
        icmp_count = len(icmp_flood_tracker[source_ip])

        if icmp_count >= ICMP_FLOOD_THRESHOLD:
            if source_ip not in active_icmp_floods or (now - active_icmp_floods[source_ip]["detected_at"] > ICMP_FLOOD_WINDOW):
                active_icmp_floods[source_ip] = {
                    "detected_at": now,
                    "count": icmp_count,
                }
                return {
                    "source_ip": source_ip,
                    "target_ip": ip.dst,
                    "target_port": 0,
                    "protocol": "ICMP",
                    "packet_count": icmp_count,
                    "attack_type": "ICMP Flood",
                    "details": f"High rate ICMP Echo Request ping flood ({icmp_count} packets in {ICMP_FLOOD_WINDOW}s)",
                    "timestamp": datetime.now(),
                }
            else:
                active_icmp_floods[source_ip]["count"] = icmp_count

    return None


# ============================================================
# BEHAVIORAL ATTACK CLEANUP WORKER
# ============================================================
def cleanup_behavioral_trackers():
    while not stop_event.is_set():
        time.sleep(1)
        now = time.time()

        # 1. PortScan cleanup
        with portscan_lock:
            for s_ip in list(portscan_tracker.keys()):
                targets = portscan_tracker[s_ip]
                for t_ip in list(targets.keys()):
                    port_data = targets[t_ip]
                    exp = [p for p, ts in port_data.items() if now - ts > PORTSCAN_WINDOW]
                    for p in exp:
                        del port_data[p]
                    if not port_data:
                        del targets[t_ip]
                if not targets:
                    del portscan_tracker[s_ip]
            exp_scans = [k for k, v in active_portscans.items() if now - v["detected_at"] > PORTSCAN_WINDOW]
            for k in exp_scans:
                del active_portscans[k]

        # 2. BruteForce cleanup
        with bruteforce_lock:
            for k in list(bruteforce_tracker.keys()):
                bruteforce_tracker[k] = [t for t in bruteforce_tracker[k] if now - t <= BRUTEFORCE_WINDOW]
                if not bruteforce_tracker[k]:
                    del bruteforce_tracker[k]
            exp_bf = [k for k, v in active_bruteforce.items() if now - v["detected_at"] > BRUTEFORCE_WINDOW]
            for k in exp_bf:
                del active_bruteforce[k]

        # 3. HTTP DoS cleanup
        with http_dos_lock:
            for ip_key in list(http_dos_tracker.keys()):
                http_dos_tracker[ip_key] = [t for t in http_dos_tracker[ip_key] if now - t <= HTTP_DOS_WINDOW]
                if not http_dos_tracker[ip_key]:
                    del http_dos_tracker[ip_key]
            exp_hd = [k for k, v in active_http_dos.items() if now - v["detected_at"] > HTTP_DOS_WINDOW]
            for k in exp_hd:
                del active_http_dos[k]

        # 4. TCP Flood cleanup
        with tcp_flood_lock:
            for k in list(tcp_flood_tracker.keys()):
                tcp_flood_tracker[k] = [t for t in tcp_flood_tracker[k] if now - t <= TCP_SYN_FLOOD_WINDOW]
                if not tcp_flood_tracker[k]:
                    del tcp_flood_tracker[k]
            exp_tf = [k for k, v in active_tcp_floods.items() if now - v["detected_at"] > TCP_SYN_FLOOD_WINDOW]
            for k in exp_tf:
                del active_tcp_floods[k]

        # 5. UDP Flood cleanup
        with udp_flood_lock:
            for k in list(udp_flood_tracker.keys()):
                udp_flood_tracker[k] = [t for t in udp_flood_tracker[k] if now - t <= UDP_FLOOD_WINDOW]
                if not udp_flood_tracker[k]:
                    del udp_flood_tracker[k]
            exp_uf = [k for k, v in active_udp_floods.items() if now - v["detected_at"] > UDP_FLOOD_WINDOW]
            for k in exp_uf:
                del active_udp_floods[k]

        # 6. ICMP Flood cleanup
        with icmp_flood_lock:
            for k in list(icmp_flood_tracker.keys()):
                icmp_flood_tracker[k] = [t for t in icmp_flood_tracker[k] if now - t <= ICMP_FLOOD_WINDOW]
                if not icmp_flood_tracker[k]:
                    del icmp_flood_tracker[k]
            exp_if = [k for k, v in active_icmp_floods.items() if now - v["detected_at"] > ICMP_FLOOD_WINDOW]
            for k in exp_if:
                del active_icmp_floods[k]


# ============================================================
# ACTIVE BEHAVIORAL ATTACK QUERY
# ============================================================
def get_active_portscan(source_ip, target_ip):
    scan_key = (source_ip, target_ip)
    now = time.time()
    with portscan_lock:
        scan = active_portscans.get(scan_key)
        if scan is None:
            return None
        if now - scan["detected_at"] > PORTSCAN_WINDOW:
            del active_portscans[scan_key]
            return None
        return {
            "source_ip": source_ip,
            "target_ip": target_ip,
            "ports": sorted(scan["ports"]),
            "port_count": len(scan["ports"]),
        }

def get_active_behavioral_attack(source_ip, dst_port=None):
    now = time.time()
    # 1. PortScan
    with portscan_lock:
        for (s, _), data in active_portscans.items():
            if s == source_ip and (now - data["detected_at"] <= PORTSCAN_WINDOW):
                return "PortScan"

    # 2. BruteForce
    with bruteforce_lock:
        for (s, p), data in active_bruteforce.items():
            if s == source_ip and (dst_port is None or p == dst_port) and (now - data["detected_at"] <= BRUTEFORCE_WINDOW):
                return "BruteForce"

    # 3. HTTP DoS
    with http_dos_lock:
        if source_ip in active_http_dos and (now - active_http_dos[source_ip]["detected_at"] <= HTTP_DOS_WINDOW):
            return "HTTP DoS"

    # 4. TCP Connection Flood
    with tcp_flood_lock:
        for (s, p), data in active_tcp_floods.items():
            if s == source_ip and (dst_port is None or p == dst_port) and (now - data["detected_at"] <= TCP_SYN_FLOOD_WINDOW):
                return "TCP Connection Flood"

    # 5. UDP Flood
    with udp_flood_lock:
        if source_ip in active_udp_floods and (now - active_udp_floods[source_ip]["detected_at"] <= UDP_FLOOD_WINDOW):
            return "UDP Flood"

    # 6. ICMP Flood
    with icmp_flood_lock:
        if source_ip in active_icmp_floods and (now - active_icmp_floods[source_ip]["detected_at"] <= ICMP_FLOOD_WINDOW):
            return "ICMP Flood"

    return None

def mark_active_flows_as_attack(source_ip, attack_type):
    with lock:
        for flow in flows.values():
            if flow["src_ip"] == source_ip:
                flow["behavioral_detection"] = attack_type

def mark_active_flows_as_portscan(source_ip, target_ip):
    mark_active_flows_as_attack(source_ip, "PortScan")


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
            f"PortScan Threshold: {PORTSCAN_PORT_THRESHOLD} ports / {PORTSCAN_WINDOW}s\n"
        )

        f.write(
            f"BruteForce Threshold: {BRUTEFORCE_THRESHOLD} attempts / {BRUTEFORCE_WINDOW}s\n"
        )

        f.write(
            f"HTTP DoS Threshold: {HTTP_DOS_THRESHOLD} requests / {HTTP_DOS_WINDOW}s\n"
        )

        f.write(
            f"TCP Flood Threshold: {TCP_SYN_FLOOD_THRESHOLD} SYNs / {TCP_SYN_FLOOD_WINDOW}s\n"
        )

        f.write(
            f"UDP Flood Threshold: {UDP_FLOOD_THRESHOLD} packets / {UDP_FLOOD_WINDOW}s\n"
        )

        f.write(
            f"ICMP Flood Threshold: {ICMP_FLOOD_THRESHOLD} packets / {ICMP_FLOOD_WINDOW}s\n"
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
    # ICMP (Ping Flood & ICMP Analysis)
    # --------------------------------------------------------

    if packet.haslayer(ICMP):
        return True

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    elif packet.haslayer(TCP):

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
    # --------------------------------------------------------

    if PORTSCAN_TEST_MODE:

        return True

    # --------------------------------------------------------
    # Normal application monitoring mode:
    # Monitor web ports, authentication services, and configured ports
    # --------------------------------------------------------

    allowed_ports = MONITORED_PORTS | AUTH_SERVICE_PORTS | HTTP_PORTS

    if (
        sport not in allowed_ports
        and
        dport not in allowed_ports
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

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    elif packet.haslayer(ICMP):

        protocol = "ICMP"
        sport = 0
        dport = int(packet[ICMP].type) if hasattr(packet[ICMP], "type") else 0

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
            timeout=2
        )


        response.raise_for_status()


        return response.json()


    except Exception as e:

        return {
            "error": str(e)
        }

def write_flow_to_csv(
    flow,
    features,
    prediction,
    final_detection
):
    """
    Save one completed flow and its
    78 ML features to today's CSV file.
    """

    csv_file = get_csv_file()

    # --------------------------------------------------------
    # CNN prediction
    # --------------------------------------------------------

    ml_prediction = "UNKNOWN"
    confidence = 0

    if isinstance(prediction, dict):

        ml_prediction = prediction.get(
            "attack_type",
            "UNKNOWN"
        )

        confidence = prediction.get(
            "confidence",
            0
        )

    # --------------------------------------------------------
    # Final NIDS detection
    # --------------------------------------------------------

    if isinstance(final_detection, dict):

        attack_type = final_detection.get(
            "attack_type",
            ml_prediction
        )

        detection_method = final_detection.get(
            "detection_method",
            "CNN"
        )

    else:

        attack_type = str(
            final_detection
        )

        detection_method = "CNN"

    # --------------------------------------------------------
    # CSV row
    # --------------------------------------------------------

    row = {

        "timestamp":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "src_ip":
            flow.get(
                "src_ip",
                ""
            ),

        "dst_ip":
            flow.get(
                "dst_ip",
                ""
            ),

        "src_port":
            flow.get(
                "src_port",
                ""
            ),

        "dst_port":
            flow.get(
                "dst_port",
                ""
            ),

        "protocol":
            flow.get(
                "protocol",
                ""
            ),

        "prediction":
            ml_prediction,

        "attack_type":
            attack_type,

        "confidence":
            confidence,

        "detection_method":
            detection_method,
    }

    # --------------------------------------------------------
    # Add the 78 ML features
    # --------------------------------------------------------

    for feature_name, feature_value in zip(
        FEATURE_NAMES,
        features
    ):

        row[feature_name] = feature_value

    # --------------------------------------------------------
    # Write CSV
    # --------------------------------------------------------

    with csv_lock:

        file_exists = csv_file.exists()

        file_has_data = (
            file_exists
            and
            csv_file.stat().st_size > 0
        )

        with open(
            csv_file,
            "a",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            writer = csv.DictWriter(
                csvfile,
                fieldnames=CSV_FIELDS
            )

            # Header only when file is new/empty
            if not file_has_data:

                writer.writeheader()

            writer.writerow(row)

    print(
        f"[CSV] Flow saved -> {csv_file}"
    )


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
    # Check behavioral detection (PortScan, BruteForce, DoS, Floods)
    # --------------------------------------------------------

    behavioral_detection = flow.get("behavioral_detection")

    if behavioral_detection is None:
        behavioral_detection = get_active_behavioral_attack(
            flow["src_ip"],
            flow.get("dst_port")
        )

    # --------------------------------------------------------
    # Final detection result
    # --------------------------------------------------------

    if behavioral_detection:
        final_detection = {
            "binary_prediction": "ATTACK",
            "attack_type": behavioral_detection,
            "detection_method": f"Behavioral {behavioral_detection} Detection",
            "confidence": 1.0,
            "is_attack": True,
            "cnn_prediction": prediction,
        }

        if behavioral_detection == "PortScan":
            active_scan = get_active_portscan(flow["src_ip"], flow["dst_ip"])
            if active_scan:
                final_detection["port_count"] = len(active_scan["ports"])
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

    if behavioral_detection:
        print(
            f"BEHAVIORAL DETECTION: {behavioral_detection}"
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


    if behavioral_detection:

        output.append(
            f"{behavioral_detection}\n"
        )

        output.append(
            f"Detection Method: "
            f"Behavioral {behavioral_detection} analysis\n"
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
# --------------------------------------------------------
# Save completed flow to daily CSV
# # --------------------------------------------------------

    write_flow_to_csv(
        flow,
        features,
        prediction,
        final_detection
    )


# Create compact payload for Live Monitoring
    live_payload = create_live_payload(
        flow,
        prediction,
        final_detection
    )
# Send compact payload to the React Live Monitoring page
    send_live_monitor(live_payload)
# --------------------------------------------------------
# Send completed flow to Node.js backend
# --------------------------------------------------------

    send_flow_to_backend(
        flow,
        prediction,
        final_detection
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



def send_portscan_to_backend(portscan_alert):
    """
    Send a confirmed behavioral PortScan detection
    from flow_cat.py to the Node.js backend.
    """

    try:
        payload = {
            "source_ip": portscan_alert["source_ip"],
            "target_ip": portscan_alert["target_ip"],
            "port_count": portscan_alert["port_count"],
            "ports": portscan_alert["ports"],
            "timestamp": portscan_alert["timestamp"].isoformat(),
        }

        response = requests.post(
            BACKEND_DETECTION_URL,
            json=payload,
            timeout=2,
        )

        if response.ok:
            print("✅ PortScan sent to backend successfully")
            return True

        print(
            f"❌ Backend rejected PortScan: "
            f"{response.status_code} - {response.text}"
        )

    except requests.exceptions.RequestException as error:
        print(
            f"❌ Could not send PortScan to backend: {error}"
        )

    return False


def send_attack_to_backend(attack_alert):
    """
    Send a confirmed behavioral attack detection (BruteForce, HTTP DoS,
    TCP Connection Flood, UDP Flood, ICMP Flood, etc.) to the Node.js backend.
    """

    try:
        ts = attack_alert.get("timestamp")
        iso_ts = ts.isoformat() if hasattr(ts, "isoformat") else datetime.now().isoformat()
        payload = {
            "source_ip": attack_alert.get("source_ip"),
            "target_ip": attack_alert.get("target_ip"),
            "source_port": attack_alert.get("source_port", 0),
            "target_port": attack_alert.get("target_port", 0),
            "protocol": attack_alert.get("protocol", "TCP"),
            "attack_type": attack_alert.get("attack_type", "Behavioral Attack"),
            "packet_count": attack_alert.get("packet_count") or attack_alert.get("attempt_count") or attack_alert.get("request_count") or 1,
            "details": attack_alert.get("details", ""),
            "timestamp": iso_ts,
        }

        response = requests.post(
            BACKEND_ATTACK_URL,
            json=payload,
            timeout=2,
        )

        if response.ok:
            print(f"✅ [{attack_alert.get('attack_type')}] sent to backend successfully")
            return True

        print(
            f"❌ Backend rejected attack: "
            f"{response.status_code} - {response.text}"
        )

    except requests.exceptions.RequestException as error:
        print(f"❌ Could not send attack to backend: {error}")

    return False


def create_live_payload(flow, prediction, final_detection):
    """
    Create a compact payload for Live Monitoring.

    The ML model still uses all 78 features internally.
    The frontend receives only the information needed for monitoring.
    """

    attack_type = "BENIGN"
    confidence = 0.0
    is_attack = False

    if isinstance(prediction, dict):
        attack_type = prediction.get("attack_type") or "BENIGN"
        confidence = float(prediction.get("confidence", 0) or 0)
        is_attack = bool(prediction.get("is_attack", False))

    # Behavioral detection overrides ML result
    beh = flow.get("behavioral_detection")
    if beh:
        attack_type = beh
        confidence = 1.0
        is_attack = True

    detection_method = "CNN"

    if isinstance(final_detection, dict):
        detection_method = (
            final_detection.get("detection_method")
            or detection_method
        )

    return {
        "source_ip": flow["src_ip"],
        "target_ip": flow["dst_ip"],
        "source_port": flow["src_port"],
        "target_port": flow["dst_port"],
        "protocol": flow["protocol"],
        "timestamp": datetime.fromtimestamp(
            flow["first_time"]
        ).isoformat(),
        "duration": flow["last_time"] - flow["first_time"],
        "bytes": sum(len(packet) for packet in flow["packets"]),
        "packets": len(flow["packets"]),
        "label": attack_type if is_attack else "BENIGN",
        "prediction": attack_type if is_attack else "BENIGN",
        "attack_type": attack_type if is_attack else "BENIGN",
        "confidence": confidence,
        "is_attack": is_attack,
        "detection_method": detection_method,
    }


def send_live_monitor(payload):
    """
    Send compact flow information to the Live Monitoring system.
    This endpoint only emits Socket.IO data and does not store
    the live stream in MongoDB.
    """

    try:
        response = requests.post(
            BACKEND_FLOW_URL,
            json=payload,
            timeout=2
        )

        if response.status_code != 200:
            print(
                f"[LIVE] Backend error: "
                f"{response.status_code} {response.text}"
            )

    except requests.RequestException as error:
        print(f"[LIVE] Failed to send live traffic: {error}")


def send_flow_to_backend(flow, prediction, final_detection):
    """
    Send a completed network flow to the Node.js backend
    so it can be stored and displayed in Live Monitoring.
    """

    try:
        attack_type = None
        confidence = 0
        is_attack = False

        if isinstance(prediction, dict):
            attack_type = prediction.get("attack_type")
            confidence = float(
                prediction.get("confidence", 0) or 0
            )
            is_attack = bool(
                prediction.get("is_attack", False)
            )

        # Behavioral detection overrides CNN result
        beh = flow.get("behavioral_detection")
        if beh:
            attack_type = beh
            confidence = 1.0
            is_attack = True

        payload = {
            "source_ip": flow["src_ip"],
            "target_ip": flow["dst_ip"],
            "source_port": flow["src_port"],
            "target_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "timestamp": datetime.fromtimestamp(
                flow["first_time"]
            ).isoformat(),
            "duration": (
                flow["last_time"]
                - flow["first_time"]
            ),
            "bytes": sum(
                len(packet)
                for packet in flow["packets"]
            ),
            "packets": len(flow["packets"]),
            "label": (
                attack_type
                if is_attack
                else "BENIGN"
            ),
            "prediction": (
                attack_type
                if is_attack
                else "BENIGN"
            ),
            "confidence": confidence,
            "is_attack": is_attack,
            "detection_method": (
                final_detection.get(
                    "detection_method"
                )
                if isinstance(final_detection, dict)
                else "CNN"
            ),
        }

        response = requests.post(
            BACKEND_FLOW_URL,
            json=payload,
            timeout=2,
        )

        if response.ok:
            print(
                "✅ Traffic flow sent to backend successfully"
            )
            return True

        print(
            f"❌ Backend rejected traffic flow: "
            f"{response.status_code} - {response.text}"
        )

    except requests.exceptions.RequestException as error:

        print(
            f"❌ Could not send traffic flow to backend: "
            f"{error}"
        )

    except Exception as error:

        print(
            f"❌ Flow backend processing error: "
            f"{error}"
        )

    return False

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
    # 1. PortScan behavioral detection
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

        # Mark already-active scan flows
        mark_active_flows_as_portscan(
            source_ip,
            target_ip
        )

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "PORTSCAN DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : {source_ip}\n"
            + f"Target IP       : {target_ip}\n"
            + f"Ports detected  : {portscan_alert['port_count']}\n"
            + f"Port list       : {portscan_alert['ports']}\n"
            + f"Detected at     : {portscan_alert['timestamp']}\n"
            + f"Detection method: Multi-flow TCP SYN analysis\n"
            + "!" * 70
            + "\n"
        )

        print(
            message
        )

        write_output(
            message
        )
        send_portscan_to_backend(portscan_alert)

    # --------------------------------------------------------
    # 2. BruteForce behavioral detection
    # --------------------------------------------------------

    bruteforce_alert = detect_bruteforce(packet)

    if bruteforce_alert is not None:
        source_ip = bruteforce_alert["source_ip"]
        mark_active_flows_as_attack(source_ip, "BruteForce")

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "BRUTEFORCE ATTACK DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : {source_ip}\n"
            + f"Target IP       : {bruteforce_alert['target_ip']}\n"
            + f"Target Port     : {bruteforce_alert['target_port']}\n"
            + f"Attempts        : {bruteforce_alert['attempt_count']}\n"
            + f"Details         : {bruteforce_alert.get('details', '')}\n"
            + f"Detected at     : {bruteforce_alert['timestamp']}\n"
            + f"Detection method: Behavioral Auth Service Probing Analysis\n"
            + "!" * 70
            + "\n"
        )

        print(message)
        write_output(message)
        send_attack_to_backend(bruteforce_alert)

    # --------------------------------------------------------
    # 3. HTTP DoS behavioral detection
    # --------------------------------------------------------

    http_dos_alert = detect_http_dos(packet)

    if http_dos_alert is not None:
        source_ip = http_dos_alert["source_ip"]
        mark_active_flows_as_attack(source_ip, "HTTP DoS")

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "HTTP DoS ATTACK DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : {source_ip}\n"
            + f"Target IP       : {http_dos_alert['target_ip']}\n"
            + f"Target Port     : {http_dos_alert['target_port']}\n"
            + f"Requests        : {http_dos_alert['request_count']}\n"
            + f"Details         : {http_dos_alert.get('details', '')}\n"
            + f"Detected at     : {http_dos_alert['timestamp']}\n"
            + f"Detection method: High-rate HTTP request burst analysis\n"
            + "!" * 70
            + "\n"
        )

        print(message)
        write_output(message)
        send_attack_to_backend(http_dos_alert)

    # --------------------------------------------------------
    # 4. TCP Connection Flood behavioral detection
    # --------------------------------------------------------

    tcp_flood_alert = detect_tcp_flood(packet)

    if tcp_flood_alert is not None:
        source_ip = tcp_flood_alert["source_ip"]
        mark_active_flows_as_attack(source_ip, "TCP Connection Flood")

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "TCP CONNECTION FLOOD DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : {source_ip}\n"
            + f"Target IP       : {tcp_flood_alert['target_ip']}\n"
            + f"Target Port     : {tcp_flood_alert['target_port']}\n"
            + f"SYN Count       : {tcp_flood_alert['packet_count']}\n"
            + f"Details         : {tcp_flood_alert.get('details', '')}\n"
            + f"Detected at     : {tcp_flood_alert['timestamp']}\n"
            + f"Detection method: Volumetric TCP SYN flood analysis\n"
            + "!" * 70
            + "\n"
        )

        print(message)
        write_output(message)
        send_attack_to_backend(tcp_flood_alert)

    # --------------------------------------------------------
    # 5. UDP Flood behavioral detection
    # --------------------------------------------------------

    udp_flood_alert = detect_udp_flood(packet)

    if udp_flood_alert is not None:
        source_ip = udp_flood_alert["source_ip"]
        mark_active_flows_as_attack(source_ip, "UDP Flood")

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "UDP FLOOD DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : {source_ip}\n"
            + f"Target IP       : {udp_flood_alert['target_ip']}\n"
            + f"Target Port     : {udp_flood_alert['target_port']}\n"
            + f"Packet Count    : {udp_flood_alert['packet_count']}\n"
            + f"Details         : {udp_flood_alert.get('details', '')}\n"
            + f"Detected at     : {udp_flood_alert['timestamp']}\n"
            + f"Detection method: Volumetric UDP packet analysis\n"
            + "!" * 70
            + "\n"
        )

        print(message)
        write_output(message)
        send_attack_to_backend(udp_flood_alert)

    # --------------------------------------------------------
    # 6. ICMP Flood behavioral detection
    # --------------------------------------------------------

    icmp_flood_alert = detect_icmp_flood(packet)

    if icmp_flood_alert is not None:
        source_ip = icmp_flood_alert["source_ip"]
        mark_active_flows_as_attack(source_ip, "ICMP Flood")

        message = (
            "\n"
            + "!" * 70
            + "\n"
            + "ICMP FLOOD DETECTED\n"
            + "!" * 70
            + "\n"
            + f"Source IP       : {source_ip}\n"
            + f"Target IP       : {icmp_flood_alert['target_ip']}\n"
            + f"Packet Count    : {icmp_flood_alert['packet_count']}\n"
            + f"Details         : {icmp_flood_alert.get('details', '')}\n"
            + f"Detected at     : {icmp_flood_alert['timestamp']}\n"
            + f"Detection method: High-rate ICMP Echo Request analysis\n"
            + "!" * 70
            + "\n"
        )

        print(message)
        write_output(message)
        send_attack_to_backend(icmp_flood_alert)

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
        # If this source/target is an active attack,
        # mark this flow immediately.
        # ----------------------------------------------------

        active_attack = (
            get_active_behavioral_attack(
                info["src_ip"],
                info["dst_port"]
            )
        )

        if active_attack is not None:

            flow[
                "behavioral_detection"
            ] = active_attack


# ============================================================
# FIND CAPTURE INTERFACE
# ============================================================

def find_capture_interface():
    """
    Find the Scapy network interface whose IPv4 address
    matches the AI-NIDS PC_IP.
    """

    print("\nSearching for capture interface...")

    for iface in get_if_list():

        try:
            iface_ip = get_if_addr(iface)

            print(
                f"  {iface} -> {iface_ip}"
            )

            if iface_ip == PC_IP:

                print(
                    f"\n[AI-NIDS] Capture interface selected:"
                )

                print(
                    f"           {iface}"
                )

                print(
                    f"           IPv4: {iface_ip}\n"
                )

                return iface

        except Exception:
            continue

    return None

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
        "Behavioral Detectors Active:"
    )
    print(
        f"  1. PortScan           : {PORTSCAN_PORT_THRESHOLD} ports / {PORTSCAN_WINDOW}s"
    )
    print(
        f"  2. BruteForce         : {BRUTEFORCE_THRESHOLD} attempts / {BRUTEFORCE_WINDOW}s"
    )
    print(
        f"  3. HTTP DoS           : {HTTP_DOS_THRESHOLD} reqs / {HTTP_DOS_WINDOW}s"
    )
    print(
        f"  4. TCP SYN Flood      : {TCP_SYN_FLOOD_THRESHOLD} SYNs / {TCP_SYN_FLOOD_WINDOW}s"
    )
    print(
        f"  5. UDP Flood          : {UDP_FLOOD_THRESHOLD} packets / {UDP_FLOOD_WINDOW}s"
    )
    print(
        f"  6. ICMP Ping Flood    : {ICMP_FLOOD_THRESHOLD} packets / {ICMP_FLOOD_WINDOW}s"
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
    # Start behavioral cleanup worker
    # --------------------------------------------------------

    behavioral_worker = threading.Thread(
        target=cleanup_behavioral_trackers,
        daemon=True
    )


    behavioral_worker.start()

    capture_interface = find_capture_interface()

    if capture_interface is None:

        print(
            f"\n[ERROR] Could not find a Scapy interface "
            f"with IP {PC_IP}"
        )

        print(
            "Packet capture cannot safely continue."
        )

        return


    # --------------------------------------------------------
    # Start Scapy capture
    # --------------------------------------------------------

    sniffer = None
    stopping = False

    def stop_capture(signum=None, frame=None):
        nonlocal stopping
        if stopping:
            print("\n[AI-NIDS] Forced exit requested. Terminating immediately...")
            os._exit(0)

        stopping = True
        print("\n[AI-NIDS] Stopping packet capture... (press CTRL+C again to force exit)")
        stop_event.set()

        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass


    signal.signal(
        signal.SIGINT,
        stop_capture
    )


    try:

        sniffer = AsyncSniffer(
            iface=capture_interface,
            filter="ip",
            prn=handle_packet,
            store=False
        )

        sniffer.start()


        while not stop_event.wait(0.3):

            pass


    except KeyboardInterrupt:

        stop_capture()


    except Exception as e:

        print(
            f"\n[ERROR] Packet capture failed: {e}"
        )

        write_output(
            f"\n[ERROR] Packet capture failed: "
            f"{e}\n"
        )


    finally:

        stop_event.set()

        if sniffer is not None:

            try:
                sniffer.stop()
            except Exception:
                pass

            try:
                # Use timed join so Npcap C-level wait never hangs the main thread on Windows
                sniffer.join(timeout=0.5)
            except Exception:
                pass


        # ----------------------------------------------------
        # Process remaining flows
        # ----------------------------------------------------

        remaining = []

        with lock:

            for key, flow in flows.items():

                remaining.append(flow)

            flows.clear()


        if remaining:
            print(f"[AI-NIDS] Finalizing {len(remaining)} captured flow(s)...")
            for flow in remaining:
                try:
                    process_flow(flow)
                except Exception:
                    pass


        print(
            "\nCapture stopped successfully."
        )

        print(
            f"Results saved to {OUTPUT_FILE}"
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()