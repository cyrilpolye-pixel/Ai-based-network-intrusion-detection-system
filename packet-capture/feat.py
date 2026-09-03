from statistics import mean, pstdev, pvariance


FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


def safe_mean(values):
    return mean(values) if values else 0.0


def safe_std(values):
    return pstdev(values) if len(values) > 1 else 0.0


def safe_variance(values):
    return pvariance(values) if len(values) > 1 else 0.0


def packet_lengths(packets):
    return [len(pkt) for pkt in packets]


def packet_times(packets):
    return [float(pkt.time) for pkt in packets]


def calculate_iats(times):
    if len(times) < 2:
        return []

    return [
        times[i] - times[i - 1]
        for i in range(1, len(times))
    ]


def get_tcp_header_length(pkt):
    if pkt.haslayer("TCP"):
        return int(pkt["TCP"].dataofs or 5) * 4

    return 0


def get_tcp_window(pkt):
    if pkt.haslayer("TCP"):
        return int(pkt["TCP"].window)

    return 0


def get_segment_size(pkt):
    if pkt.haslayer("TCP"):
        return len(bytes(pkt["TCP"].payload))

    return 0


def calculate_active_idle(times, threshold=1.0):
    if len(times) < 2:
        return 0.0, 0.0, 0.0, 0.0, [], []

    intervals = [
        times[i] - times[i - 1]
        for i in range(1, len(times))
    ]

    active_periods = []
    idle_periods = []

    current_active = 0.0

    for interval in intervals:
        if interval <= threshold:
            current_active += interval
        else:
            if current_active > 0:
                active_periods.append(current_active)

            idle_periods.append(interval)
            current_active = 0.0

    if current_active > 0:
        active_periods.append(current_active)

    active_mean = safe_mean(active_periods)
    active_std = safe_std(active_periods)
    active_max = max(active_periods) if active_periods else 0.0
    active_min = min(active_periods) if active_periods else 0.0

    idle_mean = safe_mean(idle_periods)
    idle_std = safe_std(idle_periods)
    idle_max = max(idle_periods) if idle_periods else 0.0
    idle_min = min(idle_periods) if idle_periods else 0.0

    return (
        active_mean,
        active_std,
        active_max,
        active_min,
        idle_periods,
        [
            idle_mean,
            idle_std,
            idle_max,
            idle_min,
        ],
    )


def calculate_features(flow):
    packets = flow["packets"]

    if not packets:
        raise ValueError("Flow contains no packets")

    first_time = float(packets[0].time)
    last_time = float(packets[-1].time)

    duration = max(last_time - first_time, 0.0)

    src_ip = flow["src_ip"]
    src_port = flow["src_port"]

    fwd_packets = []
    bwd_packets = []

    for pkt in packets:

        if not pkt.haslayer("IP"):
            continue

        ip = pkt["IP"]

        if ip.src == src_ip:
            if (
                flow["protocol"] == "TCP"
                and pkt.haslayer("TCP")
                and pkt["TCP"].sport == src_port
            ):
                fwd_packets.append(pkt)

            elif (
                flow["protocol"] == "UDP"
                and pkt.haslayer("UDP")
                and pkt["UDP"].sport == src_port
            ):
                fwd_packets.append(pkt)

        else:
            bwd_packets.append(pkt)

    all_lengths = packet_lengths(packets)
    fwd_lengths = packet_lengths(fwd_packets)
    bwd_lengths = packet_lengths(bwd_packets)

    all_times = packet_times(packets)
    fwd_times = packet_times(fwd_packets)
    bwd_times = packet_times(bwd_packets)

    all_iats = calculate_iats(all_times)
    fwd_iats = calculate_iats(fwd_times)
    bwd_iats = calculate_iats(bwd_times)

    total_fwd_packets = len(fwd_packets)
    total_bwd_packets = len(bwd_packets)

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)

    fwd_max = max(fwd_lengths) if fwd_lengths else 0
    fwd_min = min(fwd_lengths) if fwd_lengths else 0

    bwd_max = max(bwd_lengths) if bwd_lengths else 0
    bwd_min = min(bwd_lengths) if bwd_lengths else 0

    fwd_mean = safe_mean(fwd_lengths)
    fwd_std = safe_std(fwd_lengths)

    bwd_mean = safe_mean(bwd_lengths)
    bwd_std = safe_std(bwd_lengths)

    flow_bytes = total_fwd_bytes + total_bwd_bytes
    flow_packets = total_fwd_packets + total_bwd_packets

    flow_bytes_per_sec = (
        flow_bytes / duration
        if duration > 0
        else 0.0
    )

    flow_packets_per_sec = (
        flow_packets / duration
        if duration > 0
        else 0.0
    )

    flow_iat_mean = safe_mean(all_iats)
    flow_iat_std = safe_std(all_iats)
    flow_iat_max = max(all_iats) if all_iats else 0.0
    flow_iat_min = min(all_iats) if all_iats else 0.0

    fwd_iat_total = sum(fwd_iats)
    fwd_iat_mean = safe_mean(fwd_iats)
    fwd_iat_std = safe_std(fwd_iats)
    fwd_iat_max = max(fwd_iats) if fwd_iats else 0.0
    fwd_iat_min = min(fwd_iats) if fwd_iats else 0.0

    bwd_iat_total = sum(bwd_iats)
    bwd_iat_mean = safe_mean(bwd_iats)
    bwd_iat_std = safe_std(bwd_iats)
    bwd_iat_max = max(bwd_iats) if bwd_iats else 0.0
    bwd_iat_min = min(bwd_iats) if bwd_iats else 0.0

    fwd_psh = 0
    bwd_psh = 0
    fwd_urg = 0
    bwd_urg = 0

    fin_count = 0
    syn_count = 0
    rst_count = 0
    psh_count = 0
    ack_count = 0
    urg_count = 0
    cwe_count = 0
    ece_count = 0

    fwd_header_length = 0
    bwd_header_length = 0

    init_win_forward = 0
    init_win_backward = 0

    segment_sizes = []

    for pkt in fwd_packets:

        if pkt.haslayer("TCP"):

            tcp = pkt["TCP"]

            if "P" in tcp.flags:
                fwd_psh += 1

            if "U" in tcp.flags:
                fwd_urg += 1

            if init_win_forward == 0:
                init_win_forward = get_tcp_window(pkt)

            fwd_header_length += get_tcp_header_length(pkt)

            segment_sizes.append(
                get_segment_size(pkt)
            )

    for pkt in bwd_packets:

        if pkt.haslayer("TCP"):

            tcp = pkt["TCP"]

            if "P" in tcp.flags:
                bwd_psh += 1

            if "U" in tcp.flags:
                bwd_urg += 1

            if init_win_backward == 0:
                init_win_backward = get_tcp_window(pkt)

            bwd_header_length += get_tcp_header_length(pkt)

            segment_sizes.append(
                get_segment_size(pkt)
            )

    for pkt in packets:

        if not pkt.haslayer("TCP"):
            continue

        flags = pkt["TCP"].flags

        if "F" in flags:
            fin_count += 1

        if "S" in flags:
            syn_count += 1

        if "R" in flags:
            rst_count += 1

        if "P" in flags:
            psh_count += 1

        if "A" in flags:
            ack_count += 1

        if "U" in flags:
            urg_count += 1

        if "C" in flags:
            cwe_count += 1

        if "E" in flags:
            ece_count += 1

    fwd_packets_per_sec = (
        total_fwd_packets / duration
        if duration > 0
        else 0.0
    )

    bwd_packets_per_sec = (
        total_bwd_packets / duration
        if duration > 0
        else 0.0
    )

    packet_mean = safe_mean(all_lengths)
    packet_std = safe_std(all_lengths)
    packet_variance = safe_variance(all_lengths)

    min_packet_length = (
        min(all_lengths)
        if all_lengths
        else 0
    )

    max_packet_length = (
        max(all_lengths)
        if all_lengths
        else 0
    )

    down_up_ratio = (
        total_bwd_packets / total_fwd_packets
        if total_fwd_packets > 0
        else 0.0
    )

    average_packet_size = (
        flow_bytes / flow_packets
        if flow_packets > 0
        else 0.0
    )

    avg_fwd_segment_size = (
        total_fwd_bytes / total_fwd_packets
        if total_fwd_packets > 0
        else 0.0
    )

    avg_bwd_segment_size = (
        total_bwd_bytes / total_bwd_packets
        if total_bwd_packets > 0
        else 0.0
    )

    active_mean = 0.0
    active_std = 0.0
    active_max = 0.0
    active_min = 0.0

    idle_mean = 0.0
    idle_std = 0.0
    idle_max = 0.0
    idle_min = 0.0

    if len(all_times) > 1:

        intervals = calculate_iats(all_times)

        active_periods = []
        idle_periods = []

        current_active = 0.0

        for interval in intervals:

            if interval <= 1.0:
                current_active += interval

            else:

                if current_active > 0:
                    active_periods.append(
                        current_active
                    )

                idle_periods.append(interval)
                current_active = 0.0

        if current_active > 0:
            active_periods.append(
                current_active
            )

        active_mean = safe_mean(active_periods)
        active_std = safe_std(active_periods)
        active_max = (
            max(active_periods)
            if active_periods
            else 0.0
        )
        active_min = (
            min(active_periods)
            if active_periods
            else 0.0
        )

        idle_mean = safe_mean(idle_periods)
        idle_std = safe_std(idle_periods)
        idle_max = (
            max(idle_periods)
            if idle_periods
            else 0.0
        )
        idle_min = (
            min(idle_periods)
            if idle_periods
            else 0.0
        )

    features = [

        flow["dst_port"],

        duration,

        total_fwd_packets,
        total_bwd_packets,

        total_fwd_bytes,
        total_bwd_bytes,

        fwd_max,
        fwd_min,
        fwd_mean,
        fwd_std,

        bwd_max,
        bwd_min,
        bwd_mean,
        bwd_std,

        flow_bytes_per_sec,
        flow_packets_per_sec,

        flow_iat_mean,
        flow_iat_std,
        flow_iat_max,
        flow_iat_min,

        fwd_iat_total,
        fwd_iat_mean,
        fwd_iat_std,
        fwd_iat_max,
        fwd_iat_min,

        bwd_iat_total,
        bwd_iat_mean,
        bwd_iat_std,
        bwd_iat_max,
        bwd_iat_min,

        fwd_psh,
        bwd_psh,

        fwd_urg,
        bwd_urg,

        fwd_header_length,
        bwd_header_length,

        fwd_packets_per_sec,
        bwd_packets_per_sec,

        min_packet_length,
        max_packet_length,

        packet_mean,
        packet_std,
        packet_variance,

        fin_count,
        syn_count,
        rst_count,
        psh_count,
        ack_count,
        urg_count,
        cwe_count,
        ece_count,

        down_up_ratio,

        average_packet_size,

        avg_fwd_segment_size,
        avg_bwd_segment_size,

        fwd_header_length,

        0.0,
        0.0,
        0.0,

        0.0,
        0.0,
        0.0,

        total_fwd_packets,
        total_fwd_bytes,

        total_bwd_packets,
        total_bwd_bytes,

        init_win_forward,
        init_win_backward,

        sum(
            1
            for pkt in fwd_packets
            if get_segment_size(pkt) > 0
        ),

        min(
            [
                get_segment_size(pkt)
                for pkt in fwd_packets
                if get_segment_size(pkt) > 0
            ],
            default=0,
        ),

        active_mean,
        active_std,
        active_max,
        active_min,

        idle_mean,
        idle_std,
        idle_max,
        idle_min,
    ]

    if len(features) != 78:
        raise ValueError(
            f"Expected 78 features, got {len(features)}"
        )

    return features