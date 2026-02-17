"""
Feature extraction from raw network packets (Scapy) and from DataFrames.

Converts raw packet lists into the standardized feature vector
used by the Random Forest model.
"""

import pandas as pd
import numpy as np
from collections import defaultdict

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FEATURE_COLUMNS


# Protocol mapping
PROTO_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

# TCP flag mapping
FLAG_MAP = {
    "SF": 0,    # Normal (SYN + FIN)
    "S0": 1,    # Connection attempt, no reply
    "REJ": 2,   # Rejected
    "RSTO": 3,  # Reset from originator
}


def _get_protocol(packet) -> int:
    """Get protocol type from a Scapy packet."""
    try:
        from scapy.all import TCP, UDP, ICMP
        if packet.haslayer(TCP):
            return 0
        elif packet.haslayer(UDP):
            return 1
        elif packet.haslayer(ICMP):
            return 2
    except ImportError:
        pass
    return 0


def _get_tcp_flag(packet) -> int:
    """Derive a simplified flag value from TCP flags."""
    try:
        from scapy.all import TCP
        if packet.haslayer(TCP):
            flags = str(packet[TCP].flags)
            if "S" in flags and "A" in flags:
                return 0  # SF-like
            elif "S" in flags and "A" not in flags:
                return 1  # S0
            elif "R" in flags:
                return 3  # RSTO
            else:
                return 0
    except ImportError:
        pass
    return 0


def extract_features_from_packets(packets) -> pd.DataFrame:
    """
    Convert a list of Scapy packets into a DataFrame of features.

    Groups packets into flows (by src_ip → dst_ip pair) and computes
    aggregate features per flow.

    Parameters
    ----------
    packets : list
        List of Scapy packet objects.

    Returns
    -------
    pd.DataFrame
        DataFrame with columns matching FEATURE_COLUMNS.
    """
    try:
        from scapy.all import IP
    except ImportError:
        raise ImportError("Scapy is required for packet feature extraction. "
                          "Install it with: pip install scapy")

    if not packets:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    # Group packets into flows (src_ip -> dst_ip)
    flows = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(IP):
            key = (pkt[IP].src, pkt[IP].dst)
            flows[key].append(pkt)

    if not flows:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    rows = []
    all_flow_keys = list(flows.keys())

    for (src_ip, dst_ip), flow_pkts in flows.items():
        n = len(flow_pkts)

        # Timestamps
        timestamps = [float(pkt.time) for pkt in flow_pkts]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001

        # Protocol (majority vote)
        protocols = [_get_protocol(p) for p in flow_pkts]
        protocol_type = max(set(protocols), key=protocols.count)

        # Bytes
        src_bytes_total = sum(len(p) for p in flow_pkts)
        # Look for reverse flow
        reverse_key = (dst_ip, src_ip)
        reverse_pkts = flows.get(reverse_key, [])
        dst_bytes_total = sum(len(p) for p in reverse_pkts)

        # Connection counts
        count = sum(1 for k in all_flow_keys if k[1] == dst_ip)
        srv_count = sum(1 for k in all_flow_keys if k[1] == dst_ip and
                        _get_protocol(flows[k][0]) == protocol_type)
        same_srv_rate = round(srv_count / max(count, 1), 4)

        # Destination host counts
        dst_host_count = len(set(k[1] for k in all_flow_keys if k[0] == src_ip))
        dst_host_srv_count = len(set(k[1] for k in all_flow_keys if k[0] == src_ip and
                                     _get_protocol(flows[k][0]) == protocol_type))

        # Flag
        flags = [_get_tcp_flag(p) for p in flow_pkts]
        flag = max(set(flags), key=flags.count)

        # Packet size
        sizes = [len(p) for p in flow_pkts]
        packet_size_avg = round(np.mean(sizes), 4) if sizes else 0

        # Forward / backward packets
        fwd_packets = n
        bwd_packets = len(reverse_pkts)

        rows.append({
            "duration": round(duration, 4),
            "protocol_type": protocol_type,
            "src_bytes": src_bytes_total,
            "dst_bytes": dst_bytes_total,
            "count": count,
            "srv_count": srv_count,
            "same_srv_rate": same_srv_rate,
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "flag": flag,
            "packet_size_avg": packet_size_avg,
            "fwd_packets": fwd_packets,
            "bwd_packets": bwd_packets,
        })

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def validate_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure a DataFrame has exactly the expected feature columns,
    filling missing ones with 0 and dropping extras.
    """
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df[FEATURE_COLUMNS]
