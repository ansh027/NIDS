"""
Offline PCAP file analyzer.

Reads a .pcap / .pcapng file using Scapy, extracts flow features,
and runs detection through the Random Forest model.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feature_extractor import extract_features_from_packets
from core.detector import Detector


def analyze_pcap(
    pcap_path: str,
    model_path: str = None,
    verbose: bool = True,
) -> dict:
    """
    Analyze a PCAP file for network intrusions.

    Parameters
    ----------
    pcap_path : str
        Path to the .pcap or .pcapng file.
    model_path : str, optional
        Path to the trained model. Uses default if None.
    verbose : bool
        Whether to print progress.

    Returns
    -------
    dict
        Keys: features_df, results, summary, packet_count, flow_count.
    """
    try:
        from scapy.all import rdpcap
    except ImportError:
        raise ImportError(
            "Scapy is required for PCAP analysis. Install it with: pip install scapy"
        )

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Read packets
    if verbose:
        print(f"[*] Reading PCAP file: {pcap_path}")
    packets = rdpcap(pcap_path)
    packet_count = len(packets)

    if verbose:
        print(f"[+] Loaded {packet_count} packets")

    # Extract features
    if verbose:
        print("[*] Extracting flow features...")
    features_df = extract_features_from_packets(packets)
    flow_count = len(features_df)

    if verbose:
        print(f"[+] Identified {flow_count} network flows")

    if features_df.empty:
        if verbose:
            print("[!] No IP-level flows found in PCAP.")
        return {
            "features_df": features_df,
            "results": [],
            "summary": {"total": 0, "normal": 0, "intrusion": 0},
            "packet_count": packet_count,
            "flow_count": 0,
        }

    # Run detection
    if verbose:
        print("[*] Running intrusion detection...")
    detector = Detector(model_path=model_path)
    results = detector.predict(features_df)
    summary = detector.summary(results)

    # Enrich the features DataFrame
    enriched_df = detector.predict_dataframe(features_df)

    if verbose:
        print(f"\n{'='*50}")
        print(f"  PCAP ANALYSIS RESULTS")
        print(f"{'='*50}")
        print(f"  Packets analyzed:  {packet_count}")
        print(f"  Flows detected:    {flow_count}")
        print(f"  Normal flows:      {summary['normal']}")
        print(f"  Intrusion flows:   {summary['intrusion']}")
        if summary['total'] > 0:
            print(f"  Intrusion rate:    {summary['intrusion_rate']}%")
            print(f"  Malicious:         {summary['malicious']}")
            print(f"  Suspicious:        {summary['suspicious']}")
        print(f"{'='*50}")
        print()
        print(enriched_df.to_string(index=False))

    return {
        "features_df": enriched_df,
        "results": results,
        "summary": summary,
        "packet_count": packet_count,
        "flow_count": flow_count,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py <pcap_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
