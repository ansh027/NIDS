"""
Preprocess CIC-IDS2017 dataset into the format expected by our NIDS model.

Maps CIC-IDS2017 78-feature CSVs → our 13-feature schema, maps labels
to our 5 attack type categories, cleans data, and optionally balances classes.

Usage:
    python scripts/preprocess_cicids.py <path_to_cicids_folder> [--max-samples 50000]
"""

import os
import sys
import glob
import argparse

import pandas as pd
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FEATURE_COLUMNS, DATASET_PATH


# ── Label mapping: CIC-IDS2017 labels → our attack_type codes ──────────────

LABEL_MAPPING = {
    # Normal
    "BENIGN": 0,
    # Port Scan (attack_type = 1)
    "PortScan": 1,
    # DoS Flood (attack_type = 2)
    "DoS Hulk": 2,
    "DoS GoldenEye": 2,
    "DoS slowloris": 2,
    "DoS Slowhttptest": 2,
    "DDoS": 2,
    # Brute Force (attack_type = 3)
    "FTP-Patator": 3,
    "SSH-Patator": 3,
    "Web Attack \u2013 Brute Force": 3,
    "Web Attack Brute Force": 3,
    # Data Exfiltration / Infiltration (attack_type = 4)
    "Bot": 4,
    "Infiltration": 4,
    "Heartbleed": 4,
    # Web attacks → map to Brute Force category
    "Web Attack \u2013 XSS": 3,
    "Web Attack \u2013 Sql Injection": 3,
    "Web Attack XSS": 3,
    "Web Attack Sql Injection": 3,
}

ATTACK_NAMES = {0: "Normal", 1: "Port Scan", 2: "DoS Flood", 3: "Brute Force", 4: "Data Exfiltration"}


def load_cicids_csvs(folder_path: str) -> pd.DataFrame:
    """Load and concatenate all CIC-IDS2017 CSV files from a folder."""
    csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {folder_path}")

    print(f"[*] Found {len(csv_files)} CSV file(s):")
    for f in csv_files:
        print(f"    - {os.path.basename(f)}")

    frames = []
    for f in csv_files:
        try:
            df = pd.read_csv(f, encoding="utf-8", low_memory=False)
            # Strip whitespace from column names (CIC-IDS2017 has leading spaces)
            df.columns = df.columns.str.strip()
            print(f"    ✓ {os.path.basename(f)}: {len(df)} rows, {len(df.columns)} cols")
            frames.append(df)
        except Exception as e:
            print(f"    ✗ {os.path.basename(f)}: ERROR - {e}")

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n[+] Total rows loaded: {len(combined)}")
    return combined


def map_protocol(df: pd.DataFrame) -> pd.Series:
    """Map protocol column to numeric: TCP=0, UDP=1, other=2."""
    if "Protocol" in df.columns:
        return df["Protocol"].map({6: 0, 17: 1}).fillna(2).astype(int)
    return pd.Series(0, index=df.index)


def map_flags(df: pd.DataFrame) -> pd.Series:
    """Derive a simplified flag encoding from TCP flag counts."""
    flag = pd.Series(0, index=df.index)

    # Use flag counts if available
    flag_cols = {
        "SYN Flag Count": 1,
        "SYN Flag Cnt": 1,
        "FIN Flag Count": 2,
        "FIN Flag Cnt": 2,
        "RST Flag Count": 3,
        "RST Flag Cnt": 3,
    }

    for col, val in flag_cols.items():
        if col in df.columns:
            mask = df[col].fillna(0).astype(float) > 0
            flag = flag.where(~mask, val)

    return flag.astype(int)


def map_labels(df: pd.DataFrame) -> tuple:
    """Map CIC-IDS2017 Label column to our attack_type and binary label."""
    label_col = None
    for candidate in ["Label", "label", " Label"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise KeyError(f"No 'Label' column found. Available columns: {list(df.columns[:10])}...")

    raw_labels = df[label_col].astype(str).str.strip()

    # Show label distribution
    print(f"\n[*] CIC-IDS2017 label distribution:")
    for lbl, cnt in raw_labels.value_counts().items():
        mapped = LABEL_MAPPING.get(lbl, -1)
        mapped_name = ATTACK_NAMES.get(mapped, "UNMAPPED")
        print(f"    {lbl:40s} → {mapped_name:20s} ({cnt:,} samples)")

    attack_type = raw_labels.map(LABEL_MAPPING)

    # Handle unmapped labels
    unmapped = attack_type.isna()
    if unmapped.any():
        unmapped_labels = raw_labels[unmapped].unique()
        print(f"\n[!] WARNING: {unmapped.sum()} rows with unmapped labels: {unmapped_labels}")
        print(f"    Dropping these rows.")
        attack_type = attack_type.dropna()

    attack_type = attack_type.astype(int)
    binary_label = (attack_type > 0).astype(int)

    return binary_label, attack_type


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map CIC-IDS2017 columns to our 13 FEATURE_COLUMNS.

    CIC-IDS2017 uses CICFlowMeter features. We map the closest
    equivalents to our simplified feature schema.
    """
    features = pd.DataFrame(index=df.index)

    # 1. duration: Flow Duration (µs → seconds)
    if "Flow Duration" in df.columns:
        features["duration"] = df["Flow Duration"].astype(float) / 1_000_000.0
    else:
        features["duration"] = 0.0

    # 2. protocol_type: Protocol number → 0=TCP, 1=UDP, 2=other
    features["protocol_type"] = map_protocol(df)

    # 3. src_bytes: Total Length of Fwd Packets (or derived)
    for col in ["Total Length of Fwd Packets", "TotLen Fwd Pkts",
                 "Fwd Packet Length Mean", "Fwd Packets Length Total"]:
        if col in df.columns:
            if "Mean" in col and "Total Fwd Packets" in df.columns:
                features["src_bytes"] = (df[col].astype(float) *
                                         df["Total Fwd Packets"].astype(float)).fillna(0)
            else:
                features["src_bytes"] = df[col].astype(float).fillna(0)
            break
    if "src_bytes" not in features.columns:
        features["src_bytes"] = 0

    # 4. dst_bytes: Total Length of Bwd Packets (or derived)
    for col in ["Total Length of Bwd Packets", "TotLen Bwd Pkts",
                 "Bwd Packet Length Mean", "Bwd Packets Length Total"]:
        if col in df.columns:
            if "Mean" in col and "Total Backward Packets" in df.columns:
                features["dst_bytes"] = (df[col].astype(float) *
                                         df["Total Backward Packets"].astype(float)).fillna(0)
            else:
                features["dst_bytes"] = df[col].astype(float).fillna(0)
            break
    if "dst_bytes" not in features.columns:
        features["dst_bytes"] = 0

    # 5. count: Total packets in flow (fwd + bwd)
    fwd_pkts_col = _find_column(df, ["Total Fwd Packets", "Total Fwd Packet"])
    bwd_pkts_col = _find_column(df, ["Total Backward Packets", "Total Bwd packets",
                                      "Total Backward Packet"])
    fwd = df[fwd_pkts_col].astype(float).fillna(0) if fwd_pkts_col else 0
    bwd = df[bwd_pkts_col].astype(float).fillna(0) if bwd_pkts_col else 0
    features["count"] = fwd + bwd

    # 6. srv_count: Use Destination Port as a service proxy (binned/capped)
    dst_port_col = _find_column(df, ["Destination Port", "Dst Port"])
    if dst_port_col:
        features["srv_count"] = df[dst_port_col].astype(float).fillna(0).clip(0, 255).astype(int)
    else:
        features["srv_count"] = 0

    # 7. same_srv_rate: Use Flow IAT Mean / Flow IAT Max as rate proxy (0-1)
    iat_mean_col = _find_column(df, ["Flow IAT Mean"])
    iat_max_col = _find_column(df, ["Flow IAT Max"])
    if iat_mean_col and iat_max_col:
        iat_max = df[iat_max_col].astype(float).replace(0, 1)
        features["same_srv_rate"] = (df[iat_mean_col].astype(float) / iat_max).clip(0, 1).fillna(0.5)
    else:
        features["same_srv_rate"] = 0.5

    # 8. dst_host_count: Fwd Header Length (normalized)
    fwd_hdr_col = _find_column(df, ["Fwd Header Length", "Fwd Header Len"])
    if fwd_hdr_col:
        val = df[fwd_hdr_col].astype(float).fillna(0)
        features["dst_host_count"] = (val / val.max() * 255).clip(0, 255).fillna(0).astype(int)
    else:
        features["dst_host_count"] = 0

    # 9. dst_host_srv_count: Bwd Header Length (normalized)
    bwd_hdr_col = _find_column(df, ["Bwd Header Length", "Bwd Header Len"])
    if bwd_hdr_col:
        val = df[bwd_hdr_col].astype(float).fillna(0)
        features["dst_host_srv_count"] = (val / val.max() * 255).clip(0, 255).fillna(0).astype(int)
    else:
        features["dst_host_srv_count"] = 0

    # 10. flag: Derived from TCP flag counts
    features["flag"] = map_flags(df)

    # 11. packet_size_avg: Average Packet Size (direct)
    avg_pkt_col = _find_column(df, ["Average Packet Size", "Avg Packet Size",
                                     "Packet Length Mean", "Pkt Len Mean"])
    if avg_pkt_col:
        features["packet_size_avg"] = df[avg_pkt_col].astype(float).fillna(0)
    else:
        features["packet_size_avg"] = 0

    # 12. fwd_packets: Total Fwd Packets (direct)
    features["fwd_packets"] = fwd

    # 13. bwd_packets: Total Backward Packets (direct)
    features["bwd_packets"] = bwd

    return features


def _find_column(df: pd.DataFrame, candidates: list) -> str | None:
    """Find the first matching column name from a list of candidates."""
    for col in candidates:
        if col in df.columns:
            return col
    return None


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Remove NaN/Inf values and ensure correct dtypes."""
    initial = len(df)

    # Replace infinities with NaN
    df = df.replace([np.inf, -np.inf], np.nan)

    # Drop rows with any NaN
    df = df.dropna()

    dropped = initial - len(df)
    if dropped > 0:
        print(f"[*] Cleaned: dropped {dropped} rows with NaN/Inf ({dropped/initial*100:.1f}%)")

    return df.reset_index(drop=True)


def balance_classes(df: pd.DataFrame, max_per_class: int = 10000,
                    seed: int = 42) -> pd.DataFrame:
    """Undersample majority classes to balance the dataset."""
    rng = np.random.RandomState(seed)
    frames = []

    for cls in sorted(df["attack_type"].unique()):
        subset = df[df["attack_type"] == cls]
        n = min(len(subset), max_per_class)
        sampled = subset.sample(n=n, random_state=rng)
        frames.append(sampled)
        print(f"    {ATTACK_NAMES.get(cls, cls):20s}: {len(subset):>8,} → {n:>6,} samples")

    balanced = pd.concat(frames, ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=seed).reset_index(drop=True)
    return balanced


def preprocess(folder_path: str, output_path: str = None,
               max_per_class: int = 10000, seed: int = 42):
    """
    Full preprocessing pipeline: load → extract features → map labels → clean → balance → save.
    """
    output_path = output_path or DATASET_PATH

    print("=" * 60)
    print("  CIC-IDS2017 → NIDS Preprocessor")
    print("=" * 60)

    # 1. Load CSVs
    raw_df = load_cicids_csvs(folder_path)

    # 2. Map labels
    binary_label, attack_type = map_labels(raw_df)

    # Keep only rows with valid labels
    valid_idx = attack_type.index
    raw_df = raw_df.loc[valid_idx]

    # 3. Extract features
    print(f"\n[*] Extracting features...")
    features = extract_features(raw_df)

    # 4. Combine features + labels
    features["label"] = binary_label.values
    features["attack_type"] = attack_type.values

    # 5. Clean
    print(f"\n[*] Cleaning data...")
    features = clean_data(features)

    # 6. Balance classes
    print(f"\n[*] Balancing classes (max {max_per_class} per class):")
    features = balance_classes(features, max_per_class=max_per_class, seed=seed)

    # 7. Verify column order matches FEATURE_COLUMNS
    assert all(col in features.columns for col in FEATURE_COLUMNS), \
        f"Missing feature columns! Expected: {FEATURE_COLUMNS}"

    # 8. Save
    features.to_csv(output_path, index=False)
    print(f"\n[+] Saved preprocessed dataset to: {output_path}")
    print(f"[+] Shape: {features.shape}")
    print(f"[+] Columns: {list(features.columns)}")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  Final Dataset Summary")
    print(f"{'=' * 60}")
    print(f"  Total samples: {len(features):,}")
    for cls in sorted(features["attack_type"].unique()):
        n = (features["attack_type"] == cls).sum()
        print(f"  {ATTACK_NAMES.get(cls, cls):20s}: {n:>6,} ({n/len(features)*100:.1f}%)")

    return features


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Preprocess CIC-IDS2017 for NIDS training")
    parser.add_argument("folder", help="Path to folder containing CIC-IDS2017 CSV files")
    parser.add_argument("--output", default=None, help="Output CSV path (default: data/network_data.csv)")
    parser.add_argument("--max-samples", type=int, default=10000,
                        help="Max samples per class for balancing (default: 10000)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()
    preprocess(args.folder, args.output, args.max_samples, args.seed)
