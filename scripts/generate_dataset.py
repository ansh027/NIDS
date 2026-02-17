"""
Generate a synthetic network intrusion detection dataset.

Creates ~10,000 rows of labeled network flow data with realistic
distributions for normal traffic and four attack categories:
  - Port Scan
  - DoS Flood
  - Brute Force
  - Data Exfiltration

Usage:
    python scripts/generate_dataset.py
"""

import os
import sys
import numpy as np
import pandas as pd

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DATA_DIR, DATASET_PATH, FEATURE_COLUMNS


def generate_normal_traffic(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate normal network traffic patterns."""
    return pd.DataFrame({
        "duration":         rng.exponential(scale=10.0, size=n).clip(0.01, 300),
        "protocol_type":    rng.choice([0, 1, 2], size=n, p=[0.6, 0.3, 0.1]),  # TCP, UDP, ICMP
        "src_bytes":        rng.lognormal(mean=7, sigma=1.5, size=n).astype(int).clip(0, 500000),
        "dst_bytes":        rng.lognormal(mean=7, sigma=1.5, size=n).astype(int).clip(0, 500000),
        "count":            rng.poisson(lam=5, size=n).clip(1, 50),
        "srv_count":        rng.poisson(lam=3, size=n).clip(1, 30),
        "same_srv_rate":    rng.beta(a=5, b=2, size=n).round(4),
        "dst_host_count":   rng.poisson(lam=10, size=n).clip(1, 255),
        "dst_host_srv_count": rng.poisson(lam=5, size=n).clip(1, 255),
        "flag":             rng.choice([0, 1, 2, 3], size=n, p=[0.7, 0.15, 0.1, 0.05]),  # SF, S0, REJ, RSTO
        "packet_size_avg":  rng.normal(loc=500, scale=200, size=n).clip(40, 1500),
        "fwd_packets":      rng.poisson(lam=8, size=n).clip(1, 100),
        "bwd_packets":      rng.poisson(lam=6, size=n).clip(0, 80),
        "label":            0,
        "attack_type":      0,
    })


def generate_port_scan(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Port scan: many short connections to different ports, low data transfer."""
    return pd.DataFrame({
        "duration":         rng.exponential(scale=0.5, size=n).clip(0.001, 5),
        "protocol_type":    rng.choice([0, 1], size=n, p=[0.8, 0.2]),
        "src_bytes":        rng.integers(0, 200, size=n),
        "dst_bytes":        rng.integers(0, 100, size=n),
        "count":            rng.poisson(lam=50, size=n).clip(10, 500),
        "srv_count":        rng.poisson(lam=40, size=n).clip(5, 400),
        "same_srv_rate":    rng.beta(a=1, b=5, size=n).round(4),
        "dst_host_count":   rng.poisson(lam=100, size=n).clip(20, 255),
        "dst_host_srv_count": rng.poisson(lam=2, size=n).clip(1, 20),
        "flag":             rng.choice([1, 2, 0], size=n, p=[0.5, 0.35, 0.15]),  # S0, REJ mostly
        "packet_size_avg":  rng.normal(loc=60, scale=15, size=n).clip(40, 150),
        "fwd_packets":      rng.poisson(lam=2, size=n).clip(1, 10),
        "bwd_packets":      rng.poisson(lam=1, size=n).clip(0, 5),
        "label":            1,
        "attack_type":      1,
    })


def generate_dos_flood(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """DoS flood: high connection counts, very short durations, high volume."""
    return pd.DataFrame({
        "duration":         rng.exponential(scale=0.1, size=n).clip(0.001, 2),
        "protocol_type":    rng.choice([0, 2], size=n, p=[0.5, 0.5]),
        "src_bytes":        rng.integers(500, 50000, size=n),
        "dst_bytes":        rng.integers(0, 500, size=n),
        "count":            rng.poisson(lam=200, size=n).clip(50, 1000),
        "srv_count":        rng.poisson(lam=150, size=n).clip(30, 800),
        "same_srv_rate":    rng.beta(a=8, b=1, size=n).round(4),
        "dst_host_count":   rng.poisson(lam=3, size=n).clip(1, 10),
        "dst_host_srv_count": rng.poisson(lam=2, size=n).clip(1, 10),
        "flag":             rng.choice([1, 3, 0], size=n, p=[0.4, 0.4, 0.2]),
        "packet_size_avg":  rng.normal(loc=1200, scale=200, size=n).clip(500, 1500),
        "fwd_packets":      rng.poisson(lam=50, size=n).clip(10, 500),
        "bwd_packets":      rng.poisson(lam=1, size=n).clip(0, 5),
        "label":            1,
        "attack_type":      2,
    })


def generate_brute_force(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Brute force: repeated connections to same service, moderate data transfer."""
    return pd.DataFrame({
        "duration":         rng.exponential(scale=2.0, size=n).clip(0.1, 30),
        "protocol_type":    np.full(n, 0),  # TCP only
        "src_bytes":        rng.integers(100, 2000, size=n),
        "dst_bytes":        rng.integers(50, 1000, size=n),
        "count":            rng.poisson(lam=80, size=n).clip(20, 500),
        "srv_count":        rng.poisson(lam=70, size=n).clip(15, 400),
        "same_srv_rate":    rng.beta(a=9, b=1, size=n).round(4),
        "dst_host_count":   rng.poisson(lam=2, size=n).clip(1, 5),
        "dst_host_srv_count": rng.poisson(lam=50, size=n).clip(10, 255),
        "flag":             rng.choice([0, 2, 1], size=n, p=[0.3, 0.5, 0.2]),
        "packet_size_avg":  rng.normal(loc=200, scale=50, size=n).clip(60, 500),
        "fwd_packets":      rng.poisson(lam=5, size=n).clip(1, 30),
        "bwd_packets":      rng.poisson(lam=3, size=n).clip(0, 20),
        "label":            1,
        "attack_type":      3,
    })


def generate_data_exfiltration(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Data exfiltration: long duration, high outbound bytes, low inbound."""
    return pd.DataFrame({
        "duration":         rng.exponential(scale=60.0, size=n).clip(10, 600),
        "protocol_type":    rng.choice([0, 1], size=n, p=[0.7, 0.3]),
        "src_bytes":        rng.lognormal(mean=12, sigma=1.0, size=n).astype(int).clip(10000, 5000000),
        "dst_bytes":        rng.integers(50, 2000, size=n),
        "count":            rng.poisson(lam=3, size=n).clip(1, 15),
        "srv_count":        rng.poisson(lam=2, size=n).clip(1, 10),
        "same_srv_rate":    rng.beta(a=7, b=2, size=n).round(4),
        "dst_host_count":   rng.poisson(lam=2, size=n).clip(1, 5),
        "dst_host_srv_count": rng.poisson(lam=1, size=n).clip(1, 5),
        "flag":             rng.choice([0, 1], size=n, p=[0.8, 0.2]),
        "packet_size_avg":  rng.normal(loc=1400, scale=100, size=n).clip(800, 1500),
        "fwd_packets":      rng.poisson(lam=30, size=n).clip(5, 200),
        "bwd_packets":      rng.poisson(lam=2, size=n).clip(0, 10),
        "label":            1,
        "attack_type":      4,
    })


def generate_dataset(total: int = 10000, seed: int = 42) -> pd.DataFrame:
    """Generate the full synthetic dataset."""
    rng = np.random.default_rng(seed)

    # 60% normal, 10% each for 4 attack types
    n_normal = int(total * 0.60)
    n_portscan = int(total * 0.10)
    n_dos = int(total * 0.10)
    n_brute = int(total * 0.10)
    n_exfil = total - n_normal - n_portscan - n_dos - n_brute

    frames = [
        generate_normal_traffic(n_normal, rng),
        generate_port_scan(n_portscan, rng),
        generate_dos_flood(n_dos, rng),
        generate_brute_force(n_brute, rng),
        generate_data_exfiltration(n_exfil, rng),
    ]

    df = pd.concat(frames, ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    # Round floats for cleanliness
    for col in ["duration", "same_srv_rate", "packet_size_avg"]:
        df[col] = df[col].round(4)

    return df


def main():
    print("[*] Generating synthetic network intrusion dataset...")
    df = generate_dataset()
    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)

    print(f"[+] Dataset saved to: {DATASET_PATH}")
    print(f"[+] Total samples: {len(df)}")
    print(f"[+] Normal: {(df['label'] == 0).sum()}")
    print(f"[+] Intrusion: {(df['label'] == 1).sum()}")
    print(f"\n[+] Attack type breakdown:")
    for code, name in {0: "Normal", 1: "Port Scan", 2: "DoS Flood", 3: "Brute Force", 4: "Data Exfiltration"}.items():
        count = (df["attack_type"] == code).sum()
        print(f"    {name}: {count}")
    print(f"\n[+] Feature columns: {FEATURE_COLUMNS}")
    print(f"[+] Sample rows:")
    print(df.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
