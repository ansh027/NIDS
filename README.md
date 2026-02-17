# 🛡️ Network Intrusion Detection System (NIDS)

An open-source, automated tool that uses a **Random Forest** classifier to detect network intrusions from both **offline PCAP files** and **live network traffic**.

## ✨ Features

- **Random Forest Classifier** — trained on synthetic network flow data
- **PCAP File Analysis** — upload and analyze `.pcap` / `.pcapng` files
- **Live Traffic Monitoring** — real-time capture and detection
- **Web Dashboard** — premium dark-themed Flask UI with charts
- **CLI Interface** — command-line access for all features
- **4 Attack Types Detected**: Port Scan, DoS Flood, Brute Force, Data Exfiltration

## 📁 Project Structure

```
Analyzer/
├── cli.py                    # CLI entry point
├── app.py                    # Flask web dashboard
├── config.py                 # Central configuration
├── requirements.txt
├── core/
│   ├── feature_extractor.py  # Packet → feature extraction
│   ├── train_model.py        # Model training & evaluation
│   ├── detector.py           # Intrusion detection engine
│   ├── pcap_analyzer.py      # Offline PCAP analysis
│   └── live_capture.py       # Live traffic capture
├── scripts/
│   └── generate_dataset.py   # Synthetic dataset generator
├── data/                     # Generated CSV datasets
├── models/                   # Trained model files
├── templates/                # Flask HTML templates
└── static/                   # CSS and JS assets
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate Dataset & Train Model

```bash
python cli.py generate    # Creates data/network_data.csv (10,000 samples)
python cli.py train       # Trains and saves the Random Forest model
```

### 3. Analyze a PCAP File

```bash
python cli.py analyze path/to/capture.pcap
```

### 4. Launch Web Dashboard

```bash
python cli.py serve
# Open http://127.0.0.1:5000
```

### 5. Live Traffic Monitoring

```bash
python cli.py live              # Default interface
python cli.py live "Wi-Fi"      # Specific interface
```

> **Note:** Live capture requires [Npcap](https://npcap.com/) (Windows) or libpcap (Linux/Mac), and administrator/root privileges.

## 🧠 Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | Random Forest |
| Trees | 100 |
| Max Depth | 20 |
| Features | 13 network flow features |
| Training Data | 10,000 synthetic samples |
| Class Balancing | Balanced class weights |

### Features Used

`duration`, `protocol_type`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, `same_srv_rate`, `dst_host_count`, `dst_host_srv_count`, `flag`, `packet_size_avg`, `fwd_packets`, `bwd_packets`

## 📄 License

MIT License — free to use, modify, and distribute.
