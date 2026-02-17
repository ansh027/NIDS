"""
Central configuration for the Network Intrusion Detection Tool.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
DATASET_PATH = os.path.join(DATA_DIR, "network_data.csv")
MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")

# Alerting
ALERT_SETTINGS_PATH = os.path.join(DATA_DIR, "alert_settings.json")
ALERT_LOG_PATH = os.path.join(DATA_DIR, "alerts.json")
ALERT_COOLDOWN_SECONDS = 60

# Ensure directories exist
for d in [DATA_DIR, MODELS_DIR, UPLOAD_DIR, HISTORY_DIR]:
    os.makedirs(d, exist_ok=True)

# Feature columns (order matters — must match training)
FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "same_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "flag",
    "packet_size_avg",
    "fwd_packets",
    "bwd_packets",
]

# Label mappings
LABEL_MAP = {0: "Normal", 1: "Intrusion"}

ATTACK_TYPES = {
    0: "Normal",
    1: "Port Scan",
    2: "DoS Flood",
    3: "Brute Force",
    4: "Data Exfiltration",
}

# Model hyperparameters
RF_N_ESTIMATORS = 200
RF_MAX_DEPTH = 30
RF_RANDOM_STATE = 42

# Live capture settings
LIVE_CAPTURE_BUFFER_SECONDS = 5
LIVE_CAPTURE_PACKET_COUNT = 100

# Flask settings
FLASK_SECRET_KEY = "nids-secret-key-change-in-production"
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
