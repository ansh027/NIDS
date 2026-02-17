"""
PCAP Analysis History Manager.

Saves, lists, retrieves, and deletes analysis history entries as JSON files.
"""

import json
import os
import uuid
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import HISTORY_DIR


def save_analysis(filename: str, result: dict) -> str:
    """
    Save an analysis result to history.

    Parameters
    ----------
    filename : str
        Original PCAP filename.
    result : dict
        Analysis result from analyze_pcap().

    Returns
    -------
    str
        The generated history entry ID.
    """
    entry_id = uuid.uuid4().hex[:12]
    timestamp = datetime.now().isoformat()

    # Convert features DataFrame rows to serialisable list of dicts
    features = []
    if result.get("features_df") is not None and not result["features_df"].empty:
        features = result["features_df"].to_dict(orient="records")
        # Ensure all values are JSON-serialisable (convert numpy types)
        for row in features:
            for key, val in row.items():
                if hasattr(val, "item"):        # numpy scalar
                    row[key] = val.item()
                elif hasattr(val, "tolist"):     # numpy array
                    row[key] = val.tolist()

    entry = {
        "id": entry_id,
        "filename": filename,
        "timestamp": timestamp,
        "packet_count": int(result.get("packet_count", 0)),
        "flow_count": int(result.get("flow_count", 0)),
        "summary": result.get("summary", {}),
        "results": result.get("results", []),
        "features": features,
    }

    os.makedirs(HISTORY_DIR, exist_ok=True)
    filepath = os.path.join(HISTORY_DIR, f"{entry_id}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, default=str)

    return entry_id


def list_analyses() -> list:
    """
    List all saved analyses, newest first.

    Returns a list of dicts with id, filename, timestamp, packet_count,
    flow_count, and summary (no full features/results for performance).
    """
    os.makedirs(HISTORY_DIR, exist_ok=True)
    entries = []

    for fname in os.listdir(HISTORY_DIR):
        if not fname.endswith(".json"):
            continue
        filepath = os.path.join(HISTORY_DIR, fname)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries.append({
                "id": data.get("id", fname.replace(".json", "")),
                "filename": data.get("filename", "Unknown"),
                "timestamp": data.get("timestamp", ""),
                "packet_count": data.get("packet_count", 0),
                "flow_count": data.get("flow_count", 0),
                "summary": data.get("summary", {}),
            })
        except (json.JSONDecodeError, OSError):
            continue

    # Sort by timestamp, newest first
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return entries


def get_analysis(entry_id: str) -> dict | None:
    """
    Load a full analysis entry by ID.

    Returns None if not found.
    """
    filepath = os.path.join(HISTORY_DIR, f"{entry_id}.json")
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def delete_analysis(entry_id: str) -> bool:
    """
    Delete a history entry by ID.

    Returns True if deleted, False if not found.
    """
    filepath = os.path.join(HISTORY_DIR, f"{entry_id}.json")
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    return False
