"""
CLI entry point for the Network Intrusion Detection Tool.

Usage:
    python cli.py train                     Train the Random Forest model
    python cli.py analyze <pcap_file>       Analyze a PCAP file
    python cli.py live [interface]          Start live traffic capture
    python cli.py serve                     Launch the Flask web dashboard
    python cli.py generate                  Generate the synthetic dataset
    python cli.py preprocess <folder>       Preprocess CIC-IDS2017 CSVs
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def print_banner():
    banner = """
    +==================================================+
    |     Network Intrusion Detection System (NIDS)    |
    |          Random Forest Classifier v1.0           |
    +==================================================+
    """
    print(banner)


def cmd_preprocess(folder_path):
    """Preprocess CIC-IDS2017 dataset into our model format."""
    from scripts.preprocess_cicids import preprocess
    preprocess(folder_path)
    print("\n[+] Done! Now run:  python cli.py train")


def cmd_generate():
    """Generate the synthetic training dataset."""
    from scripts.generate_dataset import main as gen_main
    gen_main()


def cmd_train():
    """Train the Random Forest model."""
    from core.train_model import train
    from config import DATASET_PATH

    if not os.path.exists(DATASET_PATH):
        print("[!] Dataset not found. Generating it first...")
        cmd_generate()
        print()

    train()


def cmd_analyze(pcap_path: str):
    """Analyze a PCAP file."""
    from core.pcap_analyzer import analyze_pcap
    analyze_pcap(pcap_path)


def cmd_live(interface: str = None):
    """Start live capture and print alerts to the console."""
    from core.live_capture import LiveCapture
    from config import MODEL_PATH

    if not os.path.exists(MODEL_PATH):
        print("[!] Model not found. Training first...")
        cmd_train()
        print()

    def on_results(batch):
        summary = batch.get("summary", {})
        ts = batch.get("timestamp", "")
        pkts = batch.get("packet_count", 0)
        flows = batch.get("flow_count", 0)
        intrusions = summary.get("intrusion", 0)

        status = "🔴 ALERT" if intrusions > 0 else "🟢 OK"
        print(f"[{ts}] {status}  |  Packets: {pkts}  Flows: {flows}  "
              f"Intrusions: {intrusions}")

        # Print details for intrusions
        for r in batch.get("results", []):
            if r["prediction"] == 1:
                print(f"  ⚠  Flow #{r['index']}: {r['label']} "
                      f"(confidence: {r['confidence']:.2%}, "
                      f"severity: {r['severity']})")

    print("[*] Starting live network capture...")
    print("[*] Press Ctrl+C to stop.\n")

    capture = LiveCapture(interface=interface, callback=on_results)
    capture.start()

    try:
        while capture.is_running:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
        capture.stop()
        stats = capture.stats
        print(f"[+] Total packets captured: {stats['total_packets']}")
        print(f"[+] Total alerts raised:    {stats['total_alerts']}")
        print(f"[+] Session duration:       {stats['elapsed_seconds']}s")


def cmd_serve():
    """Launch the Flask web dashboard."""
    from app import app
    from config import FLASK_HOST, FLASK_PORT
    print(f"[*] Starting web dashboard at http://{FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=True)


def main():
    print_banner()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python cli.py generate                Generate training dataset")
        print("  python cli.py train                    Train the RF model")
        print("  python cli.py analyze <pcap_file>      Analyze a PCAP file")
        print("  python cli.py live [interface]          Start live capture")
        print("  python cli.py serve                    Launch web dashboard")
        print("  python cli.py preprocess <folder>      Preprocess CIC-IDS2017 CSVs")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "generate":
        cmd_generate()
    elif command == "train":
        cmd_train()
    elif command == "analyze":
        if len(sys.argv) < 3:
            print("[!] Please provide a PCAP file path.")
            print("    Usage: python cli.py analyze <pcap_file>")
            sys.exit(1)
        cmd_analyze(sys.argv[2])
    elif command == "live":
        iface = sys.argv[2] if len(sys.argv) > 2 else None
        cmd_live(iface)
    elif command == "serve":
        cmd_serve()
    elif command == "preprocess":
        if len(sys.argv) < 3:
            print("[!] Please provide the path to the CIC-IDS2017 CSV folder.")
            print("    Usage: python cli.py preprocess <folder_path>")
            sys.exit(1)
        cmd_preprocess(sys.argv[2])
    else:
        print(f"[!] Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
