"""
Live network traffic capture and real-time intrusion detection.

Uses Scapy's sniff() in a background thread, buffers packets,
and periodically extracts features and runs the detector.

Note: Requires Npcap (Windows) or libpcap (Linux/Mac) to be installed.
"""

import os
import sys
import time
import threading
from queue import Queue
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import LIVE_CAPTURE_BUFFER_SECONDS, LIVE_CAPTURE_PACKET_COUNT
from core.feature_extractor import extract_features_from_packets
from core.detector import Detector
from core.alerting import AlertManager


class LiveCapture:
    """
    Real-time network traffic capture and intrusion detection.

    Captures live packets using Scapy, analyzes them in batches,
    and pushes results to a queue for consumption by the dashboard.
    """

    def __init__(
        self,
        interface: str = None,
        model_path: str = None,
        buffer_seconds: int = None,
        packet_count: int = None,
        callback=None,
    ):
        """
        Parameters
        ----------
        interface : str, optional
            Network interface to capture on. None = default.
        model_path : str, optional
            Path to trained model. Uses default if None.
        buffer_seconds : int
            Seconds to buffer before analyzing.
        packet_count : int
            Max packets per capture batch.
        callback : callable, optional
            Called with (results_dict) after each analysis cycle.
        """
        self.interface = interface
        self.buffer_seconds = buffer_seconds or LIVE_CAPTURE_BUFFER_SECONDS
        self.packet_count = packet_count or LIVE_CAPTURE_PACKET_COUNT
        self.callback = callback

        self.detector = Detector(model_path=model_path)
        self.alert_manager = AlertManager()
        self.results_queue = Queue(maxsize=100)
        self._running = False
        self._capture_thread = None
        self._packet_buffer = []
        self._lock = threading.Lock()
        self._total_packets = 0
        self._total_alerts = 0
        self._start_time = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict:
        elapsed = (time.time() - self._start_time) if self._start_time else 0
        return {
            "running": self._running,
            "total_packets": self._total_packets,
            "total_alerts": self._total_alerts,
            "elapsed_seconds": round(elapsed, 1),
            "interface": self.interface or "default",
        }

    def start(self):
        """Start the live capture in a background thread."""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True
        )
        self._capture_thread.start()

    def stop(self):
        """Stop the live capture."""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
            self._capture_thread = None
        self._start_time = None

    def get_latest_results(self) -> list[dict]:
        """Drain and return all queued results."""
        results = []
        while not self.results_queue.empty():
            try:
                results.append(self.results_queue.get_nowait())
            except Exception:
                break
        return results

    def _capture_loop(self):
        """Main capture loop running in a background thread."""
        try:
            from scapy.all import sniff
        except ImportError:
            self._running = False
            raise ImportError(
                "Scapy is required for live capture. Install: pip install scapy"
            )

        while self._running:
            try:
                # Capture a batch of packets
                kwargs = {
                    "count": self.packet_count,
                    "timeout": self.buffer_seconds,
                    "store": True,
                }
                if self.interface:
                    kwargs["iface"] = self.interface

                packets = sniff(**kwargs)

                if not packets:
                    continue

                self._total_packets += len(packets)

                # Extract features and run detection
                features_df = extract_features_from_packets(list(packets))
                if features_df.empty:
                    continue

                results = self.detector.predict(features_df)
                summary = self.detector.summary(results)
                enriched_df = self.detector.predict_dataframe(features_df)

                alert_count = summary.get("intrusion", 0)
                self._total_alerts += alert_count

                batch_result = {
                    "timestamp": datetime.now().isoformat(),
                    "packet_count": len(packets),
                    "flow_count": len(features_df),
                    "results": results,
                    "summary": summary,
                    "features": enriched_df.to_dict(orient="records"),
                    "stats": self.stats,
                }

                # Push to queue
                if self.results_queue.full():
                    try:
                        self.results_queue.get_nowait()
                    except Exception:
                        pass
                self.results_queue.put(batch_result)

                # Send alerts if intrusions detected
                if alert_count > 0:
                    self.alert_manager.process_batch(batch_result)

                # Call callback if provided
                if self.callback:
                    self.callback(batch_result)

            except Exception as e:
                error_result = {
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "stats": self.stats,
                }
                if not self.results_queue.full():
                    self.results_queue.put(error_result)

                time.sleep(1)  # Back off on error

    def __del__(self):
        self.stop()
