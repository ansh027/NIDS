"""
Alerting engine — sends Email notifications when intrusions
are detected. Configuration is stored in a JSON settings file.
"""

import os
import sys
import json
import time
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import ALERT_SETTINGS_PATH, ALERT_LOG_PATH, ALERT_COOLDOWN_SECONDS


# ── Default settings ──────────────────────────────────────────────

DEFAULT_SETTINGS = {
    "email": {
        "enabled": False,
        "smtp_server": "",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_addr": "",
        "recipients": [],       # list of email addresses
        "use_tls": True,
    },
    "preferences": {
        "min_severity": "suspicious",    # "suspicious" or "malicious"
        "cooldown_seconds": ALERT_COOLDOWN_SECONDS,
    },
}


class AlertManager:
    """
    Manages alert dispatch via Email and maintains an alert log.
    Includes a cooldown to prevent alert fatigue.
    """

    def __init__(self):
        self.settings = self._load_settings()
        self._last_alert_time = {}  # key → timestamp for cooldown
        self._lock = threading.Lock()

    # ── Settings persistence ──────────────────────────────────────

    def _load_settings(self) -> dict:
        """Load settings from disk, falling back to defaults."""
        if os.path.exists(ALERT_SETTINGS_PATH):
            try:
                with open(ALERT_SETTINGS_PATH, "r") as f:
                    saved = json.load(f)
                # Merge with defaults to pick up any new keys
                merged = json.loads(json.dumps(DEFAULT_SETTINGS))
                for section in merged:
                    if section in saved:
                        merged[section].update(saved[section])
                return merged
            except Exception:
                pass
        return json.loads(json.dumps(DEFAULT_SETTINGS))

    def save_settings(self, settings: dict):
        """Save settings to disk."""
        self.settings = settings
        os.makedirs(os.path.dirname(ALERT_SETTINGS_PATH), exist_ok=True)
        with open(ALERT_SETTINGS_PATH, "w") as f:
            json.dump(settings, f, indent=2)

    def get_settings(self) -> dict:
        """Return current settings (reload from disk)."""
        self.settings = self._load_settings()
        return self.settings

    # ── Cooldown ──────────────────────────────────────────────────

    def _check_cooldown(self, key: str) -> bool:
        """Return True if we should send (cooldown expired)."""
        now = time.time()
        cooldown = self.settings.get("preferences", {}).get(
            "cooldown_seconds", ALERT_COOLDOWN_SECONDS
        )
        with self._lock:
            last = self._last_alert_time.get(key, 0)
            if now - last < cooldown:
                return False
            self._last_alert_time[key] = now
            return True

    # ── Alert dispatch ────────────────────────────────────────────

    def process_batch(self, batch_result: dict):
        """
        Check a live capture batch for intrusions and send alerts.
        Called from the live capture loop.
        """
        summary = batch_result.get("summary", {})
        intrusions = summary.get("intrusion", 0)
        if intrusions == 0:
            return

        # Check minimum severity
        min_sev = self.settings.get("preferences", {}).get(
            "min_severity", "suspicious"
        )
        results = batch_result.get("results", [])
        threats = [r for r in results if r.get("prediction") == 1]

        if min_sev == "malicious":
            threats = [t for t in threats if t.get("severity") == "malicious"]

        if not threats:
            return

        # Build a cooldown key from the attack types
        attack_types = sorted(set(t.get("attack_type", "Unknown") for t in threats))
        cooldown_key = "|".join(attack_types)

        if not self._check_cooldown(cooldown_key):
            return

        # Dispatch alerts in a background thread to avoid blocking
        thread = threading.Thread(
            target=self._dispatch_alerts,
            args=(batch_result, threats),
            daemon=True,
        )
        thread.start()

    def _dispatch_alerts(self, batch_result: dict, threats: list):
        """Send alerts via all enabled channels."""
        timestamp = batch_result.get("timestamp", datetime.now().isoformat())
        summary = batch_result.get("summary", {})

        alert_record = {
            "timestamp": timestamp,
            "threat_count": len(threats),
            "attack_types": list(set(t.get("attack_type", "Unknown") for t in threats)),
            "max_confidence": max((t.get("confidence", 0) for t in threats), default=0),
            "max_severity": "malicious" if any(
                t.get("severity") == "malicious" for t in threats
            ) else "suspicious",
            "channels_sent": [],
        }

        # Email
        email_cfg = self.settings.get("email", {})
        if email_cfg.get("enabled") and email_cfg.get("recipients"):
            try:
                self._send_email(timestamp, threats, summary)
                alert_record["channels_sent"].append("email")
            except Exception as e:
                alert_record["email_error"] = str(e)



        # Log the alert
        self._log_alert(alert_record)

    # ── Email ─────────────────────────────────────────────────────

    def _send_email(self, timestamp: str, threats: list, summary: dict):
        """Send an HTML email alert."""
        cfg = self.settings["email"]

        subject = f"🚨 NIDS Alert: {len(threats)} intrusion(s) detected"

        # Build threat rows
        rows = ""
        for t in threats:
            sev_color = "#ef4444" if t.get("severity") == "malicious" else "#f59e0b"
            rows += f"""
            <tr>
                <td style="padding:8px;border-bottom:1px solid #333;">{t.get('attack_type', 'Unknown')}</td>
                <td style="padding:8px;border-bottom:1px solid #333;">{t.get('confidence', 0):.1%}</td>
                <td style="padding:8px;border-bottom:1px solid #333;">
                    <span style="color:{sev_color};font-weight:bold;">{t.get('severity', 'unknown')}</span>
                </td>
            </tr>"""

        html = f"""
        <html>
        <body style="background:#1a1a2e;color:#e0e0e0;font-family:Arial,sans-serif;padding:20px;">
            <div style="max-width:600px;margin:0 auto;background:#16213e;border-radius:12px;padding:24px;
                        border:1px solid #0f3460;">
                <h2 style="color:#ef4444;margin-top:0;">🛡️ NIDS Intrusion Alert</h2>
                <p style="color:#a0a0a0;">Detected at: <strong>{timestamp}</strong></p>
                <p>Total threats: <strong style="color:#ef4444;">{len(threats)}</strong> |
                   Total flows: <strong>{summary.get('total', 0)}</strong></p>
                <table style="width:100%;border-collapse:collapse;margin:16px 0;">
                    <thead>
                        <tr style="background:#0f3460;">
                            <th style="padding:8px;text-align:left;">Attack Type</th>
                            <th style="padding:8px;text-align:left;">Confidence</th>
                            <th style="padding:8px;text-align:left;">Severity</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
                <p style="color:#666;font-size:12px;margin-bottom:0;">
                    Sent by Network Intrusion Detection System (NIDS)
                </p>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.get("from_addr", cfg.get("username", ""))
        msg["To"] = ", ".join(cfg["recipients"])
        msg.attach(MIMEText(html, "html"))

        server = smtplib.SMTP(cfg["smtp_server"], int(cfg["smtp_port"]))
        try:
            if cfg.get("use_tls", True):
                server.starttls()
            if cfg.get("username") and cfg.get("password"):
                server.login(cfg["username"], cfg["password"])
            server.sendmail(msg["From"], cfg["recipients"], msg.as_string())
        finally:
            server.quit()



    # ── Alert log ─────────────────────────────────────────────────

    def _log_alert(self, record: dict):
        """Append an alert record to the log file."""
        log = self._load_log()
        log.append(record)
        # Keep last 200 entries
        if len(log) > 200:
            log = log[-200:]
        os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)
        with open(ALERT_LOG_PATH, "w") as f:
            json.dump(log, f, indent=2)

    def _load_log(self) -> list:
        """Load the alert log from disk."""
        if os.path.exists(ALERT_LOG_PATH):
            try:
                with open(ALERT_LOG_PATH, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def get_log(self) -> list:
        """Return the alert log."""
        return self._load_log()

    def clear_log(self):
        """Clear the alert log."""
        if os.path.exists(ALERT_LOG_PATH):
            os.remove(ALERT_LOG_PATH)

    # ── Test alerts ───────────────────────────────────────────────

    def send_test_email(self) -> str:
        """Send a test email. Returns 'ok' or error message."""
        cfg = self.settings.get("email", {})
        if not cfg.get("smtp_server") or not cfg.get("recipients"):
            return "Email not configured: missing SMTP server or recipients"
        try:
            test_threats = [{
                "attack_type": "Test Alert",
                "confidence": 0.95,
                "severity": "malicious",
            }]
            self._send_email(
                datetime.now().isoformat(),
                test_threats,
                {"total": 1, "intrusion": 1},
            )
            return "ok"
        except Exception as e:
            return str(e)

