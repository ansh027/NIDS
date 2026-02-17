"""
Flask web dashboard for the Network Intrusion Detection System.
"""

import os
import sys
import json
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_from_directory, make_response
)
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (
    FLASK_SECRET_KEY, UPLOAD_DIR, MODEL_PATH, MODELS_DIR, DATA_DIR, HISTORY_DIR
)

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload

ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}

# Global live capture instance
_live_capture = None
_live_results_history = []

# Global alert manager
from core.alerting import AlertManager
_alert_manager = AlertManager()


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def model_is_trained() -> bool:
    return os.path.exists(MODEL_PATH)


# ── Routes ─────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Dashboard home page."""
    return render_template(
        "index.html",
        model_trained=model_is_trained(),
        live_running=_live_capture is not None and _live_capture.is_running,
    )


@app.route("/upload")
def upload():
    """PCAP file upload page."""
    from core.history import list_analyses
    recent = list_analyses()[:5]
    return render_template(
        "upload.html",
        model_trained=model_is_trained(),
        recent_history=recent,
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze an uploaded PCAP file."""
    if not model_is_trained():
        flash("Please train the model first!", "error")
        return redirect(url_for("upload"))

    if "pcap_file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("upload"))

    file = request.files["pcap_file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("upload"))

    if not allowed_file(file.filename):
        flash("Invalid file type. Please upload a .pcap, .pcapng, or .cap file.", "error")
        return redirect(url_for("upload"))

    # Save the uploaded file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    file.save(filepath)

    # Analyze the file
    try:
        from core.pcap_analyzer import analyze_pcap
        from core.history import save_analysis
        result = analyze_pcap(filepath, verbose=False)

        # Save to history
        entry_id = save_analysis(filename, result)

        return render_template(
            "results.html",
            filename=filename,
            entry_id=entry_id,
            summary=result["summary"],
            packet_count=result["packet_count"],
            flow_count=result["flow_count"],
            features=result["features_df"].to_dict(orient="records"),
            results=result["results"],
            model_trained=model_is_trained(),
        )
    except Exception as e:
        flash(f"Analysis error: {str(e)}", "error")
        return redirect(url_for("upload"))


@app.route("/history")
def history_page():
    """PCAP analysis history listing page."""
    from core.history import list_analyses
    analyses = list_analyses()
    return render_template(
        "history.html",
        analyses=analyses,
        model_trained=model_is_trained(),
    )


@app.route("/history/<entry_id>")
def history_detail(entry_id):
    """View a single past analysis."""
    from core.history import get_analysis
    entry = get_analysis(entry_id)
    if not entry:
        flash("Analysis not found.", "error")
        return redirect(url_for("history_page"))
    return render_template(
        "history_detail.html",
        entry=entry,
        model_trained=model_is_trained(),
    )


@app.route("/history/<entry_id>/delete", methods=["POST"])
def history_delete(entry_id):
    """Delete a history entry."""
    from core.history import delete_analysis
    if delete_analysis(entry_id):
        flash("Analysis deleted.", "success")
    else:
        flash("Analysis not found.", "error")
    return redirect(url_for("history_page"))


@app.route("/history/<entry_id>/download/pdf")
def history_download_pdf(entry_id):
    """Download analysis report as PDF."""
    from io import BytesIO
    from flask import send_file
    from core.history import get_analysis
    from core.report_generator import generate_pdf_report
    entry = get_analysis(entry_id)
    if not entry:
        flash("Analysis not found.", "error")
        return redirect(url_for("history_page"))

    pdf_bytes = generate_pdf_report(entry)
    buffer = BytesIO(bytes(pdf_bytes))
    fname = entry.get("filename", "report").replace(" ", "_")
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"NIDS_Report_{fname}.pdf",
    )


@app.route("/history/<entry_id>/download/csv")
def history_download_csv(entry_id):
    """Download analysis report as CSV."""
    from core.history import get_analysis
    from core.report_generator import generate_csv_report
    entry = get_analysis(entry_id)
    if not entry:
        flash("Analysis not found.", "error")
        return redirect(url_for("history_page"))

    csv_content = generate_csv_report(entry)
    response = make_response(csv_content)
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="NIDS_Report_{entry.get("filename", "report")}.csv"'
    )
    return response


@app.route("/train", methods=["POST"])
def train_model():
    """Train the Random Forest model."""
    try:
        from config import DATASET_PATH
        if not os.path.exists(DATASET_PATH):
            from scripts.generate_dataset import main as gen_main
            gen_main()

        from core.train_model import train
        result = train(verbose=False)
        flash(f"Model trained successfully! Accuracy: {result['accuracy']:.2%}", "success")
    except Exception as e:
        flash(f"Training error: {str(e)}", "error")

    return redirect(url_for("index"))


@app.route("/live")
def live_page():
    """Live capture monitoring page."""
    return render_template(
        "live.html",
        model_trained=model_is_trained(),
        live_running=_live_capture is not None and _live_capture.is_running,
    )


@app.route("/api/live/start", methods=["POST"])
def live_start():
    """Start live capture."""
    global _live_capture, _live_results_history

    if not model_is_trained():
        return jsonify({"error": "Model not trained"}), 400

    if _live_capture and _live_capture.is_running:
        return jsonify({"status": "already_running"})

    try:
        from core.live_capture import LiveCapture
        _live_results_history = []
        _live_capture = LiveCapture()
        _live_capture.start()
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/live/stop", methods=["POST"])
def live_stop():
    """Stop live capture."""
    global _live_capture
    if _live_capture and _live_capture.is_running:
        _live_capture.stop()
        return jsonify({"status": "stopped", "stats": _live_capture.stats})
    return jsonify({"status": "not_running"})


@app.route("/api/live/results")
def live_results():
    """Get latest live capture results (polled by JS)."""
    global _live_capture, _live_results_history
    if not _live_capture:
        return jsonify({"results": [], "stats": None})

    new_results = _live_capture.get_latest_results()
    _live_results_history.extend(new_results)

    # Keep last 50 batches
    if len(_live_results_history) > 50:
        _live_results_history = _live_results_history[-50:]

    return jsonify({
        "results": _live_results_history[-10:],
        "stats": _live_capture.stats if _live_capture else None,
        "running": _live_capture.is_running if _live_capture else False,
    })


@app.route("/api/model/info")
def model_info():
    """Return model status info."""
    info = {"trained": model_is_trained()}
    if model_is_trained():
        stat = os.stat(MODEL_PATH)
        info["size_kb"] = round(stat.st_size / 1024, 1)
        info["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
    return jsonify(info)


# ── Settings & Alert routes ────────────────────────────────────────

@app.route("/settings")
def settings_page():
    """Alert settings page."""
    return render_template(
        "settings.html",
        model_trained=model_is_trained(),
    )


@app.route("/api/settings")
def api_get_settings():
    """Return current alert settings."""
    return jsonify(_alert_manager.get_settings())


@app.route("/api/settings/save", methods=["POST"])
def api_save_settings():
    """Save alert settings."""
    try:
        settings = request.get_json()
        _alert_manager.save_settings(settings)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@app.route("/api/alerts/test", methods=["POST"])
def api_test_alert():
    """Send a test alert."""
    data = request.get_json() or {}
    channel = data.get("channel", "email")

    if channel == "email":
        result = _alert_manager.send_test_email()
    else:
        result = f"Unknown channel: {channel}"

    return jsonify({"result": result})


@app.route("/api/alerts/log")
def api_alert_log():
    """Return alert history."""
    return jsonify({"log": _alert_manager.get_log()})


@app.route("/api/alerts/log", methods=["DELETE"])
def api_clear_alert_log():
    """Clear alert history."""
    _alert_manager.clear_log()
    return jsonify({"status": "ok"})


# ── Error handlers ─────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    flash("File is too large. Maximum size is 100 MB.", "error")
    return redirect(url_for("upload"))


@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error="Page not found"), 404


if __name__ == "__main__":
    from config import FLASK_HOST, FLASK_PORT
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=True)
