"""
Report Generator for PCAP Analysis Results.

Generates PDF and CSV reports from saved analysis data.
"""

import csv
import io
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROTOCOL_MAP = {0: "TCP", 1: "UDP", 2: "ICMP"}


def generate_pdf_report(entry: dict) -> bytes:
    """
    Generate a professional PDF report from an analysis entry.

    Parameters
    ----------
    entry : dict
        Full analysis entry from history.

    Returns
    -------
    bytes
        PDF file content.
    """
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Header ──────────────────────────────────────────────
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 40, "F")

    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(241, 245, 249)
    pdf.set_xy(15, 10)
    pdf.cell(0, 10, "NIDS Analysis Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(148, 163, 184)
    pdf.set_xy(15, 22)
    pdf.cell(0, 6, "Network Intrusion Detection System", new_x="LMARGIN", new_y="NEXT")

    # Timestamp in header
    timestamp = entry.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp)
        date_str = dt.strftime("%B %d, %Y at %I:%M %p")
    except (ValueError, TypeError):
        date_str = timestamp[:19] if timestamp else "Unknown"

    pdf.set_xy(15, 30)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Generated: {date_str}", new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(48)
    pdf.set_text_color(30, 30, 30)

    # ── Executive Summary ───────────────────────────────────
    _section_header(pdf, "Executive Summary")

    summary = entry.get("summary", {})
    filename = entry.get("filename", "Unknown")
    packet_count = entry.get("packet_count", 0)
    flow_count = entry.get("flow_count", 0)
    normal = summary.get("normal", 0)
    intrusion = summary.get("intrusion", 0)
    rate = summary.get("intrusion_rate", 0)

    # Info table
    pdf.set_font("Helvetica", "", 10)
    info_data = [
        ("PCAP File", filename),
        ("Analysis Date", date_str),
        ("Total Packets", str(packet_count)),
        ("Total Flows", str(flow_count)),
        ("Normal Flows", str(normal)),
        ("Intrusion Flows", str(intrusion)),
        ("Intrusion Rate", f"{rate}%"),
    ]

    for label, value in info_data:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(240, 245, 250)
        pdf.cell(55, 8, f"  {label}", border=1, fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(120, 8, f"  {value}", border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # ── Threat Assessment ───────────────────────────────────
    _section_header(pdf, "Threat Assessment")

    safe = summary.get("safe", 0)
    suspicious = summary.get("suspicious", 0)
    malicious = summary.get("malicious", 0)

    if rate > 50:
        level = "HIGH"
        level_color = (239, 68, 68)
    elif rate > 20:
        level = "MEDIUM"
        level_color = (245, 158, 11)
    else:
        level = "LOW"
        level_color = (34, 197, 94)

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*level_color)
    pdf.cell(0, 10, f"Threat Level: {level}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)

    pdf.set_font("Helvetica", "", 10)
    threat_data = [
        ("Safe (benign traffic)", str(safe), (34, 197, 94)),
        ("Suspicious (needs review)", str(suspicious), (245, 158, 11)),
        ("Malicious (confirmed threat)", str(malicious), (239, 68, 68)),
    ]

    for label, value, color in threat_data:
        pdf.set_fill_color(*color)
        pdf.rect(pdf.get_x(), pdf.get_y() + 1, 4, 6, "F")
        pdf.cell(6, 8, "")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(80, 8, label)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(30, 8, value, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # ── Flow Details Table ──────────────────────────────────
    features = entry.get("features", [])
    if features:
        _section_header(pdf, "Flow Details")

        # Table header
        col_widths = [8, 18, 16, 22, 22, 24, 28, 20, 22]
        headers = ["#", "Duration", "Proto", "Src Bytes", "Dst Bytes",
                    "Attack Type", "Confidence", "Verdict", "Severity"]

        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(241, 245, 249)

        for i, h in enumerate(headers):
            pdf.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 7)

        for idx, row in enumerate(features, 1):
            # Alternate row colors
            if idx % 2 == 0:
                pdf.set_fill_color(248, 250, 252)
            else:
                pdf.set_fill_color(255, 255, 255)

            # Highlight intrusion rows
            if row.get("prediction") == 1:
                pdf.set_fill_color(254, 242, 242)

            protocol = PROTOCOL_MAP.get(row.get("protocol_type", 0), "Other")
            duration = f"{row.get('duration', 0):.3f}s"
            src_bytes = str(row.get("src_bytes", 0))
            dst_bytes = str(row.get("dst_bytes", 0))
            attack_type = row.get("attack_type", "Unknown")
            confidence = f"{row.get('confidence', 0) * 100:.1f}%"
            verdict = row.get("label", "Unknown")
            severity = row.get("severity", "safe").capitalize()

            cells = [str(idx), duration, protocol, src_bytes, dst_bytes,
                     attack_type, confidence, verdict, severity]

            for i, cell in enumerate(cells):
                pdf.cell(col_widths[i], 6, cell, border=1, fill=True, align="C")
            pdf.ln()

            # Add page if near bottom
            if pdf.get_y() > 265:
                pdf.add_page()
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_fill_color(30, 41, 59)
                pdf.set_text_color(241, 245, 249)
                for i, h in enumerate(headers):
                    pdf.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
                pdf.ln()
                pdf.set_text_color(30, 30, 30)
                pdf.set_font("Helvetica", "", 7)

    # ── Footer ──────────────────────────────────────────────
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6, "NIDS - Network Intrusion Detection System | Open Source | Random Forest Classifier",
             align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Report ID: {entry.get('id', 'N/A')} | Total Flows: {flow_count}",
             align="C", new_x="LMARGIN", new_y="NEXT")

    return pdf.output()


def generate_csv_report(entry: dict) -> str:
    """
    Generate a CSV report from an analysis entry.

    Returns
    -------
    str
        CSV file content as a string.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Metadata rows
    writer.writerow(["NIDS Analysis Report"])
    writer.writerow(["File", entry.get("filename", "Unknown")])
    writer.writerow(["Date", entry.get("timestamp", "")])
    writer.writerow(["Packets", entry.get("packet_count", 0)])
    writer.writerow(["Flows", entry.get("flow_count", 0)])

    summary = entry.get("summary", {})
    writer.writerow(["Normal", summary.get("normal", 0)])
    writer.writerow(["Intrusions", summary.get("intrusion", 0)])
    writer.writerow(["Intrusion Rate", f"{summary.get('intrusion_rate', 0)}%"])
    writer.writerow([])

    # Flow details
    features = entry.get("features", [])
    if features:
        headers = ["#", "Duration", "Protocol", "Src Bytes", "Dst Bytes",
                   "Fwd Packets", "Bwd Packets", "Avg Pkt Size",
                   "Verdict", "Attack Type", "Confidence", "Severity"]
        writer.writerow(headers)

        for idx, row in enumerate(features, 1):
            protocol = PROTOCOL_MAP.get(row.get("protocol_type", 0), "Other")
            writer.writerow([
                idx,
                f"{row.get('duration', 0):.3f}",
                protocol,
                row.get("src_bytes", 0),
                row.get("dst_bytes", 0),
                row.get("fwd_packets", 0),
                row.get("bwd_packets", 0),
                f"{row.get('packet_size_avg', 0):.1f}",
                row.get("label", "Unknown"),
                row.get("attack_type", "Unknown"),
                f"{row.get('confidence', 0) * 100:.1f}%",
                row.get("severity", "safe").capitalize(),
            ])

    return output.getvalue()


def _section_header(pdf, title: str):
    """Draw a styled section header."""
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
    # Accent line
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(0.8)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 50, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.set_draw_color(0, 0, 0)
    pdf.ln(4)
