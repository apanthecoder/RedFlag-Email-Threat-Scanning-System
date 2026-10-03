"""Monthly PDF report for the admin dashboard.

Built in memory with reportlab and returned as bytes, so nothing is
written to disk. It doesn't query the database. It formats the dict that
database.models.get_monthly_report_data returns.

The report gives totals and findings, not individual senders or subjects.
It's read by the client's management, who need the numbers, and copying
people's email details into a file that can be passed around adds privacy
risk for nothing.
"""

from __future__ import annotations

import calendar
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Same risk colours as the web interface.
_RISK_COLOURS = {
    "SAFE": colors.HexColor("#15803d"),
    "SUSPICIOUS": colors.HexColor("#b45309"),
    "DANGEROUS": colors.HexColor("#dc2626"),
}
_SLATE = colors.HexColor("#334155")
_LIGHT = colors.HexColor("#e2e8f0")

_PROVIDER_LABELS = {
    "VIRUSTOTAL": "VirusTotal",
    "SAFE_BROWSING": "Google Safe Browsing",
    "URLSCAN": "URLScan.io",
    "ABUSEIPDB": "AbuseIPDB",
}

def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "RFTitle", parent=base["Title"], fontSize=20, leading=24,
            textColor=colors.HexColor("#0f172a"), alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "RFSubtitle", parent=base["Normal"], fontSize=11, leading=15,
            textColor=_SLATE, spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "RFH2", parent=base["Heading2"], fontSize=13, leading=16,
            textColor=colors.HexColor("#0f172a"), spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "RFBody", parent=base["Normal"], fontSize=9.5, leading=13,
            textColor=_SLATE,
        ),
    }


def _month_name(period: str) -> str:
    year, month = int(period[:4]), int(period[5:7])
    return f"{calendar.month_name[month]} {year}"


def _table(rows: list[list], col_widths: list[float], header: bool = True) -> Table:
    table = Table(rows, colWidths=col_widths, hAlign="LEFT")
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (-1, -1), _SLATE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, _LIGHT),
    ]
    if header:
        style += [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, _SLATE),
        ]
    table.setStyle(TableStyle(style))
    return table


def _summary_band(by_level: dict) -> Table:
    """Three counts side by side, coloured like the risk badges.

    Row heights and leading are set by hand. FONTSIZE in a TableStyle
    doesn't change the leading, so a 26pt number in an auto-height row
    spilled down over its own label.
    """
    levels = ["SAFE", "SUSPICIOUS", "DANGEROUS"]
    counts = [str(by_level.get(level, 0)) for level in levels]

    table = Table(
        [counts, levels],
        colWidths=[55 * mm] * 3,
        rowHeights=[16 * mm, 8 * mm],
        hAlign="LEFT",
    )
    style = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        # Number row: big figures with matching leading, centred so they
        # clear the label underneath.
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 26),
        ("LEADING", (0, 0), (-1, 0), 26),
        ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
        ("TOPPADDING", (0, 0), (-1, 0), 0),
        # Label row.
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 9),
        ("LEADING", (0, 1), (-1, 1), 11),
        ("VALIGN", (0, 1), (-1, 1), "TOP"),
        ("TOPPADDING", (0, 1), (-1, 1), 0),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        # One box per column, spanning both rows.
        ("BOX", (0, 0), (0, 1), 0.8, _RISK_COLOURS["SAFE"]),
        ("BOX", (1, 0), (1, 1), 0.8, _RISK_COLOURS["SUSPICIOUS"]),
        ("BOX", (2, 0), (2, 1), 0.8, _RISK_COLOURS["DANGEROUS"]),
    ]
    for index, level in enumerate(levels):
        style.append(("TEXTCOLOR", (index, 0), (index, 1), _RISK_COLOURS[level]))
    table.setStyle(TableStyle(style))
    return table


def _percent(part: int, whole: int) -> str:
    if not whole:
        return "n/a"
    return f"{(part / whole) * 100:.1f}%"


def build_monthly_report(data: dict, generated_by: str | None = None) -> bytes:
    """Render the aggregate dict as a PDF and return its bytes."""
    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"RedFlag monthly report {data['period']}",
        author="RedFlag",
    )

    totals = data.get("totals") or {}
    by_level = data.get("by_risk_level") or {}
    total_scans = totals.get("total_scans") or 0

    story = [
        Paragraph("RedFlag monthly report", styles["title"]),
        Paragraph(
            f"{_month_name(data['period'])} &nbsp;·&nbsp; "
            f"generated {datetime.now().strftime('%d %B %Y, %H:%M')}"
            + (f" by {generated_by}" if generated_by else ""),
            styles["subtitle"],
        ),
    ]

    if total_scans == 0:
        story += [
            Paragraph("No emails were scanned in this period.", styles["h2"]),
            Paragraph(
                "This report covers a month with no recorded activity. Nothing "
                "below indicates a problem with the system.",
                styles["body"],
            ),
        ]
        doc.build(story)
        return buffer.getvalue()

    # --- Scan volume ---------------------------------------------------
    story += [Paragraph("Emails scanned", styles["h2"]), _summary_band(by_level)]
    story += [Spacer(1, 10)]
    story += [_table(
        [
            ["Measure", "Count", "Share"],
            ["Emails scanned", str(total_scans), "100%"],
            ["Completed", str(totals.get("completed") or 0),
             _percent(totals.get("completed") or 0, total_scans)],
            ["Failed to process", str(totals.get("failed") or 0),
             _percent(totals.get("failed") or 0, total_scans)],
            ["Partial scans (a provider was unavailable)", str(totals.get("partial") or 0),
             _percent(totals.get("partial") or 0, total_scans)],
        ],
        [95 * mm, 35 * mm, 35 * mm],
    )]

    flagged = (by_level.get("SUSPICIOUS", 0)) + (by_level.get("DANGEROUS", 0))
    story += [
        Spacer(1, 8),
        Paragraph(
            f"{flagged} of {total_scans} emails ({_percent(flagged, total_scans)}) "
            f"were rated Suspicious or Dangerous and shown containment advice.",
            styles["body"],
        ),
    ]

    # --- What was found ------------------------------------------------
    attachments = data.get("attachments") or {}
    urls = data.get("urls") or {}
    story += [Paragraph("What was found", styles["h2"])]
    story += [_table(
        [
            ["Indicator", "Count"],
            ["Attachments examined", str(attachments.get("total") or 0)],
            ["Attachments identified as malicious", str(attachments.get("malicious") or 0)],
            ["Program files (executables) attached", str(attachments.get("executables") or 0)],
            ["Documents containing macros", str(attachments.get("macro_documents") or 0)],
            ["Password-protected archives", str(attachments.get("password_protected") or 0)],
            ["Links examined", str(urls.get("total") or 0)],
            ["Links listed as malware or phishing", str(urls.get("flagged_by_safe_browsing") or 0)],
            ["Links whose text did not match their destination", str(urls.get("display_mismatches") or 0)],
            ["Shortened links", str(urls.get("shorteners") or 0)],
        ],
        [130 * mm, 35 * mm],
    )]

    # --- Provider reliability ------------------------------------------
    providers = data.get("provider_calls") or []
    story += [Paragraph("Threat intelligence providers", styles["h2"])]
    if providers:
        rows = [["Provider", "Calls", "Answered", "Success rate", "Avg response"]]
        for p in providers:
            total_calls = p.get("total_calls") or 0
            ok = p.get("successful_calls") or 0
            avg = p.get("avg_duration_ms")
            rows.append([
                _PROVIDER_LABELS.get(p["provider"], p["provider"]),
                str(total_calls),
                str(ok),
                _percent(ok, total_calls),
                f"{avg:.0f} ms" if avg is not None else "n/a",
            ])
        story += [_table(rows, [55 * mm, 25 * mm, 30 * mm, 30 * mm, 30 * mm])]
    else:
        story += [Paragraph("No provider calls were made in this period.", styles["body"])]

    doc.build(story)
    return buffer.getvalue()
