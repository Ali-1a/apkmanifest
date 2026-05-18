"""
Report Generator - Builds professional PDF reports of scan results.
Uses ReportLab for layout.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable,
)

PRIMARY     = HexColor("#1F2937")
ACCENT      = HexColor("#3C3489")
MUTED       = HexColor("#6B7280")
LIGHT_BG    = HexColor("#F3F4F6")
BORDER      = HexColor("#E5E7EB")
WHITE       = HexColor("#FFFFFF")

CRITICAL_BG = HexColor("#FCEBEB")
CRITICAL_FG = HexColor("#791F1F")
MEDIUM_BG   = HexColor("#FAEEDA")
MEDIUM_FG   = HexColor("#854F0B")
LOW_BG      = HexColor("#E6F1FB")
LOW_FG      = HexColor("#185FA5")
PASS_BG     = HexColor("#F0FDF4")
PASS_FG     = HexColor("#14532D")
COVERED_BG  = HexColor("#F0FDF4")
COVERED_FG  = HexColor("#15803D")
OUT_BG      = HexColor("#F9FAFB")
OUT_FG      = HexColor("#9CA3AF")


def _sev_color(severity: str):
    return {
        "critical": (CRITICAL_BG, CRITICAL_FG),
        "medium":   (MEDIUM_BG,   MEDIUM_FG),
        "low":      (LOW_BG,      LOW_FG),
    }.get(severity, (LIGHT_BG, MUTED))


def generate_pdf_report(scan_data: dict, output_path: str):
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
    )
    styles = getSampleStyleSheet()

    title_s = ParagraphStyle("T", parent=styles["Title"],
        fontSize=22, textColor=ACCENT, alignment=TA_CENTER,
        spaceAfter=4, fontName="Helvetica-Bold")
    sub_s = ParagraphStyle("S", parent=styles["Normal"],
        fontSize=10, textColor=MUTED, alignment=TA_CENTER,
        spaceAfter=14, fontName="Helvetica-Oblique")
    h2_s = ParagraphStyle("H2", parent=styles["Heading2"],
        fontSize=13, textColor=ACCENT, spaceBefore=14,
        spaceAfter=6, fontName="Helvetica-Bold")
    h3_s = ParagraphStyle("H3", parent=styles["Heading3"],
        fontSize=11, textColor=PRIMARY, spaceBefore=10,
        spaceAfter=4, fontName="Helvetica-Bold")
    body_s = ParagraphStyle("B", parent=styles["Normal"],
        fontSize=10, textColor=PRIMARY, alignment=TA_JUSTIFY,
        leading=13, spaceAfter=4)
    fix_s = ParagraphStyle("F", parent=body_s,
        backColor=HexColor("#F0FDF4"), leftIndent=8,
        rightIndent=8, spaceBefore=4, spaceAfter=4)
    note_s = ParagraphStyle("N", parent=styles["Normal"],
        fontSize=8.5, textColor=MUTED, alignment=TA_CENTER,
        fontName="Helvetica-Oblique")

    story = []

    # ── Title ──────────────────────────────────────────────────────────────
    story.append(Paragraph("APKManifest — Security Report", title_s))
    story.append(Paragraph(
        f"Generated on {scan_data.get('scan_timestamp', 'N/A')}", sub_s))

    # ── App info ───────────────────────────────────────────────────────────
    info = scan_data.get("basic_info", {})
    info_table = Table([
        ["Application Name", info.get("app_name", "N/A")],
        ["Package Name",     info.get("package_name", "N/A")],
        ["Version",          f"{info.get('version_name','N/A')} ({info.get('version_code','N/A')})"],
        ["File Size",        f"{info.get('file_size_mb','N/A')} MB"],
        ["Min SDK / Target SDK", f"{info.get('min_sdk','N/A')} / {info.get('target_sdk','N/A')}"],
    ], colWidths=[5*cm, 11*cm])
    info_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(0,-1), LIGHT_BG),
        ("TEXTCOLOR",   (0,0),(0,-1), ACCENT),
        ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0),(-1,-1), 9),
        ("LEFTPADDING", (0,0),(-1,-1), 8),
        ("RIGHTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING",  (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("GRID",        (0,0),(-1,-1), 0.25, BORDER),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(Paragraph("Application Information", h2_s))
    story.append(info_table)

    # ── Risk summary ───────────────────────────────────────────────────────
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "Unknown")
    summary    = scan_data.get("summary", {})

    story.append(Paragraph("Risk Summary", h2_s))
    risk_table = Table([
        ["Risk Score", "Risk Level", "Total Findings"],
        [f"{risk_score} / 100", risk_level, str(summary.get("total", 0))],
    ], colWidths=[5.3*cm, 5.3*cm, 5.4*cm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND",      (0,0),(-1,0), ACCENT),
        ("TEXTCOLOR",       (0,0),(-1,0), WHITE),
        ("FONTNAME",        (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTNAME",        (0,1),(-1,1), "Helvetica-Bold"),
        ("FONTSIZE",        (0,0),(-1,0), 10),
        ("FONTSIZE",        (0,1),(-1,1), 18),
        ("ALIGN",           (0,0),(-1,-1), "CENTER"),
        ("VALIGN",          (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",      (0,1),(-1,1), 14),
        ("BOTTOMPADDING",   (0,1),(-1,1), 14),
        ("GRID",            (0,0),(-1,-1), 0.25, BORDER),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 8))

    sev_table = Table([
        ["Critical", "Medium", "Low"],
        [str(summary.get("critical",0)), str(summary.get("medium",0)), str(summary.get("low",0))],
    ], colWidths=[5.3*cm, 5.3*cm, 5.4*cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(0,0), CRITICAL_BG),
        ("BACKGROUND",  (1,0),(1,0), MEDIUM_BG),
        ("BACKGROUND",  (2,0),(2,0), LOW_BG),
        ("TEXTCOLOR",   (0,0),(0,-1), CRITICAL_FG),
        ("TEXTCOLOR",   (1,0),(1,-1), MEDIUM_FG),
        ("TEXTCOLOR",   (2,0),(2,-1), LOW_FG),
        ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTNAME",    (0,1),(-1,1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0),(-1,0), 10),
        ("FONTSIZE",    (0,1),(-1,1), 22),
        ("ALIGN",       (0,0),(-1,-1), "CENTER"),
        ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",  (0,1),(-1,1), 10),
        ("BOTTOMPADDING",(0,1),(-1,1), 10),
    ]))
    story.append(sev_table)

    # ── Security Score Card ────────────────────────────────────────────────
    findings = scan_data.get("findings", [])
    if findings:
        story.append(Paragraph("Security Score Card", h2_s))
        categories = [
            ("Permissions", "Permissions"),
            ("Manifest",    "Manifest"),
            ("Network",     "Network"),
            ("Components",  "Components"),
            ("Configuration","Configuration"),
        ]
        card_header = [c[0] for c in categories]
        card_row    = []
        for _, cat in categories:
            cat_f = [f for f in findings if f.get("category") == cat]
            sevs = {f.get("severity") for f in cat_f}
            if "critical" in sevs:
                card_row.append("FAIL\nCRITICAL")
            elif "medium" in sevs:
                card_row.append("FAIL\nMEDIUM")
            elif "low" in sevs:
                card_row.append("FAIL\nLOW")
            else:
                card_row.append("PASS\nSECURE")

        score_table = Table([card_header, card_row],
            colWidths=[3.2*cm]*5)

        score_styles = [
            ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0),(-1,-1), 8),
            ("ALIGN",       (0,0),(-1,-1), "CENTER"),
            ("VALIGN",      (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING",  (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ("GRID",        (0,0),(-1,-1), 0.25, BORDER),
            ("BACKGROUND",  (0,0),(-1,0), LIGHT_BG),
        ]
        for ci, (_, cat) in enumerate(categories):
            cat_f = [f for f in findings if f.get("category") == cat]
            sevs = {f.get("severity") for f in cat_f}
            if "critical" in sevs:
                score_styles.append(("BACKGROUND", (ci,1),(ci,1), CRITICAL_BG))
                score_styles.append(("TEXTCOLOR",  (ci,1),(ci,1), CRITICAL_FG))
            elif "medium" in sevs or "low" in sevs:
                score_styles.append(("BACKGROUND", (ci,1),(ci,1), MEDIUM_BG))
                score_styles.append(("TEXTCOLOR",  (ci,1),(ci,1), MEDIUM_FG))
            else:
                score_styles.append(("BACKGROUND", (ci,1),(ci,1), PASS_BG))
                score_styles.append(("TEXTCOLOR",  (ci,1),(ci,1), PASS_FG))

        score_table.setStyle(TableStyle(score_styles))
        story.append(score_table)

        # ── Remediation Priority ───────────────────────────────────────────
        story.append(Paragraph("Remediation Priority", h2_s))
        ordered = sorted(findings,
            key=lambda f: {"critical":0,"medium":1,"low":2}.get(f.get("severity","low"), 3))
        for i, f in enumerate(ordered, 1):
            bg, fg = _sev_color(f.get("severity","low"))
            rem_row = [[f"#{i}", f.get("severity","").upper(), f.get("title","")]]
            rem_table = Table(rem_row, colWidths=[0.8*cm, 2.2*cm, 13*cm])
            rem_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(-1,-1), bg),
                ("TEXTCOLOR",   (0,0),(-1,-1), fg),
                ("FONTNAME",    (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0),(-1,-1), 9),
                ("LEFTPADDING", (0,0),(-1,-1), 6),
                ("RIGHTPADDING",(0,0),(-1,-1), 6),
                ("TOPPADDING",  (0,0),(-1,-1), 5),
                ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ]))
            story.append(rem_table)
            if f.get("fix"):
                story.append(Paragraph(f"   Fix: {f['fix']}", note_s))
            story.append(Spacer(1, 3))

    # ── Detailed Findings ─────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h2_s))
    if not findings:
        story.append(Paragraph("No security issues were found.", body_s))
    else:
        for i, finding in enumerate(findings, 1):
            sev = finding.get("severity", "low")
            bg, fg = _sev_color(sev)
            hdr = Table([[f"#{i}  {finding.get('title','')}", sev.upper()]],
                colWidths=[13*cm, 4*cm])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(-1,-1), bg),
                ("TEXTCOLOR",   (0,0),(-1,-1), fg),
                ("FONTNAME",    (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0),(0,0), 10),
                ("FONTSIZE",    (1,0),(1,0), 9),
                ("ALIGN",       (1,0),(1,0), "RIGHT"),
                ("LEFTPADDING", (0,0),(-1,-1), 8),
                ("RIGHTPADDING",(0,0),(-1,-1), 8),
                ("TOPPADDING",  (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ]))
            story.append(hdr)
            story.append(Paragraph(
                f"<b>Description:</b> {finding.get('description','N/A')}", body_s))
            masvs = finding.get("masvs","")
            masvs_str = f"<b>MASVS:</b> {masvs} &nbsp;&nbsp; " if masvs else ""
            story.append(Paragraph(
                f"<b>Category:</b> {finding.get('category','N/A')} &nbsp;&nbsp; "
                f"<b>OWASP:</b> {finding.get('owasp','N/A')} &nbsp;&nbsp; {masvs_str}",
                body_s))
            if finding.get("fix"):
                story.append(Paragraph(
                    f"<b>Recommended fix:</b> {finding['fix']}", fix_s))
            details = finding.get("details", [])
            if details:
                story.append(Paragraph(
                    "<b>Details:</b><br/>" + "<br/>".join(f"• {d}" for d in details[:5]),
                    body_s))
            story.append(Spacer(1, 6))

    # ── OWASP Mobile Top 10 Coverage ──────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("OWASP Mobile Top 10 Coverage", h2_s))
    story.append(Paragraph(
        "APKManifest covers the following OWASP Mobile Top 10 categories "
        "through AndroidManifest.xml static analysis.", body_s))
    story.append(Spacer(1, 6))

    owasp = [
        ("M1",  "Improper Platform Usage",      True),
        ("M2",  "Insecure Data Storage",         True),
        ("M3",  "Insecure Communication",        True),
        ("M4",  "Insecure Authentication",       False),
        ("M5",  "Insufficient Cryptography",     False),
        ("M6",  "Insecure Authorization",        False),
        ("M7",  "Client Code Quality",           False),
        ("M8",  "Code Tampering",                False),
        ("M9",  "Reverse Engineering",           True),
        ("M10", "Extraneous Functionality",      True),
    ]
    owasp_rows = [["Code", "Category", "Status"]]
    for code, name, covered in owasp:
        owasp_rows.append([code, name, "Covered" if covered else "Out of scope"])

    owasp_table = Table(owasp_rows, colWidths=[1.5*cm, 10*cm, 4.5*cm])
    owasp_styles = [
        ("BACKGROUND",  (0,0),(-1,0), ACCENT),
        ("TEXTCOLOR",   (0,0),(-1,0), WHITE),
        ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0),(-1,-1), 9),
        ("ALIGN",       (2,0),(2,-1), "CENTER"),
        ("LEFTPADDING", (0,0),(-1,-1), 8),
        ("RIGHTPADDING",(0,0),(-1,-1), 8),
        ("TOPPADDING",  (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("GRID",        (0,0),(-1,-1), 0.25, BORDER),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, LIGHT_BG]),
    ]
    for ri, (code, name, covered) in enumerate(owasp, 1):
        if covered:
            owasp_styles.append(("TEXTCOLOR",  (2,ri),(2,ri), COVERED_FG))
            owasp_styles.append(("FONTNAME",   (2,ri),(2,ri), "Helvetica-Bold"))
            owasp_styles.append(("TEXTCOLOR",  (0,ri),(0,ri), ACCENT))
            owasp_styles.append(("FONTNAME",   (0,ri),(0,ri), "Helvetica-Bold"))
        else:
            owasp_styles.append(("TEXTCOLOR",  (2,ri),(2,ri), OUT_FG))
            owasp_styles.append(("TEXTCOLOR",  (0,ri),(0,ri), OUT_FG))

    owasp_table.setStyle(TableStyle(owasp_styles))
    story.append(owasp_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "5 / 10 OWASP Mobile Top 10 categories covered via manifest analysis.",
        note_s))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Report generated by APKManifest", note_s))

    doc.build(story)
    return output_path
