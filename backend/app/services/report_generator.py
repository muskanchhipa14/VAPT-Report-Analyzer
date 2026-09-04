import os
from io import BytesIO
from datetime import datetime
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.pdfgen import canvas


# Custom Canvas for Header/Footer and Page Numbers
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        
        # Suppress headers/footers on the cover page (Page 1)
        if self._pageNumber == 1:
            self.restoreState()
            return

        # Running Header
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#1e293b"))  # Slate 800
        self.drawString(54, 750, "VAPT SECURITY ANALYSIS REPORT")
        
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))  # Slate 500
        self.drawRightString(612 - 54, 750, f"Generated: {datetime.now().strftime('%Y-%m-%d')}")
        
        # Header line
        self.setStrokeColor(colors.HexColor("#cbd5e1"))  # Slate 300
        self.setLineWidth(0.5)
        self.line(54, 742, 612 - 54, 742)

        # Running Footer
        self.line(54, 55, 612 - 54, 55)
        self.drawString(54, 42, "CONFIDENTIAL - INTERNAL SECURITY USE ONLY")
        self.drawRightString(612 - 54, 42, f"Page {self._pageNumber} of {page_count}")
        
        self.restoreState()


def generate_vapt_pdf_report(report_metadata: dict, vulnerabilities: list, db: Session = None) -> BytesIO:
    buffer = BytesIO()
    
    # 0.5 inch margins -> 36 points; Let's use 0.75 inch (54 points) for a cleaner layout
    # Width of Letter: 612, Height: 792. Printable width = 612 - 108 = 504.
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )

    styles = getSampleStyleSheet()
    
    # Define custom professional styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#475569"),
        spaceAfter=30
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'VulnerabilityH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'StandardBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155")
    )
    
    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )

    meta_val_style = ParagraphStyle(
        'MetaValue',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # ================= PAGE 1: COVER PAGE =================
    story.append(Spacer(1, 100))
    
    # Sleek visual indicator / accent block
    # We draw an accent block using a Table
    accent_bar = Table([[""]], colWidths=[504], rowHeights=[6])
    accent_bar.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#4f46e5")), # Indigo 600
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(accent_bar)
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("VULNERABILITY ASSESSMENT & PENETRATION TESTING (VAPT) REPORT", title_style))
    story.append(Paragraph("Automated Vulnerability Scan Findings & Analysis Dashboard", subtitle_style))
    
    story.append(Spacer(1, 150))
    
    # Metadata Block
    meta_data = [
        [Paragraph("Report Target:", meta_label_style), Paragraph(report_metadata.get("filename", "N/A"), meta_val_style)],
        [Paragraph("Scan Status:", meta_label_style), Paragraph(report_metadata.get("status", "N/A"), meta_val_style)],
        [Paragraph("Total Findings:", meta_label_style), Paragraph(str(len(vulnerabilities)), meta_val_style)],
        [Paragraph("Generation Date:", meta_label_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), meta_val_style)],
    ]
    meta_table = Table(meta_data, colWidths=[150, 354])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
    ]))
    story.append(meta_table)
    
    story.append(PageBreak())

    # ================= PAGE 2: EXECUTIVE SUMMARY =================
    story.append(Paragraph("Executive Summary", h1_style))
    story.append(Paragraph(
        "This security assessment report summarizes the findings detected during the parsing of the automated VAPT scan file. "
        "Each vulnerability listed has been analyzed and classified according to standard Common Weakness Enumerations (CWE) "
        "and mapped against OWASP Top 10 categories to facilitate rapid mitigation.",
        body_style
    ))
    story.append(Spacer(1, 15))
    
    # Severity Count Metrics Grid
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulnerabilities:
        sev = v.severity.capitalize() if hasattr(v, 'severity') else v.get('severity', 'Medium').capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1
            
    # Draw KPI Cards using Table
    kpi_headers = [
        Paragraph("<b>CRITICAL</b>", ParagraphStyle('C', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>HIGH</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>MEDIUM</b>", ParagraphStyle('M', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>LOW</b>", ParagraphStyle('L', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>INFO</b>", ParagraphStyle('I', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1))
    ]
    
    kpi_values = [
        Paragraph(f"<b>{severity_counts['Critical']}</b>", ParagraphStyle('CV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{severity_counts['High']}</b>", ParagraphStyle('HV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{severity_counts['Medium']}</b>", ParagraphStyle('MV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{severity_counts['Low']}</b>", ParagraphStyle('LV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{severity_counts['Info']}</b>", ParagraphStyle('IV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1))
    ]
    
    kpi_data = [kpi_headers, kpi_values]
    # Total printable width is 504. 5 columns -> 100.8 width each
    kpi_table = Table(kpi_data, colWidths=[100.8]*5, rowHeights=[25, 35])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#ef4444")), # Red 500
        ('BACKGROUND', (1,0), (1,-1), colors.HexColor("#f97316")), # Orange 500
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor("#eab308")), # Yellow 500
        ('BACKGROUND', (3,0), (3,-1), colors.HexColor("#3b82f6")), # Blue 500
        ('BACKGROUND', (4,0), (4,-1), colors.HexColor("#64748b")), # Slate 500
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 1, colors.white),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    
    story.append(kpi_table)
    story.append(Spacer(1, 25))
    
    # Findings summary table
    story.append(Paragraph("Findings Summary Table", ParagraphStyle('Sub', parent=h1_style, fontSize=12, leading=16)))
    
    summary_headers = [
        Paragraph("<b>ID</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Vulnerability</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Severity</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>CWE</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Status</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
    ]
    
    summary_rows = [summary_headers]
    for idx, v in enumerate(vulnerabilities):
        vid = v.id if hasattr(v, 'id') else v.get('id', idx+1)
        name = v.vulnerability_name if hasattr(v, 'vulnerability_name') else v.get('vulnerability_name', 'N/A')
        severity = v.severity if hasattr(v, 'severity') else v.get('severity', 'Medium')
        cwe = v.cwe_id if hasattr(v, 'cwe_id') else v.get('cwe_id', 'N/A')
        status = v.status if hasattr(v, 'status') else v.get('status', 'Open')
        
        # Color coding for severity text
        sev_color = "#334155"
        if severity.capitalize() == "Critical": sev_color = "#ef4444"
        elif severity.capitalize() == "High": sev_color = "#f97316"
        elif severity.capitalize() == "Medium": sev_color = "#d97706" # Yellow-dark
        elif severity.capitalize() == "Low": sev_color = "#3b82f6"
        
        summary_rows.append([
            Paragraph(str(vid), body_style),
            Paragraph(name, body_style),
            Paragraph(f"<font color='{sev_color}'><b>{severity}</b></font>", body_style),
            Paragraph(cwe, body_style),
            Paragraph(status, body_style),
        ])
        
    summary_table = Table(summary_rows, colWidths=[40, 204, 80, 100, 80])
    summary_table_style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ])
    
    # Alternate row background colors
    for r in range(1, len(summary_rows)):
        if r % 2 == 0:
            summary_table_style.add('BACKGROUND', (0, r), (-1, r), colors.HexColor("#f8fafc"))
            
    summary_table.setStyle(summary_table_style)
    story.append(summary_table)
    
    story.append(PageBreak())

    # ================= PAGE 3+: DETAILED FINDINGS =================
    story.append(Paragraph("Detailed Security Findings", h1_style))
    story.append(Spacer(1, 10))

    for idx, v in enumerate(vulnerabilities):
        name = v.vulnerability_name if hasattr(v, 'vulnerability_name') else v.get('vulnerability_name', 'N/A')
        severity = v.severity if hasattr(v, 'severity') else v.get('severity', 'Medium')
        cwe = v.cwe_id if hasattr(v, 'cwe_id') else v.get('cwe_id', 'N/A')
        file_path = v.file_name if hasattr(v, 'file_name') else v.get('file_name', 'N/A')
        line = v.line_number if hasattr(v, 'line_number') else v.get('line_number', 0)
        status = v.status if hasattr(v, 'status') else v.get('status', 'Open')
        
        # Color coding severity block
        sev_bg = "#f8fafc"
        sev_fg = "#0f172a"
        if severity.capitalize() == "Critical":
            sev_bg = "#fee2e2"; sev_fg = "#991b1b"
        elif severity.capitalize() == "High":
            sev_bg = "#ffedd5"; sev_fg = "#9a3412"
        elif severity.capitalize() == "Medium":
            sev_bg = "#fef9c3"; sev_fg = "#854d0e"
        elif severity.capitalize() == "Low":
            sev_bg = "#dbeafe"; sev_fg = "#1e40af"
            
        cwe_details = {
            "vulnerability_name": name,
            "owasp_category": "A03:2021-Injection" if "injection" in name.lower() or "xss" in name.lower() else "General Vulnerability",
            "capec_id": "N/A",
            "description": f"An occurrence of {name} has been detected in {file_path} at line {line}.",
            "recommendations": "Verify the vulnerability and validate user parameters. Restrict input validation and apply secure output escaping."
        }
        
        if db and cwe:
            from app.services import knowledge_base as kb_service
            kb_item = kb_service.get_item_by_cwe(db, cwe)
            if kb_item:
                cwe_details["vulnerability_name"] = kb_item.vulnerability_name
                cwe_details["owasp_category"] = kb_item.owasp_category
                cwe_details["capec_id"] = kb_item.capec_id or "N/A"
                cwe_details["description"] = f"{kb_item.description}\nDetected in {file_path} at line {line}."
                cwe_details["recommendations"] = kb_item.recommendations

        
        # We'll build a neat boxed layout for each finding
        finding_elements = []
        finding_elements.append(Paragraph(f"<b>Finding {idx+1}: {name}</b>", h2_style))
        
        # Inner metadata table
        inner_meta = [
            [
                Paragraph(f"<b>Severity:</b> <font color='{sev_fg}'>{severity}</font>", body_style),
                Paragraph(f"<b>CWE ID:</b> {cwe}", body_style),
                Paragraph(f"<b>Status:</b> {status}", body_style),
            ],
            [
                Paragraph(f"<b>File:</b> {file_path}", body_style),
                Paragraph(f"<b>Line Number:</b> {line}", body_style),
                Paragraph("", body_style) # Empty cell for alignment
            ]
        ]
        
        inner_table = Table(inner_meta, colWidths=[168, 168, 168])
        inner_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(sev_bg)),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor(sev_fg)),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        
        finding_elements.append(inner_table)
        finding_elements.append(Spacer(1, 8))
        
        # Description
        finding_elements.append(Paragraph("<b>Description:</b>", ParagraphStyle('B', parent=body_style, fontName='Helvetica-Bold')))
        finding_elements.append(Paragraph(cwe_details["description"], body_style))
        finding_elements.append(Spacer(1, 6))
        
        # OWASP Mapping & CAPEC
        finding_elements.append(Paragraph(f"<b>OWASP Top 10 Category:</b> {cwe_details['owasp_category']}", body_style))
        finding_elements.append(Spacer(1, 6))
        
        # Remediation
        finding_elements.append(Paragraph("<b>Secure Coding Recommendations:</b>", ParagraphStyle('B', parent=body_style, fontName='Helvetica-Bold')))
        # Split recommendations into lines for formatting
        recs = cwe_details["recommendations"].split("\n")
        for rec in recs:
            if rec.strip():
                finding_elements.append(Paragraph(rec, ParagraphStyle('Rec', parent=body_style, leftIndent=12)))
                
        finding_elements.append(Spacer(1, 20))
        
        # Wrap each finding block inside a KeepTogether to prevent orphan segments
        story.append(KeepTogether(finding_elements))
        
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer


def generate_source_code_pdf_report(analysis_meta: dict, findings: list, db: Session = None) -> BytesIO:
    """
    Generates a professional SAST (Source Code Security Analysis) PDF report.
    Includes Executive Summary, KPI metric cards, code snippets, and suggested fixes.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'SASTTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=15
    )

    subtitle_style = ParagraphStyle(
        'SASTSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#475569"),
        spaceAfter=30
    )

    h1_style = ParagraphStyle(
        'SASTH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SASTH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'SASTBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )

    code_style = ParagraphStyle(
        'SASTCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#f8fafc")
    )

    meta_label_style = ParagraphStyle(
        'SASTMetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )

    meta_val_style = ParagraphStyle(
        'SASTMetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # ================= PAGE 1: COVER PAGE =================
    story.append(Spacer(1, 80))

    # Accent bar
    accent_bar = Table([[""]], colWidths=[504], rowHeights=[6])
    accent_bar.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0284c7")), # Sky 600
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(accent_bar)
    story.append(Spacer(1, 20))

    story.append(Paragraph("SOURCE CODE SECURITY ANALYSIS (SAST) REPORT", title_style))
    story.append(Paragraph("Static Application Security Testing, AST Rule Findings & Remediation Guide", subtitle_style))

    story.append(Spacer(1, 130))

    # Metadata Block
    meta_data = [
        [Paragraph("Project Name:", meta_label_style), Paragraph(analysis_meta.get("project_name", "N/A"), meta_val_style)],
        [Paragraph("Archive Filename:", meta_label_style), Paragraph(analysis_meta.get("filename", "N/A"), meta_val_style)],
        [Paragraph("Files Scanned:", meta_label_style), Paragraph(str(analysis_meta.get("files_scanned", 0)), meta_val_style)],
        [Paragraph("Lines of Code Scanned:", meta_label_style), Paragraph(str(analysis_meta.get("lines_scanned", 0)), meta_val_style)],
        [Paragraph("Total Vulnerabilities:", meta_label_style), Paragraph(str(len(findings)), meta_val_style)],
        [Paragraph("Audit Date:", meta_label_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), meta_val_style)],
    ]
    meta_table = Table(meta_data, colWidths=[160, 344])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
    ]))
    story.append(meta_table)

    story.append(PageBreak())

    # ================= PAGE 2: EXECUTIVE SUMMARY =================
    story.append(Paragraph("Executive Summary", h1_style))
    story.append(Paragraph(
        "This security assessment summarizes vulnerabilities detected through static analysis (SAST) of the supplied source code. "
        "Each detection utilizes syntax tree (AST) inspection and pattern analysis mapped to Common Weakness Enumeration (CWE) "
        "and OWASP Top 10 standards to facilitate targeted remediation.",
        body_style
    ))
    story.append(Spacer(1, 15))

    # Severity Counts Grid
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = getattr(f, 'severity', 'Medium') or 'Medium'
        s = sev.capitalize()
        if s in sev_counts:
            sev_counts[s] += 1
        else:
            sev_counts["Medium"] += 1

    kpi_headers = [
        Paragraph("<b>CRITICAL</b>", ParagraphStyle('C', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>HIGH</b>", ParagraphStyle('H', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>MEDIUM</b>", ParagraphStyle('M', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>LOW</b>", ParagraphStyle('L', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1)),
        Paragraph("<b>INFO</b>", ParagraphStyle('I', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white, alignment=1))
    ]
    kpi_values = [
        Paragraph(f"<b>{sev_counts['Critical']}</b>", ParagraphStyle('CV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{sev_counts['High']}</b>", ParagraphStyle('HV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{sev_counts['Medium']}</b>", ParagraphStyle('MV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{sev_counts['Low']}</b>", ParagraphStyle('LV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1)),
        Paragraph(f"<b>{sev_counts['Info']}</b>", ParagraphStyle('IV', parent=body_style, fontName='Helvetica-Bold', fontSize=18, textColor=colors.white, alignment=1))
    ]
    kpi_table = Table([kpi_headers, kpi_values], colWidths=[100.8]*5, rowHeights=[24, 34])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#ef4444")),
        ('BACKGROUND', (1,0), (1,-1), colors.HexColor("#f97316")),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor("#eab308")),
        ('BACKGROUND', (3,0), (3,-1), colors.HexColor("#3b82f6")),
        ('BACKGROUND', (4,0), (4,-1), colors.HexColor("#64748b")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 1, colors.white),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 20))

    # Findings Summary Table
    story.append(Paragraph("Detected Issues Summary Table", ParagraphStyle('Sub', parent=h1_style, fontSize=12, leading=16)))
    summary_headers = [
        Paragraph("<b>#</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Vulnerability</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Severity</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>CWE</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Location</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
        Paragraph("<b>Confidence</b>", ParagraphStyle('SH', parent=body_style, fontName='Helvetica-Bold')),
    ]
    summary_rows = [summary_headers]
    for idx, f in enumerate(findings):
        name = getattr(f, 'vulnerability_name', 'N/A')
        sev = getattr(f, 'severity', 'Medium') or 'Medium'
        cwe = getattr(f, 'cwe_id', 'N/A')
        fn = getattr(f, 'file_name', 'N/A')
        ln = getattr(f, 'line_number', 0)
        conf = getattr(f, 'confidence', 'Medium')

        sev_color = "#ef4444" if sev.lower() == "critical" else (
            "#f97316" if sev.lower() == "high" else (
                "#d97706" if sev.lower() == "medium" else "#3b82f6"
            )
        )
        loc_str = f"{fn}:{ln}" if ln > 0 else fn

        summary_rows.append([
            Paragraph(str(idx + 1), body_style),
            Paragraph(name, body_style),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
            Paragraph(cwe, body_style),
            Paragraph(loc_str, ParagraphStyle('Loc', parent=body_style, fontSize=7.5, leading=10)),
            Paragraph(conf, body_style),
        ])

    sum_table = Table(summary_rows, colWidths=[24, 150, 60, 70, 140, 60])
    sum_table_style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
    ])
    for r in range(1, len(summary_rows)):
        if r % 2 == 0:
            sum_table_style.add('BACKGROUND', (0, r), (-1, r), colors.HexColor("#f8fafc"))
    sum_table.setStyle(sum_table_style)
    story.append(sum_table)

    story.append(PageBreak())

    # ================= PAGE 3+: DETAILED SECURITY FINDINGS =================
    story.append(Paragraph("Detailed Vulnerability Findings & Suggested Fixes", h1_style))
    story.append(Spacer(1, 10))

    for idx, f in enumerate(findings):
        name = getattr(f, 'vulnerability_name', 'N/A')
        sev = getattr(f, 'severity', 'Medium') or 'Medium'
        cwe = getattr(f, 'cwe_id', 'N/A')
        file_path = getattr(f, 'file_name', 'N/A')
        line = getattr(f, 'line_number', 0)
        language = getattr(f, 'language', 'N/A')
        conf = getattr(f, 'confidence', 'Medium')
        matched = getattr(f, 'matched_code', '') or ''
        snippet = getattr(f, 'code_snippet', '') or ''
        description = getattr(f, 'description', '') or 'No detailed description available.'
        remediation = getattr(f, 'remediation', '') or getattr(f, 'recommendation', '') or 'Review and validate inputs.'
        suggested_fix = getattr(f, 'suggested_fix', '') or ''
        owasp = getattr(f, 'owasp_category', 'A03:2021-Injection') or 'General Security'

        sev_bg = "#fee2e2" if sev.lower() == "critical" else (
            "#ffedd5" if sev.lower() == "high" else (
                "#fef9c3" if sev.lower() == "medium" else "#dbeafe"
            )
        )
        sev_fg = "#991b1b" if sev.lower() == "critical" else (
            "#9a3412" if sev.lower() == "high" else (
                "#854d0e" if sev.lower() == "medium" else "#1e40af"
            )
        )

        finding_elements = []
        finding_elements.append(Paragraph(f"<b>Finding {idx+1}: {name}</b>", h2_style))

        # Metadata Box
        meta_grid = [
            [
                Paragraph(f"<b>Severity:</b> <font color='{sev_fg}'>{sev}</font>", body_style),
                Paragraph(f"<b>CWE:</b> {cwe}", body_style),
                Paragraph(f"<b>Confidence:</b> {conf}", body_style),
            ],
            [
                Paragraph(f"<b>File:</b> {file_path}", body_style),
                Paragraph(f"<b>Line:</b> {line}", body_style),
                Paragraph(f"<b>Language:</b> {language.capitalize()}", body_style),
            ]
        ]
        meta_table_block = Table(meta_grid, colWidths=[168, 168, 168])
        meta_table_block.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(sev_bg)),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor(sev_fg)),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        finding_elements.append(meta_table_block)
        finding_elements.append(Spacer(1, 8))

        # Vulnerable Code Box
        if snippet:
            finding_elements.append(Paragraph("<b>Vulnerable Code Context:</b>", ParagraphStyle('B', parent=body_style, fontName='Helvetica-Bold')))
            # Wrap snippet in dark background table
            code_paras = [Paragraph(line.replace(" ", "&nbsp;"), code_style) for line in snippet.split("\n")]
            code_box = Table([[p] for p in code_paras], colWidths=[504])
            code_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#0f172a")),
                ('TOPPADDING', (0,0), (-1,-1), 2),
                ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            finding_elements.append(code_box)
            finding_elements.append(Spacer(1, 8))

        # Description
        finding_elements.append(Paragraph("<b>Vulnerability Description:</b>", ParagraphStyle('B', parent=body_style, fontName='Helvetica-Bold')))
        finding_elements.append(Paragraph(description, body_style))
        finding_elements.append(Spacer(1, 6))

        # OWASP Mapping
        finding_elements.append(Paragraph(f"<b>OWASP Top 10 Category:</b> {owasp}", body_style))
        finding_elements.append(Spacer(1, 6))

        # Remediation
        finding_elements.append(Paragraph("<b>Remediation Guidelines:</b>", ParagraphStyle('B', parent=body_style, fontName='Helvetica-Bold')))
        recs = remediation.split("\n")
        for rec in recs:
            if rec.strip():
                finding_elements.append(Paragraph(rec, ParagraphStyle('Rec', parent=body_style, leftIndent=12)))
        finding_elements.append(Spacer(1, 8))

        # Suggested Fix
        if suggested_fix:
            finding_elements.append(Paragraph("<b>Suggested Fix (Example Safer Implementation):</b>", ParagraphStyle('B', parent=body_style, fontName='Helvetica-Bold', textColor=colors.HexColor("#0284c7"))))
            fix_paras = [Paragraph(line.replace(" ", "&nbsp;"), code_style) for line in suggested_fix.split("\n")]
            fix_box = Table([[p] for p in fix_paras], colWidths=[504])
            fix_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#1e293b")),
                ('TOPPADDING', (0,0), (-1,-1), 2),
                ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            finding_elements.append(fix_box)
            finding_elements.append(Paragraph("<font size=7 color='#64748b'><i>Note: Suggested fixes are illustrative recommendations. Review carefully before deploying to production.</i></font>", body_style))

        finding_elements.append(Spacer(1, 18))
        story.append(KeepTogether(finding_elements))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer

