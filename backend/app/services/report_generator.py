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
