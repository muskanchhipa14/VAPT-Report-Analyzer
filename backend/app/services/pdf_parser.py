import re
import os
from pypdf import PdfReader
from sqlalchemy.orm import Session
from app.models.vulnerability import Vulnerability
from app.models.knowledge_base import KnowledgeBase

# Define prototype vulnerability rules for detection
VULNERABILITY_RULES = [
    {
        "name": "SQL Injection",
        "cwe_id": "CWE-89",
        "keywords": [r"sql\s*injection", r"sqli", r"structured\s*query\s*language\s*injection"],
        "severity": "High",
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "cwe_id": "CWE-79",
        "keywords": [r"cross-site\s*scripting", r"xss", r"cross\s*site\s*scripting"],
        "severity": "High",
    },
    {
        "name": "Buffer Overflow",
        "cwe_id": "CWE-120",
        "keywords": [r"buffer\s*overflow", r"buffer\s*overrun", r"stack\s*overflow"],
        "severity": "Critical",
    },
    {
        "name": "Hardcoded Credentials",
        "cwe_id": "CWE-798",
        "keywords": [r"hardcoded\s*credentials", r"hardcoded\s*password", r"hardcoded\s*key", r"hardcoded\s*token", r"hard-coded"],
        "severity": "High",
    },
    {
        "name": "Path Traversal",
        "cwe_id": "CWE-22",
        "keywords": [r"path\s*traversal", r"directory\s*traversal", r"dot-dot-slash"],
        "severity": "High",
    },
    {
        "name": "Insecure Direct Object Reference (IDOR)",
        "cwe_id": "CWE-639",
        "keywords": [r"insecure\s*direct\s*object\s*reference", r"idor", r"direct\s*object\s*reference"],
        "severity": "High",
    },
    {
        "name": "Missing Authentication",
        "cwe_id": "CWE-306",
        "keywords": [r"missing\s*authentication", r"unauthenticated\s*access", r"missing\s*auth", r"unauthenticated"],
        "severity": "Critical",
    },
    {
        "name": "Weak Password Policy",
        "cwe_id": "CWE-521",
        "keywords": [r"weak\s*password\s*policy", r"weak\s*password", r"password\s*complexity"],
        "severity": "Medium",
    },
    {
        "name": "Information Exposure",
        "cwe_id": "CWE-200",
        "keywords": [r"information\s*exposure", r"sensitive\s*data\s*exposure", r"information\s*leak", r"verbose\s*error", r"debug\s*info"],
        "severity": "Medium",
    },
    {
        "name": "Missing Security Headers",
        "cwe_id": "CWE-693",
        "keywords": [r"missing\s*security\s*headers", r"security\s*headers", r"x-frame-options", r"content-security-policy", r"hsts", r"nosniff"],
        "severity": "Low",
    }
]

def extract_text_from_pdf(file_path: str) -> str:
    """Extracts text from all pages of the given PDF file."""
    if not os.path.exists(file_path):
        return ""
    
    try:
        reader = PdfReader(file_path)
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        return text
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return ""

def parse_pdf_report(db: Session, file_path: str, report_name: str) -> list[Vulnerability]:
    """
    Parses a PDF report page by page. Uses a fallback system where CWE IDs are matched first,
    falling back to keywords only when CWE IDs are absent. Finds the closest filename and line number.
    """
    if not os.path.exists(file_path):
        return []
        
    try:
        reader = PdfReader(file_path)
    except Exception as e:
        print(f"Error opening PDF: {e}")
        return []
        
    detected_vulns = []
    seen_vulns = set()  # Track uniqueness by (cwe_id, file_name, line_number)

    file_regex = r"\b([a-zA-Z0-9_\-\/\\.]+\.(?:py|js|jsx|ts|tsx|java|c|cpp|h|go|rb|php|html|cs|sh|json|xml|yaml|yml))\b"
    line_regex = r"(?i)(?:line|ln|L)\s*:?\s*(\d+)"
    colon_line_regex = r"\b:(\d+)\b"

    for page_num, page in enumerate(reader.pages):
        page_text = page.extract_text()
        if not page_text:
            continue
            
        for rule in VULNERABILITY_RULES:
            cwe_pattern = re.compile(rf"\b{rule['cwe_id']}\b", re.IGNORECASE)
            keyword_patterns = [re.compile(kw, re.IGNORECASE) for kw in rule["keywords"]]
            
            # Prioritize CWE IDs over keywords
            match_indices = []
            cwe_matches = list(cwe_pattern.finditer(page_text))
            
            if cwe_matches:
                for m in cwe_matches:
                    match_indices.append(m.start())
            else:
                for pat in keyword_patterns:
                    for m in pat.finditer(page_text):
                        match_indices.append(m.start())
                        
            for start_idx in match_indices:
                # Find the closest filename match on this page
                file_matches = []
                for m in re.finditer(file_regex, page_text):
                    fn = m.group(1)
                    if fn.lower() not in [report_name.lower(), "pdf", "vapt", "report.pdf"]:
                        dist = abs(m.start() - start_idx)
                        file_matches.append((fn, dist))
                
                file_name = "N/A"
                if file_matches:
                    file_matches.sort(key=lambda x: x[1])
                    if file_matches[0][1] < 400:
                        file_name = file_matches[0][0]
                        
                # Find the closest line number match on this page
                line_matches = []
                for m in re.finditer(line_regex, page_text):
                    dist = abs(m.start() - start_idx)
                    line_matches.append((int(m.group(1)), dist))
                for m in re.finditer(colon_line_regex, page_text):
                    dist = abs(m.start() - start_idx)
                    line_matches.append((int(m.group(1)), dist))
                    
                line_number = 1
                if line_matches:
                    line_matches.sort(key=lambda x: x[1])
                    if line_matches[0][1] < 400:
                        line_number = line_matches[0][0]
                        
                vuln_key = (rule["cwe_id"], file_name, line_number)
                if vuln_key not in seen_vulns:
                    seen_vulns.add(vuln_key)
                    
                    # Resolve severity and name from Knowledge Base if present
                    kb_entry = db.query(KnowledgeBase).filter(KnowledgeBase.cwe_id == rule["cwe_id"]).first()
                    if not kb_entry:
                        kb_entry = db.query(KnowledgeBase).filter(
                            KnowledgeBase.vulnerability_name.ilike(rule["name"])
                        ).first()
                        
                    severity = kb_entry.severity if kb_entry else rule["severity"]
                    vuln_name = kb_entry.vulnerability_name if kb_entry else rule["name"]
                    
                    vuln = Vulnerability(
                        report_name=report_name,
                        vulnerability_name=vuln_name,
                        severity=severity,
                        cwe_id=rule["cwe_id"],
                        file_name=file_name,
                        line_number=line_number,
                        status="Open"
                    )
                    db.add(vuln)
                    detected_vulns.append(vuln)
                    
    if detected_vulns:
        db.commit()
        for v in detected_vulns:
            db.refresh(v)
            
    return detected_vulns
