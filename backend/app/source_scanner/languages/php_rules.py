"""
PHP Source Code Security Rules (Pattern & Structural Analysis)
Detects SQL Injection (CWE-89), Cross-Site Scripting (CWE-79), Command Injection (CWE-78),
Path Traversal (CWE-22), and Hardcoded Credentials (CWE-798).
"""

import re
from typing import List, Set, Tuple
from app.source_scanner.models import ScanFinding
from app.source_scanner.utils import extract_code_snippet
from app.source_scanner.rules import get_suggested_fix

SECRET_PATTERNS = [
    (re.compile(r"""(?i)\$(?:password|passwd|apiKey|secretKey|token|secret|auth_token)\s*=\s*["']([a-zA-Z0-9_\-\.]{12,120})["']"""), "Hardcoded Credential / Secret", "Medium"),
    (re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""), "AWS Access Key ID", "High"),
]

PLACEHOLDER_WORDS = {"changeme", "password", "test", "example", "dummy", "placeholder", "your_secret", "your_key", "secret", "none", "null", "admin"}


def is_placeholder(val: str) -> bool:
    v = val.strip().lower()
    return v in PLACEHOLDER_WORDS or "your_" in v or "<" in v or "{" in v or len(v) < 6


PHP_RULES = [
    # 1. SQL Injection (CWE-89) - Concatenation or direct interpolation in query execution
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "pattern": re.compile(r"""(?:\b(?:mysqli_query|mysql_query|\$conn->query|\$db->query|\$pdo->query)\s*\(\s*(?:["'][^"']*SELECT[^"']*["']\s*\.|\$sql\b|\$"SELECT)|(?:\bSELECT\b[^;\r\n]*\.(?:\s*\$_|\s*\$user|\s*\$id)))""", re.IGNORECASE),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 2. Cross-Site Scripting (XSS) (CWE-79) - Direct echo/print of superglobals without escaping
    {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "pattern": re.compile(r"""\b(?:echo|print)\s+(?:\$_(?:GET|POST|REQUEST|COOKIE)\[|.*\.\s*\$_(?:GET|POST|REQUEST))"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 3. Command Injection (CWE-78) - Shell execution functions
    {
        "cwe_id": "CWE-78",
        "name": "Command Injection",
        "pattern": re.compile(r"""\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*(?:\$|\$_GET|\$_POST|["'][^"']*["']\s*\.)"""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 4. Path Traversal / LFI (CWE-22) - Unsanitized file inclusion or read
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal / Local File Inclusion",
        "pattern": re.compile(r"""\b(?:include|require|include_once|require_once|file_get_contents|readfile)\s*\(\s*(?:\$_(?:GET|POST|REQUEST)|\$[a-zA-Z0-9_]+)"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A01:2021-Broken Access Control"
    },
]


def scan_php_code(file_name: str, content: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    lines = content.splitlines()
    reported_locations: Set[Tuple[int, str]] = set()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        for rule in PHP_RULES:
            if rule["pattern"].search(line):
                # Filter out lines that already call htmlspecialchars or prepared statements
                if rule["cwe_id"] == "CWE-79" and ("htmlspecialchars" in line or "htmlentities" in line):
                    continue
                if rule["cwe_id"] == "CWE-89" and ("prepare(" in line or "bind_param" in line or "bindParam" in line):
                    continue

                loc_key = (line_idx, rule["cwe_id"])
                if loc_key not in reported_locations:
                    reported_locations.add(loc_key)
                    snippet = extract_code_snippet(lines, line_idx)
                    suggested_fix = get_suggested_fix(rule["cwe_id"], "php")
                    findings.append(ScanFinding(
                        file_name=file_name,
                        line_number=line_idx,
                        language="php",
                        vulnerability_name=rule["name"],
                        cwe_id=rule["cwe_id"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        matched_code=stripped,
                        code_snippet=snippet,
                        suggested_fix=suggested_fix,
                        owasp_category=rule["owasp"]
                    ))

        for pat, secret_type, sev in SECRET_PATTERNS:
            match = pat.search(line)
            if match:
                val = match.group(1)
                if not is_placeholder(val):
                    loc_key = (line_idx, "CWE-798")
                    if loc_key not in reported_locations:
                        reported_locations.add(loc_key)
                        snippet = extract_code_snippet(lines, line_idx)
                        suggested_fix = get_suggested_fix("CWE-798", "php")
                        findings.append(ScanFinding(
                            file_name=file_name,
                            line_number=line_idx,
                            language="php",
                            vulnerability_name=f"Hardcoded Credential ({secret_type})",
                            cwe_id="CWE-798",
                            severity=sev,
                            confidence="High",
                            matched_code=stripped,
                            code_snippet=snippet,
                            suggested_fix=suggested_fix,
                            owasp_category="A07:2021-Identification and Authentication Failures"
                        ))

    return findings
