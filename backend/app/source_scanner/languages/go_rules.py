"""
Go (Golang) Source Code Security Rules (Pattern & Structural Analysis)
Detects SQL Injection (CWE-89), Command Injection (CWE-78), Cross-Site Scripting (CWE-79),
Path Traversal (CWE-22), Weak Cryptography (CWE-327), and Hardcoded Credentials (CWE-798).
"""

import re
from typing import List, Set, Tuple
from app.source_scanner.models import ScanFinding
from app.source_scanner.utils import extract_code_snippet
from app.source_scanner.rules import get_suggested_fix

SECRET_PATTERNS = [
    (re.compile(r"""(?i)(?:apiKey|secretKey|token|password|passwd|secret)\s*(?::=|=)\s*["']([a-zA-Z0-9_\-\.]{12,120})["']"""), "Hardcoded Credential / Secret", "Medium"),
    (re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""), "AWS Access Key ID", "High"),
]

PLACEHOLDER_WORDS = {"changeme", "password", "test", "example", "dummy", "placeholder", "your_secret", "your_key", "secret", "none", "null", "admin"}


def is_placeholder(val: str) -> bool:
    v = val.strip().lower()
    return v in PLACEHOLDER_WORDS or "your_" in v or "<" in v or "{" in v or len(v) < 6


GO_RULES = [
    # 1. SQL Injection (CWE-89) - db.Query / db.Exec or fmt.Sprintf query formatting
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "pattern": re.compile(r"""(?:\bfmt\.Sprintf\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b|\b(?:db|tx)\.(?:Query|QueryRow|Exec)\s*\(\s*(?:fmt\.Sprintf|["'][^"']*SELECT[^"']*["']\s*\+))""", re.IGNORECASE),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 2. Command Injection (CWE-78) - exec.Command with shell / concat
    {
        "cwe_id": "CWE-78",
        "name": "Command Injection",
        "pattern": re.compile(r"""\bexec\.Command\s*\(\s*(?:["'](?:sh|bash|cmd)["']\s*,\s*["']-c["']\s*,\s*.*(?:\+|\bfmt\.Sprintf)|.*(?:\+|\bfmt\.Sprintf))"""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 3. Cross-Site Scripting (CWE-79) - template.HTML cast on dynamic input
    {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "pattern": re.compile(r"""\btemplate\.(?:HTML|JS|CSS)\s*\(\s*(?!\s*["'][^"']*["']\s*\))[a-zA-Z0-9_]+"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 4. Path Traversal (CWE-22) - os.Open / os.ReadFile with dynamic input
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "pattern": re.compile(r"""\b(?:os\.Open|os\.ReadFile|ioutil\.ReadFile)\s*\(\s*(?:.*(?:\+|fmt\.Sprintf)|filepath\.Join\s*\([^)]*(?:r\.URL|param))"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A01:2021-Broken Access Control"
    },
    # 5. Weak Cryptography (CWE-327)
    {
        "cwe_id": "CWE-327",
        "name": "Weak Cryptographic Hashing",
        "pattern": re.compile(r"""\b(?:md5\.New|sha1\.New|des\.NewCipher)\s*\(\)"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A02:2021-Cryptographic Failures"
    },
]


def scan_go_code(file_name: str, content: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    lines = content.splitlines()
    reported_locations: Set[Tuple[int, str]] = set()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        for rule in GO_RULES:
            if rule["pattern"].search(line):
                loc_key = (line_idx, rule["cwe_id"])
                if loc_key not in reported_locations:
                    reported_locations.add(loc_key)
                    snippet = extract_code_snippet(lines, line_idx)
                    suggested_fix = get_suggested_fix(rule["cwe_id"], "go")
                    findings.append(ScanFinding(
                        file_name=file_name,
                        line_number=line_idx,
                        language="go",
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
                        suggested_fix = get_suggested_fix("CWE-798", "go")
                        findings.append(ScanFinding(
                            file_name=file_name,
                            line_number=line_idx,
                            language="go",
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
