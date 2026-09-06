"""
C and C++ Source Code Security Rules (Pattern & Structural Analysis)
Detects Buffer Overflow (CWE-120), Format String (CWE-134), Command Injection (CWE-78),
Path Traversal (CWE-22), Integer Overflow (CWE-190), and Hardcoded Secrets (CWE-798).
"""

import re
from typing import List, Set, Tuple
from app.source_scanner.models import ScanFinding
from app.source_scanner.utils import extract_code_snippet
from app.source_scanner.rules import get_suggested_fix

SECRET_PATTERNS = [
    (re.compile(r"""(?i)(?:char\s*\*|const\s+char\s*\*|std::string)\s*(?:password|passwd|apiKey|secretKey|token|secret)\s*=\s*["']([a-zA-Z0-9_\-\.]{12,120})["']"""), "Hardcoded Credential / Secret", "Medium"),
    (re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""), "AWS Access Key ID", "High"),
]

PLACEHOLDER_WORDS = {"changeme", "password", "test", "example", "dummy", "placeholder", "your_secret", "your_key", "secret", "none", "null", "admin"}


def is_placeholder(val: str) -> bool:
    v = val.strip().lower()
    return v in PLACEHOLDER_WORDS or "your_" in v or "<" in v or "{" in v or len(v) < 6


C_CPP_RULES = [
    # 1. Buffer Overflow (CWE-120) - Unsafe string copying / memory manipulation
    {
        "cwe_id": "CWE-120",
        "name": "Buffer Overflow (Unbounded Copy / gets)",
        "pattern": re.compile(r"""\b(?:strcpy|strcat|gets|vsprintf|sprintf)\s*\("""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A06:2021-Vulnerable and Outdated Components"
    },
    # 1b. Buffer Overflow (CWE-120) - Unbounded scanf format
    {
        "cwe_id": "CWE-120",
        "name": "Buffer Overflow (Unbounded scanf)",
        "pattern": re.compile(r"""\bscanf\s*\(\s*["']%s["']\s*,"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A06:2021-Vulnerable and Outdated Components"
    },
    # 2. Format String Vulnerability (CWE-134)
    {
        "cwe_id": "CWE-134",
        "name": "Format String Vulnerability",
        "pattern": re.compile(r"""\b(?:printf|fprintf|syslog|snprintf)\s*\(\s*(?!(?:["']|stderr|stdout))[a-zA-Z0-9_]+(?:\s*,\s*[^)]*)?\s*\)"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A03:2021-Injection"
    },
    # 3. Command Injection (CWE-78)
    {
        "cwe_id": "CWE-78",
        "name": "Command Injection",
        "pattern": re.compile(r"""\b(?:system|popen)\s*\(\s*(?:[a-zA-Z0-9_]+\s*\+|strcat|sprintf|[a-zA-Z0-9_]+(?!\s*["']))"""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 4. Path Traversal (CWE-22)
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "pattern": re.compile(r"""\bfopen\s*\(\s*(?:[a-zA-Z0-9_]+\s*\+|[a-zA-Z0-9_]+,\s*["'][rwab+]+["'])"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A01:2021-Broken Access Control"
    },
    # 5. Integer Overflow (CWE-190)
    {
        "cwe_id": "CWE-190",
        "name": "Integer Overflow to Buffer Allocation",
        "pattern": re.compile(r"""\bmalloc\s*\(\s*(?:[a-zA-Z0-9_]+\s*\*\s*sizeof|[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+)\s*\)"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A03:2021-Injection"
    },
]


def scan_c_cpp_code(file_name: str, content: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    lines = content.splitlines()
    reported_locations: Set[Tuple[int, str]] = set()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Check structural rules
        for rule in C_CPP_RULES:
            if rule["pattern"].search(line):
                loc_key = (line_idx, rule["cwe_id"])
                if loc_key not in reported_locations:
                    reported_locations.add(loc_key)
                    snippet = extract_code_snippet(lines, line_idx)
                    suggested_fix = get_suggested_fix(rule["cwe_id"], "c") or get_suggested_fix(rule["cwe_id"], "cpp")
                    findings.append(ScanFinding(
                        file_name=file_name,
                        line_number=line_idx,
                        language="c",
                        vulnerability_name=rule["name"],
                        cwe_id=rule["cwe_id"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        matched_code=stripped,
                        code_snippet=snippet,
                        suggested_fix=suggested_fix,
                        owasp_category=rule["owasp"]
                    ))

        # Check secret patterns
        for pat, secret_type, sev in SECRET_PATTERNS:
            match = pat.search(line)
            if match:
                val = match.group(1)
                if not is_placeholder(val):
                    loc_key = (line_idx, "CWE-798")
                    if loc_key not in reported_locations:
                        reported_locations.add(loc_key)
                        snippet = extract_code_snippet(lines, line_idx)
                        suggested_fix = get_suggested_fix("CWE-798", "c")
                        findings.append(ScanFinding(
                            file_name=file_name,
                            line_number=line_idx,
                            language="c",
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
