"""
Java Source Code Security Rules (Structural & Pattern Analysis)
Detects SQL Injection, Command Injection, XXE, Path Traversal,
Hardcoded Credentials, Weak Cryptography, and Insecure Deserialization.
"""

import re
from typing import List, Set, Tuple
from app.source_scanner.models import ScanFinding
from app.source_scanner.utils import extract_code_snippet
from app.source_scanner.rules import get_suggested_fix

SECRET_PATTERNS = [
    (re.compile(r"""(?i)(?:String\s+)?(?:password|passwd|apiKey|secretKey|token|authToken)\s*=\s*['"]([a-zA-Z0-9_\-\.]{12,120})['"]"""), "Hardcoded Credential / Secret", "Medium"),
    (re.compile(r"""['"](AKIA[0-9A-Z]{16})['"]"""), "AWS Access Key ID", "High"),
    (re.compile(r"""['"](eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]*)['"]"""), "Hardcoded JWT Token", "High"),
]

PLACEHOLDER_WORDS = {"changeme", "password", "test", "example", "dummy", "placeholder", "your_secret", "your_key", "secret", "none", "null", "admin"}


def is_placeholder(val: str) -> bool:
    v = val.strip().lower()
    return v in PLACEHOLDER_WORDS or "your_" in v or "<" in v or "{" in v or len(v) < 6


JAVA_RULES = [
    # 1. SQL Injection (CWE-89)
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "pattern": re.compile(r"""(?:(?:\.executeQuery|\.executeUpdate|\.execute)\s*\(|(?:\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\r\n]*\+))""", re.IGNORECASE),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 2. Command Injection (CWE-78)
    {
        "cwe_id": "CWE-78",
        "name": "Command Injection",
        "pattern": re.compile(r"""(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(\s*(?:['"][^'"]*['"]\s*\+|\w+\s*\+)"""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 3. XXE Injection (CWE-611)
    {
        "cwe_id": "CWE-611",
        "name": "XML External Entity (XXE) Injection",
        "pattern": re.compile(r"""(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A05:2021-Security Misconfiguration"
    },
    # 4. Path Traversal (CWE-22)
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "pattern": re.compile(r"""new\s+(?:File|FileInputStream|FileReader|FileOutputStream)\s*\(\s*(?:[a-zA-Z0-9_]+\s*,\s*)?(?:req\.getParameter|['"][^'"]*['"]\s*\+|\w+\s*\+|userInput)"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A01:2021-Broken Access Control"
    },
    # 5. Insecure Deserialization (CWE-502)
    {
        "cwe_id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "pattern": re.compile(r"""(?:new\s+ObjectInputStream|\.readObject\(\)|XMLDecoder)"""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A08:2021-Software and Data Integrity Failures"
    },
    # 6. Weak Cryptography (CWE-327)
    {
        "cwe_id": "CWE-327",
        "name": "Weak Cryptographic Hashing",
        "pattern": re.compile(r"""MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-1|SHA1)['"]\s*\)|Cipher\.getInstance\(\s*['"]DES""", re.IGNORECASE),
        "severity": "High",
        "confidence": "High",
        "owasp": "A02:2021-Cryptographic Failures"
    },
]


def scan_java_code(file_path: str, content: str) -> List[ScanFinding]:
    """
    Scans Java source code using structural pattern matching for high-value security rules.
    """
    findings: List[ScanFinding] = []
    lines = content.splitlines(keepends=True)
    seen_lines_by_cwe: Set[Tuple[str, int]] = set()

    for idx, line in enumerate(lines):
        line_num = idx + 1
        stripped = line.strip()

        # Skip comment lines
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Check structural security rules
        for rule in JAVA_RULES:
            if rule["pattern"].search(line):
                key = (rule["cwe_id"], line_num)
                if key not in seen_lines_by_cwe:
                    seen_lines_by_cwe.add(key)
                    findings.append(ScanFinding(
                        file_name=file_path,
                        line_number=line_num,
                        language="java",
                        vulnerability_name=rule["name"],
                        cwe_id=rule["cwe_id"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        matched_code=stripped,
                        code_snippet=extract_code_snippet(lines, line_num),
                        suggested_fix=get_suggested_fix(rule["cwe_id"], "java"),
                        owasp_category=rule.get("owasp")
                    ))

        # Check hardcoded secrets
        for pattern, desc, confidence in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                val = match.group(1) if match.groups() else match.group(0)
                if not is_placeholder(val):
                    key = ("CWE-798", line_num)
                    if key not in seen_lines_by_cwe:
                        seen_lines_by_cwe.add(key)
                        findings.append(ScanFinding(
                            file_name=file_path,
                            line_number=line_num,
                            language="java",
                            vulnerability_name="Hardcoded Credentials",
                            cwe_id="CWE-798",
                            severity="High",
                            confidence=confidence,
                            matched_code=stripped,
                            code_snippet=extract_code_snippet(lines, line_num),
                            suggested_fix=get_suggested_fix("CWE-798", "java"),
                            owasp_category="A07:2021-Identification and Authentication Failures"
                        ))

    return findings
