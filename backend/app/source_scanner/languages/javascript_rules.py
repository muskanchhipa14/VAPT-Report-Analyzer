"""
JavaScript / TypeScript / React JSX Source Code Security Rules
Detects XSS, Command Injection, SQL Injection, Hardcoded Secrets,
Prototype Pollution, Path Traversal, and SSRF.
"""

import re
from typing import List, Set, Tuple
from app.source_scanner.models import ScanFinding
from app.source_scanner.utils import extract_code_snippet
from app.source_scanner.rules import get_suggested_fix

SECRET_PATTERNS = [
    (re.compile(r"""(?i)(?:api_key|apiKey|secretKey|jwtSecret|authToken|token|password|passwd)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{12,120})['"]"""), "Hardcoded Credential / Secret", "Medium"),
    (re.compile(r"""['"](AKIA[0-9A-Z]{16})['"]"""), "AWS Access Key ID", "High"),
    (re.compile(r"""['"](eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]*)['"]"""), "Hardcoded JWT Token", "High"),
]

PLACEHOLDER_WORDS = {"changeme", "password", "test", "example", "dummy", "placeholder", "your_secret", "your_key", "secret", "none", "null", "admin"}


def is_placeholder(val: str) -> bool:
    v = val.strip().lower()
    return v in PLACEHOLDER_WORDS or "your_" in v or "<" in v or "{" in v or len(v) < 6


# Regex rules for JavaScript / JSX
JS_RULES = [
    # 1. XSS (CWE-79) - React dangerouslySetInnerHTML
    {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "pattern": re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 1b. XSS (CWE-79) - DOM innerHTML / outerHTML / document.write
    {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "pattern": re.compile(r"""(?:\.innerHTML|\.outerHTML)\s*=\s*(?!['"][^'"]*['"]\s*;)(?!``\s*;)[^;]+|document\.write\s*\("""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A03:2021-Injection"
    },
    # 2. Command Injection (CWE-78) - child_process.exec
    {
        "cwe_id": "CWE-78",
        "name": "Command Injection",
        "pattern": re.compile(r"""(?:child_process\s*\.\s*(?:exec|execSync)|exec\s*)\(\s*(?:`[^`]*\${|['"][^'"]*['"]\s*\+|\w+\s*\+)"""),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 3. SQL Injection (CWE-89) - dynamic SQL query in pool/db/connection.query
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "pattern": re.compile(r"""(?:\b(?:db|pool|client|connection|sequelize)\.query\s*\(|\bquery\s*\()\s*(?:`\s*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\${|['"]\s*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+)""", re.IGNORECASE),
        "severity": "Critical",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 4. Prototype Pollution (CWE-1321)
    {
        "cwe_id": "CWE-1321",
        "name": "Prototype Pollution",
        "pattern": re.compile(r"""(?:\[['"]__proto__['"]\]|\[['"]prototype['"]\]|__proto__|constructor\.prototype)"""),
        "severity": "High",
        "confidence": "High",
        "owasp": "A03:2021-Injection"
    },
    # 5. Path Traversal (CWE-22) - fs.readFile / readFileSync with non-constant path
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "pattern": re.compile(r"""\bfs\s*\.\s*(?:readFile|readFileSync|createReadStream|unlink|unlinkSync)\s*\(\s*(?:req\.|\w+\s*\+|`[^`]*\${)"""),
        "severity": "High",
        "confidence": "Medium",
        "owasp": "A01:2021-Broken Access Control"
    },
    # 6. SSRF (CWE-918) - fetch / axios with user parameter
    {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "pattern": re.compile(r"""(?:axios\s*\.\s*(?:get|post|put|delete)|fetch)\s*\(\s*(?:req\.(?:query|body|params)|\w+_url|userInputUrl|targetUrl)"""),
        "severity": "Critical",
        "confidence": "Medium",
        "owasp": "A10:2021-Server-Side Request Forgery"
    },
    # 7. Weak Cryptography (CWE-327) - md5 / sha1
    {
        "cwe_id": "CWE-327",
        "name": "Weak Cryptographic Hashing",
        "pattern": re.compile(r"""crypto\s*\.\s*createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)""", re.IGNORECASE),
        "severity": "High",
        "confidence": "High",
        "owasp": "A02:2021-Cryptographic Failures"
    },
]


def scan_javascript_code(file_path: str, content: str) -> List[ScanFinding]:
    """
    Scans JavaScript / React JSX / TypeScript source code for security vulnerabilities.
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
        for rule in JS_RULES:
            if rule["pattern"].search(line):
                key = (rule["cwe_id"], line_num)
                if key not in seen_lines_by_cwe:
                    seen_lines_by_cwe.add(key)
                    findings.append(ScanFinding(
                        file_name=file_path,
                        line_number=line_num,
                        language="javascript",
                        vulnerability_name=rule["name"],
                        cwe_id=rule["cwe_id"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        matched_code=stripped,
                        code_snippet=extract_code_snippet(lines, line_num),
                        suggested_fix=get_suggested_fix(rule["cwe_id"], "javascript"),
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
                            language="javascript",
                            vulnerability_name="Hardcoded Credentials",
                            cwe_id="CWE-798",
                            severity="High",
                            confidence=confidence,
                            matched_code=stripped,
                            code_snippet=extract_code_snippet(lines, line_num),
                            suggested_fix=get_suggested_fix("CWE-798", "javascript"),
                            owasp_category="A07:2021-Identification and Authentication Failures"
                        ))

    return findings
