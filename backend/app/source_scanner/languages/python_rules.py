"""
Python Source Code Security Rules (AST + Pattern Analysis)
Detects SQLi, Command Injection, Insecure Deserialization, Weak Cryptography,
Hardcoded Secrets, Path Traversal, SSRF, Insecure Randomness, and Debug Configuration.
"""

import ast
import re
from typing import List, Dict, Set, Optional
from app.source_scanner.models import ScanFinding
from app.source_scanner.utils import extract_code_snippet
from app.source_scanner.rules import get_suggested_fix

# Regex heuristics for hardcoded secrets
SECRET_PATTERNS = [
    (re.compile(r"""(?i)(?:api_key|apikey|secret_key|secret|token|password|passwd|pwd|auth_token)\s*=\s*['"]([a-zA-Z0-9_\-\.]{12,120})['"]"""), "Hardcoded Credential / Secret", "Medium"),
    (re.compile(r"""['"](AKIA[0-9A-Z]{16})['"]"""), "AWS Access Key ID", "High"),
    (re.compile(r"""['"](eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]*)['"]"""), "Hardcoded JWT Token", "High"),
    (re.compile(r"""(?i)(?:db_pass|database_password|db_password|mysql_password|postgres_password)\s*=\s*['"]([^'"]{6,64})['"]"""), "Hardcoded Database Password", "High"),
]

PLACEHOLDER_WORDS = {"changeme", "password", "test", "example", "dummy", "placeholder", "your_secret", "your_key", "secret", "none", "null", "admin"}


def is_placeholder(val: str) -> bool:
    v = val.strip().lower()
    return v in PLACEHOLDER_WORDS or "your_" in v or "<" in v or "{" in v or len(v) < 6


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, file_name: str, lines: List[str]):
        self.file_name = file_name
        self.lines = lines
        self.findings: List[ScanFinding] = []
        
        # Track string variables containing dynamic SQL queries
        # e.g., query = "SELECT ... " + user_id
        self.sql_concat_vars: Dict[str, int] = {}
        self.sql_fstring_vars: Dict[str, int] = {}

    def _get_call_name(self, node: ast.Call) -> str:
        """Returns dotted call name such as 'os.system' or 'cursor.execute'."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            curr = func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return ""

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Checks if an AST expression represents dynamic string concatenation/formatting."""
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        elif isinstance(node, ast.JoinedStr):
            # f"..." string containing formatted values
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    return True
        elif isinstance(node, ast.Call):
            # .format(...)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def _contains_sql_keyword(self, node: ast.AST) -> bool:
        """Checks if a string literal or constant in node has SQL syntax keywords."""
        sql_keywords = ["select ", "insert into ", "update ", "delete from ", "drop table", "alter table"]
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                lower_val = child.value.lower()
                if any(kw in lower_val for kw in sql_keywords):
                    return True
        return False

    def visit_Assign(self, node: ast.Assign):
        # Check if assigning dynamic SQL concatenation to a variable
        # e.g. query = "SELECT * FROM users WHERE id = " + user_id
        if self._is_dynamic_string(node.value) and self._contains_sql_keyword(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.sql_concat_vars[target.id] = node.lineno

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node)
        call_name_lower = call_name.lower()
        lineno = getattr(node, "lineno", 1)

        # 1. SQL Injection (CWE-89)
        # Check cursor.execute(...) or execute(...) with dynamic SQL
        if call_name.endswith(".execute") or call_name == "execute" or call_name.endswith(".raw_sql"):
            if node.args:
                first_arg = node.args[0]
                matched_code = ""
                try:
                    matched_code = self.lines[lineno - 1].strip()
                except Exception:
                    matched_code = "cursor.execute(...)"

                # Direct concatenation or f-string inside execute()
                if self._is_dynamic_string(first_arg):
                    self.findings.append(ScanFinding(
                        file_name=self.file_name,
                        line_number=lineno,
                        language="python",
                        vulnerability_name="SQL Injection",
                        cwe_id="CWE-89",
                        severity="Critical",
                        confidence="High",
                        matched_code=matched_code,
                        code_snippet=extract_code_snippet(self.lines, lineno),
                        suggested_fix=get_suggested_fix("CWE-89", "python"),
                        owasp_category="A03:2021-Injection"
                    ))
                # Passing a variable previously constructed via dynamic SQL
                elif isinstance(first_arg, ast.Name) and first_arg.id in self.sql_concat_vars:
                    self.findings.append(ScanFinding(
                        file_name=self.file_name,
                        line_number=lineno,
                        language="python",
                        vulnerability_name="SQL Injection",
                        cwe_id="CWE-89",
                        severity="Critical",
                        confidence="High",
                        matched_code=matched_code,
                        code_snippet=extract_code_snippet(self.lines, lineno),
                        suggested_fix=get_suggested_fix("CWE-89", "python"),
                        owasp_category="A03:2021-Injection"
                    ))

        # 2. Command Injection (CWE-78)
        # os.system, os.popen, subprocess.Popen(..., shell=True), subprocess.run/call(..., shell=True)
        if call_name in ["os.system", "os.popen"]:
            matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(...)"
            # Higher confidence if argument is not a constant
            confidence = "High" if node.args and not isinstance(node.args[0], ast.Constant) else "Medium"
            self.findings.append(ScanFinding(
                file_name=self.file_name,
                line_number=lineno,
                language="python",
                vulnerability_name="Command Injection",
                cwe_id="CWE-78",
                severity="Critical",
                confidence=confidence,
                matched_code=matched_code,
                code_snippet=extract_code_snippet(self.lines, lineno),
                suggested_fix=get_suggested_fix("CWE-78", "python"),
                owasp_category="A03:2021-Injection"
            ))
        elif call_name.startswith("subprocess."):
            # Check for shell=True
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_shell_true = True
                    break
            if has_shell_true:
                matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(..., shell=True)"
                self.findings.append(ScanFinding(
                    file_name=self.file_name,
                    line_number=lineno,
                    language="python",
                    vulnerability_name="Command Injection",
                    cwe_id="CWE-78",
                    severity="Critical",
                    confidence="High",
                    matched_code=matched_code,
                    code_snippet=extract_code_snippet(self.lines, lineno),
                    suggested_fix=get_suggested_fix("CWE-78", "python"),
                    owasp_category="A03:2021-Injection"
                ))

        # 3. Insecure Deserialization (CWE-502)
        # pickle.loads, pickle.load, _pickle.loads, yaml.load without SafeLoader
        if call_name in ["pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"]:
            matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(...)"
            self.findings.append(ScanFinding(
                file_name=self.file_name,
                line_number=lineno,
                language="python",
                vulnerability_name="Deserialization of Untrusted Data",
                cwe_id="CWE-502",
                severity="Critical",
                confidence="High",
                matched_code=matched_code,
                code_snippet=extract_code_snippet(self.lines, lineno),
                suggested_fix=get_suggested_fix("CWE-502", "python"),
                owasp_category="A08:2021-Software and Data Integrity Failures"
            ))
        elif call_name == "yaml.load":
            # Check if Loader is specified and safe
            is_unsafe_yaml = True
            for kw in node.keywords:
                if kw.arg == "Loader":
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr in ["SafeLoader", "CSafeLoader"]:
                        is_unsafe_yaml = False
            if is_unsafe_yaml:
                matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else "yaml.load(...)"
                self.findings.append(ScanFinding(
                    file_name=self.file_name,
                    line_number=lineno,
                    language="python",
                    vulnerability_name="Deserialization of Untrusted Data",
                    cwe_id="CWE-502",
                    severity="High",
                    confidence="High",
                    matched_code=matched_code,
                    code_snippet=extract_code_snippet(self.lines, lineno),
                    suggested_fix=get_suggested_fix("CWE-502", "python"),
                    owasp_category="A08:2021-Software and Data Integrity Failures"
                ))

        # 4. Weak Cryptography (CWE-327)
        # hashlib.md5, hashlib.sha1
        if call_name in ["hashlib.md5", "hashlib.sha1"]:
            matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(...)"
            self.findings.append(ScanFinding(
                file_name=self.file_name,
                line_number=lineno,
                language="python",
                vulnerability_name="Weak Cryptographic Hashing",
                cwe_id="CWE-327",
                severity="High",
                confidence="High",
                matched_code=matched_code,
                code_snippet=extract_code_snippet(self.lines, lineno),
                suggested_fix=get_suggested_fix("CWE-327", "python"),
                owasp_category="A02:2021-Cryptographic Failures"
            ))

        # 5. Path Traversal (CWE-22)
        # open(...) or os.remove/os.unlink with concatenated/f-string path
        if call_name in ["open", "os.remove", "os.unlink"]:
            if node.args and self._is_dynamic_string(node.args[0]):
                matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(...)"
                self.findings.append(ScanFinding(
                    file_name=self.file_name,
                    line_number=lineno,
                    language="python",
                    vulnerability_name="Path Traversal",
                    cwe_id="CWE-22",
                    severity="High",
                    confidence="Medium",
                    matched_code=matched_code,
                    code_snippet=extract_code_snippet(self.lines, lineno),
                    suggested_fix=get_suggested_fix("CWE-22", "python"),
                    owasp_category="A01:2021-Broken Access Control"
                ))

        # 6. SSRF (CWE-918)
        # requests.get, requests.post, urllib.request.urlopen with dynamic argument
        if call_name in [
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "urllib.request.urlopen", "httpx.get", "httpx.post"
        ]:
            if node.args and not isinstance(node.args[0], ast.Constant):
                matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(...)"
                self.findings.append(ScanFinding(
                    file_name=self.file_name,
                    line_number=lineno,
                    language="python",
                    vulnerability_name="Server-Side Request Forgery (SSRF)",
                    cwe_id="CWE-918",
                    severity="Critical",
                    confidence="Medium",
                    matched_code=matched_code,
                    code_snippet=extract_code_snippet(self.lines, lineno),
                    suggested_fix=get_suggested_fix("CWE-918", "python"),
                    owasp_category="A10:2021-Server-Side Request Forgery"
                ))

        # 7. Insecure Randomness (CWE-330)
        # random.random, random.randint, random.choice
        if call_name in ["random.random", "random.randint", "random.choice", "random.sample", "random.randrange"]:
            matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(...)"
            # Check context: if line has words like token, secret, auth, key, password
            line_text = self.lines[lineno - 1].lower() if lineno <= len(self.lines) else ""
            if any(term in line_text for term in ["token", "secret", "auth", "key", "pwd", "password", "session", "otp"]):
                self.findings.append(ScanFinding(
                    file_name=self.file_name,
                    line_number=lineno,
                    language="python",
                    vulnerability_name="Insecure Randomness / PRNG",
                    cwe_id="CWE-330",
                    severity="Medium",
                    confidence="High",
                    matched_code=matched_code,
                    code_snippet=extract_code_snippet(self.lines, lineno),
                    suggested_fix=get_suggested_fix("CWE-330", "python"),
                    owasp_category="A02:2021-Cryptographic Failures"
                ))

        # 8. Debug Configuration (CWE-489)
        # app.run(debug=True)
        if call_name.endswith(".run") or call_name == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    matched_code = self.lines[lineno - 1].strip() if lineno <= len(self.lines) else f"{call_name}(debug=True)"
                    self.findings.append(ScanFinding(
                        file_name=self.file_name,
                        line_number=lineno,
                        language="python",
                        vulnerability_name="Active Debug Code / Debug Configuration",
                        cwe_id="CWE-489",
                        severity="Medium",
                        confidence="High",
                        matched_code=matched_code,
                        code_snippet=extract_code_snippet(self.lines, lineno),
                        suggested_fix=get_suggested_fix("CWE-489", "python"),
                        owasp_category="A05:2021-Security Misconfiguration"
                    ))

        self.generic_visit(node)


def scan_python_code(file_path: str, content: str) -> List[ScanFinding]:
    """
    Parses Python source using ast, walks nodes for security rules,
    and applies regex heuristics for hardcoded secrets.
    """
    findings: List[ScanFinding] = []
    lines = content.splitlines(keepends=True)

    # 1. AST Analysis
    try:
        tree = ast.parse(content, filename=file_path)
        visitor = PythonASTVisitor(file_path, lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError as se:
        # If syntax error, still scan with line-by-line fallback
        pass
    except Exception as e:
        pass

    # 2. Hardcoded Secrets Heuristics
    seen_lines: Set[int] = {f.line_number for f in findings if f.cwe_id == "CWE-798"}
    for idx, line in enumerate(lines):
        line_num = idx + 1
        if line_num in seen_lines:
            continue

        stripped = line.strip()
        # Skip comments
        if stripped.startswith("#"):
            continue

        for pattern, desc, confidence in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                matched_val = match.group(1) if match.groups() else match.group(0)
                if not is_placeholder(matched_val):
                    findings.append(ScanFinding(
                        file_name=file_path,
                        line_number=line_num,
                        language="python",
                        vulnerability_name="Hardcoded Credentials",
                        cwe_id="CWE-798",
                        severity="High",
                        confidence=confidence,
                        matched_code=stripped,
                        code_snippet=extract_code_snippet(lines, line_num),
                        suggested_fix=get_suggested_fix("CWE-798", "python"),
                        owasp_category="A07:2021-Identification and Authentication Failures"
                    ))
                    seen_lines.add(line_num)
                    break

    return findings
