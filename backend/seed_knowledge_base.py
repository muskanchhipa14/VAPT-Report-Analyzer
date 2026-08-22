from app.core.database import SessionLocal
from app.models.knowledge_base import KnowledgeBase

db = SessionLocal()

knowledge_base_entries = [
    {
        "vulnerability_name": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "High",
        "description": "SQL Injection allows attackers to manipulate database queries by injecting malicious SQL statements through user inputs.",
        "remediation": "Use parameterized queries, prepared statements, input validation, and least privilege database accounts."
    },
    {
        "vulnerability_name": "Cross-Site Scripting (XSS)",
        "cwe_id": "CWE-79",
        "severity": "High",
        "description": "XSS allows attackers to inject malicious JavaScript into web pages viewed by other users.",
        "remediation": "Validate inputs, encode outputs, use Content Security Policy (CSP), and sanitize user-generated content."
    },
    {
        "vulnerability_name": "Buffer Overflow",
        "cwe_id": "CWE-120",
        "severity": "Critical",
        "description": "Buffer Overflow occurs when a program writes more data to a buffer than it can hold, leading to memory corruption or arbitrary code execution.",
        "remediation": "Use safe library functions (e.g., strlcpy instead of strcpy), perform strict bounds checks, and use modern memory-safe languages."
    },
    {
        "vulnerability_name": "Hardcoded Credentials",
        "cwe_id": "CWE-798",
        "severity": "High",
        "description": "Hardcoded Credentials refers to the practice of embedding passwords, keys, or tokens directly in source code.",
        "remediation": "Use environment variables, secret vaults (like HashiCorp Vault), or configuration files stored securely outside the source tree."
    },
    {
        "vulnerability_name": "Path Traversal",
        "cwe_id": "CWE-22",
        "severity": "High",
        "description": "Path Traversal allows attackers to access files and directories outside the intended application directory.",
        "remediation": "Validate file paths, restrict file access, and use allowlists."
    },
    {
        "vulnerability_name": "Insecure Direct Object Reference (IDOR)",
        "cwe_id": "CWE-639",
        "severity": "High",
        "description": "IDOR occurs when users can access resources belonging to other users by modifying object identifiers.",
        "remediation": "Perform server-side authorization checks for every request."
    },
    {
        "vulnerability_name": "Missing Authentication",
        "cwe_id": "CWE-306",
        "severity": "Critical",
        "description": "Missing Authentication for Critical Function occurs when the application does not verify the identity of the user before performing a sensitive function.",
        "remediation": "Implement strict authentication checks for all administrative and user endpoints."
    },
    {
        "vulnerability_name": "Weak Password Policy",
        "cwe_id": "CWE-521",
        "severity": "Medium",
        "description": "Weak Password Policy allows users to create easily guessable or simple passwords, exposing them to brute force attacks.",
        "remediation": "Enforce password complexity rules, minimum length (e.g., 12 characters), and check passwords against lists of breached credentials."
    },
    {
        "vulnerability_name": "Information Exposure",
        "cwe_id": "CWE-200",
        "severity": "Medium",
        "description": "Information Exposure allows attackers to gain insights about system internals, configuration, or user data from verbose logs or error messages.",
        "remediation": "Disable detailed error messages in production, use generic error messages, and restrict log file access."
    },
    {
        "vulnerability_name": "Missing Security Headers",
        "cwe_id": "CWE-693",
        "severity": "Low",
        "description": "Missing Security Headers (like HSTS, CSP, X-Frame-Options, or X-Content-Type-Options) exposes the application to attacks like clickjacking and content sniffing.",
        "remediation": "Configure the web server (Nginx, Apache) or FastAPI middleware to include security headers on all responses."
    }
]

added = 0
updated = 0

for item in knowledge_base_entries:
    existing = (
        db.query(KnowledgeBase)
        .filter(KnowledgeBase.cwe_id == item["cwe_id"])
        .first()
    )

    if not existing:
        db.add(KnowledgeBase(**item))
        added += 1
    else:
        existing.vulnerability_name = item["vulnerability_name"]
        existing.severity = item["severity"]
        existing.description = item["description"]
        existing.remediation = item["remediation"]
        updated += 1

db.commit()
db.close()

print(f"Knowledge Base seeded successfully! Added {added} and updated {updated} entries.")