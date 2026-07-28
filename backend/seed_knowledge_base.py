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
        "vulnerability_name": "Cross-Site Request Forgery (CSRF)",
        "cwe_id": "CWE-352",
        "severity": "Medium",
        "description": "CSRF tricks authenticated users into performing unintended actions on a web application.",
        "remediation": "Implement CSRF tokens, SameSite cookies, and verify the Origin or Referer headers."
    },
    {
        "vulnerability_name": "Command Injection",
        "cwe_id": "CWE-77",
        "severity": "Critical",
        "description": "Command Injection allows attackers to execute arbitrary operating system commands on the server.",
        "remediation": "Avoid shell execution, validate inputs, and use safe APIs instead of system commands."
    },
    {
        "vulnerability_name": "Path Traversal",
        "cwe_id": "CWE-22",
        "severity": "High",
        "description": "Path Traversal allows attackers to access files and directories outside the intended application directory.",
        "remediation": "Validate file paths, restrict file access, and use allowlists."
    },
    {
        "vulnerability_name": "Broken Authentication",
        "cwe_id": "CWE-287",
        "severity": "Critical",
        "description": "Improper authentication mechanisms allow attackers to compromise user accounts.",
        "remediation": "Implement MFA, strong password policies, secure session management, and account lockout mechanisms."
    },
    {
        "vulnerability_name": "Insecure Direct Object Reference (IDOR)",
        "cwe_id": "CWE-639",
        "severity": "High",
        "description": "IDOR occurs when users can access resources belonging to other users by modifying object identifiers.",
        "remediation": "Perform server-side authorization checks for every request."
    },
    {
        "vulnerability_name": "Security Misconfiguration",
        "cwe_id": "CWE-16",
        "severity": "Medium",
        "description": "Default configurations, unnecessary services, and exposed error messages increase security risks.",
        "remediation": "Harden systems, disable unnecessary services, and apply secure default configurations."
    },
    {
        "vulnerability_name": "Sensitive Data Exposure",
        "cwe_id": "CWE-200",
        "severity": "High",
        "description": "Sensitive information is exposed due to insufficient protection during storage or transmission.",
        "remediation": "Encrypt sensitive data, use HTTPS, and avoid storing unnecessary confidential information."
    },
    {
        "vulnerability_name": "XML External Entity (XXE)",
        "cwe_id": "CWE-611",
        "severity": "High",
        "description": "XXE allows attackers to exploit XML parsers to access local files or perform server-side request forgery.",
        "remediation": "Disable external entity processing and use secure XML parser configurations."
    }
]

added = 0

for item in knowledge_base_entries:
    existing = (
        db.query(KnowledgeBase)
        .filter(KnowledgeBase.cwe_id == item["cwe_id"])
        .first()
    )

    if not existing:
        db.add(KnowledgeBase(**item))
        added += 1

db.commit()
db.close()

print(f"Knowledge Base seeded successfully! Added {added} new entries.")