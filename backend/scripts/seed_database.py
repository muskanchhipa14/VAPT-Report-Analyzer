from app.core.database import SessionLocal
from app.models.knowledge_base import KnowledgeBase

db = SessionLocal()

vulnerabilities = [

    {
        "cwe_id": "CWE-79",
        "vulnerability_name": "Cross Site Scripting (XSS)",
        "severity": "High",
        "description": "Application reflects unsanitized user input.",
        "remediation": "Escape output and validate user input.",
        "references": "https://cwe.mitre.org/data/definitions/79.html"
    },

    {
        "cwe_id": "CWE-89",
        "vulnerability_name": "SQL Injection",
        "severity": "Critical",
        "description": "User input is directly concatenated into SQL queries.",
        "remediation": "Use parameterized queries.",
        "references": "https://cwe.mitre.org/data/definitions/89.html"
    },

    {
        "cwe_id": "CWE-22",
        "vulnerability_name": "Path Traversal",
        "severity": "High",
        "description": "Allows access to files outside intended directory.",
        "remediation": "Validate file paths.",
        "references": "https://cwe.mitre.org/data/definitions/22.html"
    },

    {
        "cwe_id": "CWE-352",
        "vulnerability_name": "Cross Site Request Forgery",
        "severity": "Medium",
        "description": "Unauthorised actions performed on behalf of users.",
        "remediation": "Implement CSRF tokens.",
        "references": "https://cwe.mitre.org/data/definitions/352.html"
    },

    {
        "cwe_id": "CWE-434",
        "vulnerability_name": "Unrestricted File Upload",
        "severity": "Critical",
        "description": "Attackers can upload malicious files.",
        "remediation": "Validate extensions and MIME types.",
        "references": "https://cwe.mitre.org/data/definitions/434.html"
    },

    {
        "cwe_id": "CWE-287",
        "vulnerability_name": "Improper Authentication",
        "severity": "Critical",
        "description": "Weak authentication mechanism.",
        "remediation": "Use strong authentication and MFA.",
        "references": "https://cwe.mitre.org/data/definitions/287.html"
    },

    {
        "cwe_id": "CWE-306",
        "vulnerability_name": "Missing Authentication",
        "severity": "High",
        "description": "Sensitive functionality lacks authentication.",
        "remediation": "Require authentication before access.",
        "references": "https://cwe.mitre.org/data/definitions/306.html"
    },

    {
        "cwe_id": "CWE-200",
        "vulnerability_name": "Information Exposure",
        "severity": "Medium",
        "description": "Sensitive information is exposed.",
        "remediation": "Restrict confidential data exposure.",
        "references": "https://cwe.mitre.org/data/definitions/200.html"
    },

    {
        "cwe_id": "CWE-611",
        "vulnerability_name": "XML External Entity",
        "severity": "High",
        "description": "XML parser processes external entities.",
        "remediation": "Disable external entities.",
        "references": "https://cwe.mitre.org/data/definitions/611.html"
    },

    {
        "cwe_id": "CWE-918",
        "vulnerability_name": "Server Side Request Forgery",
        "severity": "Critical",
        "description": "Server can be forced to access internal resources.",
        "remediation": "Validate outbound requests.",
        "references": "https://cwe.mitre.org/data/definitions/918.html"
    }

]

added = 0

for item in vulnerabilities:

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

print(f"{added} vulnerabilities inserted successfully.")