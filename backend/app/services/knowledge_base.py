from sqlalchemy.orm import Session
from app.models.knowledge_base import KnowledgeBaseItem
from app.schemas.knowledge_base import KnowledgeBaseItemCreate

def get_item_by_cwe(db: Session, cwe_id: str):
    return db.query(KnowledgeBaseItem).filter(KnowledgeBaseItem.cwe_id.iexact(cwe_id.strip())).first()

def get_all_items(db: Session):
    return db.query(KnowledgeBaseItem).all()

def seed_knowledge_base(db: Session):
    # Check if we already have items
    if db.query(KnowledgeBaseItem).count() > 0:
        return
        
    items = [
        {
            "cwe_id": "CWE-79",
            "vulnerability_name": "Cross-Site Scripting (XSS)",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-63",
            "description": "The application does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            "recommendations": "1. Use context-aware output encoding (e.g., HTML entity encoding, JavaScript escaping).\n2. Implement a strict Content Security Policy (CSP) with nonce-based or hash-based scripts.\n3. Utilize modern frontend frameworks (such as React or Angular) which perform automatic XSS protection.\n4. Sanitize rich HTML user inputs using a robust library like DOMPurify."
        },
        {
            "cwe_id": "CWE-89",
            "vulnerability_name": "SQL Injection (SQLi)",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-66",
            "description": "The software constructs all or part of an SQL command using externally-influenced input, allowing attackers to alter the SQL statement execution logic.",
            "recommendations": "1. Always use parameterized queries or prepared statements (using ORMs like SQLAlchemy or Hibernate).\n2. Apply the Principle of Least Privilege to database connection credentials.\n3. Perform strict validation against an allowlist for any dynamic SQL queries (e.g., column names or table names).\n4. Evade executing raw queries directly from input inputs."
        },
        {
            "cwe_id": "CWE-22",
            "vulnerability_name": "Path Traversal (Directory Traversal)",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-126",
            "description": "The application uses external input to construct a pathname that is intended to identify a file or directory located under a restricted directory, but the input is not properly neutralized.",
            "recommendations": "1. Avoid passing file paths directly from user inputs to file system APIs.\n2. Use a hardcoded map of allowed files or reference keys instead of file paths.\n3. Use `os.path.basename` to extract the file name and append it to a safe base directory.\n4. Validate that the resolved canonical path remains within the intended target directory."
        },
        {
            "cwe_id": "CWE-352",
            "vulnerability_name": "Cross-Site Request Forgery (CSRF)",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-62",
            "description": "The web application does not sufficiently verify whether a request was initiated by the user who owns the active session, allowing attackers to make state-changing requests.",
            "recommendations": "1. Implement Anti-CSRF double-submit cookies or unique request tokens (CSRF Tokens).\n2. Utilize modern cookie flags: set `SameSite=Strict` or `SameSite=Lax` and `Secure` on session cookies.\n3. Ensure GET requests are idempotent and do not perform state-changing operations.\n4. Implement re-authentication for sensitive actions (like password changes)."
        },
        {
            "cwe_id": "CWE-502",
            "vulnerability_name": "Deserialization of Untrusted Data",
            "owasp_category": "A08:2021-Software and Data Integrity Failures",
            "capec_id": "CAPEC-586",
            "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, leading to remote code execution (RCE) or denial of service.",
            "recommendations": "1. Avoid using unsafe serialization formats like Python's `pickle` or `marshal` with user input.\n2. Use safer, standard formats like JSON or Protocol Buffers for data exchange.\n3. If Python pickle is required, restrict/verify the types using custom Unpickler classes or verify digital signatures (HMAC) of the payload before deserialization."
        },
        {
            "cwe_id": "CWE-200",
            "vulnerability_name": "Exposure of Sensitive Information",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-13",
            "description": "The application exposes sensitive information to unauthorized users, such as system configurations, error details, internal code details, or database logs.",
            "recommendations": "1. Turn off detailed error responses, stack traces, and debug modes in production environments.\n2. Standardize error message handling and return general statements to users (e.g. 'Internal Server Error').\n3. Protect sensitive endpoints with authentication checks.\n4. Implement proper access control filters on API schema outputs."
        },
        {
            "cwe_id": "CWE-798",
            "vulnerability_name": "Use of Hard-coded Credentials",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "capec_id": "CAPEC-16",
            "description": "The application contains hardcoded credentials, such as passwords, API keys, or private keys, inside the source code, which can be extracted by attackers.",
            "recommendations": "1. Extract all secrets and credentials to environment variables or local configuration files excluded from source control.\n2. Implement a secure secrets manager (like HashiCorp Vault, AWS Secrets Manager, or Google Secret Manager).\n3. Rotate credentials regularly.\n4. Run automated secret scanner checks in continuous integration pipelines."
        },
        {
            "cwe_id": "CWE-287",
            "vulnerability_name": "Improper Authentication",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "capec_id": "CAPEC-115",
            "description": "The application does not properly authenticate a user, allowing attackers to access functions or data reserved for specific roles.",
            "recommendations": "1. Implement multi-factor authentication (MFA) for administrative and sensitive accounts.\n2. Use established, verified authentication frameworks instead of implementing custom authentication logic.\n3. Secure session IDs and JWT tokens by implementing short timeouts, strict HTTPS, and secure cookies.\n4. Enforce strong password complexity rules."
        },
        {
            "cwe_id": "CWE-862",
            "vulnerability_name": "Missing Authorization (BOLA/IDOR)",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-180",
            "description": "The software does not perform authorization checks when an actor attempts to access a resource or execute an action, leading to data exposure or unauthorized actions.",
            "recommendations": "1. Implement server-side check validations for every request to verify the requesting user owns or is authorized to view the resource.\n2. Adopt a Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) design.\n3. Use non-sequential, randomly generated identifiers (UUIDs) for database rows to restrict guessing attacks.\n4. Deny access by default."
        }
    ]
    
    for item in items:
        db_item = KnowledgeBaseItem(**item)
        db.add(db_item)
    db.commit()
    print("Knowledge base seeded successfully!")
