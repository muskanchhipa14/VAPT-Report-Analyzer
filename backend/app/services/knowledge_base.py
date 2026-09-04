from sqlalchemy.orm import Session
from app.models.knowledge_base import KnowledgeBaseItem

def get_item_by_cwe(db: Session, cwe_id: str):
    if not cwe_id:
        return None
    return db.query(KnowledgeBaseItem).filter(KnowledgeBaseItem.cwe_id.ilike(cwe_id.strip())).first()

def get_all_items(db: Session):
    return db.query(KnowledgeBaseItem).all()

def seed_knowledge_base(db: Session):
    items = [
        {
            "cwe_id": "CWE-89",
            "vulnerability_name": "SQL Injection",
            "severity": "High",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-66",
            "description": "SQL Injection allows attackers to manipulate database queries by injecting malicious SQL statements through user inputs.",
            "remediation": "Use parameterized queries, prepared statements (using ORMs like SQLAlchemy), input validation, and least privilege database accounts.",
            "recommendations": "1. Use parameterized queries and prepared statements.\n2. Apply the Principle of Least Privilege to database connection credentials.\n3. Perform strict validation against an allowlist for dynamic query components.\n4. Avoid executing raw queries built from untrusted inputs."
        },
        {
            "cwe_id": "CWE-79",
            "vulnerability_name": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-63",
            "description": "XSS allows attackers to inject malicious JavaScript into web pages viewed by other users.",
            "remediation": "Validate inputs, encode outputs, use Content Security Policy (CSP), and sanitize user-generated content.",
            "recommendations": "1. Use context-aware output encoding (HTML entity encoding, JS escaping).\n2. Implement a strict Content Security Policy (CSP) with nonce-based or hash-based scripts.\n3. Utilize modern frontend frameworks (React, Angular) that auto-escape output.\n4. Sanitize rich HTML user inputs using a robust library like DOMPurify."
        },
        {
            "cwe_id": "CWE-120",
            "vulnerability_name": "Buffer Overflow",
            "severity": "Critical",
            "owasp_category": "A06:2021-Vulnerable and Outdated Components",
            "capec_id": "CAPEC-100",
            "description": "Buffer Overflow occurs when a program writes more data to a buffer than it can hold, leading to memory corruption or arbitrary code execution.",
            "remediation": "Use safe library functions (e.g., strlcpy instead of strcpy), perform strict bounds checks, and use modern memory-safe languages.",
            "recommendations": "1. Replace unsafe functions with safe alternatives that mandate explicit size bounds.\n2. Perform strict bounds checking on inputs prior to copying to fixed-size buffers.\n3. Enable compiler flags like Stack Smashing Protector (-fstack-protector) and ASLR/DEP.\n4. Prefer memory-safe languages for performance-critical logic."
        },
        {
            "cwe_id": "CWE-798",
            "vulnerability_name": "Hardcoded Credentials",
            "severity": "High",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "capec_id": "CAPEC-16",
            "description": "Hardcoded Credentials refers to embedding passwords, secret keys, or tokens directly in source code.",
            "remediation": "Use environment variables, secret vaults (like HashiCorp Vault), or configuration files stored securely outside the source tree.",
            "recommendations": "1. Extract all secrets and credentials to environment variables or secret vaults.\n2. Use secure secrets management services (AWS Secrets Manager, HashiCorp Vault).\n3. Rotate credentials and API keys regularly.\n4. Run automated secret scanner tools in CI/CD pipelines."
        },
        {
            "cwe_id": "CWE-22",
            "vulnerability_name": "Path Traversal",
            "severity": "High",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-126",
            "description": "Path Traversal allows attackers to access files and directories outside the intended application directory.",
            "remediation": "Validate file paths, restrict file access, and use allowlists or canonical path verification.",
            "recommendations": "1. Avoid passing user-supplied file paths directly to file system APIs.\n2. Use a hardcoded map or allowlist of permitted file keys.\n3. Sanitize inputs using os.path.basename and verify resolved canonical paths remain in the target directory."
        },
        {
            "cwe_id": "CWE-639",
            "vulnerability_name": "Insecure Direct Object Reference (IDOR)",
            "severity": "High",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-180",
            "description": "IDOR occurs when users can access or modify resources belonging to other users by changing object identifiers.",
            "remediation": "Perform strict server-side authorization checks for every request before fulfilling resource access.",
            "recommendations": "1. Enforce server-side authorization checks verifying user ownership.\n2. Implement Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC).\n3. Use cryptographically secure random identifiers (UUIDs) for database objects.\n4. Deny resource access by default."
        },
        {
            "cwe_id": "CWE-306",
            "vulnerability_name": "Missing Authentication",
            "severity": "Critical",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "capec_id": "CAPEC-115",
            "description": "Missing Authentication for Critical Function occurs when the application fails to verify user identity before executing a sensitive action.",
            "remediation": "Implement strict authentication middleware and checks for all administrative and sensitive endpoints.",
            "recommendations": "1. Enforce mandatory authentication middleware across all protected routes.\n2. Implement Multi-Factor Authentication (MFA) for administrative access.\n3. Ensure short session timeouts and secure cookie flags."
        },
        {
            "cwe_id": "CWE-521",
            "vulnerability_name": "Weak Password Policy",
            "severity": "Medium",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "capec_id": "CAPEC-56",
            "description": "Weak Password Policy allows easily guessable passwords, exposing accounts to dictionary and brute-force attacks.",
            "remediation": "Enforce password complexity rules, minimum length (e.g. 12+ characters), and check passwords against breached database lists.",
            "recommendations": "1. Require minimum password length of 12+ characters.\n2. Screen new passwords against haveibeenpwned breach lists.\n3. Implement rate limiting and lockout mechanisms on login endpoints."
        },
        {
            "cwe_id": "CWE-200",
            "vulnerability_name": "Information Exposure",
            "severity": "Medium",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-13",
            "description": "Information Exposure allows attackers to gain insights about system internals, configurations, or data from verbose logs or error messages.",
            "remediation": "Disable detailed error messages in production, use generic error responses, and restrict access to log files.",
            "recommendations": "1. Disable detailed stack traces and debug flags in production.\n2. Return generic user-facing error messages.\n3. Restrict log file permissions and strip sensitive tokens from logs."
        },
        {
            "cwe_id": "CWE-693",
            "vulnerability_name": "Missing Security Headers",
            "severity": "Low",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-222",
            "description": "Missing Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) exposes the web application to clickjacking and content sniffing.",
            "remediation": "Configure web server or middleware to add security headers (Strict-Transport-Security, X-Frame-Options, Content-Security-Policy) on all HTTP responses.",
            "recommendations": "1. Add Content-Security-Policy header to control allowed script/style resources.\n2. Set Strict-Transport-Security (HSTS) with long max-age.\n3. Include X-Frame-Options: DENY and X-Content-Type-Options: nosniff headers."
        },
        {
            "cwe_id": "CWE-918",
            "vulnerability_name": "Server-Side Request Forgery (SSRF)",
            "severity": "Critical",
            "owasp_category": "A10:2021-Server-Side Request Forgery",
            "capec_id": "CAPEC-664",
            "description": "SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to force the server to issue requests to internal systems.",
            "remediation": "Validate and sanitize all user-supplied URLs against an allowlist, disable HTTP redirections, and restrict outbound requests to internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
            "recommendations": "1. Validate URL schemas (allow only https://) and enforce domain allowlists.\n2. Block requests targeting private, loopback, or metadata IP ranges.\n3. Segment internal services using network firewalls."
        },
        {
            "cwe_id": "CWE-611",
            "vulnerability_name": "XML External Entity (XXE) Injection",
            "severity": "High",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-228",
            "description": "XXE occurs when weakly configured XML parsers process user-supplied XML input containing references to external entities, enabling SSRF or file disclosure.",
            "remediation": "Disable DTDs (External Entity Resolution) in XML parsers across all application components.",
            "recommendations": "1. Disable DTD processing entirely in XML parsers (e.g. defusedxml in Python).\n2. Use less complex data formats such as JSON where possible.\n3. Patch XML parsing libraries to the latest secure release."
        },
        {
            "cwe_id": "CWE-78",
            "vulnerability_name": "Command Injection",
            "severity": "Critical",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-88",
            "description": "Command Injection allows attackers to execute arbitrary shell commands on the host operating system by passing unvalidated input to system execution functions.",
            "remediation": "Avoid invoking shell interpreters directly (e.g., shell=True in Python). Use parameterized APIs or built-in library functions instead.",
            "recommendations": "1. Use built-in programming APIs instead of launching system shell commands.\n2. If system calls are mandatory, pass arguments as fixed arrays without shell interpretation.\n3. Sanitize and validate inputs against strict allowlists."
        },
        {
            "cwe_id": "CWE-352",
            "vulnerability_name": "Cross-Site Request Forgery (CSRF)",
            "severity": "High",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-62",
            "description": "CSRF allows attackers to induce victims to perform unintended state-changing actions on a trusted application where they are currently authenticated.",
            "remediation": "Implement Anti-CSRF double-submit cookies or unique session-bound tokens, and enforce SameSite=Strict on cookies.",
            "recommendations": "1. Implement Anti-CSRF double-submit tokens.\n2. Set SameSite=Strict or SameSite=Lax and Secure flags on session cookies.\n3. Re-authenticate users prior to sensitive actions."
        },
        {
            "cwe_id": "CWE-502",
            "vulnerability_name": "Deserialization of Untrusted Data",
            "severity": "Critical",
            "owasp_category": "A08:2021-Software and Data Integrity Failures",
            "capec_id": "CAPEC-586",
            "description": "Insecure Deserialization occurs when untrusted data is deserialized without verification, leading to arbitrary remote code execution.",
            "remediation": "Avoid using native serialization formats (e.g., Python pickle, Java native serialization). Use safe formats like JSON or Protocol Buffers.",
            "recommendations": "1. Do not accept native serialized objects from untrusted sources.\n2. Use standard JSON schema validation.\n3. Sign serialized data with cryptographic HMAC tokens if native formats cannot be avoided."
        },
        {
            "cwe_id": "CWE-601",
            "vulnerability_name": "Open Redirect",
            "severity": "Medium",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-383",
            "description": "Open Redirect occurs when an application accepts a user-controlled URL in a redirect parameter, enabling phishing attacks.",
            "remediation": "Validate target redirect URLs against an allowlist of relative paths or approved external domains.",
            "recommendations": "1. Force all redirects to use relative paths (e.g. starting with a single slash /).\n2. Maintain a strict allowlist for external target URLs.\n3. Display an intermediate confirmation page when redirecting externally."
        },
        {
            "cwe_id": "CWE-942",
            "vulnerability_name": "CORS Misconfiguration",
            "severity": "Medium",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-587",
            "description": "Wildcard or overly permissive Access-Control-Allow-Origin headers allow malicious websites to read sensitive API responses.",
            "remediation": "Do not reflect origin headers dynamically or set Access-Control-Allow-Origin: * on authenticated API endpoints.",
            "recommendations": "1. Restrict CORS origins to trusted, explicit domains.\n2. Avoid Access-Control-Allow-Credentials: true with wildcard origins.\n3. Regularly audit API CORS configuration headers."
        },
        {
            "cwe_id": "CWE-434",
            "vulnerability_name": "Unrestricted File Upload",
            "severity": "Critical",
            "owasp_category": "A04:2021-Insecure Design",
            "capec_id": "CAPEC-650",
            "description": "Allowing users to upload files without validating extension, MIME type, or location can lead to web shell deployment and server compromise.",
            "remediation": "Validate file extension against allowlists, re-encode uploaded media files, store uploads outside web root, and execute static analysis.",
            "recommendations": "1. Enforce strict file extension allowlists (e.g., .pdf, .png).\n2. Randomize file names upon upload.\n3. Store uploaded files outside the public web server document root."
        },
        {
            "cwe_id": "CWE-384",
            "vulnerability_name": "Broken Session Management",
            "severity": "High",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "capec_id": "CAPEC-61",
            "description": "Session Fixation or weak session management allows attackers to hijack or reuse valid session tokens.",
            "remediation": "Regenerate session identifiers upon user authentication and invalidate tokens on logout.",
            "recommendations": "1. Issue fresh session tokens immediately after successful login.\n2. Set short idle timeouts on active sessions.\n3. Store session keys exclusively in HttpOnly, Secure cookies."
        },
        {
            "cwe_id": "CWE-319",
            "vulnerability_name": "Cleartext Transmission of Sensitive Information",
            "severity": "Medium",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "capec_id": "CAPEC-94",
            "description": "Transmitting passwords or tokens over unencrypted HTTP channels enables eavesdropping and man-in-the-middle attacks.",
            "remediation": "Enforce HTTPS with TLS 1.3 across all endpoints and configure HSTS header with max-age=31536000.",
            "recommendations": "1. Redirect all HTTP traffic automatically to HTTPS.\n2. Enable HTTP Strict Transport Security (HSTS).\n3. Disable legacy TLS 1.0 and 1.1 protocol versions."
        },
        {
            "cwe_id": "CWE-90",
            "vulnerability_name": "LDAP Injection",
            "severity": "High",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-136",
            "description": "LDAP Injection allows attackers to alter LDAP queries issued to directory servers by injecting control characters.",
            "remediation": "Escape user inputs using LDAP encoding functions before embedding them into filter expressions.",
            "recommendations": "1. Escape special LDAP characters (e.g. *, (, ), \\, NUL).\n2. Use parameterized LDAP search functions.\n3. Bind to LDAP with minimal necessary permissions."
        },
        {
            "cwe_id": "CWE-1021",
            "vulnerability_name": "Clickjacking",
            "severity": "Low",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-222",
            "description": "Clickjacking tricks users into clicking transparent iframe elements layered over legitimate UI controls.",
            "remediation": "Send X-Frame-Options: DENY header and frame-ancestors 'none' Content-Security-Policy directive.",
            "recommendations": "1. Add Content-Security-Policy: frame-ancestors 'none'.\n2. Configure X-Frame-Options: DENY or SAMEORIGIN.\n3. Test iframe embedding protections."
        },
        {
            "cwe_id": "CWE-20",
            "vulnerability_name": "Improper Input Validation",
            "severity": "Medium",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-153",
            "description": "Failing to validate format, length, or data type of incoming requests allows unexpected payloads to cause application errors or injection.",
            "remediation": "Enforce schema validation (e.g. Pydantic models) for all API payloads and query parameters.",
            "recommendations": "1. Validate inputs using strict allowlist schemas.\n2. Reject malformed payloads early at API entry points.\n3. Enforce string length limits and numerical ranges."
        },
        {
            "cwe_id": "CWE-1104",
            "vulnerability_name": "Vulnerable / Outdated Component",
            "severity": "Medium",
            "owasp_category": "A06:2021-Vulnerable and Outdated Components",
            "capec_id": "CAPEC-310",
            "description": "Using third-party libraries or dependencies with known security vulnerabilities (CVEs) exposes the application to exploits.",
            "remediation": "Maintain software bill of materials (SBOM) and run automated dependency auditing tools (e.g. Safety, Snyk, npm audit).",
            "recommendations": "1. Run automated security vulnerability scanners in CI pipelines.\n2. Keep core framework and packages updated to supported versions.\n3. Remove unused libraries and transitive dependencies."
        },
        {
            "cwe_id": "CWE-532",
            "vulnerability_name": "Sensitive Data Leakage in Logs",
            "severity": "Low",
            "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
            "capec_id": "CAPEC-93",
            "description": "Writing sensitive information (passwords, JWT tokens, credit card numbers) to application logs exposes secrets to unauthorized readers.",
            "remediation": "Filter and scrub sensitive keys from loggers using log masking middleware.",
            "recommendations": "1. Redact password, authorization, and token keys from log outputs.\n2. Restrict log file permissions to authorized administrators.\n3. Centralize and encrypt log storage."
        },
        {
            "cwe_id": "CWE-1336",
            "vulnerability_name": "Server-Side Template Injection (SSTI)",
            "severity": "Critical",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-242",
            "description": "SSTI occurs when user input is concatenated directly into template engine engines (Jinja2, Twig, Freemarker) leading to remote code execution.",
            "remediation": "Never concatenate user input directly into template string evaluations. Pass input variables via context objects into sandboxed templates.",
            "recommendations": "1. Pass parameters via context dictionaries rather than string interpolation.\n2. Enable template engine sandbox modes.\n3. Restrict template access to environment objects."
        },
        {
            "cwe_id": "CWE-444",
            "vulnerability_name": "HTTP Request Smuggling",
            "severity": "Critical",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-273",
            "description": "HTTP Request Smuggling occurs when front-end proxies and back-end web servers interpret Content-Length and Transfer-Encoding headers differently.",
            "remediation": "Normalize HTTP requests at reverse proxies, disable Transfer-Encoding obfuscation, and enforce HTTP/2 end-to-end.",
            "recommendations": "1. Use HTTP/2 end-to-end to eliminate ambiguity.\n2. Normalize Content-Length and Transfer-Encoding headers on front-end reverse proxies.\n3. Reject ambiguous requests containing both headers."
        },
        {
            "cwe_id": "CWE-915",
            "vulnerability_name": "Mass Assignment",
            "severity": "High",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-60",
            "description": "Mass Assignment occurs when framework object binders automatically map client parameters directly to domain models, allowing attackers to overwrite sensitive fields (e.g., is_admin).",
            "remediation": "Use explicit DTO/schema transfer models with strict field allowlists instead of binding request bodies directly to database ORM models.",
            "recommendations": "1. Bind incoming requests strictly to DTO schemas.\n2. Explicitly specify writable properties on domain models.\n3. Block sensitive control attributes from mass binding."
        },
        {
            "cwe_id": "CWE-362",
            "vulnerability_name": "Race Condition / TOCTOU",
            "severity": "High",
            "owasp_category": "A04:2021-Insecure Design",
            "capec_id": "CAPEC-29",
            "description": "Time-of-check to time-of-use (TOCTOU) race conditions occur when a resource state changes between checking condition and executing operation.",
            "remediation": "Use database row-level locking (SELECT FOR UPDATE) or atomic transactions to enforce concurrency isolation.",
            "recommendations": "1. Use atomic database operations and row locking.\n2. Enforce unique constraints at database layer.\n3. Avoid non-atomic check-then-act logic."
        },
        {
            "cwe_id": "CWE-327",
            "vulnerability_name": "Weak Cryptographic Hashing",
            "severity": "High",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "capec_id": "CAPEC-97",
            "description": "Using weak or broken cryptographic algorithms (MD5, SHA1, DES) exposes sensitive data and password hashes to rapid collision and rainbow table cracking.",
            "remediation": "Migrate password hashing to Argon2id or bcrypt with appropriate work factors. Use SHA-256/SHA-3 for message digests.",
            "recommendations": "1. Replace MD5 and SHA1 with Argon2id or bcrypt.\n2. Ensure adequate salt length for hashed values.\n3. Audit cryptographic implementations regularly."
        },
        {
            "cwe_id": "CWE-778",
            "vulnerability_name": "Insufficient Logging & Monitoring",
            "severity": "Medium",
            "owasp_category": "A09:2021-Security Logging & Monitoring Failures",
            "capec_id": "CAPEC-81",
            "description": "Failing to log security-relevant events (failed logins, privilege escalation, access control bypass) prevents detection of active intrusion attempts.",
            "remediation": "Implement comprehensive structured logging for authentication, access control failures, and administrative actions.",
            "recommendations": "1. Log all security events with timestamps and user identifiers.\n2. Establish real-time alerting mechanisms for high-severity audit logs.\n3. Retain logs securely to prevent tampering."
        },
        {
            "cwe_id": "CWE-284",
            "vulnerability_name": "Subdomain Takeover",
            "severity": "High",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-538",
            "description": "Subdomain Takeover occurs when a DNS CNAME record points to a decommissioned external cloud service (AWS S3, GitHub Pages), allowing attackers to claim the domain.",
            "remediation": "Remove dangling DNS records immediately after decommissioning third-party cloud services.",
            "recommendations": "1. Conduct regular external attack surface audits for dangling DNS records.\n2. Automate DNS record removal upon resource deletion.\n3. Verify cloud endpoint ownership prior to pointing CNAME records."
        },
        {
            "cwe_id": "CWE-347",
            "vulnerability_name": "JWT Signature Bypass",
            "severity": "Critical",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "capec_id": "CAPEC-115",
            "description": "Failing to verify JWT signature algorithms (e.g. accepting 'alg': 'none') enables attackers to forge arbitrary user claims and elevate privileges.",
            "remediation": "Enforce explicit JWT signature verification algorithms (e.g., RS256, HS256) and reject tokens with 'none' algorithm.",
            "recommendations": "1. Explicitly restrict accepted JWT algorithms in verification middleware.\n2. Reject unverified tokens.\n3. Rotate JWT signing keys periodically."
        },
        {
            "cwe_id": "CWE-1321",
            "vulnerability_name": "Prototype Pollution",
            "severity": "High",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-588",
            "description": "Prototype Pollution occurs when malicious input modifies Object.prototype in JavaScript, leading to property injection, denial of service, or RCE.",
            "remediation": "Sanitize recursive object merge functions, freeze Object.prototype, or use Map objects instead of plain objects.",
            "recommendations": "1. Freeze object prototypes using Object.freeze(Object.prototype).\n2. Filter out __proto__, constructor, and prototype keys during object merges.\n3. Use Object.create(null) for dictionary objects."
        },
        {
            "cwe_id": "CWE-134",
            "vulnerability_name": "Format String Vulnerability",
            "severity": "High",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-67",
            "description": "Format String vulnerability occurs when format specifiers (%s, %x) are evaluated directly from untrusted input in printf-style functions.",
            "remediation": "Always supply static format strings to string formatting functions (e.g. printf(\"%s\", user_input)).",
            "recommendations": "1. Never pass variable user inputs as format string arguments.\n2. Use safe string formatting functions.\n3. Enable compiler warnings for format string vulnerabilities."
        },
        {
            "cwe_id": "CWE-190",
            "vulnerability_name": "Integer Overflow",
            "severity": "High",
            "owasp_category": "A06:2021-Vulnerable Components",
            "capec_id": "CAPEC-128",
            "description": "Integer Overflow occurs when an integer value exceeds the maximum storable size, wrapping around to a negative or zero value and causing logic errors.",
            "remediation": "Perform pre-condition range checks before arithmetic calculations or use arbitrary-precision integer types.",
            "recommendations": "1. Validate arithmetic operands against maximum thresholds.\n2. Use checked arithmetic libraries where available.\n3. Enable compiler overflow detection flags."
        },
        {
            "cwe_id": "CWE-285",
            "vulnerability_name": "Broken Function Level Authorization",
            "severity": "High",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-180",
            "description": "BFLA occurs when applications expose administrative or privileged endpoints without verifying user role permissions.",
            "remediation": "Enforce role-based access control (RBAC) middleware checks on every administrative API endpoint.",
            "recommendations": "1. Require role permission checks on all non-public routes.\n2. Deny access by default.\n3. Audit endpoint authorization annotations across API controllers."
        },
        {
            "cwe_id": "CWE-235",
            "vulnerability_name": "HTTP Parameter Pollution (HPP)",
            "severity": "Medium",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-460",
            "description": "HPP occurs when multiple parameters with the same name are supplied in HTTP requests, causing unexpected parameter parsing behavior.",
            "remediation": "Standardize request parameter parsing middleware to take only the first or last occurrence of duplicate parameters.",
            "recommendations": "1. Reject HTTP requests with duplicate query parameters.\n2. Explicitly configure web frameworks to parse parameters deterministically.\n3. Validate parameter types strictly."
        },
        {
            "cwe_id": "CWE-330",
            "vulnerability_name": "Insecure Randomness / PRNG",
            "severity": "Medium",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "capec_id": "CAPEC-112",
            "description": "Using standard pseudo-random number generators (like Python random or C rand) for tokens or passwords generates predictable values.",
            "remediation": "Use cryptographically secure pseudo-random number generators (CSPRNGs, e.g. Python secrets or os.urandom).",
            "recommendations": "1. Use secrets module or crypto.getRandomValues for token generation.\n2. Never use standard pseudo-random functions for security tokens.\n3. Ensure sufficient entropy for secret generation."
        },
        {
            "cwe_id": "CWE-489",
            "vulnerability_name": "Active Debug Code / Debug Configuration",
            "severity": "Medium",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-13",
            "description": "Leaving active debug code or enabling debug flags (e.g., debug=True) in production exposes internal application state, stack traces, and interactive execution consoles to attackers.",
            "remediation": "Disable all debug modes, diagnostic flags, and testing endpoints before deploying code to production environments.",
            "recommendations": "1. Set debug=False in production web framework configurations.\n2. Use environment variables (e.g., FLASK_ENV=production) to control diagnostic modes.\n3. Implement centralized, non-verbose logging instead of exposing live debug consoles."
        }
    ]

    for item in items:
        existing = db.query(KnowledgeBaseItem).filter(KnowledgeBaseItem.cwe_id.ilike(item["cwe_id"])).first()
        if not existing:
            db_item = KnowledgeBaseItem(**item)
            db.add(db_item)
        else:
            existing.vulnerability_name = item["vulnerability_name"]
            existing.severity = item["severity"]
            existing.owasp_category = item["owasp_category"]
            existing.capec_id = item["capec_id"]
            existing.description = item["description"]
            existing.remediation = item["remediation"]
            existing.recommendations = item["recommendations"]

    db.commit()
    print("Knowledge base seeded successfully!")
