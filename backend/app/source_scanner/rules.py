"""
Vulnerability rules metadata and suggested remediation implementations.
"""

from typing import Dict, Optional

SUGGESTED_FIXES: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "python": (
            "# Suggested Fix (Example parameterized database query):\n"
            "# 1. With standard cursor:\n"
            "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\n"
            "# 2. With SQLAlchemy ORM:\n"
            "user = db.query(User).filter(User.id == user_id).first()"
        ),
        "javascript": (
            "// Suggested Fix (Parameterized SQL execution):\n"
            "// Using pg / mysql2 prepared statements:\n"
            "const query = 'SELECT * FROM users WHERE id = $1';\n"
            "const result = await pool.query(query, [userId]);"
        ),
        "java": (
            "// Suggested Fix (PreparedStatement):\n"
            "String sql = \"SELECT * FROM users WHERE id = ?\";\n"
            "PreparedStatement pstmt = conn.prepareStatement(sql);\n"
            "pstmt.setString(1, userId);\n"
            "ResultSet rs = pstmt.executeQuery();"
        ),
    },
    "CWE-78": {
        "python": (
            "# Suggested Fix (Parameterized subprocess call without shell):\n"
            "import subprocess\n\n"
            "# Pass command arguments as a list with shell=False:\n"
            "result = subprocess.run([\"ping\", \"-c\", \"1\", host], capture_output=True, text=True, check=True)"
        ),
        "javascript": (
            "// Suggested Fix (Avoid child_process.exec with concatenated strings):\n"
            "const { execFile } = require('child_process');\n\n"
            "// Use execFile with arguments array:\n"
            "execFile('ping', ['-c', '1', host], (error, stdout, stderr) => {\n"
            "  if (error) throw error;\n"
            "  console.log(stdout);\n"
            "});"
        ),
        "java": (
            "// Suggested Fix (Use ProcessBuilder with array/list arguments):\n"
            "ProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", host);\n"
            "Process process = pb.start();"
        ),
    },
    "CWE-79": {
        "javascript": (
            "// Suggested Fix (Safe DOM rendering / Output sanitization):\n"
            "// 1. In React, prefer standard JSX text rendering which auto-escapes:\n"
            "return <div>{userInput}</div>;\n\n"
            "// 2. If rich HTML is strictly necessary, sanitize first with DOMPurify:\n"
            "import DOMPurify from 'dompurify';\n"
            "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />"
        ),
        "python": (
            "# Suggested Fix (Template auto-escaping):\n"
            "from markupsafe import escape\n"
            "safe_html = escape(user_input)"
        ),
    },
    "CWE-502": {
        "python": (
            "# Suggested Fix (Use safe serialization formats like JSON):\n"
            "import json\n\n"
            "# Replace pickle with json or protobuf:\n"
            "data = json.loads(payload)"
        ),
        "java": (
            "// Suggested Fix (Avoid native Java deserialization with untrusted streams):\n"
            "// Use JSON or XML serialization with Jackson / Gson:\n"
            "ObjectMapper mapper = new ObjectMapper();\n"
            "MyData data = mapper.readValue(jsonString, MyData.class);"
        ),
    },
    "CWE-327": {
        "python": (
            "# Suggested Fix (Use modern cryptographic hashing algorithms):\n"
            "import hashlib\n\n"
            "# For general data digests, use SHA-256 or SHA-512:\n"
            "digest = hashlib.sha256(data.encode('utf-8')).hexdigest()\n\n"
            "# For passwords, use bcrypt or argon2:\n"
            "from passlib.hash import bcrypt\n"
            "hashed_pw = bcrypt.hash(raw_password)"
        ),
        "javascript": (
            "// Suggested Fix (Use SHA-256 or modern hash algorithm):\n"
            "const crypto = require('crypto');\n"
            "const hash = crypto.createHash('sha256').update(data).digest('hex');"
        ),
        "java": (
            "// Suggested Fix (Use SHA-256 or SHA-512):\n"
            "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
            "byte[] digest = md.digest(data.getBytes(StandardCharsets.UTF_8));"
        ),
    },
    "CWE-798": {
        "python": (
            "# Suggested Fix (Load sensitive credentials from environment variables):\n"
            "import os\n\n"
            "API_KEY = os.getenv(\"API_SECRET_KEY\")\n"
            "if not API_KEY:\n"
            "    raise RuntimeError(\"API_SECRET_KEY environment variable is not configured\")"
        ),
        "javascript": (
            "// Suggested Fix (Load credentials from environment variables):\n"
            "require('dotenv').config();\n"
            "const apiKey = process.env.API_SECRET_KEY;\n"
            "if (!apiKey) throw new Error('API_SECRET_KEY is not set');"
        ),
        "java": (
            "// Suggested Fix (Read credentials from environment variables or vault):\n"
            "String apiKey = System.getenv(\"API_SECRET_KEY\");\n"
            "if (apiKey == null) throw new IllegalStateException(\"API_SECRET_KEY is missing\");"
        ),
    },
    "CWE-22": {
        "python": (
            "# Suggested Fix (Path Traversal prevention):\n"
            "import os\n\n"
            "BASE_DIR = \"/path/to/allowed/directory\"\n"
            "filename = os.path.basename(user_input_filename)\n"
            "resolved_path = os.path.abspath(os.path.join(BASE_DIR, filename))\n\n"
            "if not resolved_path.startswith(os.path.abspath(BASE_DIR)):\n"
            "    raise PermissionError(\"Access denied: Path outside allowable directory\")\n\n"
            "with open(resolved_path, 'r') as f:\n"
            "    content = f.read()"
        ),
        "javascript": (
            "// Suggested Fix (Canonical path validation):\n"
            "const path = require('path');\n"
            "const BASE_DIR = path.resolve('/allowed/uploads');\n"
            "const safeFilename = path.basename(userInputFilename);\n"
            "const targetPath = path.resolve(BASE_DIR, safeFilename);\n\n"
            "if (!targetPath.startsWith(BASE_DIR)) {\n"
            "  throw new Error('Access denied');\n"
            "}"
        ),
        "java": (
            "// Suggested Fix (Path Traversal sanitization):\n"
            "File baseDir = new File(\"/allowed/dir\");\n"
            "File targetFile = new File(baseDir, new File(userInput).getName()).getCanonicalFile();\n"
            "if (!targetFile.toPath().startsWith(baseDir.toPath())) {\n"
            "    throw new SecurityException(\"Access denied: Invalid file path\");\n"
            "}"
        ),
    },
    "CWE-918": {
        "python": (
            "# Suggested Fix (SSRF validation with allowlist and private IP check):\n"
            "from urllib.parse import urlparse\n"
            "import ipaddress\n\n"
            "ALLOWED_DOMAINS = {\"api.example.com\", \"services.internal.org\"}\n"
            "parsed = urlparse(user_url)\n\n"
            "if parsed.scheme not in [\"https\"] or parsed.hostname not in ALLOWED_DOMAINS:\n"
            "    raise ValueError(\"Untrusted destination target\")\n\n"
            "# Ensure request does not point to internal metadata/loopback addresses:\n"
            "response = requests.get(user_url, timeout=5, allow_redirects=False)"
        ),
        "javascript": (
            "// Suggested Fix (URL allowlist validation):\n"
            "const ALLOWED_HOSTS = ['api.example.com'];\n"
            "const parsedUrl = new URL(userInputUrl);\n\n"
            "if (parsedUrl.protocol !== 'https:' || !ALLOWED_HOSTS.includes(parsedUrl.hostname)) {\n"
            "  throw new Error('Forbidden URL host');\n"
            "}\n"
            "const res = await axios.get(parsedUrl.toString(), { timeout: 5000 });"
        ),
    },
    "CWE-330": {
        "python": (
            "# Suggested Fix (Use cryptographically secure PRNG):\n"
            "import secrets\n\n"
            "# Use secrets module instead of random for tokens and authentication:\n"
            "secure_token = secrets.token_hex(32)"
        ),
        "javascript": (
            "// Suggested Fix (Use crypto.randomBytes):\n"
            "const crypto = require('crypto');\n"
            "const secureToken = crypto.randomBytes(32).toString('hex');"
        ),
    },
    "CWE-489": {
        "python": (
            "# Suggested Fix (Disable debug mode in production):\n"
            "import os\n\n"
            "DEBUG = os.getenv(\"APP_DEBUG\", \"False\").lower() == \"true\"\n"
            "app.run(debug=False, host=\"127.0.0.1\")"
        ),
    },
    "CWE-1321": {
        "javascript": (
            "// Suggested Fix (Prototype Pollution prevention):\n"
            "// 1. Reject dangerous keys when merging objects:\n"
            "function isSafeKey(key) {\n"
            "  return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';\n"
            "}\n\n"
            "// 2. Or create dictionaries with null prototype:\n"
            "const safeMap = Object.create(null);"
        ),
    },
    "CWE-611": {
        "java": (
            "// Suggested Fix (Disable external DTD entities in XML parser):\n"
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
            "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
            "dbf.setXIncludeAware(false);\n"
            "dbf.setExpandEntityReferences(false);"
        ),
    },
}


def get_suggested_fix(cwe_id: str, language: str) -> Optional[str]:
    """
    Returns suggested fix code example for the given CWE and language.
    """
    cwe_fixes = SUGGESTED_FIXES.get(cwe_id.upper())
    if not cwe_fixes:
        return None
    return cwe_fixes.get(language.lower()) or next(iter(cwe_fixes.values()), None)
