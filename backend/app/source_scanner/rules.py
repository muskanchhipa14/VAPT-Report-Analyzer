"""
Vulnerability rules metadata and suggested remediation implementations across languages.
"""

from typing import Dict, Optional

SUGGESTED_FIXES: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "python": (
            "# Suggested Fix (Parameterized database query):\n"
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
        "typescript": (
            "// Suggested Fix (Parameterized SQL execution):\n"
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
        "php": (
            "// Suggested Fix (PDO Prepared Statements):\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
            "$stmt->execute(['id' => $userId]);\n"
            "$user = $stmt->fetch();"
        ),
        "csharp": (
            "// Suggested Fix (SqlCommand with Parameterized Query):\n"
            "string query = \"SELECT * FROM Users WHERE Id = @UserId\";\n"
            "using (SqlCommand cmd = new SqlCommand(query, conn)) {\n"
            "    cmd.Parameters.AddWithValue(\"@UserId\", userId);\n"
            "    using (SqlDataReader reader = cmd.ExecuteReader()) { /* process */ }\n"
            "}"
        ),
        "go": (
            "// Suggested Fix (database/sql Parameterized Query):\n"
            "query := \"SELECT id, name FROM users WHERE id = $1\"\n"
            "row := db.QueryRow(query, userID)"
        ),
        "c": (
            "/* Suggested Fix (Prepared statement via libpq/sqlite3): */\n"
            "sqlite3_stmt *stmt;\n"
            "sqlite3_prepare_v2(db, \"SELECT * FROM users WHERE id = ?;\", -1, &stmt, NULL);\n"
            "sqlite3_bind_text(stmt, 1, user_id, -1, SQLITE_STATIC);"
        ),
        "cpp": (
            "// Suggested Fix (Prepared statement via C++ DB client):\n"
            "auto stmt = conn.prepare(\"SELECT * FROM users WHERE id = ?\");\n"
            "stmt->execute(userId);"
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
        "typescript": (
            "// Suggested Fix (Use execFile with argument array):\n"
            "import { execFile } from 'child_process';\n"
            "execFile('ping', ['-c', '1', host], (error, stdout) => { console.log(stdout); });"
        ),
        "java": (
            "// Suggested Fix (Use ProcessBuilder with array/list arguments):\n"
            "ProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", host);\n"
            "Process process = pb.start();"
        ),
        "php": (
            "// Suggested Fix (Sanitize shell arguments with escapeshellarg):\n"
            "$safeHost = escapeshellarg($host);\n"
            "$output = shell_exec(\"ping -c 1 \" . $safeHost);"
        ),
        "csharp": (
            "// Suggested Fix (Use ProcessStartInfo with ArgumentList):\n"
            "var psi = new ProcessStartInfo {\n"
            "    FileName = \"ping\",\n"
            "    UseShellExecute = false,\n"
            "    RedirectStandardOutput = true\n"
            "};\n"
            "psi.ArgumentList.Add(\"-c\");\n"
            "psi.ArgumentList.Add(\"1\");\n"
            "psi.ArgumentList.Add(host);\n"
            "using (var process = Process.Start(psi)) { /* process */ }"
        ),
        "go": (
            "// Suggested Fix (Pass command arguments as slice in exec.Command):\n"
            "cmd := exec.Command(\"ping\", \"-c\", \"1\", host)\n"
            "out, err := cmd.Output()"
        ),
        "c": (
            "/* Suggested Fix (Use fork + execvp instead of system()): */\n"
            "char *args[] = {\"ping\", \"-c\", \"1\", host, NULL};\n"
            "execvp(args[0], args);"
        ),
        "cpp": (
            "// Suggested Fix (Avoid system(); use POSIX execvp or boost::process):\n"
            "boost::process::child c(\"/bin/ping\", \"-c\", \"1\", host);"
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
        "typescript": (
            "// Suggested Fix (Safe DOM rendering with DOMPurify):\n"
            "import DOMPurify from 'dompurify';\n"
            "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />"
        ),
        "python": (
            "# Suggested Fix (Template auto-escaping):\n"
            "from markupsafe import escape\n"
            "safe_html = escape(user_input)"
        ),
        "php": (
            "// Suggested Fix (Escape HTML output):\n"
            "echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');"
        ),
        "csharp": (
            "// Suggested Fix (HTML encode output):\n"
            "string safeOutput = System.Net.WebUtility.HtmlEncode(userInput);\n"
            "Response.Write(safeOutput);"
        ),
        "go": (
            "// Suggested Fix (Use html/template which auto-escapes):\n"
            "import \"html/template\"\n"
            "tmpl.Execute(w, userInput)"
        ),
        "java": (
            "// Suggested Fix (Use OWASP Java HTML Sanitizer / HtmlUtils):\n"
            "String safeHtml = HtmlUtils.htmlEscape(userInput);"
        ),
    },
    "CWE-120": {
        "c": (
            "/* Suggested Fix (Use bounded string copy and buffers): */\n"
            "/* 1. strncpy with null-termination guarantee: */\n"
            "strncpy(dest, src, sizeof(dest) - 1);\n"
            "dest[sizeof(dest) - 1] = '\\0';\n\n"
            "/* 2. Or C11 strncpy_s / snprintf: */\n"
            "snprintf(dest, sizeof(dest), \"%s\", src);"
        ),
        "cpp": (
            "// Suggested Fix (Use modern C++ std::string and bounds-checked containers):\n"
            "std::string dest = src;\n"
            "// Avoid raw char arrays and unchecked strcpy"
        ),
    },
    "CWE-134": {
        "c": (
            "/* Suggested Fix (Always provide format specifier): */\n"
            "printf(\"%s\", user_input);\n"
            "syslog(LOG_INFO, \"%s\", user_input);"
        ),
        "cpp": (
            "// Suggested Fix (Always pass explicit format string or use std::cout / std::format):\n"
            "std::cout << user_input << std::endl;\n"
            "// Or: printf(\"%s\", user_input.c_str());"
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
            "// Use JSON serialization with Jackson / Gson:\n"
            "ObjectMapper mapper = new ObjectMapper();\n"
            "MyData data = mapper.readValue(jsonString, MyData.class);"
        ),
        "php": (
            "// Suggested Fix (Use json_decode instead of unserialize):\n"
            "$data = json_decode($jsonPayload, true);"
        ),
        "csharp": (
            "// Suggested Fix (Use System.Text.Json instead of BinaryFormatter):\n"
            "MyData data = JsonSerializer.Deserialize<MyData>(jsonString);"
        ),
    },
    "CWE-327": {
        "python": (
            "# Suggested Fix (Use modern cryptographic hashing algorithms):\n"
            "import hashlib\n"
            "# For general data digests, use SHA-256:\n"
            "digest = hashlib.sha256(data.encode('utf-8')).hexdigest()\n"
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
        "csharp": (
            "// Suggested Fix (Use SHA256.Create()):\n"
            "using (SHA256 sha256 = SHA256.Create()) {\n"
            "    byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));\n"
            "}"
        ),
        "go": (
            "// Suggested Fix (Use crypto/sha256):\n"
            "import \"crypto/sha256\"\n"
            "h := sha256.Sum256([]byte(data))"
        ),
        "c": (
            "/* Suggested Fix (Use SHA-256 via OpenSSL EVP): */\n"
            "EVP_MD_CTX *mdctx = EVP_MD_CTX_new();\n"
            "EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);"
        ),
        "cpp": (
            "// Suggested Fix (Use SHA-256 via OpenSSL or Crypto++):\n"
            "EVP_MD_CTX *mdctx = EVP_MD_CTX_new();\n"
            "EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);"
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
        "typescript": (
            "// Suggested Fix (Load credentials from environment variables):\n"
            "const apiKey = process.env.API_SECRET_KEY;\n"
            "if (!apiKey) throw new Error('API_SECRET_KEY is not set');"
        ),
        "java": (
            "// Suggested Fix (Read credentials from environment variables or vault):\n"
            "String apiKey = System.getenv(\"API_SECRET_KEY\");\n"
            "if (apiKey == null) throw new IllegalStateException(\"API_SECRET_KEY is missing\");"
        ),
        "php": (
            "// Suggested Fix (Load credentials from environment variables):\n"
            "$apiKey = getenv('API_SECRET_KEY');\n"
            "if (!$apiKey) { throw new Exception('API_SECRET_KEY is not configured'); }"
        ),
        "csharp": (
            "// Suggested Fix (Read credentials from environment variables or secret manager):\n"
            "string apiKey = Environment.GetEnvironmentVariable(\"API_SECRET_KEY\");\n"
            "if (string.IsNullOrEmpty(apiKey)) throw new InvalidOperationException(\"API key missing\");"
        ),
        "go": (
            "// Suggested Fix (Read credentials from environment variable):\n"
            "apiKey := os.Getenv(\"API_SECRET_KEY\")\n"
            "if apiKey == \"\" { log.Fatal(\"API_SECRET_KEY must be set\") }"
        ),
        "c": (
            "/* Suggested Fix (Read credential from environment variable): */\n"
            "const char *apiKey = getenv(\"API_SECRET_KEY\");\n"
            "if (!apiKey) { fprintf(stderr, \"Missing API_SECRET_KEY\\n\"); return -1; }"
        ),
        "cpp": (
            "// Suggested Fix (Read credential from environment variable):\n"
            "const char *apiKey = std::getenv(\"API_SECRET_KEY\");\n"
            "if (!apiKey) { throw std::runtime_error(\"Missing API_SECRET_KEY\"); }"
        ),
    },
    "CWE-22": {
        "python": (
            "# Suggested Fix (Path traversal prevention):\n"
            "import os\n\n"
            "safe_filename = os.path.basename(user_input)\n"
            "safe_path = os.path.abspath(os.path.join(BASE_DIR, safe_filename))\n"
            "if not safe_path.startswith(os.path.abspath(BASE_DIR) + os.sep):\n"
            "    raise ValueError(\"Access Denied: Path traversal detected\")"
        ),
        "javascript": (
            "// Suggested Fix (Path traversal prevention):\n"
            "const path = require('path');\n\n"
            "const safeName = path.basename(userInput);\n"
            "const safePath = path.resolve(BASE_DIR, safeName);\n"
            "if (!safePath.startsWith(path.resolve(BASE_DIR))) {\n"
            "  throw new Error('Path traversal detected');\n"
            "}"
        ),
        "java": (
            "// Suggested Fix (Validate canonical path within base directory):\n"
            "File file = new File(BASE_DIR, new File(userInput).getName());\n"
            "if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {\n"
            "    throw new SecurityException(\"Path traversal detected\");\n"
            "}"
        ),
        "php": (
            "// Suggested Fix (Path traversal prevention):\n"
            "$safeFile = basename($userInput);\n"
            "$target = realpath($baseDir . '/' . $safeFile);\n"
            "if ($target === false || strpos($target, realpath($baseDir)) !== 0) {\n"
            "    die('Access Denied: Path Traversal');\n"
            "}"
        ),
        "csharp": (
            "// Suggested Fix (Path traversal prevention):\n"
            "string safeFileName = Path.GetFileName(userInput);\n"
            "string fullPath = Path.GetFullPath(Path.Combine(baseDir, safeFileName));\n"
            "if (!fullPath.StartsWith(Path.GetFullPath(baseDir))) {\n"
            "    throw new UnauthorizedAccessException(\"Path traversal detected\");\n"
            "}"
        ),
        "go": (
            "// Suggested Fix (Path traversal prevention with filepath.Clean):\n"
            "safeName := filepath.Base(userInput)\n"
            "fullPath := filepath.Join(baseDir, safeName)\n"
            "if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(baseDir)) {\n"
            "    return errors.New(\"path traversal detected\")\n"
            "}"
        ),
        "c": (
            "/* Suggested Fix (Strip directory separators using basename): */\n"
            "#include <libgen.h>\n"
            "char *safe_name = basename(user_input);\n"
            "/* verify canonical path */"
        ),
        "cpp": (
            "// Suggested Fix (Use std::filesystem::canonical):\n"
            "namespace fs = std::filesystem;\n"
            "fs::path p = fs::canonical(fs::path(baseDir) / fs::path(userInput).filename());"
        ),
    },
    "CWE-918": {
        "python": (
            "# Suggested Fix (SSRF Prevention via allowlist validation):\n"
            "from urllib.parse import urlparse\n\n"
            "ALLOWED_HOSTS = {\"api.myservice.com\", \"internal.data.org\"}\n"
            "parsed = urlparse(target_url)\n"
            "if parsed.hostname not in ALLOWED_HOSTS:\n"
            "    raise ValueError(\"Untrusted destination host\")"
        ),
        "javascript": (
            "// Suggested Fix (SSRF Prevention via host allowlist):\n"
            "const { URL } = require('url');\n"
            "const ALLOWED_HOSTS = new Set(['api.myservice.com']);\n"
            "const parsed = new URL(targetUrl);\n"
            "if (!ALLOWED_HOSTS.has(parsed.hostname)) {\n"
            "  throw new Error('SSRF: Destination host not allowed');\n"
            "}"
        ),
    },
    "CWE-330": {
        "python": (
            "# Suggested Fix (Use secrets module for cryptographic randomness):\n"
            "import secrets\n"
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
            "function isSafeKey(key) {\n"
            "  return key !== '__proto__' && key !== 'constructor' && key !== 'prototype';\n"
            "}\n"
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
    "CWE-190": {
        "c": (
            "/* Suggested Fix (Check for integer overflow before allocation): */\n"
            "if (num_items > SIZE_MAX / sizeof(int)) {\n"
            "    /* handle overflow error */\n"
            "    return -1;\n"
            "}\n"
            "int *buf = malloc(num_items * sizeof(int));"
        ),
        "cpp": (
            "// Suggested Fix (Use bounds-checked std::vector or check overflow):\n"
            "std::vector<int> buf;\n"
            "buf.reserve(num_items); // throws std::length_error if exceeds max_size"
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
    lang_key = language.lower() if language else ""
    if lang_key in cwe_fixes:
        return cwe_fixes[lang_key]
    # Check aliases
    if lang_key in ("typescript", "tsx", "jsx") and "javascript" in cwe_fixes:
        return cwe_fixes["javascript"]
    if lang_key in ("cpp", "cxx") and "c" in cwe_fixes and "cpp" not in cwe_fixes:
        return cwe_fixes["c"]
    return next(iter(cwe_fixes.values()), None)
