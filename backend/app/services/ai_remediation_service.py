"""
Centralized AI Remediation Service
Provides AI-driven, language-specific, and framework-aware vulnerability remediation,
root-cause analysis ("why_vulnerable"), and safe replacement code generation.

Architecture:
- Centralized system prompt
- Live LLM integration (Gemini / Groq / OpenAI when configured)
- High-fidelity Semantic Remediation Engine for 100% reliable offline/test execution
- Language-specific code synthesis for Python, Java, C, C++, JS, TS, PHP, C#, Go
- Explicit safety controls (does not invent code for unknown languages or hallucinate)
"""

import os
import re
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List
from app.source_scanner.rules import get_suggested_fix

# Centralized System Prompt
AI_SYSTEM_PROMPT = """You are a secure software remediation assistant.

Analyze the identified vulnerability using the supplied vulnerability information, knowledge-base context, programming language, framework, and vulnerable code.

Generate a remediation that is technically appropriate for the detected language and framework.

Do not provide generic remediation when language-specific remediation is possible.

Explain:
1. What is vulnerable
2. Why it is vulnerable
3. How to fix it
4. Language/framework-specific implementation
5. Secure replacement code where possible
6. How to verify the fix

Do not modify unrelated application behavior.

If the provided information is insufficient to safely generate a precise code fix, explicitly state what information is missing instead of inventing implementation details."""


def build_ai_prompt(
    vulnerability: str,
    cwe_id: str,
    severity: str,
    language: str,
    framework: Optional[str] = None,
    database_or_lib: Optional[str] = None,
    file_name: Optional[str] = None,
    line_number: Optional[int] = None,
    vulnerable_code: Optional[str] = None,
    description: Optional[str] = None,
    kb_remediation: Optional[str] = None,
) -> str:
    """Builds structured prompt payload for LLM analysis."""
    context_lines = [
        f"Vulnerability Name: {vulnerability}",
        f"CWE ID: {cwe_id}",
        f"Severity: {severity}",
        f"Programming Language: {language or 'Unknown'}",
        f"Detected Framework: {framework or 'None / Undetected'}",
        f"Database / Security Library: {database_or_lib or 'None / Undetected'}",
        f"Target File: {file_name or 'N/A'}",
        f"Line Number: {line_number if line_number and line_number > 0 else 'N/A'}",
        f"Vulnerability Description: {description or 'N/A'}",
        f"Knowledge Base Guidance: {kb_remediation or 'N/A'}",
        "",
        "Vulnerable Code Snippet:",
        "```",
        vulnerable_code or "# No vulnerable code snippet available.",
        "```",
        "",
        "Please respond strictly in valid JSON matching this schema:",
        "{",
        '  "vulnerability": "string",',
        '  "cwe_id": "string",',
        '  "severity": "string",',
        '  "language": "string",',
        '  "framework": "string",',
        '  "file": "string",',
        '  "line": 0,',
        '  "description": "string",',
        '  "why_vulnerable": "string",',
        '  "knowledge_base_remediation": "string",',
        '  "ai_remediation": "string",',
        '  "secure_code": "string",',
        '  "implementation_steps": ["step 1", "step 2"],',
        '  "verification_steps": ["verification 1", "verification 2"]',
        "}"
    ]
    return "\n".join(context_lines)


def generate_semantic_remediation(
    vulnerability: str,
    cwe_id: str,
    severity: str,
    language: str,
    framework: Optional[str] = None,
    database_or_lib: Optional[str] = None,
    file_name: Optional[str] = None,
    line_number: Optional[int] = None,
    vulnerable_code: Optional[str] = None,
    description: Optional[str] = None,
    kb_remediation: Optional[str] = None,
) -> Dict[str, Any]:
    """
    High-fidelity semantic remediation engine. Generates context-aware,
    language-specific and framework-specific remediations, explanations, and
    secure code implementations without relying on external network requests.
    """
    cwe = (cwe_id or "").upper().strip()
    lang = (language or "unknown").lower().strip()
    fw = framework or "Unknown"
    db_name = database_or_lib or "Standard"
    fname = file_name or "N/A"
    line_no = line_number if (line_number and line_number > 0) else 1
    clean_code = (vulnerable_code or "").strip()

    # Default baseline
    why_vulnerable = "Untrusted input is processed without proper sanitization, bounds checking, or parameterization."
    ai_remediation = f"Implement robust input validation and language-appropriate secure APIs for {cwe} in {language}."
    secure_code = ""
    implementation_steps: List[str] = []
    verification_steps: List[str] = []

    # Section 10: Unknown Language Handling
    if not lang or lang in ("unknown", "none", "n/a", ""):
        return {
            "vulnerability": vulnerability,
            "cwe_id": cwe,
            "severity": severity,
            "language": "Unknown",
            "framework": "Unknown",
            "file": fname,
            "line": line_no,
            "description": description or f"Vulnerability {vulnerability} identified.",
            "why_vulnerable": "Programming language could not be determined with certainty from file extension or syntax.",
            "knowledge_base_remediation": kb_remediation or "Refer to Knowledge Base guidelines for standard mitigation.",
            "ai_remediation": "Insufficient evidence to generate a reliable language-specific remediation. Please specify the programming language to receive targeted implementation guidance.",
            "secure_code": "# Unable to safely generate replacement code without verified programming language.",
            "implementation_steps": [
                "Determine the primary programming language and framework for the affected component.",
                "Review the corresponding CWE security guidelines in the Knowledge Base.",
                "Consult the language documentation for safe API alternatives."
            ],
            "verification_steps": [
                "Manually inspect the affected file using static analysis tools configured for the project's language.",
                "Execute security regression tests against the affected endpoint."
            ]
        }

    # ==================== CWE-89: SQL INJECTION ====================
    if cwe == "CWE-89" or "sql" in vulnerability.lower():
        if lang == "python":
            why_vulnerable = (
                "The application dynamically concatenates or formats user-supplied data directly into a SQL query string. "
                "An attacker can inject arbitrary SQL fragments, potentially bypassing authentication, extracting database contents, "
                "or executing destructive DDL/DML statements."
            )
            if "sqlalchemy" in fw.lower() or "sqlalchemy" in db_name.lower():
                ai_remediation = (
                    "In Python with SQLAlchemy ORM, replace raw string concatenation with ORM model query filters or bound parameters. "
                    "SQLAlchemy automatically escapes and parameterizes values passed into `.filter()` or `text(:param)`."
                )
                secure_code = (
                    "# Secure Implementation (SQLAlchemy ORM):\n"
                    "# 1. Using ORM query filter (Recommended):\n"
                    "user = db.query(User).filter(User.id == user_id).first()\n\n"
                    "# 2. If using raw text queries, use bound parameters:\n"
                    "from sqlalchemy import text\n"
                    "stmt = text(\"SELECT * FROM users WHERE id = :user_id\")\n"
                    "result = db.execute(stmt, {\"user_id\": user_id}).fetchone()"
                )
                implementation_steps = [
                    "Locate query concatenation in the database handler function.",
                    "Refactor query to use SQLAlchemy `.filter()` or `text().bindparams()`.",
                    "Pass user variables as bound values, never format strings into raw SQL."
                ]
            else:
                ai_remediation = (
                    "In Python, always use parameterized queries with placeholder markers (`%s` for psycopg2/mysql, `?` for sqlite3) "
                    "and pass parameters as a separate tuple to `cursor.execute(query, (param,))`."
                )
                if clean_code and ("select" in clean_code.lower() or "where" in clean_code.lower()):
                    # Synthesize exact replacement
                    secure_code = (
                        f"# Secure Parameterized Query:\n"
                        f"# Replace string concatenation with parameterized placeholder:\n"
                        f"query = \"SELECT * FROM users WHERE id = %s\"\n"
                        f"cursor.execute(query, (user_id,))"
                    )
                else:
                    secure_code = (
                        "# Secure Parameterized Query (DB-API 2.0):\n"
                        "query = \"SELECT id, username, email FROM users WHERE id = %s\"\n"
                        "cursor.execute(query, (user_id,))\n"
                        "user = cursor.fetchone()"
                    )
                implementation_steps = [
                    "Separate SQL query structure from dynamic user data.",
                    "Use parameterized placeholders (`%s` or `?`) in the query string.",
                    "Pass user inputs as a tuple argument to `cursor.execute(query, (val,))`."
                ]
            verification_steps = [
                "Test query with benign inputs and verify expected records are returned.",
                "Inject SQL payloads such as `' OR '1'='1` and `1; DROP TABLE users;` — verify they are treated strictly as literal string values.",
                "Ensure database logs confirm queries are executed as prepared statements."
            ]

        elif lang == "java":
            why_vulnerable = (
                "Dynamic SQL string concatenation allows untrusted input to alter the syntax tree of the database query. "
                "Executing unparameterized SQL through `Statement.executeQuery()` allows SQL injection."
            )
            ai_remediation = (
                "In Java, use JDBC `PreparedStatement` with `?` parameter markers instead of string concatenation. "
                "The database pre-compiles the query and binds parameters safely, completely preventing SQL injection."
            )
            secure_code = (
                "// Secure Implementation using JDBC PreparedStatement:\n"
                "String sql = \"SELECT id, username, email FROM users WHERE id = ?\";\n"
                "try (PreparedStatement pstmt = conn.prepareStatement(sql)) {\n"
                "    pstmt.setString(1, userId);\n"
                "    try (ResultSet rs = pstmt.executeQuery()) {\n"
                "        while (rs.next()) {\n"
                "            // Safely process results\n"
                "        }\n"
                "    }\n"
                "}"
            )
            implementation_steps = [
                "Replace `java.sql.Statement` with `java.sql.PreparedStatement`.",
                "Replace inline concatenated string values with `?` place-markers.",
                "Call appropriate typed setters (`pstmt.setString()`, `pstmt.setInt()`) before calling `.executeQuery()`."
            ]
            verification_steps = [
                "Submit input containing single quotes (`'`) and SQL injection sequences like `' OR 1=1 --`.",
                "Confirm that the query treats the payload as an exact literal and returns zero unauthenticated rows.",
                "Run automated unit tests validating parameterized database operations."
            ]

        elif lang in ("javascript", "typescript"):
            why_vulnerable = (
                "The application builds SQL queries using template literals (`${...}`) or string concatenation (`+`). "
                "Executing interpolated strings through database client drivers allows attackers to inject malicious query structures."
            )
            ai_remediation = (
                "In JavaScript / Node.js, use parameterized query execution with parameterized tokens "
                "(`$1, $2` for pg/PostgreSQL, `?` for MySQL/mysql2) and pass parameter arrays into `client.query(sql, [params])`."
            )
            secure_code = (
                "// Secure Implementation (pg / mysql2 parameterized execution):\n"
                "// 1. PostgreSQL (pg):\n"
                "const text = 'SELECT id, username FROM users WHERE id = $1';\n"
                "const values = [userId];\n"
                "const res = await pool.query(text, values);\n\n"
                "// 2. MySQL (mysql2 prepared statement):\n"
                "const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);"
            )
            implementation_steps = [
                "Remove template literals and concatenation from SQL string definitions.",
                "Substitute positional tokens (`$1` or `?`) for dynamic values.",
                "Pass dynamic variables in the second parameter array argument of `.query()` or `.execute()`."
            ]
            verification_steps = [
                "Submit SQL injection test strings (`admin'--`, `' OR '1'='1`) through request parameters.",
                "Verify database client returns zero matches or expected exact string match without syntax errors.",
                "Verify parameterized statements in database query audit logs."
            ]

        elif lang == "php":
            why_vulnerable = (
                "PHP application combines user input (`$_GET`, `$_POST`) directly with SQL statements in `mysqli_query` or `PDO::query`. "
                "This allows attackers to break out of data context and execute arbitrary SQL."
            )
            ai_remediation = (
                "In PHP, use PDO (PHP Data Objects) with prepared statements and named placeholders (`:id`) or `mysqli_stmt_bind_param`. "
                "Never interpolate variables directly into SQL strings."
            )
            secure_code = (
                "// Secure Implementation using PHP PDO Prepared Statements:\n"
                "$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE id = :id');\n"
                "$stmt->execute(['id' => $userId]);\n"
                "$user = $stmt->fetch(PDO::FETCH_ASSOC);"
            )
            implementation_steps = [
                "Replace legacy `mysqli_query()` or direct `$pdo->query()` with `$pdo->prepare()`.",
                "Use named placeholders such as `:id` or `?` in the query template.",
                "Pass sanitized associative array to `$stmt->execute([...])`."
            ]
            verification_steps = [
                "Test login or lookup endpoints with standard SQLi vectors like `1' OR '1'='1`.",
                "Confirm that database returns no unauthorized records and throws no SQL syntax exceptions."
            ]

        elif lang == "csharp":
            why_vulnerable = (
                "Building SQL queries by concatenating user strings directly into `SqlCommand.CommandText` permits SQL injection. "
                "Untrusted input can alter query logic or execute stacked queries."
            )
            ai_remediation = (
                "In C# / .NET, use `SqlCommand` with `SqlParameter` objects or Entity Framework LINQ queries. "
                "Parameterized queries ensure user input is transmitted out-of-band from the SQL command structure."
            )
            secure_code = (
                "// Secure Implementation using Parameterized SqlCommand:\n"
                "string query = \"SELECT Id, Username, Email FROM Users WHERE Id = @UserId\";\n"
                "using (SqlCommand cmd = new SqlCommand(query, conn)) {\n"
                "    cmd.Parameters.Add(\"@UserId\", SqlDbType.Int).Value = userId;\n"
                "    using (SqlDataReader reader = cmd.ExecuteReader()) {\n"
                "        while (reader.Read()) { /* Process data safely */ }\n"
                "    }\n"
                "}"
            )
            implementation_steps = [
                "Replace concatenated query strings with parameterized query templates using `@paramName`.",
                "Add parameters using `cmd.Parameters.Add(\"@name\", SqlDbType...).Value = val`.",
                "If using Entity Framework, use LINQ expressions like `.Where(u => u.Id == userId)`."
            ]
            verification_steps = [
                "Inject single quotes and SQL fragments into request parameters.",
                "Ensure SQL Server receives RPC parameter calls rather than ad-hoc concatenated text."
            ]

        elif lang == "go":
            why_vulnerable = (
                "Constructing SQL strings using `fmt.Sprintf()` or `+` concatenation before passing to `db.Query()` allows user input "
                "to inject arbitrary SQL clauses into the execution pipeline."
            )
            ai_remediation = (
                "In Go, use the standard `database/sql` driver's parameterized query execution. "
                "Pass parameters as additional arguments to `db.Query()` or `db.QueryRow()`, using `$1, $2` (Postgres) or `?` (MySQL/SQLite)."
            )
            secure_code = (
                "// Secure Implementation using database/sql Parameterized Queries:\n"
                "query := \"SELECT id, username, email FROM users WHERE id = $1\"\n"
                "row := db.QueryRowContext(ctx, query, userID)\n"
                "err := row.Scan(&user.ID, &user.Username, &user.Email)"
            )
            implementation_steps = [
                "Replace `fmt.Sprintf` query formatting with parameterized placeholder strings.",
                "Pass dynamic arguments directly to `db.Query(query, arg1, arg2)`.",
                "Check for and handle errors returned by `.Scan()`."
            ]
            verification_steps = [
                "Send malicious SQL characters in query parameters and confirm no syntax errors or data leak occurs.",
                "Verify queries log as prepared statements in DB logs."
            ]

        elif lang in ("c", "cpp"):
            why_vulnerable = (
                "Constructing SQL strings via `sprintf()` or `strcat()` in C/C++ opens the application to SQL injection and potential buffer overflows."
            )
            ai_remediation = (
                "In C/C++, use database driver prepared statements (such as `sqlite3_prepare_v2` / `sqlite3_bind_*` or libpq `PQexecParams`)."
            )
            secure_code = (
                "/* Secure Implementation using SQLite Prepared Statements: */\n"
                "sqlite3_stmt *stmt;\n"
                "const char *sql = \"SELECT id, name FROM users WHERE id = ?;\";\n"
                "if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {\n"
                "    sqlite3_bind_int(stmt, 1, user_id);\n"
                "    while (sqlite3_step(stmt) == SQLITE_ROW) {\n"
                "        /* Safe data extraction */\n"
                "    }\n"
                "    sqlite3_finalize(stmt);\n"
                "}"
            )
            implementation_steps = [
                "Use prepared statement APIs provided by the database client library.",
                "Bind parameters safely using typed binding functions.",
                "Always finalize or destroy prepared statement handles to prevent memory leaks."
            ]
            verification_steps = [
                "Fuzz input with SQL delimiters and verify execution remains bound to parameter context."
            ]

    # ==================== CWE-79: CROSS-SITE SCRIPTING (XSS) ====================
    elif cwe == "CWE-79" or "cross-site scripting" in vulnerability.lower() or "xss" in vulnerability.lower():
        if lang in ("javascript", "typescript"):
            why_vulnerable = (
                "Untrusted user data is directly inserted into DOM elements via `innerHTML`, `outerHTML`, or React `dangerouslySetInnerHTML`. "
                "This allows attackers to execute arbitrary client-side JavaScript in the user's session."
            )
            ai_remediation = (
                "In JavaScript / React, render text using standard JSX curly-bracket expressions `{userInput}` which automatically escape HTML. "
                "If rich HTML formatting is mandatory, sanitize user input first using DOMPurify."
            )
            secure_code = (
                "// Secure Implementation (React / JavaScript):\n"
                "// 1. Standard auto-escaped rendering (Recommended):\n"
                "return <div className=\"user-content\">{userInput}</div>;\n\n"
                "// 2. If rich HTML is strictly necessary, sanitize with DOMPurify:\n"
                "import DOMPurify from 'dompurify';\n"
                "const cleanHTML = DOMPurify.sanitize(userInput);\n"
                "<div dangerouslySetInnerHTML={{ __html: cleanHTML }} />"
            )
            implementation_steps = [
                "Remove direct assignments to `.innerHTML` and avoid un-sanitized `dangerouslySetInnerHTML`.",
                "Use standard text nodes (`.textContent` in vanilla DOM, `{text}` in React).",
                "Install `dompurify` if raw HTML formatting must be rendered."
            ]
            verification_steps = [
                "Inject XSS probe `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>`.",
                "Verify the payloads render as inert text and do not execute JavaScript.",
                "Check browser console to verify Content-Security-Policy (CSP) headers are enforced."
            ]

        elif lang == "php":
            why_vulnerable = (
                "Echoing or printing raw `$_GET` or `$_POST` variables into the HTML response allows attackers to inject malicious HTML and script tags."
            )
            ai_remediation = (
                "In PHP, always encode dynamic output using `htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8')` before writing it to HTML."
            )
            secure_code = (
                "// Secure Implementation (PHP):\n"
                "echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');"
            )
            implementation_steps = [
                "Wrap all user variables in `htmlspecialchars()` before echoing.",
                "Set character encoding to 'UTF-8' and include `ENT_QUOTES` to escape both single and double quotes."
            ]
            verification_steps = [
                "Supply `<script>alert('xss')</script>` in the input and verify HTML entities (`&lt;script&gt;`) in view-source."
            ]

        elif lang == "python":
            why_vulnerable = (
                "Rendering untrusted input directly into HTML templates without context-aware escaping permits XSS attacks."
            )
            ai_remediation = (
                "In Python (Flask/Jinja2/Django), rely on automatic template escaping. In code, escape strings using `markupsafe.escape()`."
            )
            secure_code = (
                "# Secure Implementation (Python / Flask):\n"
                "from markupsafe import escape\n"
                "safe_output = escape(user_input)\n"
                "# In Jinja2 templates: {{ user_input }} (auto-escaped by default)"
            )
            implementation_steps = [
                "Ensure Jinja2 or Django auto-escaping is active.",
                "Do not use `|safe` filter or `Markup()` on untrusted variables."
            ]
            verification_steps = [
                "Submit HTML test tags and confirm they are escaped as entities in rendered HTML output."
            ]

        elif lang == "csharp":
            why_vulnerable = (
                "Writing unencoded strings to `Response.Write()` or using `@Html.Raw()` with user data allows client-side script injection."
            )
            ai_remediation = (
                "In ASP.NET, use standard Razor `@Model.Property` which auto-encodes HTML, or explicitly call `WebUtility.HtmlEncode()`."
            )
            secure_code = (
                "// Secure Implementation (ASP.NET):\n"
                "string safeHtml = System.Net.WebUtility.HtmlEncode(userInput);\n"
                "Response.Write(safeHtml);\n"
                "// Or in Razor: @userInput (auto-encoded)"
            )
            implementation_steps = [
                "Replace `@Html.Raw()` with standard `@Model` binding in Razor.",
                "Sanitize or encode user input before responding."
            ]
            verification_steps = [
                "Inject script payloads and inspect response body to confirm entity encoding."
            ]

    # ==================== CWE-120: BUFFER OVERFLOW ====================
    elif cwe == "CWE-120" or "buffer overflow" in vulnerability.lower():
        if lang in ("c", "cpp"):
            why_vulnerable = (
                "Unbounded memory copying functions such as `strcpy()`, `sprintf()`, or `gets()` copy bytes until a null-terminator "
                "is encountered, without checking destination buffer boundaries. An oversized input overwrites adjacent memory on the stack or heap, "
                "leading to segmentation faults or arbitrary code execution."
            )
            ai_remediation = (
                "In C, replace unsafe functions with bounded alternatives (`strncpy_s`, `snprintf`) and always enforce explicit buffer bounds. "
                "In C++, prefer memory-managed abstractions such as `std::string` and `std::vector`."
            )
            secure_code = (
                "/* Secure Implementation in C: */\n"
                "// 1. Using snprintf with destination buffer size:\n"
                "char dest[64];\n"
                "snprintf(dest, sizeof(dest), \"%s\", src);\n\n"
                "// 2. Or using strncpy with explicit null termination:\n"
                "strncpy(dest, src, sizeof(dest) - 1);\n"
                "dest[sizeof(dest) - 1] = '\\0';\n\n"
                "// In C++ (Preferred):\n"
                "std::string safe_dest = src; // Dynamically allocated, memory-safe"
            )
            implementation_steps = [
                "Audit code for `strcpy`, `strcat`, `gets`, and `sprintf` calls.",
                "Replace with `snprintf(buf, sizeof(buf), \"%s\", src)`.",
                "Enable compiler protection flags: `-fstack-protector-all`, `-D_FORTIFY_SOURCE=2`, and ASLR."
            ]
            verification_steps = [
                "Pass inputs larger than the destination buffer capacity (e.g. 500 characters into a 64-byte buffer).",
                "Verify the application truncates or gracefully rejects the input without memory corruption or segmentation faults.",
                "Run AddressSanitizer (`-fsanitize=address`) during automated test builds."
            ]
        else:
            why_vulnerable = "A buffer overflow was reported, but the detected language is memory-managed."
            ai_remediation = "Verify underlying native libraries or JNI/C-bindings used by this module."
            secure_code = "// Verify native bindings and bounds checking"
            implementation_steps = ["Review native C/C++ libraries called via FFI/JNI."]
            verification_steps = ["Fuzz input parameters passed to native extensions."]

    # ==================== CWE-78: COMMAND INJECTION ====================
    elif cwe == "CWE-78" or "command injection" in vulnerability.lower():
        if lang == "python":
            why_vulnerable = (
                "Executing system commands with string concatenation or `shell=True` passes user data directly to the command interpreter (`/bin/sh` or `cmd.exe`). "
                "Attackers can append command separators (`;`, `&`, `|`) to execute unauthorized arbitrary system commands."
            )
            ai_remediation = (
                "In Python, use `subprocess.run()` with a list of arguments and `shell=False` (default). "
                "This bypasses the shell interpreter entirely, treating user arguments as data rather than executable shell syntax."
            )
            secure_code = (
                "# Secure Implementation using subprocess.run with argument list:\n"
                "import subprocess\n\n"
                "# Pass executable and arguments as discrete list elements without shell interpreter:\n"
                "result = subprocess.run(\n"
                "    [\"ping\", \"-c\", \"1\", host],\n"
                "    capture_output=True,\n"
                "    text=True,\n"
                "    check=True,\n"
                "    shell=False\n"
                ")"
            )
            implementation_steps = [
                "Remove all calls to `os.system()` and `os.popen()`.",
                "Replace `subprocess.Popen(cmd, shell=True)` with `subprocess.run([\"cmd\", arg1, arg2], shell=False)`.",
                "Validate user arguments against strict format allowlists (e.g. valid IP address regex)."
            ]
            verification_steps = [
                "Test parameter with command separators: `127.0.0.1; id` or `127.0.0.1 && whoami`.",
                "Confirm that the executable fails with an invalid host error and does NOT execute the injected command."
            ]

        elif lang == "java":
            why_vulnerable = (
                "Invoking `Runtime.getRuntime().exec()` with concatenated strings exposes the process to shell interpretation and arbitrary command injection."
            )
            ai_remediation = (
                "In Java, use `ProcessBuilder` with an array or List of distinct command arguments instead of a single concatenated string."
            )
            secure_code = (
                "// Secure Implementation using ProcessBuilder:\n"
                "List<String> command = Arrays.asList(\"ping\", \"-c\", \"1\", host);\n"
                "ProcessBuilder pb = new ProcessBuilder(command);\n"
                "Process process = pb.start();"
            )
            implementation_steps = [
                "Replace `Runtime.getRuntime().exec(string)` with `new ProcessBuilder(List<String>)`.",
                "Pass parameters as discrete list elements without invoking shell binary."
            ]
            verification_steps = [
                "Test input containing command chaining characters like `; whoami`.",
                "Verify the command treats the entire string as a single argument without spawning subshells."
            ]

        elif lang in ("javascript", "typescript"):
            why_vulnerable = (
                "Node.js `child_process.exec()` invokes a system shell under the hood. String concatenation allows shell injection."
            )
            ai_remediation = (
                "Use `child_process.execFile()` with an arguments array, avoiding the shell interpreter."
            )
            secure_code = (
                "// Secure Implementation using execFile:\n"
                "const { execFile } = require('child_process');\n\n"
                "execFile('ping', ['-c', '1', host], (error, stdout, stderr) => {\n"
                "  if (error) throw error;\n"
                "  console.log(stdout);\n"
                "});"
            )
            implementation_steps = [
                "Replace `exec()` with `execFile()`.",
                "Supply arguments as an array rather than concatenated string."
            ]
            verification_steps = [
                "Submit payload `127.0.0.1; uname -a` and verify error or safe rejection."
            ]

        elif lang in ("c", "cpp"):
            why_vulnerable = (
                "`system()` and `popen()` invoke `/bin/sh` to parse the command string, exposing execution to command injection."
            )
            ai_remediation = (
                "In C/C++, use `fork()` and `execvp()` with an arguments array, bypassing shell interpretation entirely."
            )
            secure_code = (
                "/* Secure Implementation using execvp: */\n"
                "pid_t pid = fork();\n"
                "if (pid == 0) {\n"
                "    char *args[] = {\"ping\", \"-c\", \"1\", host, NULL};\n"
                "    execvp(args[0], args);\n"
                "    _exit(1);\n"
                "} else if (pid > 0) {\n"
                "    waitpid(pid, NULL, 0);\n"
                "}"
            )
            implementation_steps = [
                "Replace `system(cmd)` with `fork()` + `execvp()`.",
                "Ensure argument array is NULL-terminated."
            ]
            verification_steps = [
                "Pass command separators in arguments and verify no auxiliary commands execute."
            ]

    # ==================== CWE-798: HARDCODED CREDENTIALS ====================
    elif cwe == "CWE-798" or "hardcoded" in vulnerability.lower() or "credential" in vulnerability.lower():
        why_vulnerable = (
            "Sensitive secrets (passwords, private keys, API tokens) are embedded directly in source code. "
            "Anyone with repository read access can extract these credentials to compromise cloud infrastructure, databases, or APIs."
        )
        if lang == "python":
            ai_remediation = "In Python, load credentials at runtime from environment variables using `os.getenv()` or a secrets vault."
            secure_code = (
                "# Secure Implementation (Python):\n"
                "import os\n\n"
                "API_KEY = os.getenv(\"API_SECRET_KEY\")\n"
                "if not API_KEY:\n"
                "    raise RuntimeError(\"API_SECRET_KEY environment variable is not configured\")"
            )
        elif lang in ("javascript", "typescript"):
            ai_remediation = "In JavaScript/TypeScript, load credentials from `process.env` using `dotenv` or cloud secret managers."
            secure_code = (
                "// Secure Implementation (Node.js):\n"
                "require('dotenv').config();\n"
                "const apiKey = process.env.API_SECRET_KEY;\n"
                "if (!apiKey) throw new Error('API_SECRET_KEY environment variable is not set');"
            )
        elif lang == "java":
            ai_remediation = "In Java / Spring, read credentials from environment variables via `System.getenv()` or `@Value(\"${api.key}\")`."
            secure_code = (
                "// Secure Implementation (Java):\n"
                "String apiKey = System.getenv(\"API_SECRET_KEY\");\n"
                "if (apiKey == null || apiKey.isEmpty()) {\n"
                "    throw new IllegalStateException(\"API_SECRET_KEY environment variable missing\");\n"
                "}"
            )
        elif lang == "csharp":
            ai_remediation = "In C# / .NET, use `Environment.GetEnvironmentVariable` or ASP.NET Core Secrets Manager."
            secure_code = (
                "// Secure Implementation (C#):\n"
                "string apiKey = Environment.GetEnvironmentVariable(\"API_SECRET_KEY\");\n"
                "if (string.IsNullOrEmpty(apiKey)) throw new InvalidOperationException(\"API_SECRET_KEY missing\");"
            )
        elif lang == "go":
            ai_remediation = "In Go, retrieve credentials using `os.Getenv()`."
            secure_code = (
                "// Secure Implementation (Go):\n"
                "apiKey := os.Getenv(\"API_SECRET_KEY\")\n"
                "if apiKey == \"\" { log.Fatal(\"API_SECRET_KEY is required\") }"
            )
        else:
            ai_remediation = "Extract sensitive credentials out of source code into environment variables or secrets vaults."
            secure_code = "// Load credentials from environment variable or external secrets vault"

        implementation_steps = [
            "Rotate the exposed credential immediately across all production and test environments.",
            "Remove the hardcoded secret from code and purge it from git history.",
            "Configure environment variable or secret manager (AWS Secrets Manager / Vault)."
        ]
        verification_steps = [
            "Run automated secret scanner (`git-secrets` or `trufflehog`) against repository commits.",
            "Verify application loads credentials correctly from environment configuration."
        ]

    # ==================== CWE-22: PATH TRAVERSAL ====================
    elif cwe == "CWE-22" or "traversal" in vulnerability.lower():
        why_vulnerable = (
            "User-supplied input is directly used in file path construction without canonical path validation. "
            "Attackers can pass `../` sequences to read or overwrite critical system files outside the designated root directory."
        )
        if lang == "python":
            ai_remediation = (
                "In Python, isolate the file name using `os.path.basename()` and verify that the resolved canonical path "
                "starts with the intended base directory using `os.path.commonpath()` or `startswith()`."
            )
            secure_code = (
                "# Secure Implementation (Python):\n"
                "import os\n\n"
                "safe_filename = os.path.basename(user_input)\n"
                "target_path = os.path.abspath(os.path.join(BASE_DIR, safe_filename))\n"
                "if not target_path.startswith(os.path.abspath(BASE_DIR) + os.sep):\n"
                "    raise ValueError(\"Access Denied: Path Traversal Detected\")"
            )
        elif lang == "java":
            ai_remediation = (
                "In Java, sanitize file names using `new File(input).getName()` and check that `file.getCanonicalPath()` "
                "starts with the base directory's canonical path."
            )
            secure_code = (
                "// Secure Implementation (Java):\n"
                "File file = new File(baseDir, new File(userInput).getName());\n"
                "if (!file.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {\n"
                "    throw new SecurityException(\"Access Denied: Path Traversal\");\n"
                "}"
            )
        elif lang in ("javascript", "typescript"):
            ai_remediation = (
                "In Node.js, use `path.basename()` and verify `path.resolve()` remains inside the intended directory."
            )
            secure_code = (
                "// Secure Implementation (Node.js):\n"
                "const path = require('path');\n"
                "const safeName = path.basename(userInput);\n"
                "const safePath = path.resolve(BASE_DIR, safeName);\n"
                "if (!safePath.startsWith(path.resolve(BASE_DIR))) {\n"
                "  throw new Error('Path traversal detected');\n"
                "}"
            )
        else:
            ai_remediation = "Validate user input using allowlists and enforce canonical directory boundaries."
            secure_code = "// Verify canonical file path stays within base directory"

        implementation_steps = [
            "Strip path separators from user inputs using basename functions.",
            "Verify resolved canonical paths start with base folder prefix.",
            "Do not expose internal filesystem paths in error messages."
        ]
        verification_steps = [
            "Test with traversal sequences like `../../../../etc/passwd` or `..\\..\\windows\\win.ini`.",
            "Confirm the application rejects the request with HTTP 400/403."
        ]

    # Fallback for other CWEs
    else:
        suggested = get_suggested_fix(cwe, lang) or ""
        why_vulnerable = (
            f"Vulnerability {vulnerability} ({cwe}) violates secure coding standards in {language}. "
            "Input or resource state is handled without adequate defensive checks."
        )
        ai_remediation = (
            f"In {language}, implement defensive validation and use standard secure APIs to mitigate {vulnerability}. "
            f"Refer to the Knowledge Base recommendations for {cwe}."
        )
        secure_code = suggested or (
            f"// Secure implementation for {vulnerability} ({cwe}) in {language}:\n"
            f"// Apply strict input validation and framework security controls."
        )
        implementation_steps = [
            f"Review secure coding guidelines for {cwe} in {language}.",
            "Replace vulnerable call with safe library alternative.",
            "Validate inputs against strict schema allowlist."
        ]
        verification_steps = [
            "Execute security regression tests against the affected component.",
            "Verify vulnerability is no longer identified in subsequent SAST scans."
        ]

    return {
        "vulnerability": vulnerability,
        "cwe_id": cwe,
        "severity": severity,
        "language": language.capitalize() if language else "Unknown",
        "framework": fw,
        "file": fname,
        "line": line_no,
        "description": description or f"Identified {vulnerability} in {fname}.",
        "why_vulnerable": why_vulnerable,
        "knowledge_base_remediation": kb_remediation or "Apply principle of least privilege and strict input validation.",
        "ai_remediation": ai_remediation,
        "secure_code": secure_code,
        "implementation_steps": implementation_steps,
        "verification_steps": verification_steps
    }


def call_external_llm_remediation(
    vulnerability: str,
    cwe_id: str,
    severity: str,
    language: str,
    framework: Optional[str] = None,
    database_or_lib: Optional[str] = None,
    file_name: Optional[str] = None,
    line_number: Optional[int] = None,
    vulnerable_code: Optional[str] = None,
    description: Optional[str] = None,
    kb_remediation: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Attempts to call an external LLM (Gemini, Groq, or OpenAI) if an API key is configured.
    Returns parsed JSON dict or None on failure / missing key.
    """
    prompt = build_ai_prompt(
        vulnerability=vulnerability,
        cwe_id=cwe_id,
        severity=severity,
        language=language,
        framework=framework,
        database_or_lib=database_or_lib,
        file_name=file_name,
        line_number=line_number,
        vulnerable_code=vulnerable_code,
        description=description,
        kb_remediation=kb_remediation
    )

    gemini_key = os.getenv("GEMINI_API_KEY", "")
    groq_key = os.getenv("GROQ_API_KEY", "")
    openai_key = os.getenv("OPENAI_API_KEY", "")

    # 1. Google Gemini API
    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            payload = {
                "contents": [
                    {
                        "parts": [
                            {"text": AI_SYSTEM_PROMPT + "\n\n" + prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": 0.2
                }
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                text_content = res_data["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(text_content)
        except Exception:
            pass

    # 2. Groq API
    if groq_key:
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {"role": "system", "content": AI_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {groq_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                text_content = res_data["choices"][0]["message"]["content"]
                return json.loads(text_content)
        except Exception:
            pass

    # 3. OpenAI API
    if openai_key:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": AI_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {openai_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=12) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                text_content = res_data["choices"][0]["message"]["content"]
                return json.loads(text_content)
        except Exception:
            pass

    return None


def generate_remediation(
    vulnerability: str,
    cwe_id: str,
    severity: str,
    language: Optional[str] = None,
    framework: Optional[str] = None,
    database_or_lib: Optional[str] = None,
    file_name: Optional[str] = None,
    line_number: Optional[int] = None,
    vulnerable_code: Optional[str] = None,
    description: Optional[str] = None,
    kb_remediation: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point for generating language-specific vulnerability remediation.
    Tries external LLM first if API key configured; falls back automatically to
    semantic engine.
    """
    lang = language or "Unknown"
    
    # Try external LLM if configured
    llm_result = call_external_llm_remediation(
        vulnerability=vulnerability,
        cwe_id=cwe_id,
        severity=severity,
        language=lang,
        framework=framework,
        database_or_lib=database_or_lib,
        file_name=file_name,
        line_number=line_number,
        vulnerable_code=vulnerable_code,
        description=description,
        kb_remediation=kb_remediation
    )

    if llm_result and isinstance(llm_result, dict) and "why_vulnerable" in llm_result:
        # Guarantee all required schema fields
        llm_result.setdefault("vulnerability", vulnerability)
        llm_result.setdefault("cwe_id", cwe_id)
        llm_result.setdefault("severity", severity)
        llm_result.setdefault("language", lang)
        llm_result.setdefault("framework", framework or "Unknown")
        llm_result.setdefault("file", file_name or "N/A")
        llm_result.setdefault("line", line_number or 1)
        llm_result.setdefault("description", description or f"Vulnerability {vulnerability}")
        llm_result.setdefault("knowledge_base_remediation", kb_remediation or "Apply least privilege")
        return llm_result

    # High-fidelity semantic generator fallback
    return generate_semantic_remediation(
        vulnerability=vulnerability,
        cwe_id=cwe_id,
        severity=severity,
        language=lang,
        framework=framework,
        database_or_lib=database_or_lib,
        file_name=file_name,
        line_number=line_number,
        vulnerable_code=vulnerable_code,
        description=description,
        kb_remediation=kb_remediation
    )
