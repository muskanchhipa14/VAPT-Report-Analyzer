import os
import re
from typing import Optional, Tuple, Dict, Any

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
}

IGNORED_DIRECTORIES = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    "dist",
    "build",
    "target",
    "out",
    "bin",
    "obj",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".next",
    ".nuxt",
    "vendor",
    "coverage",
    ".nyc_output",
}

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".class", ".jar", ".war", ".ear",
    ".pyc", ".pyo", ".pyd",
    ".wasm", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi",
    ".db", ".sqlite", ".sqlite3",
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB max file size limit for static scanning


def is_ignored_directory(dir_name: str) -> bool:
    return dir_name.strip().lower() in IGNORED_DIRECTORIES


def should_skip_path(path: str) -> bool:
    normalized = os.path.normpath(path)
    parts = normalized.split(os.sep)
    for part in parts:
        if part.lower() in IGNORED_DIRECTORIES:
            return True
    return False


def is_binary_file(file_path: str) -> bool:
    """
    Inspects first 1024 bytes to check for null bytes or binary characters.
    """
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
            return True
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
        return False
    except Exception:
        return True


def detect_language_from_syntax(content: str) -> Optional[str]:
    """
    Syntactically inspects code content to determine language when extension is absent or ambiguous.
    """
    if not content or not content.strip():
        return None

    # PHP tag check (very distinctive)
    if re.search(r"<\?php", content, re.IGNORECASE) or re.search(r"\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*\s*=", content):
        return "php"

    # Go package/import syntax
    if re.search(r"\bpackage\s+[a-zA-Z0-9_]+", content) and re.search(r"\bfunc\s+(?:\([^\)]+\)\s*)?[a-zA-Z0-9_]+\s*\(", content):
        return "go"

    # C# namespace / using System
    if re.search(r"\busing\s+System(?:\.[a-zA-Z0-9_]+)*\s*;", content) or re.search(r"\bnamespace\s+[a-zA-Z0-9_.]+", content):
        return "csharp"

    # Java class / package syntax
    if re.search(r"\b(?:public\s+|private\s+|protected\s+)?class\s+[a-zA-Z0-9_]+\s*\{", content) and (
        re.search(r"\bSystem\.(?:out|err)\.print", content) or
        re.search(r"\bpublic\s+static\s+void\s+main\s*\(", content) or
        re.search(r"\bimport\s+java\.", content)
    ):
        return "java"

    # C++ distinctive patterns
    if (re.search(r"#include\s*<iostream>", content) or
        re.search(r"\bstd::(?:cout|cin|vector|string|make_shared|unique_ptr)\b", content) or
        re.search(r"\bnamespace\s+[a-zA-Z0-9_]+\s*\{", content) or
        re.search(r"\btemplate\s*<\s*typename", content)):
        return "cpp"

    # C distinctive patterns
    if (re.search(r"#include\s*<stdio\.h>", content) or
        re.search(r"#include\s*<stdlib\.h>", content) or
        re.search(r"\bint\s+main\s*\(\s*(?:void|int\s+[a-zA-Z0-9_]+)", content) or
        re.search(r"\bprintf\s*\(", content)):
        return "c"

    # Python distinctive patterns
    if (re.search(r"\bdef\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*:", content) or
        re.search(r"\bimport\s+[a-zA-Z0-9_]+", content) or
        re.search(r"\bfrom\s+[a-zA-Z0-9_.]+\s+import\b", content) or
        re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]:", content) or
        re.search(r"\belif\s+[^:]+:", content)):
        return "python"

    # TypeScript distinctive patterns
    if (re.search(r"\binterface\s+[A-Z][a-zA-Z0-9_]*\s*\{", content) or
        re.search(r"\btype\s+[A-Z][a-zA-Z0-9_]*\s*=", content) or
        re.search(r":\s*(?:string|number|boolean|any|void)\b", content)):
        return "typescript"

    # JavaScript distinctive patterns
    if (re.search(r"\b(?:const|let|var)\s+[a-zA-Z0-9_]+\s*=", content) or
        re.search(r"\bfunction\s+[a-zA-Z0-9_]*\s*\(", content) or
        re.search(r"\bconsole\.(?:log|warn|error)\s*\(", content) or
        re.search(r"\bmodule\.exports\b", content) or
        re.search(r"=>", content)):
        return "javascript"

    # Ruby distinctive patterns
    if (re.search(r"\bdef\s+[a-zA-Z0-9_]+(?:\([^\)]*\))?\s*$", content, re.MULTILINE) and
        re.search(r"\bend\b", content) and
        (re.search(r"\bputs\b", content) or re.search(r"\brequire\s+['\"][^'\"]+['\"]", content))):
        return "ruby"

    return None


def detect_framework_and_library(content: str, language: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Infers the web/application framework and database or major security library
    from source code imports, decorators, or function calls.
    """
    if not content:
        return None, None

    framework = None
    database_or_lib = None
    lang = (language or "").lower()

    # Framework Detection
    if lang == "python" or not lang:
        if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b|\bFlask\s*\(|@app\.route", content):
            framework = "Flask"
        elif re.search(r"\bfrom\s+django\b|\bimport\s+django\b|django\.db|models\.Model", content):
            framework = "Django"
        elif re.search(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b|\bFastAPI\s*\(", content):
            framework = "FastAPI"
        elif re.search(r"\btornado\b", content):
            framework = "Tornado"

    if lang in ("javascript", "typescript") or not lang:
        if re.search(r"\bfrom\s+['\"]react['\"]|\bimport\s+React\b|dangerouslySetInnerHTML|useState\(|useEffect\(", content):
            framework = "React"
        elif re.search(r"\bfrom\s+['\"]express['\"]|require\(['\"]express['\"]\)|\bexpress\(\)", content):
            framework = "Express"
        elif re.search(r"\bnext/router\b|\bgetStaticProps\b|\bgetServerSideProps\b", content):
            framework = "Next.js"
        elif re.search(r"@Controller\b|@Injectable\b|@nestjs", content):
            framework = "NestJS"
        elif not framework and re.search(r"\bhttp\.createServer\b|\bchild_process\b|\bfs\b", content):
            framework = "Node.js"

    if lang == "java" or not lang:
        if re.search(r"org\.springframework|@RestController|@Controller|@RequestMapping|@GetMapping|@Autowired", content):
            framework = "Spring Boot"
        elif re.search(r"javax\.servlet|jakarta\.servlet|@WebServlet|HttpServletRequest", content):
            framework = "Jakarta Servlets"

    if lang == "php" or not lang:
        if re.search(r"use\s+Illuminate\\|\bRoute::(?:get|post)\b|\bEloquent\b", content):
            framework = "Laravel"
        elif re.search(r"use\s+Symfony\\|\bSymfony\b", content):
            framework = "Symfony"
        elif not framework and re.search(r"<\?php", content):
            framework = "Plain PHP"

    if lang == "csharp" or not lang:
        if re.search(r"Microsoft\.AspNetCore|\[ApiController\]|\[Route\(", content):
            framework = "ASP.NET Core"
        elif re.search(r"System\.Web\.Mvc|System\.Web\.Http", content):
            framework = "ASP.NET MVC"

    if lang == "go" or not lang:
        if re.search(r"github\.com/gin-gonic/gin", content):
            framework = "Gin"
        elif re.search(r"github\.com/labstack/echo", content):
            framework = "Echo"
        elif re.search(r"github\.com/go-chi/chi", content):
            framework = "Chi"
        elif re.search(r"net/http", content):
            framework = "net/http (Standard)"

    # Database / Client Library Detection
    if re.search(r"\bsqlalchemy\b", content, re.IGNORECASE):
        database_or_lib = "SQLAlchemy ORM"
    elif re.search(r"\bpsycopg2\b|\bpg\b|\bpostgres\b", content, re.IGNORECASE):
        database_or_lib = "PostgreSQL Client"
    elif re.search(r"\bsqlite3\b|\bsqlite\b", content, re.IGNORECASE):
        database_or_lib = "SQLite3"
    elif re.search(r"\bmysql2?\b|\bpymysql\b", content, re.IGNORECASE):
        database_or_lib = "MySQL Client"
    elif re.search(r"\bmongodb\b|\bmongoose\b|\bpymongo\b", content, re.IGNORECASE):
        database_or_lib = "MongoDB"
    elif re.search(r"\bPreparedStatement\b|\bjava\.sql\b", content):
        database_or_lib = "JDBC PreparedStatement"
    elif re.search(r"\bPDO\b|\bmysqli\b", content):
        database_or_lib = "PHP PDO"
    elif re.search(r"\bSqlCommand\b|\bSqlConnection\b", content):
        database_or_lib = "ADO.NET SqlCommand"
    elif re.search(r"\bdatabase/sql\b", content):
        database_or_lib = "Go database/sql"

    return framework, database_or_lib


def detect_language(file_path: Optional[str] = None, content: Optional[str] = None) -> Optional[str]:
    """
    Returns detected language identifier ('python', 'javascript', 'typescript',
    'java', 'c', 'cpp', 'php', 'csharp', 'go', 'ruby') or None if unknown/ignored.
    Multi-tier strategy:
      1. File extension check (fast & authoritative)
      2. Content syntax inspection fallback
    """
    if file_path:
        if should_skip_path(file_path):
            return None

        ext = os.path.splitext(file_path)[1].lower()
        if ext in IGNORED_EXTENSIONS:
            return None

        detected = SUPPORTED_EXTENSIONS.get(ext)
        if detected:
            return detected

    # Fallback to syntax inspection if content provided or readable from file
    if content:
        return detect_language_from_syntax(content)
    elif file_path and os.path.exists(file_path) and not is_binary_file(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                snippet = f.read(4096)
                return detect_language_from_syntax(snippet)
        except Exception:
            return None

    return None


def detect_language_and_context(file_path: Optional[str] = None, content: Optional[str] = None) -> Dict[str, Any]:
    """
    Comprehensive context detection returning language, framework, database/library,
    and the detection method.
    """
    code_text = content or ""
    if not code_text and file_path and os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code_text = f.read()
        except Exception:
            code_text = ""

    # Tier 1: Extension
    ext = os.path.splitext(file_path)[1].lower() if file_path else ""
    lang = SUPPORTED_EXTENSIONS.get(ext)
    method = "file_extension" if lang else "unknown"

    # Tier 2: Syntax analysis
    if not lang and code_text:
        lang = detect_language_from_syntax(code_text)
        if lang:
            method = "code_syntax"

    # Tier 3: Framework and library
    framework, db_lib = detect_framework_and_library(code_text, lang)

    return {
        "language": lang or "Unknown",
        "framework": framework or "Unknown",
        "database_or_library": db_lib or "Unknown",
        "detection_method": method
    }
