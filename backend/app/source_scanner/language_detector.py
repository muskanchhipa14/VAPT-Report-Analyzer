import os
from typing import Optional

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
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

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2MB max file size limit for static scanning


def is_ignored_directory(dir_name: str) -> bool:
    return dir_name.strip().lower() in IGNORED_DIRECTORIES


def should_skip_path(path: str) -> bool:
    normalized = os.path.normpath(path)
    parts = normalized.split(os.sep)
    for part in parts:
        if part.lower() in IGNORED_DIRECTORIES:
            return True
    return False


def detect_language(file_path: str) -> Optional[str]:
    """
    Returns detected language identifier ('python', 'javascript', 'java')
    or None if unsupported / ignored.
    """
    if should_skip_path(file_path):
        return None

    ext = os.path.splitext(file_path)[1].lower()
    if ext in IGNORED_EXTENSIONS:
        return None

    return SUPPORTED_EXTENSIONS.get(ext)


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
