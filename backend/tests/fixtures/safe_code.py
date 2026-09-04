import os
import hashlib
import secrets
import subprocess
from urllib.parse import urlparse

# Safe credential loading
API_KEY = os.getenv("API_KEY")

# Safe parameterized SQL query
def get_user_safe(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

# Safe command execution (array arguments without shell)
def ping_safe(host):
    return subprocess.run(["ping", "-c", "1", host], check=True, capture_output=True)

# Safe hashing
def hash_safe(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Safe CSPRNG
def generate_token_safe():
    return secrets.token_hex(32)

# Safe file path resolution
def read_file_safe(base_dir, filename):
    safe_name = os.path.basename(filename)
    full_path = os.path.abspath(os.path.join(base_dir, safe_name))
    if not full_path.startswith(os.path.abspath(base_dir)):
        raise PermissionError("Path traversal attempt detected")
    with open(full_path, "r") as f:
        return f.read()
