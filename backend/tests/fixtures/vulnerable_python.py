import os
import pickle
import hashlib
import random
import requests
from flask import Flask, request
import sqlite3

app = Flask(__name__)

# 1. Hardcoded Secret (CWE-798)
API_SECRET_KEY = "STRIPE_TEST_SECRET_PLACEHOLDER"
AWS_KEY = "AWS_ACCESS_KEY_TEST_PLACEHOLDER"

# 2. SQL Injection (CWE-89)
def get_user_bad(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()

def get_user_fstring(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_id}'")
    return cursor.fetchall()

# 3. Command Injection (CWE-78)
def ping_server_bad(host):
    os.system("ping -c 1 " + host)

# 4. Insecure Deserialization (CWE-502)
def load_session_bad(serialized_data):
    return pickle.loads(serialized_data)

# 5. Weak Cryptography (CWE-327)
def hash_password_bad(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def hash_sha1_bad(pwd):
    return hashlib.sha1(pwd.encode()).hexdigest()

# 6. Path Traversal (CWE-22)
def read_user_file_bad(filename):
    with open("/var/www/uploads/" + filename, "r") as f:
        return f.read()

# 7. SSRF (CWE-918)
def fetch_external_url_bad(user_url):
    return requests.get(user_url, timeout=5)

# 8. Insecure Randomness (CWE-330)
def generate_auth_token():
    auth_token = str(random.randint(100000, 999999))
    return auth_token

# 9. Debug Configuration (CWE-489)
if __name__ == "__main__":
    app.run(debug=True)
