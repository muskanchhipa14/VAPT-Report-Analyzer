# VAPT Report Analyzer & Source Code Security Scanner (SAST)

A full-stack, enterprise-grade cybersecurity application for automated vulnerability assessment, report parsing, and source code static analysis (SAST).

The platform features two operational analysis modes:
1. **VAPT Report Analysis**: Parses `.pdf` and `.docx` penetration test reports, extracts findings via heuristic keyword and CWE matching, maps issues to the Knowledge Base, and generates remediation reports.
2. **Source Code Analysis (SAST)**: Accepts project source archives (`.zip`), safely unpacks files, detects languages, performs Abstract Syntax Tree (AST) and structural rule analysis across Python, JavaScript/React, and Java, matches findings with the Knowledge Base, highlights vulnerable code lines, provides suggested fixes, and exports executive PDF reports.

---

## System Architecture

```text
                               +----------------------------------------+
                               |              User Browser              |
                               +----------------------------------------+
                                                    |
                                                    v
                               +----------------------------------------+
                               |     React + Tailwind CSS Frontend      |
                               +----------------------------------------+
                                         |                    |
                 Mode 1: VAPT Reports    |                    |    Mode 2: SAST Upload
                 (.pdf / .docx)          |                    |    (.zip archive)
                                         v                    v
                               +----------------------------------------+
                               |            FastAPI Backend             |
                               |    (JWT Auth, RBAC, Audit Logging)     |
                               +----------------------------------------+
                                         |                    |
                                         |                    v
                                         |     +-------------------------------+
                                         |     |     Safe ZIP Extraction       |
                                         |     |  (Anti-ZipSlip, Quota Guards) |
                                         |     +-------------------------------+
                                         |                    |
                                         |                    v
                                         |     +-------------------------------+
                                         |     |    Language Detector Engine   |
                                         |     |   (Python, JS/JSX, Java, etc) |
                                         |     +-------------------------------+
                                         |                    |
                                         |                    v
                                         |     +-------------------------------+
                                         |     |      Static Analysis AST      |
                                         |     |   - Python: AST NodeVisitor   |
                                         |     |   - JS/JSX: Structural Parser |
                                         |     |   - Java: Pattern Analyzer    |
                                         |     +-------------------------------+
                                         |                    |
                                         +----------+---------+
                                                    |
                                                    v
                               +----------------------------------------+
                               |       CWE Vulnerability Mapper         |
                               +----------------------------------------+
                                                    |
                                                    v
                               +----------------------------------------+
                               |       Vulnerability Knowledge Base     |
                               |    (39+ CWEs, OWASP 2021, CAPEC, Fixes)|
                               +----------------------------------------+
                                         |                    |
                                         v                    v
                               +-------------------+   +--------------------+
                               | SQLite / Postgres |   | ReportLab Engine   |
                               |   Database Store  |   | (PDF Generation)   |
                               +-------------------+   +--------------------+
```

---

## Analysis Workflow: Source Code Scanner

```text
User Uploads (.zip)
    ↓
File Type & Quota Validation (Max 50MB, max 2000 files, 150MB uncompressed)
    ↓
Safe Extraction (Canonical path resolution prevents Zip Slip directory traversal)
    ↓
Language Detection (Filters binary files, vendor dirs, node_modules, .git, venv)
    ↓
AST / Structural Parsing
    ├── Python: ast.parse() + AST NodeVisitor for dynamic queries, exec, pickle, etc.
    ├── JavaScript / React: Regex & structural patterns for innerHTML, dangerouslySetInnerHTML, child_process.exec, etc.
    └── Java: Pattern analyzer for dynamic SQL, ProcessBuilder, XXE, etc.
    ↓
CWE Vulnerability Mapping (CWE-89, CWE-79, CWE-78, CWE-502, CWE-327, CWE-798, CWE-22, CWE-918, CWE-330, CWE-489)
    ↓
Knowledge Base Retrieval (Pulls descriptions, remediation guidelines, OWASP Top 10)
    ↓
Suggested Fix Synthesis (Attaches example safer implementation)
    ↓
Database Persistence (Stores in source_code_analyses & source_code_findings)
    ↓
Audit Logging (Records SOURCE_CODE_ANALYSIS_COMPLETED)
    ↓
Interactive Frontend Dashboard (Visual charts, filters, code inspector drawer)
    ↓
Executive PDF Export (ReportLab styled report with code context and suggested fixes)
```

---

## Supported Languages & File Types

| Language | Extensions | Analysis Method |
| :--- | :--- | :--- |
| **Python** | `.py` | Full Abstract Syntax Tree (`ast` module) + regex heuristics |
| **JavaScript / React** | `.js`, `.jsx`, `.mjs`, `.cjs` | Structural pattern analyzer + JSX regex heuristics |
| **TypeScript / React** | `.ts`, `.tsx` | Structural pattern analyzer + TSX regex heuristics |
| **Java** | `.java` | Structural pattern matching & API signature inspection |

---

## Supported Security Rules & CWE Mappings

### Python Rules
1. **SQL Injection (CWE-89)**: Detects dynamic string concatenations (`+`), modulo formatting (`%`), and formatted strings (`f"..."`) passed into `cursor.execute()`, `session.execute()`, or `raw_sql()`.
2. **Command Injection (CWE-78)**: Detects unsafe invocations of `os.system()`, `os.popen()`, and `subprocess.Popen(..., shell=True)`.
3. **Insecure Deserialization (CWE-502)**: Detects unverified object deserialization with `pickle.loads()`, `pickle.load()`, `_pickle.loads()`, and unsafe `yaml.load()` without SafeLoader.
4. **Weak Cryptography (CWE-327)**: Identifies broken cryptographic algorithms such as `hashlib.md5()` and `hashlib.sha1()`.
5. **Hardcoded Credentials / Secrets (CWE-798)**: Identifies hardcoded API keys, AWS credentials (`AKIA...`), JWT tokens (`eyJ...`), and passwords with entropy validation and placeholder filtering.
6. **Path Traversal (CWE-22)**: Detects user-controlled or dynamically concatenated paths in `open()`, `os.remove()`, and file stream operations without `os.path.basename` validation.
7. **Server-Side Request Forgery (SSRF) (CWE-918)**: Identifies dynamic URL inputs in `requests.get()`, `requests.post()`, and `urllib.request.urlopen()`.
8. **Insecure Randomness / PRNG (CWE-330)**: Detects use of standard pseudo-random generators (`random.random()`, `random.randint()`) in authentication or token contexts instead of `secrets`.
9. **Active Debug Configuration (CWE-489)**: Detects insecure production configurations like Flask `app.run(debug=True)`.

### JavaScript & React JSX Rules
1. **Cross-Site Scripting - XSS (CWE-79)**: Detects direct assignments to `element.innerHTML`, `element.outerHTML`, `document.write()`, and React JSX `<div dangerouslySetInnerHTML={{ __html: ... }} />`.
2. **Command Injection (CWE-78)**: Detects untrusted shell executions using Node.js `child_process.exec()` and `child_process.execSync()`.
3. **SQL Injection (CWE-89)**: Detects dynamically constructed SQL queries executed in `db.query()`, `pool.query()`, or `connection.query()`.
4. **Prototype Pollution (CWE-1321)**: Detects unsafe modifications of `__proto__` or `constructor.prototype` in recursive object merge operations.
5. **Path Traversal (CWE-22)**: Identifies unvalidated paths supplied to Node filesystem methods like `fs.readFile()` and `fs.createReadStream()`.
6. **Server-Side Request Forgery (SSRF) (CWE-918)**: Detects dynamic, unvalidated URLs passed to `axios.get()` or `fetch()`.
7. **Weak Cryptography (CWE-327)**: Identifies use of `crypto.createHash('md5')` or `crypto.createHash('sha1')`.
8. **Hardcoded Secrets (CWE-798)**: Scans for embedded API tokens, passwords, and AWS secrets.

### Java Rules
1. **SQL Injection (CWE-89)**: Identifies dynamic SQL strings and `Statement.executeQuery()` concatenations.
2. **Command Injection (CWE-78)**: Identifies command executions via `Runtime.getRuntime().exec()` and `ProcessBuilder`.
3. **XML External Entity - XXE Injection (CWE-611)**: Detects unhardened `DocumentBuilderFactory`, `SAXParserFactory`, and `XMLInputFactory` configurations lacking external entity restrictions.
4. **Path Traversal (CWE-22)**: Detects concatenated file paths in `new File()`, `new FileInputStream()`, and `new FileReader()`.
5. **Insecure Deserialization (CWE-502)**: Identifies native object deserialization via `ObjectInputStream.readObject()` and `XMLDecoder`.
6. **Weak Cryptography (CWE-327)**: Detects `MessageDigest.getInstance("MD5")`, `MessageDigest.getInstance("SHA-1")`, and `DES`.
7. **Hardcoded Credentials (CWE-798)**: Identifies embedded passwords, secret keys, and tokens.

---

## API Endpoints Reference

### Source Code Scanner Endpoints
* `POST /source-code/analyze`: Upload project ZIP archive for static analysis. Returns files scanned, lines scanned, severity summary, and findings.
* `GET /source-code/analyses`: List all source code analyses conducted by the authenticated user.
* `GET /source-code/analyses/{id}`: Retrieve detailed analysis record including findings, code snippets, and suggested fixes.
* `DELETE /source-code/analyses/{id}`: Delete analysis record and associated findings.
* `GET /source-code/analyses/{id}/download`: Download executive SAST PDF report.

### Existing VAPT Report Endpoints (Preserved)
* `POST /reports/upload`: Upload and parse VAPT scan report (`.pdf` / `.docx`).
* `GET /reports/`: List user's uploaded reports.
* `GET /reports/{id}`: View report status and vulnerability counts.
* `DELETE /reports/{id}`: Delete report and its vulnerabilities.
* `GET /reports/{id}/download`: Download executive VAPT PDF report.

### Vulnerability & Knowledge Base Endpoints
* `GET /vulnerabilities/`: List vulnerabilities across reports.
* `GET /vulnerabilities/{id}`: View specific vulnerability.
* `PUT /vulnerabilities/{id}`: Update severity and status (`Open` / `Resolved`).
* `GET /knowledge-base/`: Retrieve all Knowledge Base vulnerability definitions.
* `GET /knowledge-base/{cwe_id}`: Retrieve Knowledge Base details for a specific CWE.
* `GET /logs/`: View security audit trail logs.

---

## Security Architecture & Defenses

1. **Zip Slip / Path Traversal Prevention**:
   - `safe_extract_zip()` validates that the canonical destination path of every archive entry starts with the designated extraction folder:
     ```python
     target_path = os.path.abspath(os.path.join(destination_abs, member.filename))
     if not target_path.startswith(destination_abs + os.sep):
         raise ZipSecurityError("Path traversal detected")
     ```
   - Archive entries with `..`, absolute paths, or symlink flags are rejected.
2. **Decompression Bomb Protection**:
   - Max upload size: 50MB.
   - Max file count limit: 2,000 files per archive.
   - Max uncompressed size: 150MB.
   - Max single file size: 10MB.
3. **No Code Execution**:
   - The scanner performs strictly static parsing (syntax tree inspection and pattern matching). Uploaded code is never run, loaded into the Python runtime, or compiled.
4. **Directory & File Sanitization**:
   - Skips dependency directories (`node_modules`, `venv`, `__pycache__`, `.git`, `dist`, `build`, etc.).
   - Skips binary formats (`.png`, `.exe`, `.class`, `.jar`, `.pyc`, etc.) via extension checks and null-byte heuristic inspection.
5. **Temporary Data Cleanup**:
   - Extracted project directories are managed in system temp folders and guaranteed to be deleted using `cleanup_directory()` in `finally` blocks.

---

## How to Run the Application

### Prerequisites
* Python 3.10+
* Node.js 18+ and npm

### 1. Start Backend

```bash
cd backend

# Create and activate virtual environment (optional)
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The backend will start at `http://localhost:8000`.
Interactive API documentation is available at:
* Swagger UI: `http://localhost:8000/docs`
* ReDoc: `http://localhost:8000/redoc`

### 2. Start Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start React development server
npm start
```

The frontend will open in your browser at `http://localhost:3000`.

---

## Running Automated Tests

A comprehensive automated test suite covers the SAST engine, AST rules, safe ZIP extraction, Knowledge Base mapping, PDF generation, and REST APIs.

Run tests using pytest:

```bash
cd backend
python -m pytest tests/ -v
```

Test coverage includes:
* `tests/test_source_scanner.py`:
  - AST Python security rule verification (SQLi, Command Injection, Pickle, Weak Crypto, Path Traversal, SSRF, Randomness, Debug True).
  - JavaScript structural and JSX rule verification (XSS, innerHTML, dangerouslySetInnerHTML, exec, prototype pollution, path traversal, SSRF).
  - Java structural pattern verification (SQLi, exec, XXE, path traversal, deserialization, weak hashing).
  - Safe code verification (zero false positives on secure implementations).
  - Zip Slip path traversal security rejection.
  - Directory scanning and metrics computation.
  - ReportLab SAST PDF report generation.
* `tests/test_source_code_api.py`:
  - JWT authentication and authorization checks.
  - ZIP upload and static scanning endpoint (`/source-code/analyze`).
  - Analysis retrieval (`/source-code/analyses`).
  - Detailed findings inspection (`/source-code/analyses/{id}`).
  - PDF report download streaming (`/source-code/analyses/{id}/download`).
  - Analysis deletion (`DELETE /source-code/analyses/{id}`).

---

## How to Extend the Scanner

### Adding a New Rule
1. Open the appropriate language rules file in `backend/app/source_scanner/languages/` (e.g. `python_rules.py`).
2. Add an AST visitor method (for Python) or regex/structural rule (for JavaScript/Java).
3. Specify the appropriate `cwe_id`, `name`, `severity`, and `confidence`.
4. In `backend/app/source_scanner/rules.py`, add the recommended safer implementation to `SUGGESTED_FIXES`.

### Adding a New Knowledge Base Entry
1. Open `backend/app/services/knowledge_base.py`.
2. Add a dictionary entry to the `items` array inside `seed_knowledge_base()` with `cwe_id`, `vulnerability_name`, `severity`, `owasp_category`, `capec_id`, `description`, and `remediation`.
3. Restart the backend or run `python -c "from app.core.database import SessionLocal; from app.services.knowledge_base import seed_knowledge_base; db = SessionLocal(); seed_knowledge_base(db); db.close()"`.

---

## Limitations & Considerations

1. **Static Analysis Limitations**:
   - SAST analyzes code structures and patterns without runtime execution. Complex dynamic runtime behaviors (e.g. reflective function resolution in Java, dynamic `eval()` expressions) may not be fully traced.
2. **False Positive Handling**:
   - Every finding is tagged with a `confidence` level (`High`, `Medium`, `Low`). Detections are intended as actionable alerts for developer review, not definitive guarantees of exploitability.
3. **Suggested Fixes**:
   - Suggested fixes provide clear, secure implementation patterns (e.g. parameterized queries, safe subprocess arguments, environment variable secrets). Developers should adapt them to their application's architecture.
