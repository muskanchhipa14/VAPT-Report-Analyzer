# Intelligent VAPT Report Analysis & Remediation System

A full-stack web application designed for automated Vulnerability Assessment and Penetration Testing (VAPT) PDF report parsing, Knowledge Base vulnerability-remediation matching, and **independent AI evaluation powered by Google Gemini**.

---

## 🌟 Overview & Architecture

The system processes VAPT reports through a modular pipeline where existing detection and Knowledge Base remediations are verified by Google Gemini acting as an **independent LLM evaluator / reference judge**.

```
  USER
   │
   ▼
 UPLOAD VAPT PDF
   │
   ▼
 FASTAPI BACKEND
   │
   ▼
 PDF TEXT PARSER (pypdf)
   │
   ▼
 VULNERABILITY EXTRACTION (CWE / Keyword Pattern Matching)
   │
   ▼
 KNOWLEDGE BASE LOOKUP (Local Database Remediations)
   │
   ▼
 VULNERABILITY + KB REMEDIATION
   │
   ▼
 GEMINI API (Official google-genai SDK)
   │
   ▼
 INDEPENDENT EVALUATION (Schema-Enforced JSON)
   │
   ▼
 METRICS ENGINE (Accuracy, Precision, Recall, F1, Remediation Score)
   │
   ▼
 REACT FRONTEND (Evaluation Summary & Side-by-Side Breakdown)
```

> [!NOTE]
> **Independent Evaluator vs. Ground Truth**: Gemini is utilized as an **independent LLM reference judge** to calculate accuracy, error rates, and omissions without altering the primary VAPT detection pipeline. The metrics are explicitly labeled as *"LLM-based Evaluation"* to distinguish them from manual ground truth datasets.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Node.js 18+ and npm
- A Google Gemini API Key from [Google AI Studio](https://aistudio.google.com/)

---

### 2. Getting a Google Gemini API Key
1. Visit [Google AI Studio](https://aistudio.google.com/).
2. Sign in with your Google account.
3. Click on **"Get API Key"** -> **"Create API Key"**.
4. Copy the generated key.

---

### 3. Backend Setup

1. **Navigate to the backend folder**:
   ```bash
   cd backend
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Create a `.env` file inside `backend/.env` (or project root `.env`):
   ```env
   # Google Gemini API Key (Required for AI evaluation)
   GEMINI_API_KEY=AIzaSy...your_real_key_here

   # Gemini Model (Default: gemini-2.5-flash)
   GEMINI_MODEL=gemini-2.5-flash

   # Database & Server Settings
   DATABASE_URL=sqlite:///./vapt.db
   PORT=8000
   ```

4. **Seed the Knowledge Base** (Initial database setup):
   ```bash
   python seed_knowledge_base.py
   ```

5. **Start the FastAPI Server**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   FastAPI Interactive Docs will be accessible at: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 4. Frontend Setup

1. **Navigate to the frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install dependencies and start development server**:
   ```bash
   npm install
   npm start
   ```
   The React frontend will be available at: [http://localhost:3000](http://localhost:3000)

---

## 📡 API Reference: Independent Evaluation

### Check Gemini Configuration Status
- **Endpoint**: `GET /evaluation/status`
- **Description**: Verifies if the Gemini API key is configured without exposing secret values.
- **Example Response**:
  ```json
  {
    "configured": true,
    "model": "gemini-2.5-flash",
    "provider": "Google GenAI SDK (google-genai)",
    "message": "Google Gemini API is ready for independent evaluation."
  }
  ```

---

### Upload & Evaluate VAPT PDF Report
- **Endpoint**: `POST /evaluate-report` (or `POST /reports/evaluate`)
- **Content-Type**: `multipart/form-data`
- **Parameters**: `file` (PDF file)

#### Example cURL Request:
```bash
curl -X POST "http://localhost:8000/evaluate-report" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@backend/uploads/sample_vapt_report.pdf"
```

#### Example JSON Response:
```json
{
  "report_id": 1,
  "report_name": "Synthetic_Vulnerability_Test_Report_3_Findings.pdf",
  "total_vulnerabilities": 3,
  "total_findings": 3,
  "evaluation_type": "LLM-based Evaluation (Gemini Reference Judge)",
  "disclaimer": "Accuracy is calculated only from successfully evaluated findings. API failures are excluded from accuracy calculations.",
  "metrics": {
    "total_findings": 3,
    "successfully_evaluated": 2,
    "failed_evaluations": 1,
    "evaluation_coverage": 0.6667,
    "vulnerability_accuracy": 1.0,
    "remediation_accuracy": 1.0,
    "average_remediation_score": 0.90,
    "precision": 1.0,
    "recall": 1.0,
    "f1_score": 1.0,
    "correct_vulnerabilities": 2,
    "incorrect_vulnerabilities": 0,
    "correct_remediations": 2,
    "incorrect_remediations": 0,
    "overall_accuracy": 1.0,
    "total_vulnerabilities": 3,
    "evaluated_count": 2,
    "evaluation_type": "LLM-based Evaluation (Gemini Reference Judge)",
    "disclaimer": "Accuracy is calculated only from successfully evaluated findings. API failures are excluded from accuracy calculations."
  },
  "evaluations": [
    {
      "vulnerability": "SQL Injection",
      "cwe_id": "CWE-89",
      "severity": "High",
      "file_name": "login.py",
      "line_number": 45,
      "knowledge_base_remediation": "Use parameterized queries, prepared statements, input validation, and least privilege database accounts.",
      "evaluation_status": "success",
      "error_message": null,
      "gemini_evaluation": {
        "vulnerability": "SQL Injection (CWE-89)",
        "is_vulnerability_correct": true,
        "vulnerability_confidence": 0.98,
        "remediation_is_correct": true,
        "remediation_score": 0.95,
        "missing_points": [
          "Use Object-Relational Mapping (ORM) parameter binding",
          "Ensure database error messages are not exposed to clients"
        ],
        "gemini_recommended_remediation": "Implement parameterized queries or prepared statements across all database access layers. Enforce principle of least privilege on database accounts and apply input validation.",
        "reason": "Vulnerability detection correctly matches CWE-89. Knowledge base remediation follows industry standard OWASP Top 10 guidelines.",
        "severity_assessment": "High",
        "overall_correct": true
      }
    },
    {
      "vulnerability": "Buffer Overflow",
      "cwe_id": "CWE-120",
      "severity": "Critical",
      "file_name": "N/A",
      "line_number": 1,
      "knowledge_base_remediation": "Use safe library functions, perform strict bounds checks, and use modern memory-safe languages.",
      "evaluation_status": "failed",
      "error_message": "Gemini quota exceeded; this finding was not evaluated.",
      "gemini_evaluation": null
    }
  ],
  "status": "success",
  "message": "VAPT report evaluated successfully with Google Gemini."
}
```

---

## 📊 Explanation of Evaluation Metrics

| Metric | Formula | Description |
| :--- | :--- | :--- |
| **Total Findings** | Count of unique vulnerabilities | Total unique vulnerabilities detected across the report. |
| **Successfully Evaluated** | Count of completed LLM evaluations | Findings that successfully received a valid Gemini evaluation. |
| **Failed Evaluations** | Count of API/network failures | Findings where Gemini evaluation encountered an issue (e.g. 429 quota exhaustion). |
| **Evaluation Coverage** | $\frac{\text{Successfully Evaluated}}{\text{Total Findings}}$ | Percentage of total findings covered by LLM evaluation. |
| **Vulnerability Accuracy** | $\frac{\text{Correct Detections}}{\text{Successfully Evaluated Findings}}$ | Proportion of evaluated findings verified as valid vulnerabilities (API failures excluded). |
| **Remediation Accuracy** | $\frac{\text{Correct Remediations}}{\text{Successfully Evaluated Remediations}}$ | Proportion of evaluated KB remediations judged technically appropriate. |
| **Average Remediation Score** | $\frac{\sum \text{remediation\_score}}{\text{Successfully Evaluated}}$ | Mean score ($0.0$ to $1.0$) evaluating completeness and depth among evaluated findings. |
| **Precision** | $\frac{TP}{TP + FP}$ | True Positives / (True Positives + False Positives) on evaluated findings. |
| **Recall** | $\frac{TP}{TP + FN}$ | True Positives / (True Positives + False Negatives) on evaluated findings. |
| **F1 Score** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | Harmonic mean balancing precision and recall. |
| **Overall Accuracy** | $\frac{\text{Both Detection \& Remediation Valid}}{\text{Successfully Evaluated Findings}}$ | Proportion of evaluated findings where both detection and remediation are sound. |

---

## 🧪 Running Automated Tests

Automated unit and integration tests run with mocked Gemini API calls (no external API consumption):

```bash
cd backend
pytest tests/ -v
```

---

## 🔒 Security & Best Practices

- **Never Commit Secrets**: `.env` and `*.db` are included in `.gitignore`.
- **Server-Side API Calls**: All Google Gemini API interactions occur strictly on the FastAPI backend; API keys are never sent to the browser.
- **Fail-Safe Per-Item Evaluation & Quota Handling**: If an individual vulnerability evaluation experiences a 429 quota exhaustion, the system marks that item as `failed` with `"Gemini quota exceeded; this finding was not evaluated."` without crashing the report or penalizing accuracy scores.

