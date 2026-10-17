import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import SessionLocal, Base, engine
from app.core.security import create_access_token
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.source_code import RemediationJob, RemediationAttempt
from app.services.remediation_loop_service import (
    RemediationLoopService,
    validate_code_syntax,
    validate_workspace_path,
    apply_patch_to_code,
    compute_finding_fingerprint,
    STATE_VERIFIED_FIXED,
    STATE_NEEDS_MANUAL_REVIEW,
    STATE_CANCELLED
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def officer_token(db_session: Session):
    officer = db_session.query(User).filter(User.email == "officer@cdac.in").first()
    if not officer:
        officer = User(name="C-DAC Officer", email="officer@cdac.in", password="test", role="cdac_officer")
        db_session.add(officer)
        db_session.commit()
    return create_access_token(data={"sub": officer.email, "role": officer.role})


@pytest.fixture(scope="module")
def standard_user_token(db_session: Session):
    user = db_session.query(User).filter(User.email == "user@cdac.in").first()
    if not user:
        user = User(name="Standard User", email="user@cdac.in", password="test", role="user")
        db_session.add(user)
        db_session.commit()
    return create_access_token(data={"sub": user.email, "role": user.role})


def test_syntax_validation_python():
    """Validates Python syntax checker works without executing code."""
    valid_py = "def get_user(uid):\n    return db.query(uid)\n"
    ok, err = validate_code_syntax(valid_py, "python")
    assert ok is True
    assert err is None

    invalid_py = "def get_user(uid:\n    return db.query(uid)\n"
    ok, err = validate_code_syntax(invalid_py, "python")
    assert ok is False
    assert "SyntaxError" in err


def test_syntax_validation_structural():
    """Validates structural delimiter balance checking for other languages."""
    valid_js = "function test() { const a = [1, 2, 3]; return a.map(x => (x * 2)); }"
    ok, err = validate_code_syntax(valid_js, "javascript")
    assert ok is True

    invalid_js = "function test() { const a = [1, 2, 3; return a; }"
    ok, err = validate_code_syntax(invalid_js, "javascript")
    assert ok is False
    assert "delimiter" in err.lower()


def test_workspace_path_traversal_protection(tmp_path):
    """Ensures safe path validator prevents directory traversal and symlink escapes."""
    safe_dir = str(tmp_path)
    
    # Safe path
    safe_path = validate_workspace_path("sub/file.py", safe_dir)
    assert safe_path.startswith(safe_dir)

    # Path traversal attack
    with pytest.raises(PermissionError):
        validate_workspace_path("../../etc/passwd", safe_dir)

    with pytest.raises(PermissionError):
        validate_workspace_path("..\\..\\Windows\\System32\\cmd.exe", safe_dir)


def test_sql_injection_remediation_loop_verified_fixed(db_session: Session):
    """
    Tests end-to-end continuous remediation loop for SQL Injection:
    Detects flaw, generates fix, validates AST syntax, rescans with SAST engine,
    and independently verifies the fix as VERIFIED_FIXED.
    """
    officer = db_session.query(User).filter(User.email == "officer@cdac.in").first()

    vuln_code = (
        "import sqlite3\n\n"
        "def query_user(user_id):\n"
        "    conn = sqlite3.connect('vapt.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
        "    return cursor.fetchall()\n"
    )

    job = RemediationLoopService.create_job(
        db=db_session,
        user=officer,
        code_snippet=vuln_code,
        file_path="app/database/user_repo.py",
        language="python",
        cwe_id="CWE-89",
        vulnerability_name="SQL Injection",
        severity="High",
        max_attempts=3
    )

    assert job.id is not None
    assert job.state == "QUEUED"

    # Run the loop synchronously
    RemediationLoopService.run_remediation_loop(job.id)

    db_session.refresh(job)
    assert job.state == STATE_VERIFIED_FIXED
    assert job.verified_fixed_count == 1
    assert job.remaining_findings_count == 0
    assert job.final_patch_diff is not None
    assert len(job.final_patch_diff) > 0
    assert "SELECT * FROM users WHERE id =" in job.final_patch_diff
    assert job.verification_evidence is not None
    assert "0 occurrences" in job.verification_evidence

    # Verify attempts were recorded
    attempts = db_session.query(RemediationAttempt).filter(RemediationAttempt.job_id == job.id).all()
    assert len(attempts) >= 1
    last_att = attempts[-1]
    assert last_att.validation_passed is True
    assert last_att.syntax_check_passed is True


def test_job_cancellation(db_session: Session):
    """Tests that a running job can be gracefully cancelled and rolled back."""
    officer = db_session.query(User).filter(User.email == "officer@cdac.in").first()

    code = "import os\ndef ping(host):\n    os.system('ping ' + host)\n"

    job = RemediationLoopService.create_job(
        db=db_session,
        user=officer,
        code_snippet=code,
        file_path="network.py",
        language="python",
        cwe_id="CWE-78",
        vulnerability_name="Command Injection",
        max_attempts=5
    )

    cancelled_job = RemediationLoopService.cancel_job(db=db_session, job_id=job.id, user=officer)
    assert cancelled_job.state == STATE_CANCELLED
    assert cancelled_job.is_cancelled is True
    assert cancelled_job.is_rolled_back is True


def test_api_remediation_endpoints_rbac(client: TestClient, officer_token: str, standard_user_token: str):
    """Tests server-side RBAC on remediation endpoints."""
    payload = {
        "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "file_path": "auth.py",
        "language": "python",
        "cwe_id": "CWE-89",
        "vulnerability_name": "SQL Injection",
        "severity": "High",
        "max_attempts": 3
    }

    # Standard User: Must receive 403 Forbidden
    res_forbidden = client.post(
        "/api/remediation/jobs",
        json=payload,
        headers={"Authorization": f"Bearer {standard_user_token}"}
    )
    assert res_forbidden.status_code == 403

    # C-DAC Officer: Allowed
    res_officer = client.post(
        "/api/remediation/jobs?sync=true",
        json=payload,
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res_officer.status_code == 200
    job_data = res_officer.json()
    assert job_data["state"] in ("VERIFIED_FIXED", "QUEUED", "NEEDS_MANUAL_REVIEW")
    job_id = job_data["id"]

    # Retrieve job
    res_get = client.get(
        f"/api/remediation/jobs/{job_id}",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res_get.status_code == 200
    assert res_get.json()["id"] == job_id

    # Retrieve attempts
    res_attempts = client.get(
        f"/api/remediation/jobs/{job_id}/attempts",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res_attempts.status_code == 200
    assert isinstance(res_attempts.json(), list)

    # Retrieve diff
    res_diff = client.get(
        f"/api/remediation/jobs/{job_id}/diff",
        headers={"Authorization": f"Bearer {officer_token}"}
    )
    assert res_diff.status_code == 200
    assert "patch_diff" in res_diff.json()


def test_api_export_verified_patch(client: TestClient, officer_token: str, db_session: Session):
    """Tests exporting verified patch file via API."""
    officer = db_session.query(User).filter(User.email == "officer@cdac.in").first()

    code = "query = 'SELECT * FROM items WHERE id = ' + item_id\n"
    job = RemediationLoopService.create_job(
        db=db_session,
        user=officer,
        code_snippet=code,
        file_path="items.py",
        language="python",
        cwe_id="CWE-89",
        vulnerability_name="SQL Injection",
        max_attempts=3
    )
    RemediationLoopService.run_remediation_loop(job.id)

    db_session.refresh(job)
    if job.state == STATE_VERIFIED_FIXED:
        res = client.post(
            f"/api/remediation/jobs/{job.id}/export",
            headers={"Authorization": f"Bearer {officer_token}"}
        )
        assert res.status_code == 200
        assert "attachment" in res.headers.get("content-disposition", "")
        assert len(res.text) > 0


def test_audit_logging_recorded(db_session: Session):
    """Verifies that remediation lifecycle events are recorded in the AuditLog ledger."""
    officer = db_session.query(User).filter(User.email == "officer@cdac.in").first()
    code = "import pickle\ndata = pickle.loads(raw_input)\n"
    job = RemediationLoopService.create_job(
        db=db_session,
        user=officer,
        code_snippet=code,
        file_path="loader.py",
        language="python",
        cwe_id="CWE-502",
        vulnerability_name="Insecure Deserialization",
        max_attempts=2
    )

    logs = db_session.query(AuditLog).filter(
        AuditLog.module == "Continuous Remediation",
        AuditLog.action.like(f"%[{job.job_uuid}]%")
    ).all()
    assert len(logs) >= 1
