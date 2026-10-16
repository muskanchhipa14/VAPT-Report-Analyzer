import os
import zipfile
import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal
from app.models.user import User
from app.core.security import create_access_token

client = TestClient(app)


@pytest.fixture(scope="module")
def auth_header():
    db = SessionLocal()
    # Ensure test user exists with C-DAC officer authorization
    user = db.query(User).filter(User.email == "test_sast_user@example.com").first()
    if not user:
        user = User(
            name="SAST Test User",
            email="test_sast_user@example.com",
            password="SecretPassword123!",
            role="security_analyst"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.role = "security_analyst"
        db.commit()
    token = create_access_token({"sub": user.email, "role": user.role})
    db.close()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def other_user_auth_header():
    db = SessionLocal()
    user = db.query(User).filter(User.email == "other_sast_user@example.com").first()
    if not user:
        user = User(
            name="Other Test User",
            email="other_sast_user@example.com",
            password="SecretPassword123!",
            role="security_analyst"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.role = "security_analyst"
        db.commit()
    token = create_access_token({"sub": user.email, "role": user.role})
    db.close()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def normal_user_auth_header():
    db = SessionLocal()
    user = db.query(User).filter(User.email == "restricted_user@example.com").first()
    if not user:
        user = User(
            name="Restricted Normal User",
            email="restricted_user@example.com",
            password="SecretPassword123!",
            role="user"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.role = "user"
        db.commit()
    token = create_access_token({"sub": user.email, "role": user.role})
    db.close()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/vulnerable.py", """import os
def run_cmd(user_arg):
    os.system("echo " + user_arg)
""")
        zf.writestr("app/safe.py", """import os
def get_env():
    return os.getenv("API_KEY")
""")
    buf.seek(0)
    return buf.getvalue()


def test_unauthenticated_requests():
    # Listing analyses without token should return 401
    res = client.get("/source-code/analyses")
    assert res.status_code == 401
    assert res.json()["detail"] == "Could not validate credentials"

    # Downloading PDF without token should return 401
    res_download = client.get("/source-code/analyses/1/download")
    assert res_download.status_code == 401
    assert res_download.json()["detail"] == "Could not validate credentials"


def test_upload_invalid_file_type(auth_header):
    res = client.post(
        "/source-code/analyze",
        headers=auth_header,
        files={"file": ("test.txt", b"plain text", "text/plain")}
    )
    assert res.status_code == 400


def test_upload_and_analyze_zip_and_download(auth_header, other_user_auth_header, sample_zip_bytes):
    # 1. Upload & Analyze
    res = client.post(
        "/source-code/analyze",
        headers=auth_header,
        files={"file": ("sample_project.zip", sample_zip_bytes, "application/zip")}
    )
    assert res.status_code == 200
    data = res.json()
    assert "analysis_id" in data
    assert data["files_scanned"] == 2
    assert data["vulnerabilities_found"] >= 1
    assert data["severity_summary"]["critical"] >= 1
    analysis_id = data["analysis_id"]

    # 2. List analyses
    list_res = client.get("/source-code/analyses", headers=auth_header)
    assert list_res.status_code == 200
    analyses = list_res.json()
    assert any(a["id"] == analysis_id for a in analyses)

    # 3. Get analysis detail
    detail_res = client.get(f"/source-code/analyses/{analysis_id}", headers=auth_header)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["findings"]) >= 1
    assert detail["findings"][0]["cwe_id"] == "CWE-78"

    # 4. Attempt unauthenticated download (Must be rejected with 401)
    unauth_dl = client.get(f"/source-code/analyses/{analysis_id}/download")
    assert unauth_dl.status_code == 401
    assert unauth_dl.json()["detail"] == "Could not validate credentials"

    # 5. Attempt download by unauthorized user (Must be rejected with 403)
    unauthorized_dl = client.get(
        f"/source-code/analyses/{analysis_id}/download",
        headers=other_user_auth_header
    )
    assert unauthorized_dl.status_code == 403
    assert "Not authorized" in unauthorized_dl.json()["detail"]

    # 6. Authenticated owner downloads PDF report (Must succeed with 200 and %PDF stream)
    pdf_res = client.get(f"/source-code/analyses/{analysis_id}/download", headers=auth_header)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")
    assert len(pdf_res.content) > 1000

    # 7. Delete analysis
    del_res = client.delete(f"/source-code/analyses/{analysis_id}", headers=auth_header)
    assert del_res.status_code == 200

    # 8. Verify deleted analysis returns 404
    get_res = client.get(f"/source-code/analyses/{analysis_id}", headers=auth_header)
    assert get_res.status_code == 404

    # 9. Verify download of deleted analysis returns 404
    post_del_dl = client.get(f"/source-code/analyses/{analysis_id}/download", headers=auth_header)
    assert post_del_dl.status_code == 404


def test_upload_and_analyze_single_file(auth_header):
    c_code = b"""
    #include <stdio.h>
    #include <string.h>
    void test(char *input) {
        char buf[32];
        strcpy(buf, input);
    }
    """
    res = client.post(
        "/source-code/analyze",
        headers=auth_header,
        files={"file": ("vulnerable.c", c_code, "text/x-c")}
    )
    assert res.status_code == 200
    data = res.json()
    assert "analysis_id" in data
    assert data["files_scanned"] == 1
    assert data["vulnerabilities_found"] >= 1
    # Check that findings include AI remediation
    findings = data["findings"]
    assert any(f["cwe_id"] == "CWE-120" for f in findings)
    assert any(f.get("secure_code") is not None for f in findings)


def test_normal_user_denied_source_code_access(normal_user_auth_header, sample_zip_bytes):
    """
    C-DAC Confidentiality Policy Test:
    Ensures that standard users ('user' role) are strictly denied from
    fetching, listing, or analyzing confidential source code.
    """
    # 1. Listing analyses should return 403 Forbidden
    res_list = client.get("/source-code/analyses", headers=normal_user_auth_header)
    assert res_list.status_code == 403
    assert "C-DAC Confidentiality Guidelines" in res_list.json()["detail"]

    # 2. Uploading & Scanning source code should return 403 Forbidden
    res_upload = client.post(
        "/source-code/analyze",
        headers=normal_user_auth_header,
        files={"file": ("project.zip", sample_zip_bytes, "application/zip")}
    )
    assert res_upload.status_code == 403
    assert "C-DAC Confidentiality Guidelines" in res_upload.json()["detail"]

    # 3. Direct analysis engine POST /api/analyze/source-code should return 403 Forbidden
    res_engine = client.post(
        "/api/analyze/source-code",
        headers=normal_user_auth_header,
        data={"code_content": "import os; os.system('echo hi')"}
    )
    assert res_engine.status_code == 403
    assert "C-DAC Confidentiality Guidelines" in res_engine.json()["detail"]

    # 4. Audit Log verification: Check that the unauthorized attempt was recorded
    log_res = client.get("/logs/", headers=normal_user_auth_header)
    assert log_res.status_code == 200
    logs = log_res.json()
    assert any(
        log["status"] == "Denied" and "Access Control" in log["module"]
        for log in logs
    )


