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
    user = db.query(User).filter(User.email == "test_upload_user@example.com").first()
    if not user:
        user = User(
            name="Upload Test User",
            email="test_upload_user@example.com",
            password="SecretPassword123!",
            role="user"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    token = create_access_token({"sub": user.email})
    db.close()
    return {"Authorization": f"Bearer {token}"}


def test_upload_image_report(auth_header):
    # Minimal PNG byte stream
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?"
        b"\x03\x00\x05\xfe\x02\xfe\xa7\x35\x81\x84\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = client.post(
        "/reports/upload",
        files={"file": ("vulnerability_scan_screenshot.png", io.BytesIO(png_bytes), "image/png")},
        headers=auth_header
    )
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Report uploaded and parsed successfully"
    assert data["filename"] == "vulnerability_scan_screenshot.png"
    assert data["status"] == "Completed"
    assert data["vulnerabilities_count"] >= 1


def test_upload_invalid_extension(auth_header):
    response = client.post(
        "/reports/upload",
        files={"file": ("malicious_script.exe", io.BytesIO(b"binary data"), "application/octet-stream")},
        headers=auth_header
    )
    assert response.status_code == 400
    assert "Only PDF, DOCX, and Image files" in response.json()["detail"]
