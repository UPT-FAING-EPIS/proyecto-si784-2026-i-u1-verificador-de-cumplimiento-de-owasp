import os

os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["APP_ENV"] = "test"

from fastapi.testclient import TestClient

from app.db import Base, engine
from app.main import app

Base.metadata.create_all(bind=engine)
client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_api_code_flow():
    payload = {
        "target_type": "code",
        "target_value": "password = 'secret'\nprint(eval(data))",
    }
    response = client.post("/analyze/api", json=payload)
    assert response.status_code == 200

    scan = response.json()
    assert scan["target_type"] == "code"
    assert scan["score"] <= 100
    assert len(scan["findings"]) >= 1

    report_response = client.get(f"/reports/api/{scan['id']}")
    assert report_response.status_code == 200
    assert report_response.json()["id"] == scan["id"]
