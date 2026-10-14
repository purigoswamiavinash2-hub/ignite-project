import pytest
from fastapi.testclient import TestClient
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ThreatGuard AI"

def test_analyze_phishing_message():
    payload = {
        "text": "URGENT: Your account has been suspended! Click here to verify your OTP: http://paypa1-login.xyz/verify"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["risk_score"] >= 50
    assert len(data["urls_found"]) > 0
    assert "paypa1-login.xyz" in data["urls_found"][0]
    assert data["scan_id"].startswith("TG-")

def test_analyze_safe_message():
    payload = {
        "text": "Hey mom, dinner is ready! Call me when you leave work."
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] < 40

def test_analyze_url():
    payload = {
        "url": "http://paypa1-security-update.xyz/verify-login.php"
    }
    response = client.post("/api/analyze-url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["url_analysis"]["suspicious_tld"] == True

def test_history_and_deletion():
    # Fetch history
    res = client.get("/api/history")
    assert res.status_code == 200
    history_data = res.json()
    assert history_data["total"] > 0
    
    # Get last scan ID
    case_id = history_data["items"][0]["scan_id"]
    
    # Get case detail
    detail_res = client.get(f"/api/history/{case_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == case_id
    
    # Delete case
    del_res = client.delete(f"/api/history/{case_id}")
    assert del_res.status_code == 200
    assert del_res.json()["scan_id"] == case_id

def test_analytics():
    response = client.get("/api/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "risk_distribution" in data
