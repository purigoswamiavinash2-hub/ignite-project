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

# --- Companion Device & SMS Ingestion Tests ---

def test_device_registration_and_heartbeat():
    reg_payload = {
        "device_id": "test-pixel-device-01",
        "device_name": "Test Pixel 7 (Unit Test)",
        "app_version": "1.0.0"
    }
    reg_res = client.post("/api/device/register", json=reg_payload)
    assert reg_res.status_code == 200
    reg_data = reg_res.json()
    assert reg_data["device_id"] == "test-pixel-device-01"
    assert reg_data["status"] == "CONNECTED"
    assert "api_key" in reg_data
    assert len(reg_data["api_key"]) > 10

    # Heartbeat
    hb_payload = {
        "device_id": "test-pixel-device-01",
        "status": "CONNECTED",
        "battery_pct": 85,
        "monitoring_mode": "AUTOMATIC_SMS"
    }
    hb_res = client.post("/api/device/heartbeat", json=hb_payload)
    assert hb_res.status_code == 200
    assert hb_res.json()["status"] == "ok"

    # Status check
    status_res = client.get("/api/device/status")
    assert status_res.status_code == 200
    devices = status_res.json()["devices"]
    found = any(d["device_id"] == "test-pixel-device-01" for d in devices)
    assert found == True

def test_authenticated_sms_scan_with_otp_redaction():
    # 1. Register a test companion device
    reg_res = client.post("/api/device/register", json={
        "device_id": "test-device-auth-02",
        "device_name": "Test Device Auth"
    })
    api_key = reg_res.json()["api_key"]

    # 2. Submit SMS with sensitive OTP
    sms_payload = {
        "sender_id": "VK-SBIBNK",
        "text": "Dear customer, your SBI YONO account will be suspended today. Update PAN immediately at http://sbi-yono-update.xyz. Your verification OTP is 849201. Do not share.",
        "opt_in_store_raw": False
    }
    headers = {"X-Device-Token": api_key}
    scan_res = client.post("/api/sms/scan", json=sms_payload, headers=headers)
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["risk_level"] in ["HIGH", "CRITICAL"]
    assert scan_data["risk_score"] >= 50
    assert len(scan_data["urls_found"]) > 0
    assert "sbi-yono-update.xyz" in scan_data["urls_found"][0]
    
    # Verify OTP was redacted for privacy
    assert "849201" not in scan_data["redacted_text"]
    assert "[REDACTED_OTP]" in scan_data["redacted_text"]

def test_unauthenticated_sms_scan_rejected():
    sms_payload = {
        "sender_id": "UNKNOWN",
        "text": "Phishing test"
    }
    # No auth header
    res_no_auth = client.post("/api/sms/scan", json=sms_payload)
    assert res_no_auth.status_code == 401

    # Invalid token
    res_bad_auth = client.post("/api/sms/scan", json=sms_payload, headers={"X-Device-Token": "INVALID-FAKE-KEY"})
    assert res_bad_auth.status_code == 401

def test_sms_simulator_endpoint():
    payload = {
        "sender_id": "SIMULATOR-TEST",
        "text": "URGENT: Click http://free-crypto-giveaway.club to claim 5000 USDT reward!",
        "device_id": "dashboard-sim"
    }
    res = client.post("/api/sms/simulate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["scan_id"].startswith("TG-SMS-")

def test_indian_kyc_and_electricity_scam():
    # Electricity disconnection threat in Hinglish
    hinglish_payload = {
        "sender_id": "+919876543210",
        "text": "Dear Consumer, aapka bijli connection aaj raat 9:30 PM ko disconnect kar diya jayega. Bill payment turant update karein call 9876543210.",
        "device_id": "test-device-auth-02"
    }
    res = client.post("/api/sms/simulate", json=hinglish_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    # Should flag utility disconnection and suspicious 10-digit sender
    reasons_text = " ".join(data["reasons"]).lower()
    assert "electricity" in reasons_text or "utility" in reasons_text or "urgency" in reasons_text

def test_upi_pin_fraud():
    payload = {
        "sender_id": "PAYTM-CASH",
        "text": "Congratulations! You won cashback of Rs 1999. Enter UPI PIN to claim money directly to bank."
    }
    res = client.post("/api/sms/simulate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    reasons_text = " ".join(data["reasons"]).lower()
    assert "upi pin" in reasons_text or "credential" in reasons_text or "financial" in reasons_text

def test_legitimate_normal_sms():
    payload = {
        "sender_id": "AM-SWIGGY",
        "text": "Your order #98213 is on the way. Delivery executive will reach your location in 15 mins."
    }
    res = client.post("/api/sms/simulate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] <= 25

def test_sms_recent_feed():
    res = client.get("/api/sms/recent?limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert len(data["items"]) > 0
    assert data["items"][0]["input_type"] == "sms"

