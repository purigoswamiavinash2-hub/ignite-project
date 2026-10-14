import pytest
from fastapi.testclient import TestClient
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.main import app
from backend.services.telegram_bot import telegram_bot_service

client = TestClient(app)

def test_telegram_status_endpoint():
    res = client.get("/api/telegram/status")
    assert res.status_code == 200
    data = res.json()
    assert "bot_configured" in data
    assert "bot_username" in data
    assert "privacy_mode_info" in data
    assert "privacy_mode" in data["privacy_mode_info"]
    assert "channel_access" in data["privacy_mode_info"]
    assert "private_chats_limitation" in data["privacy_mode_info"]

def test_telegram_check_crypto_airdrop():
    payload = {
        "text": "🚨 OFFICIAL AIRDROP: Claim 2500 USDT giveaway now! Connect wallet and enter 12-word recovery seed phrase at http://t-me.claim-airdrop.xyz to receive funds instantly.",
        "sender_username": "CryptoAirdropAdmin",
        "chat_title": "Telegram Crypto Announcements",
        "is_forwarded": True,
        "forward_from": "Solana Giveaway Channel"
    }
    res = client.post("/api/telegram/check", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["risk_score"] >= 65
    assert len(data["urls_found"]) > 0
    assert "claim-airdrop.xyz" in data["urls_found"][0]
    # Check that seed phrase and telegram scam indicators were caught
    reasons_str = " ".join(data["reasons"]).lower()
    assert "seed phrase" in reasons_str or "telegram" in reasons_str or "airdrop" in reasons_str

def test_telegram_check_admin_impersonator():
    payload = {
        "text": "Hello, I am the group admin of ThreatGuard Community. We detected suspicious activity on your Telegram account. Please DM me privately with your secret key to prevent account deletion.",
        "sender_username": "Admin_ThreatGuard_Support",
        "chat_title": "ThreatGuard Official Group",
        "is_forwarded": False
    }
    res = client.post("/api/telegram/check", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    reasons_str = " ".join(data["reasons"]).lower()
    assert "admin" in reasons_str or "impersonat" in reasons_str or "key" in reasons_str

def test_telegram_check_task_scam_hinglish():
    payload = {
        "text": "Dear user, aapko Telegram part-time job me select kiya gaya hai. Like 3 YouTube videos and earn Rs 3000 daily salary. Contact receptionist @TaskLeader_99 to start prepaid task.",
        "sender_username": "HR_Sneha",
        "is_forwarded": True
    }
    res = client.post("/api/telegram/check", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    reasons_str = " ".join(data["reasons"]).lower()
    assert "task" in reasons_str or "job" in reasons_str or "part-time" in reasons_str or "prepaid" in reasons_str

def test_telegram_check_safe_message():
    payload = {
        "text": "Hey everyone, the new documentation update for FastAPI has been merged. Check it out when you have time!",
        "sender_username": "developer_monish",
        "chat_title": "Python Developers India"
    }
    res = client.post("/api/telegram/check", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] <= 25

def test_telegram_webhook_start_command():
    update = {
        "update_id": 99001,
        "message": {
            "message_id": 1,
            "from": {"id": 12345678, "first_name": "Monish", "username": "monish_test"},
            "chat": {"id": 12345678, "type": "private"},
            "text": "/start"
        }
    }
    res = client.post("/api/telegram/webhook", json=update)
    assert res.status_code == 200
    assert res.json()["result"]["status"] == "command_handled"

def test_telegram_webhook_help_and_privacy_commands():
    # Help command
    update_help = {
        "update_id": 99002,
        "message": {
            "message_id": 2,
            "from": {"id": 12345678, "first_name": "Monish"},
            "chat": {"id": 12345678, "type": "private"},
            "text": "/help"
        }
    }
    res_help = client.post("/api/telegram/webhook", json=update_help)
    assert res_help.status_code == 200
    assert res_help.json()["result"]["status"] == "command_handled"

    # Privacy command
    update_priv = {
        "update_id": 99003,
        "message": {
            "message_id": 3,
            "from": {"id": 12345678, "first_name": "Monish"},
            "chat": {"id": 12345678, "type": "private"},
            "text": "/privacy"
        }
    }
    res_priv = client.post("/api/telegram/webhook", json=update_priv)
    assert res_priv.status_code == 200
    assert res_priv.json()["result"]["status"] == "command_handled"

def test_telegram_webhook_forwarded_scam():
    update_scam = {
        "update_id": 99004,
        "message": {
            "message_id": 4,
            "from": {"id": 88776655, "first_name": "InvestUser", "username": "invest_user"},
            "chat": {"id": 88776655, "type": "private"},
            "text": "GUARANTEED 300% DAILY PROFIT! Send 100 USDT to activate VIP pump signals: http://pump-signals-vip.top. Contact @CryptoGuru directly.",
            "forward_date": 1720000000,
            "forward_from": {"id": 112233, "first_name": "VIP Signals Channel"}
        }
    }
    res = client.post("/api/telegram/webhook", json=update_scam)
    assert res.status_code == 200
    result = res.json()["result"]
    assert result["status"] == "success"
    assert result["risk_level"] in ["HIGH", "CRITICAL"]

def test_telegram_duplicate_update_protection():
    # Send update with ID 99005
    update = {
        "update_id": 99005,
        "message": {
            "message_id": 5,
            "from": {"id": 12345678, "first_name": "Monish"},
            "chat": {"id": 12345678, "type": "private"},
            "text": "Hello bot"
        }
    }
    res1 = client.post("/api/telegram/webhook", json=update)
    assert res1.status_code == 200
    
    # Send exact same update_id 99005 again
    res2 = client.post("/api/telegram/webhook", json=update)
    assert res2.status_code == 200
    assert res2.json()["result"]["status"] == "duplicate_ignored"

def test_telegram_rate_limiting():
    import time
    # Spammer user ID
    spammer_id = 99999999
    # Fill up to limit with current timestamps
    telegram_bot_service.rate_limit_tracker[spammer_id] = [time.time()] * 16

    update = {
        "update_id": 99010,
        "message": {
            "message_id": 10,
            "from": {"id": spammer_id, "first_name": "Spammer"},
            "chat": {"id": spammer_id, "type": "private"},
            "text": "/check spam"
        }
    }
    res = client.post("/api/telegram/webhook", json=update)
    assert res.status_code == 200
    assert res.json()["result"]["status"] == "rate_limited"

def test_telegram_recent_and_deletion():
    recent_res = client.get("/api/telegram/recent?limit=5")
    assert recent_res.status_code == 200
    data = recent_res.json()
    assert "items" in data
    assert "total" in data

    # Delete history
    del_res = client.delete("/api/telegram/history")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"

    # Verify count is 0
    recent_after = client.get("/api/telegram/recent")
    assert recent_after.status_code == 200
    assert recent_after.json()["total"] == 0
