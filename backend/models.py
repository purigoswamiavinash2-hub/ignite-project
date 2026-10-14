import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Boolean
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class DeviceRegistration(Base):
    __tablename__ = "registered_devices"

    id = Column(String, primary_key=True, default=generate_uuid)
    device_id = Column(String, unique=True, index=True, nullable=False)
    device_name = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, default="CONNECTED") # CONNECTED, OFFLINE, AWAITING_PERMISSION, UNABLE_TO_SCAN
    monitoring_mode = Column(String, default="AUTOMATIC_SMS") # AUTOMATIC_SMS, MANUAL_ONLY, DISABLED
    battery_pct = Column(Integer, default=100)
    app_version = Column(String, default="1.0.0")
    last_heartbeat = Column(DateTime, default=datetime.datetime.utcnow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "api_key": self.api_key,
            "status": self.status,
            "monitoring_mode": self.monitoring_mode,
            "battery_pct": self.battery_pct,
            "app_version": self.app_version,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, unique=True, index=True, nullable=False)
    input_type = Column(String, nullable=False) # 'message', 'url', 'sms'
    sender_id = Column(String, nullable=True) # e.g. 'VK-SBIBNK', '+919876543210'
    device_id = Column(String, nullable=True) # linked companion device
    content_preview = Column(String, nullable=False) # sanitized preview, no sensitive full text
    sanitized_content = Column(Text, nullable=True) # redacted SMS body (OTPs masked)
    raw_content_stored = Column(Boolean, default=False)
    risk_level = Column(String, nullable=False) # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    risk_score = Column(Integer, nullable=False) # 0 to 100
    reasons = Column(JSON, nullable=False) # List of reason strings
    urls_found = Column(JSON, nullable=False) # List of extracted URLs
    url_analysis = Column(JSON, nullable=True) # URL structural detail dict
    recommendation = Column(Text, nullable=False)
    analysis_type = Column(String, nullable=False) # 'ML + Rules', 'Rule-Based Fallback'
    model_confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "input_type": self.input_type,
            "sender_id": self.sender_id,
            "device_id": self.device_id,
            "content_preview": self.content_preview,
            "sanitized_content": self.sanitized_content,
            "raw_content_stored": self.raw_content_stored,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "reasons": self.reasons or [],
            "urls_found": self.urls_found or [],
            "url_analysis": self.url_analysis or {},
            "recommendation": self.recommendation,
            "analysis_type": self.analysis_type,
            "model_confidence": self.model_confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
