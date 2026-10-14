import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, unique=True, index=True, nullable=False)
    input_type = Column(String, nullable=False) # 'message' or 'url'
    content_preview = Column(String, nullable=False) # sanitized preview, no sensitive full text
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
            "content_preview": self.content_preview,
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
