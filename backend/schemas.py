from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="The message/email/SMS text to analyze")

class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="The URL to analyze")

class UrlDetail(BaseModel):
    url: str
    domain: str
    is_ip: bool
    is_shortener: bool
    suspicious_tld: bool
    subdomain_count: int
    lookalike_detected: bool
    reputation_status: str
    risk_score: int
    reasons: List[str]

class AnalysisResponse(BaseModel):
    scan_id: str
    input_type: str
    sender_id: Optional[str] = None
    device_id: Optional[str] = None
    risk_level: str
    risk_score: int
    reasons: List[str]
    urls_found: List[str]
    url_analysis: Optional[Dict[str, Any]] = None
    recommendation: str
    analysis_type: str
    model_confidence: Optional[float] = None
    sanitized_content: Optional[str] = None
    content_preview: Optional[str] = None
    created_at: str

class HistoryResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[AnalysisResponse]

class AnalyticsResponse(BaseModel):
    total_scans: int
    risk_distribution: Dict[str, int]
    high_risk_count: int
    recent_trend: List[Dict[str, Any]]
    top_threat_categories: List[Dict[str, Any]]
    demo_mode: bool

# --- Device Companion & SMS Specific Schemas ---

class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(..., min_length=3, max_length=128, description="Unique Android hardware or installation ID")
    device_name: str = Field(..., min_length=1, max_length=128, description="Human friendly device name, e.g., 'Pixel 7 - Monish'")
    app_version: Optional[str] = Field("1.0.0", max_length=32)

class DeviceRegisterResponse(BaseModel):
    device_id: str
    device_name: str
    api_key: str
    status: str
    pairing_code: str
    message: str

class DeviceHeartbeatRequest(BaseModel):
    device_id: str
    status: str = Field("CONNECTED", description="CONNECTED, OFFLINE, AWAITING_PERMISSION, UNABLE_TO_SCAN")
    battery_pct: Optional[int] = Field(100, ge=0, le=100)
    monitoring_mode: Optional[str] = Field("AUTOMATIC_SMS", description="AUTOMATIC_SMS, MANUAL_ONLY, DISABLED")

class DeviceStatusItem(BaseModel):
    device_id: str
    device_name: str
    status: str
    monitoring_mode: str
    battery_pct: int
    app_version: str
    last_heartbeat: Optional[str] = None
    is_online: bool

class DeviceStatusResponse(BaseModel):
    devices: List[DeviceStatusItem]
    active_count: int

class SmsScanRequest(BaseModel):
    sender_id: Optional[str] = Field(None, max_length=64, description="SMS sender alphanumeric ID or phone number (e.g., 'VK-SBIBNK')")
    text: str = Field(..., min_length=1, max_length=5000, description="SMS body text")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of SMS reception")
    opt_in_store_raw: Optional[bool] = Field(False, description="Explicit opt-in required to store unredacted text")
    device_id: Optional[str] = Field(None, description="Paired Android device ID")

class SmsScanResponse(BaseModel):
    scan_id: str
    sender_id: Optional[str] = None
    device_id: Optional[str] = None
    risk_level: str
    risk_score: int
    reasons: List[str]
    urls_found: List[str]
    url_analysis: Optional[Dict[str, Any]] = None
    recommendation: str
    analysis_type: str
    model_confidence: Optional[float] = None
    sanitized_preview: str
    redacted_text: str
    created_at: str

# --- Telegram Scam Checker & Bot Schemas ---

class TelegramScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="Telegram message or forwarded channel post text")
    sender_username: Optional[str] = Field(None, description="Telegram @username of sender or channel")
    sender_first_name: Optional[str] = Field(None, description="Sender display name")
    chat_title: Optional[str] = Field(None, description="Telegram group or channel title")
    is_forwarded: Optional[bool] = Field(False, description="Flag indicating if message was forwarded")
    forward_from: Optional[str] = Field(None, description="Original channel or sender name forwarded from")
    opt_in_store_raw: Optional[bool] = Field(False, description="Explicit user consent to store raw unredacted text")

class TelegramBotStatusResponse(BaseModel):
    bot_configured: bool
    bot_username: str
    mode: str
    total_scans_processed: int
    webhook_url: Optional[str] = None
    privacy_mode_info: Dict[str, Any]

class TelegramRecentResponse(BaseModel):
    total: int
    high_threat_count: int
    items: List[Dict[str, Any]]
    timestamp: str
