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
    risk_level: str
    risk_score: int
    reasons: List[str]
    urls_found: List[str]
    url_analysis: Optional[Dict[str, Any]] = None
    recommendation: str
    analysis_type: str
    model_confidence: Optional[float] = None
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
