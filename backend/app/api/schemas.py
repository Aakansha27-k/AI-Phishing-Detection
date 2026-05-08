from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Dict, Any
from datetime import datetime

class ScanRequest(BaseModel):
    url: str = Field(..., description="The website URL to scan")

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str = Field(..., description="Current status: pending, scanning, completed, failed")
    message: Optional[str] = None

class ScanResultResponse(BaseModel):
    id: str
    url: str
    status: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = Field(None, description="Safe, Suspicious, or Phishing")
    ml_probability: Optional[float] = None
    heuristic_score: Optional[float] = None
    domain_reputation_score: Optional[float] = None
    features: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
