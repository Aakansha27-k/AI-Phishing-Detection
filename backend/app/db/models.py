import uuid
import json
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Text
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=generate_uuid, index=True)
    url = Column(String, index=True, nullable=False)
    status = Column(String, default="pending", index=True) # pending, scanning, completed, failed
    
    # Scores
    risk_score = Column(Float, nullable=True) # 0 to 100
    risk_level = Column(String, nullable=True) # Safe, Suspicious, Phishing
    ml_probability = Column(Float, nullable=True)
    heuristic_score = Column(Float, nullable=True)
    domain_reputation_score = Column(Float, nullable=True)
    
    # JSON encoded features
    features_json = Column(Text, nullable=True)
    
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def features(self):
        if self.features_json:
            return json.loads(self.features_json)
        return None

    @features.setter
    def features(self, value):
        if value is not None:
            self.features_json = json.dumps(value)
        else:
            self.features_json = None
