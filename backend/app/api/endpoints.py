from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
import os

from .schemas import ScanRequest, ScanStatusResponse, ScanResultResponse
from app.db.database import get_db
from app.db.models import ScanResult
from app.tasks.scanner_tasks import run_scan
from app.core.features import FeatureExtractor
from app.core.ml_model import model_instance

router = APIRouter()

@router.post("/scan", response_model=ScanStatusResponse)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    # Create DB entry
    db_scan = ScanResult(url=request.url, status="pending")
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Start background task via Celery
    run_scan.delay(db_scan.id, request.url)
    
    return {"scan_id": db_scan.id, "status": "pending", "message": "Scan initiated in background."}

@router.post("/quick-check")
def quick_check(request: ScanRequest):
    """
    Lightweight, fast heuristic scan for live typing feedback.
    No Playwright, no DB write.
    """
    extractor = FeatureExtractor(request.url)
    features = extractor.extract_url_features()
    # Fast inference with only URL features
    results = model_instance.predict(features)
    return {
        "risk_level": results["risk_level"],
        "risk_score": results["risk_score"]
    }

@router.get("/result/{scan_id}", response_model=ScanResultResponse)
def get_scan_result(scan_id: str, db: Session = Depends(get_db)):
    result = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@router.get("/history", response_model=List[ScanResultResponse])
def get_scan_history(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    results = db.query(ScanResult).order_by(ScanResult.created_at.desc()).offset(skip).limit(limit).all()
    return results

@router.get("/screenshot/{scan_id}")
def get_screenshot(scan_id: str):
    from app.tasks.scanner_tasks import SCREENSHOTS_DIR
    file_path = os.path.join(SCREENSHOTS_DIR, f"{scan_id}.png")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(file_path, media_type="image/png")

@router.get("/health")
def health_check():
    return {"status": "healthy"}

@router.get("/admin/analytics")
def get_admin_analytics(db: Session = Depends(get_db)):
    total_scans = db.query(ScanResult).count()
    phishing_count = db.query(ScanResult).filter(ScanResult.risk_level == "Phishing").count()
    suspicious_count = db.query(ScanResult).filter(ScanResult.risk_level == "Suspicious").count()
    safe_count = db.query(ScanResult).filter(ScanResult.risk_level == "Safe").count()
    
    # Just basic mock trend data for MVP since we don't have extensive history
    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "recent_scans": get_scan_history(skip=0, limit=10, db=db)
    }
