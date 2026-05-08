import os
from celery import Celery
from app.config import settings
from app.db.database import SessionLocal
from app.db.models import ScanResult
from app.core.features import FeatureExtractor
from app.core.ml_model import model_instance
from app.integrations.virustotal import check_virustotal
from app.integrations.gsb import check_google_safe_browsing
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# Celery Initialization
celery_app = Celery(
    "scanner_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

# Optional: Configuration for Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCREENSHOTS_DIR = os.path.join(BASE_DIR, 'screenshots')
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

@celery_app.task(bind=True, max_retries=3)
def run_scan(self, scan_id: str, url: str):
    db = SessionLocal()
    try:
        # 1. Update status to scanning
        scan_record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if not scan_record:
            return
            
        scan_record.status = "scanning"
        db.commit()

        # 2. SSRF Check First
        extractor_pre = FeatureExtractor(url)
        is_safe, error_msg = extractor_pre.check_ssrf()
        if not is_safe:
            scan_record.status = "failed"
            scan_record.error_message = error_msg
            db.commit()
            return

        html_content = ""
        screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{scan_id}.png")
        
        # 3. Playwright for Screenshot and HTML
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-dev-shm-usage",
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-blink-features=AutomationControlled"
                    ]
                )
                context = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                    geolocation=None,
                    permissions=[]
                )
                page = context.new_page()
                page.goto(url, timeout=10000, wait_until="domcontentloaded")
                page.wait_for_timeout(1000)
                html_content = page.content()
                page.screenshot(path=screenshot_path, full_page=True, type="png")
                browser.close()
        except PlaywrightTimeoutError:
            print(f"Playwright timeout for {url}")
        except Exception as e:
            print(f"Playwright error for {url}: {e}")

        # 4. Extract Features
        extractor = FeatureExtractor(url, html_content=html_content if html_content else None)
        features = extractor.extract_all()
        features['has_screenshot'] = os.path.exists(screenshot_path)
        
        # 5. External Integrations
        vt_data = check_virustotal(url)
        gsb_data = check_google_safe_browsing(url)
        
        # Add integration results to features for frontend to render
        features['vt_data'] = vt_data
        features['gsb_data'] = gsb_data
        
        # 6. Model Prediction & Scoring
        results = model_instance.predict(features, vt_data=vt_data, gsb_data=gsb_data)
        
        # 7. Save Results
        scan_record.status = "completed"
        scan_record.features = features
        scan_record.risk_score = results['risk_score']
        scan_record.risk_level = results['risk_level']
        scan_record.ml_probability = results['ml_probability']
        scan_record.heuristic_score = results['heuristic_score']
        scan_record.domain_reputation_score = results['domain_reputation_score']
        
        db.commit()
        return {"status": "success", "scan_id": scan_id}
        
    except Exception as e:
        db.rollback()
        scan_record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan_record:
            scan_record.status = "failed"
            scan_record.error_message = str(e)
            db.commit()
        raise self.retry(exc=e, countdown=5) # Retry on unexpected failure
    finally:
        db.close()
