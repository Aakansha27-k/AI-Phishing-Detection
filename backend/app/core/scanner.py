import os
from sqlalchemy.orm import Session
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from .features import FeatureExtractor
from .ml_model import model_instance
from app.db.models import ScanResult

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCREENSHOTS_DIR = os.path.join(BASE_DIR, 'screenshots')
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

def perform_scan_background(scan_id: str, url: str, db: Session):
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
                    # Security recommendations: block location, permissions
                    geolocation=None,
                    permissions=[]
                )
                page = context.new_page()
                
                # Timeout 10s
                page.goto(url, timeout=10000, wait_until="domcontentloaded")
                
                # Let it settle for a sec to capture popups/redirects
                page.wait_for_timeout(1000)
                
                html_content = page.content()
                page.screenshot(path=screenshot_path, full_page=True, type="png")
                
                browser.close()
        except PlaywrightTimeoutError:
            # It timed out, but we might still have extracted some features or we just proceed with what we have
            print(f"Playwright timeout for {url}")
        except Exception as e:
            print(f"Playwright error for {url}: {e}")
            # Graceful degradation, continue without screenshot/html

        # 4. Extract Features
        extractor = FeatureExtractor(url, html_content=html_content if html_content else None)
        features = extractor.extract_all()
        
        # Mark if screenshot was successful
        features['has_screenshot'] = os.path.exists(screenshot_path)
        
        # 5. Model Prediction & Scoring
        results = model_instance.predict(features)
        
        # 6. Save Results
        scan_record.status = "completed"
        scan_record.features = features
        scan_record.risk_score = results['risk_score']
        scan_record.risk_level = results['risk_level']
        scan_record.ml_probability = results['ml_probability']
        scan_record.heuristic_score = results['heuristic_score']
        scan_record.domain_reputation_score = results['domain_reputation_score']
        
        db.commit()
        
    except Exception as e:
        scan_record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan_record:
            scan_record.status = "failed"
            scan_record.error_message = str(e)
            db.commit()
