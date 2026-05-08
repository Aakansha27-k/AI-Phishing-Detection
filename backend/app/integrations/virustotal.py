import requests
import base64
from app.config import settings
from .mocks import mock_virustotal_response

def check_virustotal(url: str):
    """
    Checks URL against VirusTotal API v3.
    """
    if not settings.VT_API_KEY or settings.ENVIRONMENT == "development":
        return mock_virustotal_response(url)
        
    try:
        # VT v3 API requires URL to be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {
            "x-apikey": settings.VT_API_KEY
        }
        
        response = requests.get(endpoint, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0) > 0
            suspicious = stats.get("suspicious", 0) > 0
            
            # Simple score: 100 if malicious, 50 if suspicious, 0 otherwise
            score = 0
            if malicious:
                score = 100
            elif suspicious:
                score = 50
                
            return {
                "malicious": malicious,
                "suspicious": suspicious,
                "score": score,
                "source": "virustotal"
            }
            
    except Exception as e:
        print(f"VirusTotal error: {e}")
        
    # Fallback to mock on error so we don't crash the scanner
    return mock_virustotal_response(url)
