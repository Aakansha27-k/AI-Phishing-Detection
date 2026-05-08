import requests
from app.config import settings
from .mocks import mock_gsb_response

def check_google_safe_browsing(url: str):
    """
    Checks URL against Google Safe Browsing API v4.
    """
    if not settings.GOOGLE_SAFE_BROWSING_KEY or settings.ENVIRONMENT == "development":
        return mock_gsb_response(url)
        
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_KEY}"
        
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        response = requests.post(endpoint, json=payload, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            
            threats = [match["threatType"] for match in matches]
            
            return {
                "threats": threats,
                "source": "gsb"
            }
            
    except Exception as e:
        print(f"GSB error: {e}")
        
    return mock_gsb_response(url)
