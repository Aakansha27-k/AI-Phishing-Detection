def mock_virustotal_response(url: str):
    """
    Simulates a VirusTotal response when the API key is not provided.
    In development mode, we mock it based on simple heuristics or randomly
    if it's a known demo url.
    """
    is_phish = "paypal" in url or "login" in url or "update" in url
    
    return {
        "malicious": is_phish,
        "suspicious": is_phish,
        "score": 60 if is_phish else 0,
        "source": "mock"
    }

def mock_gsb_response(url: str):
    """
    Simulates a Google Safe Browsing response.
    """
    is_phish = "phishing" in url or "paypal-update-login" in url
    
    if is_phish:
        return {
            "threats": ["SOCIAL_ENGINEERING"],
            "source": "mock"
        }
        
    return {
        "threats": [],
        "source": "mock"
    }
