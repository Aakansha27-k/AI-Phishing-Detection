import math
import re
import socket
import ipaddress
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
from functools import lru_cache
from typing import Dict, Any, Tuple
import datetime

# Cache WHOIS requests to avoid rate limits and improve speed
@lru_cache(maxsize=128)
def get_whois_data(domain: str):
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None

def is_safe_ip(ip_str: str) -> bool:
    """Check for SSRF protection."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_link_local:
            return False
        return True
    except ValueError:
        return False

def resolve_domain_and_check_ssrf(domain: str) -> bool:
    """Resolve domain to IP and check if it's safe."""
    try:
        ip_addr = socket.gethostbyname(domain)
        return is_safe_ip(ip_addr)
    except socket.gaierror:
        # Domain might not exist
        return True

def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

KNOWN_BRANDS = ["paypal", "google", "microsoft", "amazon", "apple", "netflix"]

class FeatureExtractor:
    def __init__(self, url: str, html_content: str = None):
        self.url = url
        self.html_content = html_content
        # Add scheme if missing for parsing
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url
            
        self.parsed_url = urlparse(self.url)
        self.domain = self.parsed_url.netloc.split(':')[0] if self.parsed_url.netloc else ''
        
    def check_ssrf(self) -> Tuple[bool, str]:
        """Returns (is_safe, error_message)."""
        if self.parsed_url.scheme in ['file', 'ftp', 'gopher', 'dict']:
            return False, "Unsupported protocol."
        
        # Check if domain is an IP
        try:
            ipaddress.ip_address(self.domain)
            if not is_safe_ip(self.domain):
                return False, "Local/Private IP addresses are not allowed."
        except ValueError:
            # It's a domain name, resolve and check
            if not resolve_domain_and_check_ssrf(self.domain):
                return False, "Domain resolves to an internal network IP."
                
        return True, ""

    def extract_url_features(self) -> Dict[str, Any]:
        url = self.url
        domain = self.domain
        
        # Suspicious keywords
        suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'paypal', 'apple', 'microsoft']
        
        # URL shorteners
        shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'yfrog.com', 'ow.ly', 'deck.ly']
        
        # Suspicious TLDs (cheap or commonly abused)
        suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.click', '.link', '.pw']
        
        # Brand impersonation detection
        has_brand_impersonation = 0
        for brand in KNOWN_BRANDS:
            if brand in url.lower() and brand not in domain.lower().split('.'):
                # Brand is in the URL but not in the main domain parts
                has_brand_impersonation = 1
                break
                
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_at_symbols': url.count('@'),
            'num_double_slash_in_path': self.parsed_url.path.count('//'),
            'has_ip_in_domain': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
            'is_shortener': 1 if any(s in domain for s in shorteners) else 0,
            'has_suspicious_tld': 1 if any(domain.endswith(t) for t in suspicious_tlds) else 0,
            'num_digits_in_domain': sum(c.isdigit() for c in domain),
            'entropy': calculate_entropy(url),
            'num_suspicious_keywords': sum(1 for kw in suspicious_keywords if kw in url.lower()),
            'is_https': 1 if self.parsed_url.scheme == 'https' else 0,
            'has_brand_impersonation': has_brand_impersonation,
        }
        return features

    def extract_domain_features(self) -> Dict[str, Any]:
        features = {
            'domain_age_days': -1,
            'has_whois': 0
        }
        
        # WHOIS data
        w = get_whois_data(self.domain)
        if w and w.creation_date:
            features['has_whois'] = 1
            creation_date = w.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]
            
            if isinstance(creation_date, datetime.datetime):
                age = (datetime.datetime.now() - creation_date).days
                features['domain_age_days'] = age
                
        return features

    def extract_html_features(self) -> Dict[str, Any]:
        features = {
            'has_password_input': 0,
            'has_hidden_inputs': 0,
            'form_action_mismatch': 0,
            'num_external_scripts': 0,
            'has_iframe': 0,
            'has_suspicious_title': 0
        }
        
        try:
            html = self.html_content
            if not html:
                # Fallback to requests if no html_content provided
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                response = requests.get(self.url, timeout=5, headers=headers)
                if response.status_code == 200:
                    html = response.text

            if html:
                soup = BeautifulSoup(html, 'html.parser')
                
                # Title check
                title = soup.title.string.lower() if soup.title and soup.title.string else ""
                if any(kw in title for kw in ['login', 'verify', 'update', 'secure', 'account']):
                    features['has_suspicious_title'] = 1

                # Check for password inputs
                if soup.find('input', type='password'):
                    features['has_password_input'] = 1
                    
                # Check for hidden inputs
                if soup.find('input', type='hidden'):
                    features['has_hidden_inputs'] = 1
                    
                # Check for iframes
                iframes = soup.find_all('iframe')
                if iframes:
                    features['has_iframe'] = len(iframes) # count iframes to determine if heavy
                    
                # Check external scripts
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    src = script['src']
                    if src.startswith('http') and self.domain not in src:
                        features['num_external_scripts'] += 1
                        
                # Form action mismatch
                forms = soup.find_all('form', action=True)
                for form in forms:
                    action = form['action']
                    if action.startswith('http') and self.domain not in action:
                        features['form_action_mismatch'] = 1
                        break
                        
        except Exception:
            pass # Ignore HTML errors for MVP
            
        return features

    def extract_all(self) -> Dict[str, Any]:
        features = {}
        features.update(self.extract_url_features())
        features.update(self.extract_domain_features())
        features.update(self.extract_html_features())
        return features
