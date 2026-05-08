import os
import pickle
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'rf_model.pkl')

class PhishModel:
    def __init__(self):
        self.model = None
        self.feature_names = []
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.feature_names = data['features']
        else:
            print("WARNING: Model file not found. Inference will fallback to heuristics only.")

    def calculate_heuristic_score(self, features: dict) -> float:
        score = 0.0
        max_possible = 100.0
        
        # Penalize long URLs
        if features.get('url_length', 0) > 75: score += 10
        if features.get('url_length', 0) > 150: score += 10
        
        # IP in domain
        if features.get('has_ip_in_domain'): score += 30
        
        # Shorteners
        if features.get('is_shortener'): score += 15
        
        # Entropy
        if features.get('entropy', 0) > 4.0: score += 10
        
        # Suspicious Keywords
        score += features.get('num_suspicious_keywords', 0) * 5
        
        # Brand Impersonation
        if features.get('has_brand_impersonation'): score += 40
        
        # HTML features
        if features.get('has_password_input') and features.get('form_action_mismatch'):
            score += 20
        if features.get('has_hidden_inputs'): score += 5
        if features.get('has_suspicious_title'): score += 10
        if features.get('has_iframe') and features.get('has_iframe', 0) > 2: score += 10
        
        # Age
        age = features.get('domain_age_days', -1)
        if 0 <= age < 30: score += 20
        elif 30 <= age < 90: score += 10
        
        return min(score, max_possible)

    def calculate_domain_reputation(self, features: dict) -> float:
        # Simplified reputation score based on MVP features
        score = 0.0
        if features.get('has_suspicious_tld'): score += 50
        if features.get('num_digits_in_domain', 0) > 3: score += 20
        if features.get('domain_age_days', -1) < 14 and features.get('domain_age_days', -1) != -1:
            score += 30
            
        return min(score, 100.0)

    def predict(self, features: dict, vt_data: dict = None, gsb_data: dict = None) -> dict:
        heuristic = self.calculate_heuristic_score(features)
        reputation = self.calculate_domain_reputation(features)
        
        ml_prob = 0.0
        if self.model and self.feature_names:
            # Prepare dataframe matching exact feature order
            row = {f: features.get(f, 0) for f in self.feature_names}
            df = pd.DataFrame([row])
            
            # Predict probability of class 1 (Phishing)
            probs = self.model.predict_proba(df)[0]
            if len(probs) > 1:
                ml_prob = probs[1] * 100.0 # Convert to percentage
        else:
            # Fallback if no model
            ml_prob = heuristic
            
        # VirusTotal Score (0 to 100)
        vt_score = 0.0
        if vt_data:
            vt_score = vt_data.get("score", 0.0)
            
        # Hybrid Scoring
        # 0.3 * heuristic_score + 0.3 * ml_probability + 0.2 * domain_reputation + 0.2 * VT
        final_score = (0.3 * heuristic) + (0.3 * ml_prob) + (0.2 * reputation) + (0.2 * vt_score)
        
        # Google Safe Browsing Penalty
        if gsb_data and gsb_data.get("threats"):
            final_score += 35.0
            
        final_score = min(final_score, 100.0)
        
        # Determine Level
        if final_score <= 30:
            level = "Safe"
        elif final_score <= 60:
            level = "Suspicious"
        else:
            level = "Phishing"
            
        return {
            "risk_score": round(final_score, 2),
            "risk_level": level,
            "ml_probability": round(ml_prob, 2),
            "heuristic_score": round(heuristic, 2),
            "domain_reputation_score": round(reputation, 2),
            "vt_score": round(vt_score, 2),
            "gsb_threats": gsb_data.get("threats", []) if gsb_data else []
        }

model_instance = PhishModel()
