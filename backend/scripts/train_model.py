import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'model')
os.makedirs(MODEL_DIR, exist_ok=True)
MODEL_PATH = os.path.join(MODEL_DIR, 'rf_model.pkl')

def create_synthetic_data(n_samples=1000):
    """
    Generate synthetic data for the MVP.
    0 = Safe, 1 = Phishing
    """
    np.random.seed(42)
    
    # Safe sites
    n_safe = int(n_samples * 0.5)
    safe_data = {
        'url_length': np.random.normal(30, 10, n_safe),
        'domain_length': np.random.normal(15, 5, n_safe),
        'num_dots': np.random.poisson(2, n_safe),
        'num_hyphens': np.random.poisson(0.5, n_safe),
        'num_at_symbols': np.zeros(n_safe),
        'num_double_slash_in_path': np.zeros(n_safe),
        'has_ip_in_domain': np.zeros(n_safe),
        'is_shortener': np.random.binomial(1, 0.05, n_safe),
        'has_suspicious_tld': np.random.binomial(1, 0.05, n_safe),
        'num_digits_in_domain': np.random.poisson(1, n_safe),
        'entropy': np.random.normal(3.5, 0.5, n_safe),
        'num_suspicious_keywords': np.random.poisson(0.1, n_safe),
        'is_https': np.random.binomial(1, 0.9, n_safe),
        'domain_age_days': np.random.normal(1000, 500, n_safe).clip(min=100),
        'has_whois': np.ones(n_safe),
        'has_password_input': np.random.binomial(1, 0.2, n_safe),
        'has_hidden_inputs': np.random.binomial(1, 0.3, n_safe),
        'form_action_mismatch': np.random.binomial(1, 0.05, n_safe),
        'num_external_scripts': np.random.poisson(2, n_safe),
        'has_iframe': np.random.binomial(1, 0.1, n_safe),
        'label': np.zeros(n_safe)
    }
    
    # Phishing sites
    n_phish = n_samples - n_safe
    phish_data = {
        'url_length': np.random.normal(70, 20, n_phish),
        'domain_length': np.random.normal(25, 10, n_phish),
        'num_dots': np.random.poisson(4, n_phish),
        'num_hyphens': np.random.poisson(2, n_phish),
        'num_at_symbols': np.random.binomial(1, 0.1, n_phish),
        'num_double_slash_in_path': np.random.binomial(1, 0.1, n_phish),
        'has_ip_in_domain': np.random.binomial(1, 0.2, n_phish),
        'is_shortener': np.random.binomial(1, 0.3, n_phish),
        'has_suspicious_tld': np.random.binomial(1, 0.4, n_phish),
        'num_digits_in_domain': np.random.poisson(5, n_phish),
        'entropy': np.random.normal(4.5, 0.8, n_phish),
        'num_suspicious_keywords': np.random.poisson(2, n_phish),
        'is_https': np.random.binomial(1, 0.3, n_phish),
        'domain_age_days': np.random.normal(30, 20, n_phish).clip(min=0),
        'has_whois': np.random.binomial(1, 0.5, n_phish),
        'has_password_input': np.random.binomial(1, 0.8, n_phish),
        'has_hidden_inputs': np.random.binomial(1, 0.7, n_phish),
        'form_action_mismatch': np.random.binomial(1, 0.6, n_phish),
        'num_external_scripts': np.random.poisson(8, n_phish),
        'has_iframe': np.random.binomial(1, 0.5, n_phish),
        'label': np.ones(n_phish)
    }
    
    df_safe = pd.DataFrame(safe_data)
    df_phish = pd.DataFrame(phish_data)
    df = pd.concat([df_safe, df_phish], ignore_index=True)
    return df

def train_and_save():
    print("Generating synthetic data...")
    df = create_synthetic_data(2000)
    
    features = [c for c in df.columns if c != 'label']
    X = df[features]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    clf.fit(X_train, y_train)
    
    score = clf.score(X_test, y_test)
    print(f"Model Accuracy on Test Set: {score:.4f}")
    
    print(f"Saving model to {MODEL_PATH}")
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump({'model': clf, 'features': features}, f)
    print("Done!")

if __name__ == "__main__":
    train_and_save()
