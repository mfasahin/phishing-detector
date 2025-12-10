# app/detector.py - ML MODEL ENTEGRELİ VERSİYON

import re
import os
import requests
import joblib
import numpy as np
from urllib.parse import urlparse
from difflib import SequenceMatcher

# Popüler sitelerin domain listesi
LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
    'apple.com', 'microsoft.com', 'netflix.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'github.com', 'youtube.com',
    'ebay.com', 'walmart.com', 'banking.com', 'chase.com',
    'wellsfargo.com', 'bankofamerica.com', 'citibank.com'
]

# Google Safe Browsing API endpoint
SAFE_BROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# ML Model'i yükle (global - bir kere yükle)
ML_MODEL = None
FEATURE_NAMES = None

def load_ml_model():
    """ML modelini yükle"""
    global ML_MODEL, FEATURE_NAMES
    
    if ML_MODEL is None:
        try:
            ML_MODEL = joblib.load('data/phishing_model.pkl')
            FEATURE_NAMES = joblib.load('data/feature_names.pkl')
            print("✅ ML Model loaded successfully!")
        except Exception as e:
            print(f"⚠️ Could not load ML model: {e}")
            ML_MODEL = None
            FEATURE_NAMES = None

# Model'i başlangıçta yükle
load_ml_model()

def analyze_url(url):
    """URL analizi yapar - ML MODEL İLE!"""
    
    # Feature'ları çıkar
    features = extract_features(url)
    
    # Domain benzerlik kontrolü
    similarity_result = check_domain_similarity(url)
    features['similarity_check'] = similarity_result
    
    # Google Safe Browsing kontrolü
    safe_browsing_result = check_google_safe_browsing(url)
    features['safe_browsing'] = safe_browsing_result
    
    # YENİ: ML Model prediction
    ml_result = predict_with_ml(url, features)
    features['ml_prediction'] = ml_result
    
    # Şüpheli mi kontrol et (ML + Rules)
    is_suspicious = check_suspicious_patterns(features)
    
    # Güven skoru hesapla (ML + Rules)
    confidence = calculate_confidence(features)
    
    return {
        "url": url,
        "is_phishing": is_suspicious,
        "confidence": confidence,
        "features": features,
        "warnings": get_warnings(features),
        "similar_domains": similarity_result,
        "safe_browsing": safe_browsing_result,
        "ml_prediction": ml_result  # YENİ!
    }

def predict_with_ml(url, basic_features):
    """
    YENİ FONKSİYON: ML modeli ile prediction
    """
    if ML_MODEL is None or FEATURE_NAMES is None:
        return {
            'available': False,
            'prediction': None,
            'probability': None,
            'error': 'Model not loaded'
        }
    
    try:
        # URL'den gelişmiş feature'lar çıkar
        ml_features = extract_ml_features(url)
        
        # Feature vektörünü oluştur
        feature_vector = []
        for feature_name in FEATURE_NAMES:
            if feature_name in ml_features:
                feature_vector.append(ml_features[feature_name])
            else:
                feature_vector.append(0)  # Eksik feature'lar için 0
        
        # Numpy array'e çevir
        X = np.array([feature_vector])
        
        # Prediction
        prediction = ML_MODEL.predict(X)[0]
        probability = ML_MODEL.predict_proba(X)[0]
        
        return {
            'available': True,
            'prediction': 'phishing' if prediction == 1 else 'legitimate',
            'is_phishing': bool(prediction == 1),
            'probability_legitimate': round(float(probability[0]) * 100, 2),
            'probability_phishing': round(float(probability[1]) * 100, 2),
            'confidence': round(float(max(probability)) * 100, 2)
        }
    
    except Exception as e:
        return {
            'available': False,
            'prediction': None,
            'probability': None,
            'error': str(e)
        }

def extract_ml_features(url):
    """
    URL'den ML modeli için feature'lar çıkarır
    Dataset'teki feature'larla uyumlu olmalı
    """
    parsed = urlparse(url)
    
    # URL string
    url_str = url.lower()
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    features = {
        # Temel özellikler
        'length_url': len(url),
        'length_hostname': len(domain),
        'ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        
        # Domain özellikleri
        'nb_www': 1 if 'www' in domain else 0,
        'nb_com': 1 if '.com' in url else 0,
        'nb_dslash': url.count('//'),
        'http_in_path': 1 if 'http' in path else 0,
        'https_token': 1 if 'https' in domain else 0,
        
        # Ratio özellikleri
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'ratio_digits_host': sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0,
        
        # Subdomain özellikleri
        'nb_subdomains': len(domain.split('.')) - 2 if domain else 0,
        'prefix_suffix': 1 if '-' in domain else 0,
        
        # Basit heuristic'ler
        'shortening_service': 1 if any(short in domain for short in ['bit.ly', 'goo.gl', 'tinyurl', 't.co']) else 0,
        'abnormal_subdomain': 1 if len(domain.split('.')) > 4 else 0,
        
        # Diğer basit feature'lar
        'punycode': 1 if 'xn--' in url else 0,
        'port': 1 if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443') else 0,
        'tld_in_path': 1 if any(tld in path for tld in ['.com', '.net', '.org']) else 0,
        'tld_in_subdomain': 1 if any(tld in domain for tld in ['.com.', '.net.', '.org.']) else 0,
        
        # Kelime özellikleri
        'length_words_raw': len(url.split()),
        'char_repeat': max([len(list(g)) for k, g in __import__('itertools').groupby(url)] or [0]),
        
        # Phishing hint'leri
        'phish_hints': sum(1 for hint in ['login', 'signin', 'account', 'update', 'confirm', 'verify', 'secure'] if hint in url.lower()),
        
        # Brand kontrolü
        'domain_in_brand': 1 if any(brand in domain for brand in ['paypal', 'amazon', 'google', 'facebook', 'apple']) else 0,
        'brand_in_subdomain': 1 if any(brand in domain.split('.')[0] for brand in ['paypal', 'amazon', 'google'] if '.' in domain) else 0,
        'brand_in_path': 1 if any(brand in path for brand in ['paypal', 'amazon', 'google', 'facebook']) else 0,
        
        # TLD kontrolü
        'suspecious_tld': 1 if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf', '.gq', '.zip']) else 0,
    }
    
    # Eksik feature'lar için default değerler
    default_features = {
        'random_domain': 0,
        'path_extension': 0,
        'nb_redirection': 0,
        'nb_external_redirection': 0,
        'shortest_words_raw': 0,
        'shortest_word_host': 0,
        'shortest_word_path': 0,
        'longest_words_raw': 0,
        'longest_word_host': 0,
        'longest_word_path': 0,
        'avg_words_raw': 0,
        'avg_word_host': 0,
        'avg_word_path': 0,
        'statistical_report': 0,
        'nb_hyperlinks': 0,
        'ratio_intHyperlinks': 0,
        'ratio_extHyperlinks': 0,
        'ratio_nullHyperlinks': 0,
        'nb_extCSS': 0,
        'ratio_intRedirection': 0,
        'ratio_extRedirection': 0,
        'ratio_intErrors': 0,
        'ratio_extErrors': 0,
        'login_form': 0,
        'external_favicon': 0,
        'links_in_tags': 0,
        'submit_email': 0,
        'ratio_intMedia': 0,
        'ratio_extMedia': 0,
        'sfh': 0,
        'iframe': 0,
        'popup_window': 0,
        'safe_anchor': 0,
        'onmouseover': 0,
        'right_clic': 0,
        'empty_title': 0,
        'domain_in_title': 0,
        'domain_with_copyright': 0,
        'whois_registered_domain': 0,
        'domain_registration_length': 0,
        'domain_age': -1,
        'web_traffic': 0,
        'dns_record': 0,
        'google_index': 0,
        'page_rank': 0
    }
    
    # Default'ları ekle
    for key, value in default_features.items():
        if key not in features:
            features[key] = value
    
    return features

def check_google_safe_browsing(url):
    """Google Safe Browsing API ile URL kontrolü"""
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    
    if not api_key:
        return {
            'checked': False,
            'is_threat': False,
            'threat_types': [],
            'error': 'API key not configured'
        }
    
    try:
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(
            f"{SAFE_BROWSING_API}?key={api_key}",
            json=payload,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            matches = data.get('matches', [])
            
            if matches:
                threat_types = [match['threatType'] for match in matches]
                return {
                    'checked': True,
                    'is_threat': True,
                    'threat_types': threat_types,
                    'platform_types': [match['platformType'] for match in matches],
                    'threat_entries': matches
                }
            else:
                return {
                    'checked': True,
                    'is_threat': False,
                    'threat_types': []
                }
        else:
            return {
                'checked': False,
                'is_threat': False,
                'threat_types': [],
                'error': f'API returned status {response.status_code}'
            }
    
    except Exception as e:
        return {
            'checked': False,
            'is_threat': False,
            'threat_types': [],
            'error': str(e)
        }

def extract_features(url):
    """URL'den temel özellikler çıkar"""
    parsed = urlparse(url)
    
    return {
        "url_length": len(url),
        "domain_length": len(parsed.netloc),
        "has_ip": bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
        "has_at_symbol": '@' in url,
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_underscores": url.count('_'),
        "has_https": parsed.scheme == 'https',
        "num_subdomains": len(parsed.netloc.split('.')) - 2 if parsed.netloc else 0
    }

def check_domain_similarity(url):
    """Domain'i meşru sitelerle karşılaştırır"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    if domain.startswith('www.'):
        domain = domain[4:]
    
    similar_domains = []
    
    for legit_domain in LEGITIMATE_DOMAINS:
        similarity = calculate_similarity(domain, legit_domain)
        
        if similarity > 0.70 and domain != legit_domain:
            similar_domains.append({
                'legitimate': legit_domain,
                'similarity': round(similarity * 100, 2),
                'suspicious_domain': domain
            })
    
    similar_domains.sort(key=lambda x: x['similarity'], reverse=True)
    
    return {
        'is_similar': len(similar_domains) > 0,
        'matches': similar_domains[:3]
    }

def calculate_similarity(str1, str2):
    """İki string arasındaki benzerliği hesaplar"""
    basic_similarity = SequenceMatcher(None, str1, str2).ratio()
    
    if has_single_char_substitution(str1, str2):
        return max(basic_similarity, 0.85)
    
    if has_char_insertion_deletion(str1, str2):
        return max(basic_similarity, 0.80)
    
    return basic_similarity

def has_single_char_substitution(str1, str2):
    """Tek karakter değişimi var mı"""
    if abs(len(str1) - len(str2)) != 0:
        return False
    
    differences = sum(1 for a, b in zip(str1, str2) if a != b)
    return differences == 1

def has_char_insertion_deletion(str1, str2):
    """Tek karakter ekleme/çıkarma var mı"""
    if abs(len(str1) - len(str2)) != 1:
        return False
    
    shorter = str1 if len(str1) < len(str2) else str2
    longer = str2 if len(str1) < len(str2) else str1
    
    for i in range(len(longer)):
        if longer[:i] + longer[i+1:] == shorter:
            return True
    
    return False

def check_suspicious_patterns(features):
    """Şüpheli pattern'leri kontrol et - ML + RULES"""
    score = 0
    
    # Rule-based kontroller
    if features['has_ip']: score += 2
    if features['has_at_symbol']: score += 2
    if features['url_length'] > 75: score += 1
    if features['num_hyphens'] > 3: score += 1
    if not features['has_https']: score += 1
    if features['num_subdomains'] > 3: score += 1
    
    # Domain benzerlik kontrolü
    similarity = features.get('similarity_check', {})
    if similarity.get('is_similar', False):
        top_match = similarity['matches'][0] if similarity['matches'] else None
        if top_match:
            similarity_score = top_match['similarity']
            if similarity_score > 85:
                score += 3
            elif similarity_score > 75:
                score += 2
    
    # Google Safe Browsing
    safe_browsing = features.get('safe_browsing', {})
    if safe_browsing.get('is_threat', False):
        score += 5
    
    # YENİ: ML prediction
    ml_pred = features.get('ml_prediction', {})
    if ml_pred.get('available', False):
        if ml_pred.get('is_phishing', False):
            # ML yüksek confidence ile phishing diyorsa
            if ml_pred.get('probability_phishing', 0) > 70:
                score += 4
            else:
                score += 2
    
    return score >= 3

def calculate_confidence(features):
    """Güven skoru hesapla - ML + RULES"""
    # Eğer ML modeli varsa, öncelikle onu kullan
    ml_pred = features.get('ml_prediction', {})
    if ml_pred.get('available', False):
        ml_confidence = ml_pred.get('confidence', 0)
        
        # Rule-based skorları da ekle
        rule_score = 0
        if features['has_ip']: rule_score += 10
        if features['has_at_symbol']: rule_score += 10
        if not features['has_https']: rule_score += 5
        
        similarity = features.get('similarity_check', {})
        if similarity.get('is_similar', False):
            rule_score += 15
        
        safe_browsing = features.get('safe_browsing', {})
        if safe_browsing.get('is_threat', False):
            rule_score += 20
        
        # ML confidence + rule bonus
        final_confidence = min(ml_confidence + (rule_score * 0.5), 100)
        return round(final_confidence, 2)
    
    # ML yoksa eski yöntemi kullan
    score = 0
    if features['has_ip']: score += 20
    if features['has_at_symbol']: score += 20
    if features['url_length'] > 75: score += 15
    if features['num_hyphens'] > 3: score += 15
    if not features['has_https']: score += 10
    if features['num_subdomains'] > 3: score += 20
    
    similarity = features.get('similarity_check', {})
    if similarity.get('is_similar', False):
        score += 30
    
    safe_browsing = features.get('safe_browsing', {})
    if safe_browsing.get('is_threat', False):
        score += 50
    
    return min(score, 100)

def get_warnings(features):
    """Uyarı mesajları"""
    warnings = []
    
    # Rule-based uyarılar
    if features['has_ip']:
        warnings.append("⚠️ URL contains IP address")
    if not features['has_https']:
        warnings.append("⚠️ Not using HTTPS")
    if features['url_length'] > 75:
        warnings.append("⚠️ Unusually long URL")
    if features['has_at_symbol']:
        warnings.append("⚠️ URL contains @ symbol")
    
    # Domain benzerlik uyarıları
    similarity = features.get('similarity_check', {})
    if similarity.get('is_similar', False):
        for match in similarity['matches']:
            warnings.append(
                f"🚨 Domain very similar to '{match['legitimate']}' "
                f"({match['similarity']}% match) - Possible typosquatting!"
            )
    
    # Google Safe Browsing
    safe_browsing = features.get('safe_browsing', {})
    if safe_browsing.get('is_threat', False):
        threat_types = safe_browsing.get('threat_types', [])
        threat_str = ', '.join(threat_types)
        warnings.append(f"🔴 DANGER: Google Safe Browsing flagged as {threat_str}")
    elif safe_browsing.get('checked', False):
        warnings.append("✅ Google Safe Browsing: No threats detected")
    
    # YENİ: ML uyarıları
    ml_pred = features.get('ml_prediction', {})
    if ml_pred.get('available', False):
        if ml_pred.get('is_phishing', False):
            confidence = ml_pred.get('probability_phishing', 0)
            warnings.append(f"🤖 ML Model: Phishing detected ({confidence}% confidence)")
        else:
            confidence = ml_pred.get('probability_legitimate', 0)
            warnings.append(f"✅ ML Model: Legitimate ({confidence}% confidence)")
    
    return warnings