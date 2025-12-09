# app/detector.py - GOOGLE SAFE BROWSING EKLENMİŞ VERSİYON

import re
import os
import requests
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

def analyze_url(url):
    """URL analizi yapar"""
    
    # Feature'ları çıkar
    features = extract_features(url)
    
    # Domain benzerlik kontrolü
    similarity_result = check_domain_similarity(url)
    features['similarity_check'] = similarity_result
    
    # YENİ: Google Safe Browsing kontrolü
    safe_browsing_result = check_google_safe_browsing(url)
    features['safe_browsing'] = safe_browsing_result
    
    # Şüpheli mi kontrol et
    is_suspicious = check_suspicious_patterns(features)
    
    # Güven skoru hesapla
    confidence = calculate_confidence(features)
    
    return {
        "url": url,
        "is_phishing": is_suspicious,
        "confidence": confidence,
        "features": features,
        "warnings": get_warnings(features),
        "similar_domains": similarity_result,
        "safe_browsing": safe_browsing_result  # YENİ!
    }

def check_google_safe_browsing(url):
    """
    YENİ FONKSİYON: Google Safe Browsing API ile URL kontrolü
    """
    # API key'i environment variable'dan al
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
                    "SOCIAL_ENGINEERING",  # Phishing
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
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
    
    except requests.exceptions.Timeout:
        return {
            'checked': False,
            'is_threat': False,
            'threat_types': [],
            'error': 'API request timeout'
        }
    except Exception as e:
        return {
            'checked': False,
            'is_threat': False,
            'threat_types': [],
            'error': str(e)
        }

def extract_features(url):
    """URL'den özellikler çıkar"""
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
    """Şüpheli pattern'leri kontrol et - GÜNCELLENDİ"""
    score = 0
    
    # Mevcut kontroller
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
    
    # YENİ: Google Safe Browsing kontrolü
    safe_browsing = features.get('safe_browsing', {})
    if safe_browsing.get('is_threat', False):
        score += 5  # Google tehdit olarak işaretlemişse kesinlikle phishing!
    
    return score >= 3

def calculate_confidence(features):
    """Güven skoru hesapla (0-100) - GÜNCELLENDİ"""
    score = 0
    
    # Mevcut skorlar
    if features['has_ip']: score += 20
    if features['has_at_symbol']: score += 20
    if features['url_length'] > 75: score += 15
    if features['num_hyphens'] > 3: score += 15
    if not features['has_https']: score += 10
    if features['num_subdomains'] > 3: score += 20
    
    # Domain benzerlik skoru
    similarity = features.get('similarity_check', {})
    if similarity.get('is_similar', False):
        top_match = similarity['matches'][0] if similarity['matches'] else None
        if top_match:
            similarity_score = top_match['similarity']
            if similarity_score > 85:
                score += 30
            elif similarity_score > 75:
                score += 20
    
    # YENİ: Google Safe Browsing skoru
    safe_browsing = features.get('safe_browsing', {})
    if safe_browsing.get('is_threat', False):
        score += 50  # Google onayladıysa çok yüksek güven!
    
    return min(score, 100)

def get_warnings(features):
    """Uyarı mesajları - GÜNCELLENDİ"""
    warnings = []
    
    # Mevcut uyarılar
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
    
    # YENİ: Google Safe Browsing uyarıları
    safe_browsing = features.get('safe_browsing', {})
    if safe_browsing.get('is_threat', False):
        threat_types = safe_browsing.get('threat_types', [])
        threat_str = ', '.join(threat_types)
        warnings.append(
            f"🔴 DANGER: Google Safe Browsing flagged as {threat_str}"
        )
    elif safe_browsing.get('checked', False) and not safe_browsing.get('is_threat', False):
        warnings.append("✅ Google Safe Browsing: No threats detected")
    
    return warnings