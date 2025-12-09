import requests
import json

# API base URL
BASE_URL = "http://127.0.0.1:5000"

def test_health():
    """Health check testi"""
    print("="*50)
    print("🏥 HEALTH CHECK TEST")
    print("="*50)
    
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

def test_phishing_detection(url):
    """Phishing detection testi"""
    print(f"🔍 Testing: {url}")
    print("-"*50)
    
    response = requests.post(
        f"{BASE_URL}/analyze",
        json={"url": url},
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Status: {response.status_code}")
        print(f"🎯 Is Phishing: {result['is_phishing']}")
        print(f"📊 Confidence: {result['confidence']}%")
        print(f"📋 Features: {json.dumps(result['features'], indent=2)}")
        if result['warnings']:
            print(f"⚠️  Warnings:")
            for warning in result['warnings']:
                print(f"   - {warning}")
    else:
        print(f"❌ Error: {response.status_code}")
        print(f"Response: {response.text}")
    
    print()

def main():
    print("\n" + "="*50)
    print("🚀 PHISHING DETECTION API TEST")
    print("="*50 + "\n")
    
    # Health check
    try:
        test_health()
    except Exception as e:
        print(f"❌ Health check failed: {e}\n")
        return
    
    # Test URLs
    test_urls = [
        # Phishing şüpheli URL'ler
        "https://paypa1.com/login",
        "http://192.168.1.1/secure-login",
        "https://accounts-google.verification-required.com/signin",
        
        # Meşru URL'ler
        "https://www.google.com",
        "https://github.com",
        "https://www.python.org"
    ]
    
    print("="*50)
    print("🔍 PHISHING DETECTION TESTS")
    print("="*50 + "\n")
    
    for url in test_urls:
        try:
            test_phishing_detection(url)
        except Exception as e:
            print(f"❌ Error testing {url}: {e}\n")
    
    print("="*50)
    print("✅ ALL TESTS COMPLETED")
    print("="*50)

if __name__ == "__main__":
    main()