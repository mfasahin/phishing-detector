
# 🛡️ Phishing Detection System

Advanced ML-powered phishing detection system with web interface.

## Features
- 🤖 Machine Learning (94% accuracy)
- 🔍 Domain similarity detection (typosquatting)
- 🌐 Google Safe Browsing API integration
- 💻 Modern web interface
- 📊 Real-time analysis

## Tech Stack
- Backend: Python, Flask
- ML: Random Forest Classifier, scikit-learn
- Frontend: HTML, CSS, JavaScript
- APIs: Google Safe Browsing
- DevOps: Docker 

## Setup
1. Docker: docker run -p 5000:5000 phishing-detector
2. pip install -r requirements.txt
3. Add GOOGLE_SAFE_BROWSING_API_KEY to .env
4. python train_model.py (first time only)
5. python app/api.py
6. Open index.html or http://localhost:500