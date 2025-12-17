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

## Setup
1. pip install -r requirements.txt
2. Add GOOGLE_SAFE_BROWSING_API_KEY to .env
3. python train_model.py (first time only)
4. python app/api.py
5. Open index.html