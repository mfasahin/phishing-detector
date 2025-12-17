# app/api.py - SON HALİ

from flask import Flask, request, jsonify
from flask_cors import CORS
from detector import analyze_url
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "service": "phishing-detector"})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    result = analyze_url(url)
    return jsonify(result)

@app.route('/')
def index():
    # Bir üst dizindeki (ana klasördeki) index.html'i sun
    return send_from_directory('..', 'index.html')


if __name__ == '__main__':
    # Production için
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') != 'production'
    
    app.run(
        debug=debug,
        host='0.0.0.0',  # Docker için gerekli!
        port=port
    )