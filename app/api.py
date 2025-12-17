from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from detector import analyze_url
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

# --- YENİ EKLENEN KISIM BAŞLANGIÇ ---
# Bu kısım, biri siteye girdiğinde (root URL) index.html dosyasını gönderir.
@app.route('/')
def home():
    # api.py dosyası 'app' klasöründe, index.html ise bir üst klasörde (ana dizinde).
    # Bu yüzden bir üst dizine (..) çıkıp dosyayı oradan alıyoruz.
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(current_dir)
    return send_from_directory(root_dir, 'index.html')

# Eğer index.html içinde style.css veya script.js gibi dosyalar çağrılıyorsa
# onlar için de genel bir statik dosya sunucusu ekleyelim:
@app.route('/<path:filename>')
def serve_static(filename):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(current_dir)
    return send_from_directory(root_dir, filename)
# --- YENİ EKLENEN KISIM BİTİŞ ---

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


if __name__ == '__main__':
    # Production için
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') != 'production'
    
    app.run(
        debug=debug,
        host='0.0.0.0',  # Docker için gerekli!
        port=port
    )