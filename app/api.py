# Flask/FastAPI routes


from flask import Flask, request, jsonify
from flask_cors import CORS  
from detector import analyze_url
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)  

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    result = analyze_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)