# Dockerfile

FROM python:3.11-slim

# Çalışma dizini oluştur
WORKDIR /app

# Sistem bağımlılıklarını yükle
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıklarını kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyalarını kopyala
COPY app/ ./app/
COPY data/ ./data/
COPY index.html .
COPY .env .

# Port'u expose et
EXPOSE 5000

# Healthcheck ekle
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/health')"

# Uygulamayı başlat
CMD ["python", "app/api.py"]