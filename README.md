URL Scam Detector API

A lightweight FastAPI service that detects whether a URL is safe or phishing using a trained machine-learning model. The API loads a saved model and vectorizer, checks trusted domains, processes the URL, and returns a real-time classification result.

Features

• FastAPI endpoint for real-time URL classification
• Trusted-domain whitelist to reduce false positives
• Uses a trained ML model and vectorizer (joblib)
• Ready for deployment on Railway or any cloud platform

Installation
git clone https://github.com/AlreemAlothman/url-scam-detector-api.git
cd url-scam-detector-api
pip install -r requirements.txt
uvicorn main:app --reload


API will run at:

http://127.0.0.1:8000


Swagger Docs:

http://127.0.0.1:8000/docs

Endpoint
POST /predict

Request:

{
  "url": "https://example.com"
}


Response:

{
  "url": "https://example.com",
  "prediction": "safe"
}

Project Files
main.py              # FastAPI application  
phishing_model.pkl   # Trained ML model  
vectorizer.pkl       # Text vectorizer  
requirements.txt     # Dependencies

How It Works

Extracts base domain

Checks if the domain is trusted

If not trusted, processes and vectorizes the URL

Model predicts safe/phishing

Deployment
uvicorn main:app --host 0.0.0.0 --port 8000

Author

Developed by Alreem Alothman
