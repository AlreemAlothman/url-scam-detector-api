from fastapi import FastAPI, Request
from pydantic import BaseModel
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
import joblib
import logging
import json

# ------------------------------
# إعداد المسارات وتحميل المودل
# ------------------------------
BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "url_phishing_model_v2.pkl"
VECTORIZER_PATH = BASE_DIR / "url_tfidf_vectorizer_v2.pkl"
THRESHOLDS_PATH = BASE_DIR / "url_model_thresholds_v2.pkl"

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
thresholds_cfg = joblib.load(THRESHOLDS_PATH)

T_SAFE = float(thresholds_cfg["safe"])
T_MAL = float(thresholds_cfg["malicious"])
MODEL_VERSION = thresholds_cfg.get("version", "v2.0")

# ------------------------------
# إعداد الـ Logging
# ------------------------------
LOG_FILE = BASE_DIR / "realtime_logs.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("realtime-logger")

# ------------------------------
# إعداد FastAPI
# ------------------------------
app = FastAPI(
    title="URL Scam Detection API",
    description="Logistic Regression + TF-IDF (char 3-5) with 3-level decision (safe / suspicious / malicious)",
    version=MODEL_VERSION,
)

# قائمة الدومينات الموثوقة 
TRUSTED_DOMAINS = {
    "google.com",
    "https://translate.google.com/",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "github.com",
    "paypal.com",
    "wikipedia.org",
    "whatsapp.com",
    "imamu.edu.sa",
    "edu.sa",
    "gov.sa",
    "moe.gov.sa",
    "kfupm.edu.sa",
    "kaust.edu.sa",
}

class URLInput(BaseModel):
    url: str

# ------------------------------
# دوال مساعدة
# ------------------------------
def extract_base_domain(url: str) -> str:
    """ترجع الدومين الأساسي بدون www."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return url.lower()

def is_trusted_domain(url: str) -> bool:
    domain = extract_base_domain(url)
    # لو كان الدومين نفسه في القائمة
    if domain in TRUSTED_DOMAINS:
        return True
    # دعم الدومينات العامة مثلاً *.edu.sa
    for trusted in TRUSTED_DOMAINS:
        if trusted.startswith(".") and domain.endswith(trusted):
            return True
    return False

def classify_proba(proba: float) -> str:
    """تحويل الاحتمال إلى 3 مستويات."""
    if proba >= T_MAL:
        return "malicious"    # احتيال
    elif proba <= T_SAFE:
        return "benign"       # آمن
    else:
        return "suspicious"   # مشكوك فيه

def model_predict(url: str):
    """تشغيل المودل على رابط واحد وإرجاع (label_3_levels, proba)."""
    X = vectorizer.transform([url])
    proba_malicious = float(model.predict_proba(X)[0][1])
    label = classify_proba(proba_malicious)
    return label, proba_malicious

# ------------------------------
# نقاط النهاية (Endpoints)
# ------------------------------
@app.get("/")
def root():
    return {
        "message": "URL Scam Detection API is running",
        "model_version": MODEL_VERSION,
        "thresholds": {"safe": T_SAFE, "malicious": T_MAL},
    }

@app.post("/predict")
async def predict_url(data: URLInput, request: Request):
    url = data.url.strip()
    domain = extract_base_domain(url)

    client_host = request.client.host if request.client else None
    now = datetime.utcnow().isoformat() + "Z"

    # 1) التحقق من الـ whitelist
    trusted = is_trusted_domain(url)
    if trusted:
        label = "benign"
        proba_malicious = 0.01
        source = "whitelist"
    else:
        # 2) استخدام المودل
        label, proba_malicious = model_predict(url)
        source = "model"

    response = {
        "url": url,
        "domain": domain,
        "trusted_domain": trusted,
        "prediction": label,                       # benign / suspicious / malicious
        "probability_malicious": proba_malicious,
        "thresholds": {"safe": T_SAFE, "malicious": T_MAL},
        "model_version": MODEL_VERSION,
        "source": source,
        "timestamp": now,
    }

    # 3) تسجيل النتيجة في ملف JSONL
    log_entry = {
        "timestamp": now,
        "client_ip": client_host,
        "url": url,
        "domain": domain,
        "prediction": label,
        "probability_malicious": proba_malicious,
        "trusted_domain": trusted,
        "thresholds": {"safe": T_SAFE, "malicious": T_MAL},
        "model_version": MODEL_VERSION,
        "source": source,
    }
    logger.info(json.dumps(log_entry, ensure_ascii=False))

    return response

# لتشغيله مباشرة بـ python main.py
if __name__ == "__main__":
    import uvicorn
    import os

    port = int(os.environ.get("PORT", 8000))

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False
    )



