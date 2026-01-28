import os
import json
import uuid
import logging
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google.cloud import pubsub_v1
from sqlalchemy import create_engine, text, Column, String, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
import stripe

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SecurBot Core API")

# --- CORS Setup ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Config ---
PROJECT_ID = os.getenv("GCP_PROJECT_ID", "securbot-dev")
PUBSUB_TOPIC_SCAN = os.getenv("PUBSUB_TOPIC_SCAN", f"projects/{PROJECT_ID}/topics/scan-jobs")
PUBSUB_TOPIC_PHISHING = os.getenv("PUBSUB_TOPIC_PHISHING", f"projects/{PROJECT_ID}/topics/phishing-jobs")
DB_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/securbot")
STRIPE_KEY = os.getenv("STRIPE_SECRET_KEY")

if STRIPE_KEY:
    stripe.api_key = STRIPE_KEY

# --- Database Setup ---
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Pub/Sub Setup ---
try:
    publisher = pubsub_v1.PublisherClient()
except Exception as e:
    logger.warning(f"Pub/Sub client init failed (ignore if local): {e}")
    publisher = None

# --- Models ---
class ScanRequest(BaseModel):
    user_id: str
    target: str
    scan_type: str = "FULL" 

class PhishingRequest(BaseModel):
    user_id: str
    domain: str

# --- DB Helpers ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Endpoints ---

@app.get("/health")
def health_check():
    return {"status": "operational", "service": "core-api"}

@app.post("/api/v1/scan/init")
async def init_scan(request: ScanRequest, db=Depends(get_db)):
    """
    Initiates a security scan by creating a DB record and pushing a job to Pub/Sub.
    """
    try:
        # 1. Create Scan Record in DB
        scan_id = str(uuid.uuid4())
        
        # Raw SQL for simplicity, normally use ORM models
        stmt = text("""
            INSERT INTO scans (id, user_id, status, started_at) 
            VALUES (:id, :uid, 'QUEUED', :now)
        """)
        db.execute(stmt, {
            "id": scan_id, 
            "uid": request.user_id, 
            "now": datetime.utcnow()
        })
        
        # Insert Asset if not exists
        stmt_asset = text("""
            INSERT INTO assets (id, user_id, type, value)
            VALUES (:aid, :uid, 'DOMAIN', :val)
        """)
        # For simplicity using a random ID for asset, ideally check existence
        db.execute(stmt_asset, {
            "aid": str(uuid.uuid4()),
            "uid": request.user_id,
            "val": request.target
        })
        
        db.commit()

        # 2. Publish Message
        if publisher:
            message_data = json.dumps({
                "scan_id": scan_id,
                "target": request.target,
                "type": request.scan_type,
                "user_id": request.user_id
            }).encode("utf-8")
            
            publisher.publish(PUBSUB_TOPIC_SCAN, message_data)
        else:
            logger.warning("Pub/Sub publisher not available. Scan queued in DB but not dispatched.")

        return {"status": "queued", "scan_id": scan_id}

    except Exception as e:
        db.rollback()
        logger.error(f"Init Scan Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/phishing/monitor")
async def monitor_domain(request: PhishingRequest, db=Depends(get_db)):
    try:
        # 1. Create Monitor Record
        stmt = text("""
            INSERT INTO domain_monitors (id, user_id, root_domain, status)
            VALUES (:id, :uid, :domain, 'ACTIVE')
        """)
        monitor_id = str(uuid.uuid4())
        db.execute(stmt, {
            "id": monitor_id,
            "uid": request.user_id,
            "domain": request.domain
        })
        db.commit()

        # 2. Dispatch Job
        if publisher:
            message_data = json.dumps({
                "monitor_id": monitor_id,
                "domain": request.domain,
                "user_id": request.user_id
            }).encode("utf-8")
            publisher.publish(PUBSUB_TOPIC_PHISHING, message_data)

        return {"status": "monitoring_started", "id": monitor_id}
    except Exception as e:
        logger.error(f"Monitor Init Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to start monitoring")
