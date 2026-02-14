import os
import json
import subprocess
import base64
import uuid
from datetime import datetime
from flask import Flask, request
from google.cloud import storage
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)

# Config
DB_URL = os.getenv("DATABASE_URL")
BUCKET_NAME = os.getenv("REPORT_BUCKET")

# DB Setup
engine = create_engine(DB_URL) if DB_URL else None
SessionLocal = sessionmaker(bind=engine) if engine else None

@app.route("/", methods=["POST"])
def receive_task():
    envelope = request.get_json()
    if not envelope:
        return "Bad Request: No JSON", 400

    pubsub_message = envelope.get("message")
    if not pubsub_message:
        return "Bad Request: No Message", 400

    try:
        data = base64.b64decode(pubsub_message["data"]).decode("utf-8")
        job = json.loads(data)
        run_scan(job)
        return "OK", 200
    except Exception as e:
        print(f"Worker Error: {e}")
        return "Internal Server Error", 500

def update_status(scan_id, status, report_url=None, score=0):
    if not SessionLocal: return
    db = SessionLocal()
    try:
        params = {"status": status, "sid": scan_id, "now": datetime.utcnow()}
        sql = "UPDATE scans SET status = :status"
        
        if status == "COMPLETED":
            sql += ", completed_at = :now, report_url = :url, risk_score = :score"
            params["url"] = report_url
            params["score"] = score
        elif status == "RUNNING":
             sql += ", started_at = :now"

        sql += " WHERE id = :sid"
        
        db.execute(text(sql), params)
        db.commit()
    except Exception as e:
        print(f"DB Update failed: {e}")
    finally:
        db.close()

def save_finding(scan_id, finding):
    if not SessionLocal: return
    db = SessionLocal()
    try:
        stmt = text("""
            INSERT INTO findings (id, scan_id, severity, title, description, remediation, fingerprint)
            VALUES (:id, :sid, :sev, :title, :desc, :rem, :fp)
        """)
        
        info = finding.get('info', {})
        
        # Nuclei specific field mapping
        db.execute(stmt, {
            "id": str(uuid.uuid4()),
            "sid": scan_id,
            "sev": info.get('severity', 'LOW').upper(),
            "title": info.get('name', 'Unknown Vulnerability'),
            "desc": info.get('description', 'No description provided'),
            "rem": info.get('remediation', 'Check vendor documentation'),
            "fp": finding.get('matcher-name', str(uuid.uuid4()))
        })
        db.commit()
    except Exception as e:
        print(f"Finding insert failed: {e}")
    finally:
        db.close()

def run_scan(job):
    target = job.get('target')
    scan_id = job.get('scan_id')
    
    if not target or not scan_id:
        print("Invalid job data")
        return

    print(f"Starting Nuclei scan for {target} (ID: {scan_id})")
    update_status(scan_id, "RUNNING")

    output_file = f"/tmp/{scan_id}.json"
    
    # Nuclei command
    # Changed flags: -json -o file (Standard for JSONL output in file)
    cmd = [
        "nuclei",
        "-target", target,
        "-json",
        "-o", output_file,
        "-silent",
        "-t", "http/misconfiguration", # Limit templates for demo speed
        "-t", "http/exposures"
    ]

    try:
        # 1. Run Scan
        subprocess.run(cmd, check=True, timeout=1200)
        
        # 2. Upload Report to GCS (if configured)
        report_url = ""
        if BUCKET_NAME:
            try:
                storage_client = storage.Client()
                bucket = storage_client.bucket(BUCKET_NAME)
                blob = bucket.blob(f"reports/{scan_id}.json")
                blob.upload_from_filename(output_file)
                report_url = blob.public_url
            except Exception as e:
                print(f"GCS Upload failed: {e}")

        # 3. Parse JSON Findings
        findings_count = 0
        total_severity_score = 0
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        finding = json.loads(line)
                        save_finding(scan_id, finding)
                        findings_count += 1
                        
                        # Simple score calc
                        sev = finding.get('info', {}).get('severity', 'low').lower()
                        if sev == 'critical': total_severity_score += 10
                        elif sev == 'high': total_severity_score += 5
                        elif sev == 'medium': total_severity_score += 2
                        else: total_severity_score += 1
                    except json.JSONDecodeError:
                        pass
        
        # 4. Complete
        final_score = max(0, 100 - total_severity_score)
        update_status(scan_id, "COMPLETED", report_url, final_score)
        print(f"Scan finished. Findings: {findings_count}")

    except subprocess.TimeoutExpired:
        print("Scan timed out")
        update_status(scan_id, "FAILED")
    except Exception as e:
        print(f"Execution error: {e}")
        update_status(scan_id, "FAILED")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
