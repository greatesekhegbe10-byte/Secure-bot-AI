import os
import json
import base64
import uuid
import whois
import dns.resolver
from datetime import datetime
from flask import Flask, request
from strsimpy.levenshtein import Levenshtein
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
levenshtein = Levenshtein()

# DB Config
DB_URL = os.getenv("DATABASE_URL")
engine = create_engine(DB_URL) if DB_URL else None
SessionLocal = sessionmaker(bind=engine) if engine else None

@app.route("/", methods=["POST"])
def receive_phishing_task():
    envelope = request.get_json()
    if not envelope: return "Bad Request", 400

    pubsub_message = envelope.get("message")
    if not pubsub_message: return "Bad Request", 400

    try:
        data = base64.b64decode(pubsub_message["data"]).decode("utf-8")
        job = json.loads(data)
        check_domain_safety(job)
        return "OK", 200
    except Exception as e:
        print(f"Error: {e}")
        return "Internal Error", 500

def save_alert(monitor_id, finding):
    if not SessionLocal: return
    db = SessionLocal()
    try:
        stmt = text("""
            INSERT INTO domain_alerts 
            (id, monitor_id, detected_domain, risk_level, similarity_score, detected_at)
            VALUES (:id, :mid, :dom, :risk, :score, :now)
        """)
        db.execute(stmt, {
            "id": str(uuid.uuid4()),
            "mid": monitor_id,
            "dom": finding['domain'],
            "risk": finding['risk'],
            "score": finding.get('score', 0),
            "now": datetime.utcnow()
        })
        db.commit()
    except Exception as e:
        print(f"DB Error: {e}")
    finally:
        db.close()

def check_domain_safety(job):
    original_domain = job.get('domain')
    monitor_id = job.get('monitor_id') # Passed from API
    
    if not original_domain: return

    variations = generate_permutations(original_domain)
    print(f"Checking {len(variations)} variations for {original_domain}")
    
    findings = []

    # 1. DNS Resolution Check
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for variant in variations:
        try:
            answers = resolver.resolve(variant, 'A')
            if answers:
                risk = "HIGH"
                # Calculate Levenshtein distance similarity
                dist = levenshtein.distance(original_domain, variant)
                sim_score = int((1 - dist/max(len(original_domain), len(variant))) * 100)

                finding = {
                    "domain": variant,
                    "risk": risk,
                    "reason": "Resolvable Typosquat",
                    "score": sim_score
                }
                findings.append(finding)
                if monitor_id:
                    save_alert(monitor_id, finding)
        except Exception:
            continue 

    # 2. WHOIS Check (Basic Age Analysis)
    try:
        w = whois.whois(original_domain)
        # Handle 'creation_date' which can be a list or datetime
        c_date = w.creation_date
        if isinstance(c_date, list):
            c_date = c_date[0]
        
        if c_date:
            age_days = (datetime.now() - c_date).days
            if age_days < 30:
                print(f"Warning: {original_domain} is new ({age_days} days)")
                # Alert regarding the root domain itself
                if monitor_id:
                    save_alert(monitor_id, {
                        "domain": original_domain,
                        "risk": "MEDIUM",
                        "reason": f"Newly Registered Domain ({age_days} days)",
                        "score": 0
                    })
    except Exception as e:
        print(f"Whois failed: {e}")

    print(f"Analysis complete. Found {len(findings)} risks.")

def generate_permutations(domain):
    try:
        parts = domain.split('.')
        if len(parts) < 2: return []
        name = parts[0]
        ext = '.'.join(parts[1:])
        
        perms = [
            f"{name}1.{ext}",
            f"{name.replace('l','1').replace('i','1')}.{ext}",
            f"{name.replace('o','0')}.{ext}",
            f"{name}-{ext}.com",
            f"secure-{name}.{ext}"
        ]
        return perms
    except:
        return []

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
