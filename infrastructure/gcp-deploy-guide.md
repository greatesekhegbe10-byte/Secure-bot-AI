
# Google Cloud Run Deployment Guide

## 1. Environment Setup
```bash
export PROJECT_ID="securbot-ai-prod"
export REGION="us-central1"
export DB_PASS="change-me-securely"

gcloud config set project $PROJECT_ID
gcloud services enable run.googleapis.com sqladmin.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com
```

## 2. Infrastructure (Cloud SQL & Pub/Sub)
```bash
# Create Postgres Instance
gcloud sql instances create securbot-db \
    --database-version=POSTGRES_15 \
    --cpu=2 --memory=4GB \
    --region=$REGION \
    --root-password=$DB_PASS

# Create Pub/Sub Topics
gcloud pubsub topics create scan-jobs
gcloud pubsub topics create phishing-jobs
```

## 3. Deploy Core API
```bash
gcloud builds submit --tag gcr.io/$PROJECT_ID/core-api ./backend/core

gcloud run deploy core-api \
    --image gcr.io/$PROJECT_ID/core-api \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --add-cloudsql-instances $PROJECT_ID:$REGION:securbot-db \
    --set-env-vars="GCP_PROJECT_ID=$PROJECT_ID,DATABASE_URL=postgresql+psycopg2://postgres:$DB_PASS@/postgres?host=/cloudsql/$PROJECT_ID:$REGION:securbot-db"
```

## 4. Deploy Scanner Worker (Internal)
```bash
gcloud builds submit --tag gcr.io/$PROJECT_ID/scanner-worker ./backend/scanner

gcloud run deploy scanner-worker \
    --image gcr.io/$PROJECT_ID/scanner-worker \
    --platform managed \
    --region $REGION \
    --no-allow-unauthenticated \
    --timeout=20m \
    --cpu=2 --memory=2Gi

# Connect Pub/Sub to Worker
SERVICE_URL=$(gcloud run services describe scanner-worker --format 'value(status.url)')
gcloud pubsub subscriptions create scanner-sub \
    --topic scan-jobs \
    --push-endpoint=$SERVICE_URL \
    --push-auth-service-account=scan-invoker-sa@$PROJECT_ID.iam.gserviceaccount.com
```

## 5. Security & Secrets
1. Go to Secret Manager.
2. Create secrets for `STRIPE_SECRET_KEY`, `GEMINI_API_KEY`.
3. Update Cloud Run services to mount secrets as environment variables.
```bash
gcloud run services update core-api \
    --update-secrets=STRIPE_SECRET_KEY=stripe-key:latest
```
