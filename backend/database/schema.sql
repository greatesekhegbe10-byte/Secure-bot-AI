-- Users & Subscriptions
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    tier VARCHAR(20) DEFAULT 'FREE', -- FREE, PRO, ENTERPRISE
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Target Assets (Domains, IPs, API Endpoints)
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    type VARCHAR(20) NOT NULL, -- DOMAIN, IP, API_SCHEMA
    value TEXT NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerability Scans (Nuclei/OWASP)
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    asset_id UUID REFERENCES assets(id),
    status VARCHAR(20) DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED
    risk_score INT DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    report_url TEXT -- Link to GCS JSON/PDF report
);

-- Findings (Individual Vulnerabilities)
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    severity VARCHAR(20), -- LOW, MEDIUM, HIGH, CRITICAL
    title VARCHAR(255),
    description TEXT,
    remediation TEXT,
    fingerprint TEXT -- For deduplication
);

-- Phishing/Domain Monitor
CREATE TABLE domain_monitors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    root_domain VARCHAR(255) NOT NULL,
    last_check TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);

CREATE TABLE domain_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_id UUID REFERENCES domain_monitors(id),
    detected_domain VARCHAR(255),
    similarity_score INT,
    dns_records JSONB,
    whois_data JSONB,
    risk_level VARCHAR(20),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
