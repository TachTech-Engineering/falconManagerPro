# Falcon Manager Pro - CrowdStrike Detection Management Platform

**Project:** CrowdStrike Falcon Detection Management & Response Platform  
**Status:** ✅ Production - Deployed on GKE  
**Domain:** https://falconmanagerpro.com  
**Version:** 4.0 - Multi-Tenant Edition with MITRE ATT&CK Integration

---

## Overview

**Falcon Manager Pro** is a comprehensive web-based platform for managing CrowdStrike Falcon detections, incidents, hosts, hashes and IOCs. It combines Python CLI tools with a full-stack web application (React + Flask) deployed on Google Kubernetes Engine with Cloudflare CDN and Full (Strict) TLS encryption.  It gives SOC analysts a much cleaner, faster way to isolate and manage hosts. The UI is significantly improved over the native console and should help you streamline triage and remediation.

### Platform Components

1. **Web Application** - Full-featured detection management dashboard
   - React frontend with real-time updates and dark mode
   - Flask backend API with CrowdStrike FalconPy integration
   - Multi-tenant architecture with automatic tenant creation
   - MITRE ATT&CK framework integration
   - Containerized and deployed on GKE

2. **CLI Tools** - Python scripts for bulk operations
   - Hash-based detection management
   - Bulk closure operations
   - Report generation (PDF, CSV, JSON)
   - Multi-customer support

---

## 🌟 Key Features

### Detection Management
- **Real-time Monitoring** - Auto-refresh dashboard with live activity indicator (30s polling)
- **Advanced Search** - FQL (Falcon Query Language) filtering with saved searches
- **Bulk Operations** - Select and update multiple detections simultaneously
- **Severity Filtering** - Quick filter by Critical, High, Medium, Low, Informational
- **Assignment Management** - Assign detections to team members
- **Comment Workflows** - Required comments before status changes for audit trail
- **MITRE ATT&CK Mapping** - Automatic mapping to tactics and techniques

### Hash-Based Operations
- **Close by Hash** - Bulk close all detections matching a SHA256 hash
  - Supports both XDR and ODS detection types
  - Dry-run mode to preview changes before execution
  - Batch processing for thousands of detections
- **Hash Analysis** - Group and analyze detections by file hash
  - Identify repetitive false positives
  - One-click bulk operations from analysis view
  - VirusTotal integration for threat intelligence

### IOC Management
- **Custom Indicators** - Create IPv4, Domain, MD5, SHA1, and SHA256 IOCs
- **IOC Exclusions** - Whitelist known-good files to prevent false positives
- **Severity Levels** - Assign criticality (Critical, High, Medium, Low, Info)
- **Policy Control** - Detect, prevent, or allow actions
- **VirusTotal Integration** - Automatic hash lookups with detection ratios

### Automated Response
- **Response Playbooks** - Automated workflows for common scenarios
- **Trigger Conditions** - Execute on critical detections, ransomware, high severity, or manual
- **Multi-Action Chains** - Contain host, create incident, close detection, kill process
- **Manual Execution** - Run playbooks on-demand with target selection
- **Auto-Trigger System** - Background job checks for matching detections every 60 seconds
- **Execution History** - Complete audit trail with success/failure counts

### Host Management & Real-Time Response (RTR)
- **Endpoint Inventory** - View all managed hosts with status (supports 25k+ hosts)
- **Network Containment** - Isolate compromised systems (reversible)
- **Agent Status** - Monitor online/offline/contained hosts
- **RTR Tier 1** (Read-Only): ls, ps, netstat, filehash
- **RTR Tier 2** (Active Responder): get-file, reg-query, memdump, cp, zip
- **RTR Tier 3** (Admin): kill, rm, runscript, put-file, reg-delete, reg-set, restart, shutdown

### Reporting & Export
- **PDF Reports** - Generate professional detection reports with charts
- **CSV Export** - Spreadsheet-compatible data exports
- **JSON Export** - Machine-readable data for integrations
- **Email Delivery** - Automated report distribution via SMTP relay
- **Saved Views** - Store custom filter configurations
- **Dashboard Statistics** - At-a-glance metrics with severity breakdown
- **Timeline Visualizations** - Hourly, 4-hour, or daily detection trends

---

## 🗂️ Architecture

### Infrastructure (Production)

```
User
  ↓
Cloudflare CDN (TLS Termination)
  ↓ [Full Strict TLS]
GCP Load Balancer (136.110.230.236)
  ↓
Kubernetes Ingress
  ├─→ /api/* → falcon-api (Flask Backend - Port 5003)
  └─→ /*     → falcon-ui (React Frontend - Port 80)
                ↓
          CrowdStrike Falcon API
          PostgreSQL Database
```

### Technology Stack

**Frontend:**
- React 18+ (Single Page Application)
- Lucide Icons for UI elements
- Modern responsive UI with dark mode support
- Session-based authentication with 24-hour expiration
- MITRE ATT&CK framework visualization

**Backend:**
- Python 3.8+ with Flask 3.0
- CrowdStrike FalconPy SDK 1.4+
- Flask-CORS for API access
- ReportLab for PDF generation
- Gunicorn WSGI server
- APScheduler for background jobs

**Infrastructure:**
- Google Kubernetes Engine (GKE Autopilot)
- Cloudflare CDN with Full (Strict) TLS
- Google Artifact Registry
- Docker containerization
- Nginx reverse proxy

**Database:**
- PostgreSQL 12+ (production)
- SQLite 3 (development/testing)
- Multi-tenant data isolation
- Automatic schema creation

**CLI Tools:**
- Python 3.8+ with FalconPy
- Tabulate for formatted output
- Colorama for terminal colors
- TQDM for progress bars

---

## 📋 Prerequisites

### System Requirements

**Backend (Flask API)**
- Python 3.8+ (tested on 3.9, 3.10, 3.11)
- 2GB RAM minimum, 4GB recommended
- Linux (Ubuntu 20.04+) or macOS

**Frontend (React)**
- Node.js 16+ and npm 8+
- Modern web browser (Chrome, Firefox, Safari, Edge)

**Database (Optional but Recommended)**
- PostgreSQL 12+
- Required for multi-tenant features, playbooks, and historical data

**Infrastructure (Production)**
- Docker 20.10+
- Kubernetes 1.21+ (GKE Autopilot recommended)
- Cloudflare account (for CDN and TLS)

### CrowdStrike Requirements

✅ **Active Falcon Subscription** with one of:
- Falcon Insight XDR
- Falcon Complete
- Falcon Enterprise
- Falcon Pro (with RTR add-on)

✅ **API Client Credentials** (see [API Permissions](#-crowdstrike-falcon-api-permissions))

✅ **Minimum Agent Version**: 6.40+ recommended for full RTR support

### Optional Integrations

🔹 **VirusTotal API Key** - For IOC threat intelligence lookups (free tier available)  
🔹 **SMTP Relay** - For email report delivery (configured: `smtp-relay.gmail.com:587`)  
🔹 **MITRE ATT&CK** - Framework data loaded automatically

---

## 🔐 CrowdStrike Falcon API Permissions

To use Falcon Manager Pro, you need to create an API client in CrowdStrike with the following scopes:

### ✅ Required Permissions (Minimum)

| API Scope | Permission | Purpose |
|-----------|------------|---------|
| **Alerts** | Read + Write | View and update detections, change status, add comments |
| **Hosts** | Read + Write | View hosts, network containment, lift containment |
| **IOC** | Read + Write | Create, view, and delete custom indicators of compromise |
| **Real Time Response** | Read + Write | Execute RTR commands (Tier 1 - read-only commands) |

### ⚡ Enhanced Permissions (Recommended)

| API Scope | Permission | Purpose |
|-----------|------------|---------|
| **Real Time Response Admin** | Write | Execute Tier 3 admin commands (runscript, reg-delete, restart, shutdown) |
| **Incidents** | Read + Write | Create incidents from detections (for advanced playbooks) |
| **Event Streams** | Read | Real-time event monitoring (future feature) |
| **Sensor Update Policies** | Read | View agent versions and update policies |

### 🔐 How to Create API Credentials

1. **Login to Falcon Console**
   - Navigate to: Support → API Clients and Keys
   - Click "Add new API client"

2. **Configure Client**
   - **Name**: `Falcon Manager Pro`
   - **Description**: `Multi-tenant detection management platform`
   - **API Scopes**: Select scopes from tables above

3. **Save Credentials**
   - Copy the **Client ID** and **Client Secret**
   - Store securely - they cannot be retrieved later
   - Use these in the login screen or `.env` file

4. **API Base URL**
   - **US-1**: `https://api.crowdstrike.com` (default)
   - **US-2**: `https://api.us-2.crowdstrike.com`
   - **EU-1**: `https://api.eu-1.crowdstrike.com`
   - **US-GOV-1**: `https://api.laggar.gcw.crowdstrike.com`

### 🎯 Permission Tiers Explained

**Tier 0 (Basic Operations)**
- View detections and hosts
- Update detection status
- Create/delete IOCs
- Network containment

**Tier 1 (Read-Only RTR)**
- `ls` - List directory contents
- `ps` - List processes
- `netstat` - Show network connections
- `filehash` - Get file SHA256

**Tier 2 (Active Responder RTR)**
- `get` - Retrieve files from host
- `reg query` - Read registry keys
- `memdump` - Capture memory dumps
- `cp` - Copy files on host
- `zip` - Create archives

**Tier 3 (Admin RTR)**
- `kill` - Terminate processes
- `rm` - Delete files
- `runscript` - Execute custom scripts
- `reg delete/set` - Modify registry
- `restart` - Reboot host
- `shutdown` - Power off host
- `put` - Upload files to host

⚠️ **Security Note**: Tier 3 commands are destructive. Use role-based access control to limit who can execute admin commands.

---

## 🚀 Quick Start

### Option 1: Access Production Web App

Visit: **https://falconmanagerpro.com**

1. Enter your CrowdStrike API credentials
2. (Optional) Enter VirusTotal API key for IOC lookups
3. Start managing detections through the web interface

### Option 2: Use CLI Tools Locally

#### Prerequisites
- Python 3.8+
- CrowdStrike Falcon API credentials

#### Setup

```bash
# Clone/navigate to project
cd /home/kthompson/Development/Projects/falconpy

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Configure API credentials
cp .env.example .env
# Edit .env with your credentials

# Test connection
python scripts/query_detections.py --test-connection
```

#### Common CLI Commands

```bash
# Generate hash report
python scripts/hash_summary.py -o report_$(date +%y%m%d).md

# Search by hash
python scripts/query_detections.py --hash "YOUR_HASH" --details

# Close by hash (dry-run first!)
python scripts/close_by_hash.py --hash "YOUR_HASH" --dry-run

# Close by hash (for real)
python scripts/close_by_hash.py --hash "YOUR_HASH" --comment "Benign - SOC approved"

# Bulk close with filter
python scripts/bulk_close_detections.py --filter 'status:"new"' --dry-run
```

---

## 🎯 First-Time Setup Guide

### Step 1: Create CrowdStrike API Client

1. Login to **Falcon Console** → **Support** → **API Clients and Keys**
2. Click **"Add new API client"**
3. Configure:
   - **Name**: `Falcon Manager Pro`
   - **Scopes**: Select required permissions (see [API Permissions](#-crowdstrike-falcon-api-permissions))
4. **Save** and copy your **Client ID** and **Client Secret**

### Step 2: Setup Database (Recommended)

**For Production:**
```bash
# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
CREATE DATABASE falcon_manager;
CREATE USER falcon_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE falcon_manager TO falcon_user;
\q

# Update backend/.env with database connection
DATABASE_URL=postgresql://falcon_user:your_secure_password@localhost/falcon_manager
```

**For Development:**
```bash
# Use SQLite (auto-created)
DATABASE_URL=sqlite:///falcon_manager.db
```

### Step 3: Deploy Backend

**Local Development:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
# CrowdStrike API (optional - can login via web UI)
FALCON_CLIENT_ID=your_client_id
FALCON_CLIENT_SECRET=your_client_secret
FALCON_BASE_URL=https://api.crowdstrike.com

# Database
DATABASE_URL=postgresql://falcon_user:password@localhost/falcon_manager

# Email (optional)
SMTP_HOST=smtp-relay.gmail.com
SMTP_PORT=587
SMTP_FROM=reports@yourdomain.com
EOF

# Run backend
python app.py
```

**Production (Docker):**
```bash
cd backend
docker build -t falcon-api:latest .
docker run -d -p 5003:5003 \
  -e DATABASE_URL=postgresql://... \
  falcon-api:latest
```

### Step 4: Deploy Frontend

**Local Development:**
```bash
npm install
npm start
# Opens http://localhost:3000
```

**Production (Docker):**
```bash
docker build -t falcon-ui:latest .
docker run -d -p 80:80 falcon-ui:latest
```

### Step 5: First Login

1. Navigate to **https://falconmanagerpro.com** (or http://localhost:3000)
2. Enter your CrowdStrike credentials:
   - **API Base URL**: Select your cloud region
   - **Client ID**: From Step 1
   - **Client Secret**: From Step 1
   - **VirusTotal API Key**: (Optional) For IOC lookups
3. Click **"Connect to Falcon"**
4. Your tenant is created automatically! 🎉

### Step 6: Verify Setup

**Test API Connection:**
```bash
curl http://localhost:5003/api/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "database": true,
  "active_sessions": 1,
  "timestamp": "2025-12-02T..."
}
```

**Test Detection Fetch:**
- Login to web UI
- Navigate to **"Detections"** tab
- Should see recent detections loading

### Step 7: Create Your First Playbook

1. Click **"Playbooks"** tab
2. Click **"Create Playbook"**
3. Try the **"Ransomware Rapid Response"** template:
   - Automatically contains infected hosts
   - Creates IOCs from malware hashes
   - Closes detection after containment
4. Enable **Auto-Trigger** to automate response

---

## 📁 Environment Variables Reference

### Backend (.env)

```bash
# === CrowdStrike API ===
FALCON_CLIENT_ID=abc123...          # Your API client ID
FALCON_CLIENT_SECRET=xyz789...      # Your API client secret  
FALCON_BASE_URL=https://api.crowdstrike.com  # API endpoint for your region

# === Database ===
DATABASE_URL=postgresql://user:pass@host:5432/dbname  # PostgreSQL connection
# OR
DATABASE_URL=sqlite:///falcon_manager.db  # SQLite (dev only)

# === Email Reports (Optional) ===
SMTP_HOST=smtp-relay.gmail.com      # SMTP server
SMTP_PORT=587                        # SMTP port (587 for TLS)
SMTP_FROM=reports@yourdomain.com    # From email address
SMTP_USE_TLS=true                   # Use TLS encryption

# === Application ===
FLASK_ENV=production                # production or development
FLASK_DEBUG=false                   # Debug mode (never true in prod)
SECRET_KEY=your-secret-key-here     # Flask secret key

# === Auto-Trigger System ===
AUTO_TRIGGER_ENABLED=true           # Enable playbook auto-execution
AUTO_TRIGGER_INTERVAL=60            # Check interval in seconds
LOOKBACK_WINDOW=5                   # Minutes to look back for detections
```

### Frontend (.env)

```bash
# === API Configuration ===
REACT_APP_API_URL=http://localhost:5003  # Backend API URL (dev)
# OR
REACT_APP_API_URL=/api                   # Production (same domain)

# === VirusTotal (Optional) ===
REACT_APP_VT_ENABLED=true           # Enable VT integration UI
```

---

## 📚 Documentation

### 🔧 Setup & Configuration
- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Complete CLI tools setup
- **[CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md)** - Infrastructure & TLS setup
- **[.env.example](.env.example)** - API credentials template

### 📖 Usage Guides
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - CLI command reference
- **[SCRIPTS_REFERENCE.md](SCRIPTS_REFERENCE.md)** - Detailed script documentation
- **[falcon_pro_README.md](falcon_pro_README.md)** - Web app features & usage

### 🔍 Troubleshooting
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues & solutions

### 📝 Reference
- **[CHANGES_2025-11-24.md](CHANGES_2025-11-24.md)** - Recent updates

---

## 🎯 Use Cases

### 🆕 First-Time Setup
1. Read: [SETUP_GUIDE.md](SETUP_GUIDE.md)
2. Configure: `.env` file with API credentials
3. Test: `python scripts/query_detections.py --test-connection`
4. Bookmark: [QUICK_REFERENCE.md](QUICK_REFERENCE.md)

### 📊 Generate Reports
```bash
python scripts/hash_summary.py -o report.md
```
Reference: [SCRIPTS_REFERENCE.md](SCRIPTS_REFERENCE.md) → hash_summary.py

### 🔍 Find Specific Detections
```bash
python scripts/query_detections.py --hash "YOUR_HASH"
```
Reference: [QUICK_REFERENCE.md](QUICK_REFERENCE.md) → Common FQL Filters

### ✅ Close Detections
**IMPORTANT:** Always dry-run first!
```bash
python scripts/close_by_hash.py --hash "HASH" --dry-run
python scripts/close_by_hash.py --hash "HASH" --comment "Reason"
```
Reference: [SCRIPTS_REFERENCE.md](SCRIPTS_REFERENCE.md) → Workflow patterns

### 🔧 Troubleshoot Issues
1. Read: [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Run diagnostic commands
3. Check environment variables and credentials

### 👥 Multi-Customer Setup
1. Read: [SETUP_GUIDE.md](SETUP_GUIDE.md) → Multi-Customer Setup
2. Create separate `.env` files per customer
3. Switch: `export ENV_FILE=customer.env`

### 🏗️ Deploy Infrastructure
1. Read: [CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md)
2. Deploy: K8s configurations to GKE
3. Configure: DNS and SSL/TLS in Cloudflare

---

## 🔑 Key Concepts

### Multi-Tenancy Architecture

**Falcon Manager Pro uses automatic tenant isolation:**

- **Tenant Creation**: Automatically created on first login with your CrowdStrike API credentials
- **Data Isolation**: Each tenant's data is completely isolated in the database
- **Session Management**: JWT-style session tokens with 24-hour expiration
- **Cache Isolation**: Per-tenant caching for hosts and detections
- **No Manual Setup**: No need to manually create tenants - just login!

**How It Works:**
1. You provide CrowdStrike API credentials via login screen
2. System generates a unique tenant ID from your Client ID
3. Tenant record is created in database automatically
4. All your data is associated with your tenant ID
5. Session token issued for 24-hour access

**Multi-Organization Support:**
- Same installation supports unlimited CrowdStrike customers
- Each customer gets isolated tenant with own playbooks, IOCs, settings
- No data leakage between tenants
- Perfect for MSSPs and SOC-as-a-Service providers

### Detection Types
| Type | Product | Hash Field | Description |
|------|---------|------------|-------------|
| XDR | `xdr` | `entities.sha256` | Behavioral detections |
| ODS | `epp` | `sha256` | On-Demand Scans |
| IDP | `idp` | None | Identity Protection |
| EPP | `epp` | `entities.sha256` | IOC matches |

### API Migration
**Important:** CrowdStrike decommissioned the Detects API.
- ❌ **Old:** Detects API → 404 error
- ✅ **New:** Alerts API → Current
- **Note:** GUI still says "Detections" but API is "Alerts"

### Status Values
- `new` - New/unreviewed
- `in_progress` - Under investigation
- `true_positive` - Confirmed threat (resolved)
- `false_positive` - Benign activity (closed)
- `closed` - Resolved/closed
- `reopened` - Reopened after closure
- `ignored` - Temporarily ignored
- ❌ **NOT VALID:** "resolved" (use "true_positive" or "closed" instead)

### MITRE ATT&CK Integration

**Automatic Mapping:**
- Detections are automatically mapped to MITRE ATT&CK tactics and techniques
- Visual heatmap shows attack patterns across your environment
- Click technique badges to view detailed framework documentation
- Supports tactics: Initial Access, Execution, Persistence, Privilege Escalation, etc.

**Data Sources:**
- Primary: `mitre_attack` array from Falcon API (new format)
- Fallback: `tactic_id`, `technique_id` top-level fields
- Legacy: Behavior-level tactic/technique strings

### Database Schema

**Core Tables:**
- `tenants` - Multi-tenant organization data
- `playbooks` - Automated response workflows
- `playbook_executions` - Execution history and results
- `iocs` - Custom indicators of compromise
- `detections` (optional) - Historical detection storage

**No Manual Migration Needed:**
- Tables auto-created on first run
- Schema updates handled automatically
- Use PostgreSQL for production, SQLite for dev/testing

---

## ⚠️ Common Setup Issues

### Problem: "Authentication failed" on login

**Possible Causes:**
1. **Incorrect API credentials** - Verify Client ID and Secret
2. **Wrong base URL** - Check your cloud region (US-1, US-2, EU-1, etc.)
3. **Insufficient permissions** - Ensure all required API scopes are enabled
4. **Expired credentials** - Regenerate in Falcon Console if > 2 years old

**Solution:**
```bash
# Test credentials directly
curl -X POST https://api.crowdstrike.com/oauth2/token \
  -d "client_id=YOUR_ID&client_secret=YOUR_SECRET&grant_type=client_credentials"
```

### Problem: "Database not available" error

**Possible Causes:**
1. PostgreSQL not running
2. Incorrect DATABASE_URL in .env
3. Database permissions issue
4. Database not created

**Solution:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test database connection
psql $DATABASE_URL -c "SELECT version();"

# Recreate database (if needed)
sudo -u postgres psql -c "DROP DATABASE falcon_manager;"
sudo -u postgres psql -c "CREATE DATABASE falcon_manager;"
```

### Problem: Hosts not loading or showing 0 hosts

**Possible Causes:**
1. **Cache issue** - Click "Force Refresh from API"
2. **API rate limiting** - Wait 60 seconds and retry
3. **Permissions** - Need "Hosts: Read" scope
4. **No hosts in Falcon** - Deploy Falcon agents first

**Solution:**
```bash
# Test host API access
curl http://localhost:5003/api/hosts \
  -H "X-Session-Token: YOUR_TOKEN"

# Clear cache
curl -X POST http://localhost:5003/api/cache/clear \
  -H "X-Session-Token: YOUR_TOKEN"
```

### Problem: RTR commands failing

**Possible Causes:**
1. Host is offline
2. Insufficient RTR permissions (need Tier 2 or 3)
3. RTR not enabled on host
4. Session timeout

**Solution:**
- Check host status is "online"
- Verify RTR permissions in API client
- Ensure host has RTR enabled in sensor policy
- Refresh session and retry command

### Problem: Playbooks not auto-triggering

**Possible Causes:**
1. Auto-trigger system disabled
2. No active playbooks with matching trigger
3. Detection already processed
4. Playbook disabled

**Solution:**
```bash
# Check auto-trigger status
curl http://localhost:5003/api/playbooks/auto-trigger/status \
  -H "X-Session-Token: YOUR_TOKEN"

# Enable auto-trigger
curl -X POST http://localhost:5003/api/playbooks/auto-trigger/toggle \
  -H "X-Session-Token: YOUR_TOKEN" \
  -d '{"enabled": true}'
```

### Problem: Email reports not sending

**Possible Causes:**
1. SMTP configuration incorrect
2. Email relay not allowing connections
3. Recipient address invalid
4. Attachment too large (>25MB)

**Solution:**
```bash
# Test SMTP connection
telnet smtp-relay.gmail.com 587

# Check backend logs
docker logs falcon-api | grep -i smtp

# Verify SMTP settings in .env
echo $SMTP_HOST
echo $SMTP_PORT
echo $SMTP_FROM
```

### Problem: MITRE ATT&CK data not showing

**Possible Causes:**
1. Detection type doesn't include MITRE data (e.g., older detections)
2. Frontend not parsing `mitre_attack` array correctly
3. Tactic/technique IDs missing from Falcon response

**Solution:**
- Most modern Falcon detections include MITRE data automatically
- Check browser console for JavaScript errors
- Verify detection has `mitre_attack` array in API response
- Update to latest Falcon Manager Pro version

### Problem: "Session expired" errors

**Solution:**
- Sessions expire after 24 hours
- Simply logout and login again
- Session extends automatically with activity

---

## 🔒 Security Best Practices

### API Credentials
- ✅ Store API credentials in `.env` file (never commit to git)
- ✅ Use separate API clients for dev/staging/production
- ✅ Rotate credentials every 90 days
- ✅ Apply principle of least privilege (only needed scopes)
- ❌ Never hardcode credentials in source code
- ❌ Never share credentials via email/chat

### Session Management
- Sessions auto-expire after 24 hours
- Use secure session tokens (32-byte random)
- Clear session on logout
- Sessions are tenant-isolated

### Database Security
- Use strong passwords (16+ characters)
- Enable SSL/TLS for database connections
- Restrict database access to application servers only
- Regular backups with encryption
- Monitor for suspicious queries

### Network Security
- Deploy behind Cloudflare or similar WAF
- Use TLS 1.2+ (Full Strict mode in Cloudflare)
- Restrict API access to known IPs if possible
- Enable DDoS protection
- Use security headers (CSP, HSTS, X-Frame-Options)

### RTR Command Safety
- **Tier 1** (Read-Only): Safe for junior analysts
- **Tier 2** (Active Responder): Requires training
- **Tier 3** (Admin): Senior analysts only, with approval
- Always test destructive commands on non-production first
- Document all RTR actions in incident tickets
- Use playbooks for repeatable, audited automation

### Audit & Compliance
- All API calls logged with tenant ID
- Playbook executions stored in database
- Detection status changes tracked
- Export audit logs for SIEM ingestion
- Retain logs per compliance requirements (e.g., PCI-DSS, HIPAA)

---

## 🛡️ Safety Features

### Built-in Protection

**CLI Tools Include:**
- ✅ **Dry-run mode** - Preview before making changes (`--dry-run` flag)
- ✅ **Confirmation prompts** - Prevents accidental execution of destructive commands
- ✅ **Batch processing** - Handles large volumes safely with pagination
- ✅ **Rate limiting** - Prevents API throttling (auto-retry with backoff)
- ✅ **Progress tracking** - Real-time progress bars (TQDM)
- ✅ **Error handling** - Graceful failure recovery with detailed error messages
- ✅ **Audit logging** - All actions logged with timestamp and tenant ID

**Web Application Safety:**
- ✅ **Session isolation** - Multi-tenant data separation (no cross-tenant access)
- ✅ **Comment requirements** - Must add comment before status changes
- ✅ **Bulk action warnings** - Confirmation dialogs for mass updates
- ✅ **Read-only mode** - View-only access for users without write permissions
- ✅ **Playbook dry-run** - Test playbooks before enabling auto-trigger
- ✅ **RTR command confirmation** - Double-check for destructive commands (Tier 3)

### Best Practices
1. **Always dry-run first** - Test commands with `--dry-run` before executing
2. **Start with small batches** - Test on 1-5 detections before scaling to thousands
3. **Include meaningful comments** - Document WHY you're taking action for audit trail
4. **Review hash summaries before closing** - Verify it's actually benign with VT lookup
5. **Test with one hash before bulk operations** - Confirm your filter is correct
6. **Keep API credentials secure** - Store in `.env`, never commit to git
7. **Use playbooks for repeatability** - Automate common workflows instead of manual actions
8. **Monitor auto-trigger executions** - Review playbook history weekly for false positives
9. **Implement role-based access** - Limit RTR Tier 3 to senior analysts only
10. **Regular backups** - Backup database nightly (automated in production)

### Undo Capabilities
- ❌ Detection closures **cannot** be undone via API (CrowdStrike limitation)
- ✅ Detections can be **reopened** manually in Falcon Console if needed
- ✅ IOC deletions **cannot** be undone (create new IOC instead)
- ✅ Host containment **can** be lifted with "Lift Containment" button
- ✅ Playbook executions logged for audit trail but actions are final
- **Best Practice**: Always use dry-run and confirm before irreversible actions

### Rate Limiting & Performance
- **API Rate Limits**: CrowdStrike enforces rate limits (varies by license)
- **Detection Queries**: Max 10,000 per request (batched automatically)
- **Host Queries**: Max 5,000 per batch (pagination for 25k+ hosts)
- **IOC Operations**: Max 2,000 per request
- **Auto-retry**: Automatic backoff when rate limited (30s, 60s, 120s)
- **Caching**: 5-minute cache for hosts, refreshable with "Force Refresh"
- **Session Pooling**: Reuses RTR sessions to reduce overhead

---

## 🔧 Maintenance & Operations

### Daily Operations

**SOC Analyst Tasks:**
- Monitor detection dashboard (auto-refreshes every 30 seconds)
- Review and close false positives using Hash Analysis tool
- Execute playbooks for confirmed threats
- Check host status and lift containment when threats cleared
- Check system health at `/api/health` endpoint

**Automated Tasks:**
- Auto-trigger playbooks check for new detections every 60 seconds
- Detection sync to database every 10 minutes (background job)
- Host cache refreshes every 5 minutes (on-demand available)
- Session cleanup for expired tokens (hourly)

### Weekly Maintenance

**Review & Optimization:**
- Check for FalconPy SDK updates: `pip list --outdated`
- Review API usage in CrowdStrike console (Usage & Billing → API)
- Monitor container image sizes and prune old images
- Review playbook execution logs for false positives
- Analyze detection trends and adjust auto-trigger thresholds
- Verify backup integrity (restore test)

**Security Tasks:**
- Review audit logs for suspicious activity
- Check for unauthorized API clients in Falcon Console
- Verify database access logs (failed login attempts)
- Update security group rules if needed
- Review user access and permissions

### Monthly Maintenance

**Data Cleanup:**
- Review closed detections accuracy (sample 50 random)
- Archive old reports to cold storage (S3 Glacier)
- Vacuum database to reclaim space: `VACUUM ANALYZE;`
- Clean up unused IOCs (review last 90 days)
- Delete obsolete playbooks (disabled + unused)

**Updates & Patches:**
- Update documentation if workflow changes
- Apply backend security patches: `pip install -U`
- Update frontend dependencies: `npm update`
- Review and merge Dependabot alerts
- Test updates in staging before production

**Monitoring:**
- Check GKE cluster health and resource usage
- Review CloudWatch/Stackdriver logs for errors
- Verify CDN cache hit rates (should be >80%)
- Monitor database performance (query slow log)
- Review API error rates (should be <1%)

### Quarterly Maintenance

**Security Hardening:**
- **Rotate API credentials** (CrowdStrike + VirusTotal)
- **Review and update API scopes** (remove unused permissions)
- **Test disaster recovery** (full redeploy from scratch)
- **Audit security configurations** (TLS ciphers, headers, etc.)
- **Penetration testing** (optional but recommended)
- **Review incident response procedures**

**Capacity Planning:**
- Analyze detection volume trends (prepare for scale)
- Review database growth (add storage if >80% full)
- Check host count growth (optimize queries if >50k hosts)
- Monitor API rate limit consumption (upgrade license if >80%)
- Evaluate playbook execution frequency (optimize triggers)

### Certificate Renewal

**TLS Certificates:**
- **Cloudflare Origin Certificate**: Expires November 20, 2040
- **Reminder set**: November 2039 (1 year advance warning)
- **Renewal process**: See [CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md)
- **Auto-renewal**: Not available for origin certificates (manual process)

**Steps to Renew:**
1. Generate new origin certificate in Cloudflare (6 months before expiry)
2. Update `cloudflare-origin-secret.yaml` with new cert
3. Apply to Kubernetes: `kubectl apply -f cloudflare-origin-secret.yaml`
4. Verify TLS: `curl -v https://falconmanagerpro.com`
5. Monitor for certificate warnings in browser

### Backup & Recovery

**Database Backups:**
```bash
# Daily automated backup (cron job)
0 2 * * * pg_dump $DATABASE_URL | gzip > /backups/falcon_$(date +\%Y\%m\%d).sql.gz

# Retention policy
# Daily: 7 days
# Weekly: 4 weeks  
# Monthly: 12 months

# Restore from backup
gunzip < falcon_20251202.sql.gz | psql $DATABASE_URL
```

**Configuration Backups:**
- K8s manifests: Version controlled in Git
- `.env` files: Encrypted and stored in secrets manager (AWS SSM, GCP Secret Manager)
- Playbooks: Exported monthly as JSON via API
- IOCs: Exported monthly as CSV via web UI

**Disaster Recovery:**
1. Restore database from most recent backup
2. Redeploy K8s configurations from Git
3. Restore `.env` from secrets manager
4. Verify health endpoint returns 200 OK
5. Import playbooks from JSON backup
6. Test critical workflows (detection fetch, host containment, RTR)

**RTO/RPO Targets:**
- **RTO** (Recovery Time Objective): 4 hours
- **RPO** (Recovery Point Objective): 24 hours (daily backups)
- **Critical Services**: Detection viewing, host containment, RTR
- **Non-Critical**: Playbook auto-trigger (can tolerate 24h downtime)

### Monitoring & Alerting

**Health Checks:**
```bash
# API Health (every 1 minute)
curl https://falconmanagerpro.com/api/health

# Expected: {"status":"healthy","database":true,"active_sessions":N}
```

**Key Metrics to Monitor:**

| Metric | Threshold | Action |
|--------|-----------|--------|
| API Response Time | >2s | Investigate slow queries |
| Detection Fetch Time | >10s | Check CrowdStrike API status |
| Database Connections | >80% pool | Increase connection pool |
| Memory Usage | >90% | Scale pods or increase limits |
| CPU Usage | >80% sustained | Add more replicas |
| Disk Usage | >85% | Expand storage or archive data |
| Failed Logins | >10/hour | Check for brute force attack |
| API Errors (5xx) | >5% | Check backend logs |
| Cache Miss Rate | >30% | Tune cache timeout |

**Alerting Setup (Example with Prometheus):**
```yaml
groups:
  - name: falcon_manager
    rules:
      - alert: HighAPIErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High API error rate detected"
          
      - alert: DatabaseConnectionPoolExhausted
        expr: db_connections_active / db_connections_max > 0.9
        for: 5m
        annotations:
          summary: "Database connection pool nearly exhausted"
```

**Log Aggregation:**
- Stream logs to ELK/Splunk/CloudWatch
- Alert on ERROR and CRITICAL level logs
- Daily log review for anomalies
- Keep logs for 90 days (compliance requirement)

### Performance Optimization

**Database Tuning:**
```sql
-- Add indexes for common queries
CREATE INDEX idx_detections_tenant_timestamp ON detections(tenant_id, created_at DESC);
CREATE INDEX idx_detections_severity ON detections(tenant_id, severity);
CREATE INDEX idx_playbooks_tenant_enabled ON playbooks(tenant_id, enabled);

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM detections WHERE tenant_id = 'xxx' AND created_at > NOW() - INTERVAL '24 hours';

-- Vacuum and analyze weekly
VACUUM ANALYZE;
```

**API Optimization:**
- Enable Redis caching for frequently accessed data (hosts, IOCs)
- Use HTTP/2 for multiplexed connections
- Compress API responses with gzip
- Implement pagination for large result sets (already done for hosts)
- Use connection pooling (already configured)

**Frontend Optimization:**
- Lazy load components with React.lazy()
- Implement virtual scrolling for large detection lists
- Use service workers for offline capability
- Minimize bundle size with tree shaking
- Use CDN for static assets (already via Cloudflare)

---

## 📊 Statistics & Capacity Planning

### Current Deployment Metrics

**Codebase:**
- **Backend**: 1,100 lines (Python/Flask)
- **Frontend**: 1,431 lines (React/JavaScript)
- **CLI Scripts**: 5 Python scripts (500+ lines total)
- **Documentation**: 10+ comprehensive guides
- **Container Images**: 62+ versions deployed
- **Registry Size**: 2.2 GB across 2 repositories

**Infrastructure:**
- **Cluster Nodes**: 2 (GKE Autopilot, auto-scales to 10)
- **Services**: 2 (falcon-api, falcon-ui)
- **Ingress**: 1 with TLS termination
- **Static IPs**: 1 reserved (136.110.230.236)
- **Domains**: 1 (falconmanagerpro.com)

**Typical Resource Usage:**
- **Backend Pod**: 256MB RAM, 0.2 CPU (idle) → 1GB RAM, 1.0 CPU (peak)
- **Frontend Pod**: 128MB RAM, 0.1 CPU (constant)
- **Database**: 2GB RAM, 10GB storage (grows ~100MB/month per 1000 detections)

### Scaling Recommendations

**Small Deployment (1-5 Analysts, <10k Hosts)**
- Backend: 1 replica, 512MB RAM, 0.5 CPU
- Database: 2GB RAM, 20GB storage
- Expected Load: <100 API req/min
- Cost: ~$50/month (GCP + Cloudflare Free)

**Medium Deployment (5-20 Analysts, 10k-50k Hosts)**
- Backend: 2-3 replicas, 1GB RAM, 1.0 CPU each
- Database: 4GB RAM, 50GB storage
- Expected Load: 100-500 API req/min
- Cost: ~$200/month (GCP + Cloudflare Pro)

**Large Deployment (20+ Analysts, 50k+ Hosts, MSSP)**
- Backend: 5-10 replicas, 2GB RAM, 2.0 CPU each
- Database: 16GB RAM, 200GB storage, read replicas
- Expected Load: 500-2000 API req/min
- Cost: ~$1000/month (GCP + Cloudflare Business)
- Consider: Redis cache, load balancing, multi-region

### Growth Projections

**Detection Storage:**
- Average detection size: ~5KB
- 1000 detections/day = ~5MB/day = ~150MB/month
- Retention: 90 days recommended (compliance)
- Archive older detections to cold storage (S3 Glacier)

**Database Growth:**
- Detections: ~5KB each × retention period
- Playbook Executions: ~2KB each (kept indefinitely)
- IOCs: ~1KB each (grows slowly)
- Audit Logs: ~0.5KB per action
- Total: Expect 2-5GB/year for typical deployment

**API Rate Limits:**
- CrowdStrike enforces rate limits (varies by license)
- Typical: 1000 req/min for Alerts API
- Upgrade to Enterprise license if approaching limits
- Implement request queuing and batching

---

## ❓ Frequently Asked Questions (FAQ)

### General Questions

**Q: Is this an official CrowdStrike product?**  
A: No, Falcon Manager Pro is a third-party tool that integrates with CrowdStrike Falcon via official APIs. It's not affiliated with or endorsed by CrowdStrike, Inc.

**Q: Does this replace the Falcon Console?**  
A: No, it's a complementary tool. Use Falcon Manager Pro for bulk operations, automation, and custom workflows. Use Falcon Console for deep forensics, agent deployment, and advanced features.

**Q: Can multiple people use this at the same time?**  
A: Yes! The web application supports unlimited concurrent users. Each user logs in with the same CrowdStrike API credentials (or you can create separate API clients per user/team).

**Q: Is my data secure?**  
A: Yes. All data is stored in your own database (self-hosted). API credentials are encrypted. TLS 1.2+ for all connections. Session tokens expire after 24 hours. Full data isolation between tenants.

**Q: How much does it cost?**  
A: The software is free (see license section). You only pay for infrastructure (GCP, domain, etc.) - typically $50-200/month depending on scale.

### Technical Questions

**Q: What CrowdStrike license do I need?**  
A: Any license that includes API access. Tested with Falcon Insight, Complete, Enterprise, and Pro (with RTR add-on for full RTR features).

**Q: Can I use this with multiple CrowdStrike tenants?**  
A: Yes! The multi-tenant architecture supports unlimited CrowdStrike customers/tenants. Each logs in with their own API credentials.

**Q: Does this work with FedRAMP/GovCloud?**  
A: Yes, set the base URL to `https://api.laggar.gcw.crowdstrike.com` for US-GOV-1 region.

**Q: Can I run this on-premises without internet access?**  
A: Partially. The backend can run air-gapped if you deploy CrowdStrike Falcon in Segregated mode. However, VirusTotal integration requires internet access.

**Q: What's the difference between CLI tools and web app?**  
A: CLI tools are for power users and automation (scripting). Web app is for analysts and managers (UI). Both use the same FalconPy SDK. Use whatever fits your workflow!

**Q: Can I customize the playbook actions?**  
A: Yes! The codebase is open. Add custom actions in `app.py` → `execute_playbook_actions()` function. Common additions: Slack notifications, Jira tickets, ServiceNow incidents.

### Operational Questions

**Q: How often should I rotate API credentials?**  
A: Every 90 days for production, 180 days for non-production. CrowdStrike best practice is 90 days.

**Q: What happens if my database goes down?**  
A: The web app will fail to load (needs database for tenants). However, CLI tools can still operate independently using `.env` credentials.

**Q: Can I migrate from SQLite to PostgreSQL later?**  
A: Yes, but manual process. Export data from SQLite, transform schema, import to PostgreSQL. Recommend starting with PostgreSQL for production.

**Q: How do I backup my playbooks?**  
A: Use the API: `GET /api/playbooks` → save JSON. Or backup the entire database. Restore by re-creating playbooks via UI or API.

**Q: What if CrowdStrike API changes break compatibility?**  
A: FalconPy SDK is maintained by CrowdStrike and handles API versioning. Keep FalconPy updated: `pip install -U crowdstrike-falconpy`. Major breaking changes are rare and announced well in advance.

### Troubleshooting Questions

**Q: Why am I seeing "Session expired" repeatedly?**  
A: Sessions expire after 24 hours. This is normal. Just logout and login again. To extend sessions, increase the expiration time in `app.py` (line with `timedelta(hours=24)`).

**Q: Why can't I see new detections?**  
A: Check: (1) Time range filter - try "Last 7 Days", (2) Status filter - try "All", (3) API permissions - need "Alerts: Read", (4) Force refresh from API, (5) Check CrowdStrike Console to verify detections exist.

**Q: RTR commands timeout or fail?**  
A: Common causes: (1) Host is offline, (2) Network latency (increase timeout), (3) RTR not enabled on host policy, (4) Session expired (refresh page), (5) Insufficient permissions (need RTR Admin for Tier 3).

**Q: Playbook executed but nothing happened?**  
A: Check playbook execution history: Playbooks tab → Click playbook → View History. Look for failed actions. Common issues: Wrong target type (detection vs host), host offline, insufficient permissions.

**Q: High memory usage on backend?**  
A: Likely causes: (1) Large detection queries (reduce time range), (2) Many concurrent sessions (scale horizontally), (3) Memory leak (restart pod). Monitor with: `docker stats` or `kubectl top pods`.

**Q: Database connection errors?**  
A: Check: (1) PostgreSQL is running, (2) DATABASE_URL is correct, (3) Connection pool not exhausted, (4) Firewall allows connection, (5) Database disk not full.

### Integration Questions

**Q: Can I integrate with Slack for notifications?**  
A: Not built-in, but easy to add. Modify `execute_playbook_actions()` to add a Slack webhook action. See [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks).

**Q: Can I send detections to SIEM?**  
A: Yes, use the `/api/detections` endpoint to poll for new detections. Or use CrowdStrike Event Streams API directly (more efficient). Common integrations: Splunk, ELK, QRadar, Sentinel.

**Q: Does this support SAML/SSO?**  
A: No, authentication is via CrowdStrike API credentials only. However, you could add a reverse proxy with SSO (e.g., Keycloak, Auth0) in front.

**Q: Can I export audit logs?**  
A: Playbook executions are stored in database (`playbook_executions` table). Query directly or add an export endpoint. Detection actions are logged by CrowdStrike Falcon natively (Audit Logs in Console).

**Q: Integration with ticketing systems (Jira, ServiceNow)?**  
A: Not built-in. Add custom playbook action to create tickets via API. Example: `create_ticket` action calls Jira REST API with detection details.

---

## 🆘 Support & Resources

### 📚 Documentation
- **README.md** (this file) - Project overview and quick start
- **[SETUP_GUIDE.md](SETUP_GUIDE.md)** - Complete CLI tools setup
- **[CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md)** - Infrastructure & TLS setup
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - CLI command reference
- **[SCRIPTS_REFERENCE.md](SCRIPTS_REFERENCE.md)** - Detailed script documentation
- **[falcon_pro_README.md](falcon_pro_README.md)** - Web app features & usage
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues & solutions
- **[CHANGES_2025-11-24.md](CHANGES_2025-11-24.md)** - Recent updates

### 🌐 External Resources
- **[CrowdStrike API Documentation](https://falcon.crowdstrike.com/documentation/)** - Official API reference
- **[FalconPy SDK Docs](https://falconpy.io/)** - Python SDK documentation
- **[CrowdStrike Support Portal](https://supportportal.crowdstrike.com/)** - Technical support
- **[MITRE ATT&CK Framework](https://attack.mitre.org/)** - Threat intelligence
- **[VirusTotal API](https://developers.virustotal.com/reference/overview)** - Hash lookup integration
- **[GKE Documentation](https://cloud.google.com/kubernetes-engine/docs)** - Kubernetes hosting
- **[Cloudflare SSL/TLS](https://developers.cloudflare.com/ssl/)** - CDN and encryption

### 🔧 Diagnostic Commands

```bash
# Test API connection
python scripts/query_detections.py --test-connection

# Check backend health
curl https://falconmanagerpro.com/api/health

# View Kubernetes status
kubectl get all
kubectl describe ingress falcon-ingress

# Check TLS certificates
kubectl describe managedcertificate falcon-managed-cert
openssl s_client -connect falconmanagerpro.com:443 -servername falconmanagerpro.com

# Database diagnostics
psql $DATABASE_URL -c "SELECT COUNT(*) FROM tenants;"
psql $DATABASE_URL -c "SELECT COUNT(*) FROM playbooks;"

# View backend logs (Docker)
docker logs falcon-api --tail 100 -f

# View backend logs (Kubernetes)
kubectl logs -f deployment/falcon-api

# Check API endpoints
curl https://falconmanagerpro.com/api/info | jq
```

### 💬 Getting Help

**Community Support:**
- Open an issue on GitHub (if public repository)
- Search existing issues for solutions
- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) first

**Commercial Support:**
- Contact: kthompson@tachtech.net
- Response time: 24-48 hours business days
- Priority support available for enterprise deployments

**Self-Help Resources:**
1. Check logs (backend, frontend, database)
2. Review error messages carefully
3. Test API credentials independently
4. Verify network connectivity
5. Check CrowdStrike Falcon Console for comparison

---

## 🚧 Known Limitations

### Current Limitations

1. **No Mobile App** - Web UI is responsive but not optimized for mobile devices
2. **Single Region Deployment** - Multi-region failover not implemented
3. **No Built-in SSO** - Authentication via API credentials only (no SAML/OAuth)
4. **Manual Certificate Renewal** - Cloudflare origin certs require manual renewal
5. **Limited RBAC** - All users with API credentials have full access (no granular permissions)
6. **No Real-time Streaming** - Event streams not implemented (polling every 30s instead)
7. **English Only** - UI and documentation in English only
8. **No Dark Mode API** - Dark mode is frontend-only (not synced across devices)

### API Limitations (CrowdStrike)

1. **Rate Limits** - Varies by license tier (typically 1000 req/min)
2. **Detection Undo** - Cannot undo detection status changes via API
3. **Bulk Limit** - Max 5000 detections per bulk update operation
4. **RTR Session Timeout** - Sessions expire after 10 minutes of inactivity
5. **Historical Data** - API only returns last 90 days of data (older requires Event Streams)
6. **Sensor Offline** - RTR commands fail if host is offline (no queue)

### Browser Compatibility

| Browser | Status | Notes |
|---------|--------|-------|
| Chrome 90+ | ✅ Full Support | Recommended |
| Firefox 88+ | ✅ Full Support | Recommended |
| Safari 14+ | ✅ Full Support | macOS/iOS |
| Edge 90+ | ✅ Full Support | Windows |
| IE 11 | ❌ Not Supported | Use modern browser |

---

## 🛣️ Roadmap

### Version 5.0 (Q1 2026) - Planned Features

**Enhanced Automation:**
- [ ] Advanced playbook conditions (AND/OR logic)
- [ ] Scheduled playbook execution (cron-style)
- [ ] Playbook templates marketplace
- [ ] Custom action plugins (Python/JavaScript)

**User Experience:**
- [ ] Role-based access control (RBAC)
- [ ] User audit logs per analyst
- [ ] Customizable dashboards (drag-and-drop widgets)
- [ ] Mobile app (iOS/Android)
- [ ] Multi-language support (Spanish, French, German)

**Integrations:**
- [ ] SIEM connectors (Splunk, ELK, QRadar, Sentinel)
- [ ] Ticketing systems (Jira, ServiceNow, PagerDuty)
- [ ] Slack/Teams notifications
- [ ] Threat intelligence feeds (MISP, ThreatConnect, Recorded Future)
- [ ] SOAR platform integration (Cortex XSOAR, Swimlane)

**Analytics:**
- [ ] Advanced threat hunting queries (saved searches)
- [ ] Detection trend analysis (machine learning)
- [ ] MTTR (Mean Time To Respond) metrics
- [ ] Analyst performance dashboards
- [ ] Executive reporting templates

**Infrastructure:**
- [ ] Multi-region deployment with failover
- [ ] Event Streams API integration (real-time)
- [ ] Redis caching layer for performance
- [ ] Elasticsearch for full-text search
- [ ] API rate limit management

### Version 6.0 (Q4 2026) - Vision

**AI/ML Features:**
- [ ] Automated false positive detection
- [ ] Threat severity prediction
- [ ] Anomaly detection for unusual patterns
- [ ] Natural language query interface ("Show me ransomware detections from last week")

**Compliance & Governance:**
- [ ] SOC 2 Type II compliance reports
- [ ] GDPR data handling tools
- [ ] Retention policy automation
- [ ] Compliance audit trail export

**Advanced Security:**
- [ ] Zero-trust architecture support
- [ ] Hardware security module (HSM) integration
- [ ] Secrets rotation automation
- [ ] Enhanced encryption (field-level)

---

## 🤝 Contributing

### How to Contribute

We welcome contributions! Here's how you can help:

1. **Report Bugs** - Open an issue with detailed reproduction steps
2. **Suggest Features** - Describe your use case and proposed solution
3. **Submit Pull Requests** - Fork, branch, code, test, PR
4. **Improve Documentation** - Fix typos, add examples, clarify concepts
5. **Share Use Cases** - Blog posts, conference talks, case studies

### Development Setup

```bash
# Fork and clone repository
git clone https://github.com/yourusername/falcon-manager-pro.git
cd falcon-manager-pro

# Create feature branch
git checkout -b feature/your-feature-name

# Setup backend development environment
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Dev dependencies (pytest, black, flake8)

# Setup frontend development environment
cd ../
npm install
npm run test  # Run tests

# Make your changes
# ... code code code ...

# Run tests
pytest backend/tests/
npm test

# Format code
black backend/
prettier --write src/

# Commit and push
git add .
git commit -m "feat: add awesome new feature"
git push origin feature/your-feature-name
```

### Code Style Guidelines

**Python (Backend):**
- Follow PEP 8 style guide
- Use Black for formatting (`black .`)
- Use Flake8 for linting (`flake8 .`)
- Type hints required for public functions
- Docstrings for all modules, classes, and functions
- Max line length: 100 characters

**JavaScript/React (Frontend):**
- Follow Airbnb JavaScript Style Guide
- Use Prettier for formatting (`prettier --write .`)
- Use ESLint for linting (`eslint .`)
- Functional components with hooks (no class components)
- PropTypes for all component props
- Max line length: 100 characters

**Commit Messages:**
- Follow Conventional Commits specification
- Format: `type(scope): description`
- Types: feat, fix, docs, style, refactor, test, chore
- Example: `feat(playbooks): add Slack notification action`

### Testing Requirements

**Backend Tests:**
- Unit tests for all utility functions
- Integration tests for API endpoints
- Coverage target: 80%+
- Use pytest and pytest-cov

**Frontend Tests:**
- Component tests with React Testing Library
- Integration tests with Cypress
- Coverage target: 70%+
- Use Jest and @testing-library/react

### Documentation Standards

- Update README.md for user-facing changes
- Update inline code comments for complex logic
- Add examples for new features
- Update API documentation (OpenAPI/Swagger)
- Include screenshots for UI changes

---

## 📄 License & Usage

### Software License

**This project uses:**
- **FalconPy SDK:** Public Domain (Unlicense) - [GitHub](https://github.com/CrowdStrike/falconpy)
- **React:** MIT License
- **Flask:** BSD 3-Clause License
- **Project Code:** MIT License (see LICENSE file)

### Proprietary & Confidential

**DO NOT COMMIT:**
- API credentials (`.env` files)
- TLS certificates (`.pem` files)
- Customer data (detections, hosts, IOCs)
- Session tokens
- Database connection strings

**Protected by .gitignore:**
```
.env
*.pem
cloudflare-origin-secret.yaml
falcon_manager.db
venv/
node_modules/
__pycache__/
.pytest_cache/
```

### Usage Rights

**You MAY:**
- ✅ Use for internal security operations
- ✅ Modify and customize for your needs
- ✅ Deploy in your own infrastructure
- ✅ Use for commercial purposes (consulting, MSSP)
- ✅ Distribute modified versions (with attribution)

**You MAY NOT:**
- ❌ Remove copyright notices
- ❌ Claim as your own work
- ❌ Use CrowdStrike trademarks without permission
- ❌ Resell as a standalone product without significant value-add
- ❌ Hold authors liable for damages

### Trademark Notice

**CrowdStrike®** and **Falcon®** are registered trademarks of CrowdStrike, Inc. This project is not affiliated with, endorsed by, or sponsored by CrowdStrike, Inc.

---

## 🎉 Acknowledgments

### Built Using

**Backend:**
- [Python 3.x](https://www.python.org/)
- [Flask 3.0](https://flask.palletsprojects.com/)
- [CrowdStrike FalconPy SDK 1.4+](https://github.com/CrowdStrike/falconpy)
- [PostgreSQL 12+](https://www.postgresql.org/)
- [Gunicorn WSGI](https://gunicorn.org/)

**Frontend:**
- [React 18](https://reactjs.org/)
- [Lucide Icons](https://lucide.dev/)
- [Tailwind CSS](https://tailwindcss.com/) (via utility classes)

**Infrastructure:**
- [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine)
- [Cloudflare CDN](https://www.cloudflare.com/)
- [Docker](https://www.docker.com/)
- [Google Artifact Registry](https://cloud.google.com/artifact-registry)

**Integrations:**
- [VirusTotal API](https://www.virustotal.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Special Thanks

- **CrowdStrike** for the excellent FalconPy SDK and comprehensive API documentation
- **CrowdStrike Support** for quick responses and API guidance
- **Google Cloud Platform** for reliable infrastructure
- **Cloudflare** for powerful CDN and security features
- **Open Source Community** for the amazing tools and libraries

### Project Team

**Primary Developer:**  
Kyle Thompson - IT Security Operations Manager  
Email: kthompson@tachtech.net  
Organization: FINDLAYAUTO.NET

**Project Information:**
- **Location:** `/home/kthompson/Development/Projects/falconpy`
- **Production URL:** https://falconmanagerpro.com
- **GCP Project:** falconmanagerpro
- **Last Updated:** December 2, 2025
- **Version:** 4.0 (Multi-Tenant with MITRE ATT&CK)

---

## 📞 Contact & Feedback

### Report Issues
- **Security Issues:** kthompson@tachtech.net (private disclosure)
- **Bug Reports:** Open GitHub issue with `[BUG]` prefix
- **Feature Requests:** Open GitHub issue with `[FEATURE]` prefix

### Feedback Welcome
- How are you using Falcon Manager Pro?
- What features would you like to see?
- What documentation needs improvement?
- Share your success stories!

### Stay Updated
- Watch this repository for updates
- Check [CHANGES.md](CHANGES_2025-11-24.md) for release notes
- Follow project announcements

---

**🚀 Production-Ready Enterprise Detection Management Platform**

*Built with ❤️ for Security Operations Teams*

**Falcon Manager Pro v4.0** - Multi-Tenant Edition with MITRE ATT&CK Integration

*For questions about this documentation, refer to the individual guide files listed above.*