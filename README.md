# Falcon Manager Pro - CrowdStrike Detection Management Platform

**Project:** CrowdStrike Falcon Detection Management & Response Platform
**Status:** ✅ Production - Deployed on GKE
**Domain:** https://falconmanagerpro.com
**Version:** 1.1

---

## Overview

**Falcon Manager Pro** is a comprehensive web-based platform for managing CrowdStrike Falcon detections, incidents, hosts, and IOCs. It combines Python CLI tools with a full-stack web application (React + Flask) deployed on Google Kubernetes Engine with Cloudflare CDN and Full (Strict) TLS encryption.

### Platform Components

1. **Web Application** - Full-featured detection management dashboard
   - React frontend with real-time updates
   - Flask backend API with CrowdStrike FalconPy integration
   - Containerized and deployed on GKE

2. **CLI Tools** - Python scripts for bulk operations
   - Hash-based detection management
   - Bulk closure operations
   - Report generation
   - Multi-customer support

---

## 🌟 Key Features

### Detection Management
- **Real-time Monitoring** - Auto-refresh dashboard with live activity indicator
- **Advanced Search** - FQL (Falcon Query Language) filtering
- **Bulk Operations** - Select and update multiple detections simultaneously
- **Severity Filtering** - Quick filter by Critical, High, Medium, Low
- **Assignment Management** - Assign detections to team members
- **Comment Workflows** - Required comments before status changes

### Hash-Based Operations
- **Close by Hash** - Bulk close all detections matching a SHA256 hash
  - Supports both XDR and ODS detection types
  - Dry-run mode to preview changes
  - Batch processing for thousands of detections
- **Hash Analysis** - Group and analyze detections by file hash
  - Identify repetitive false positives
  - One-click bulk operations from analysis view

### IOC Management
- **Custom Indicators** - Create IPv4, Domain, MD5, and SHA256 IOCs
- **IOC Exclusions** - Whitelist known-good files
- **Severity Levels** - Assign criticality to each indicator
- **Policy Control** - Detect, prevent, or allow actions

### Automated Response
- **Response Playbooks** - Automated workflows for common scenarios
- **Trigger Conditions** - Execute on critical detections, ransomware, etc.
- **Multi-Action Chains** - Contain host, create incident, close detection
- **Manual Execution** - Run playbooks on-demand

### Host Management
- **Endpoint Inventory** - View all managed hosts with status
- **Network Containment** - Isolate compromised systems
- **Agent Status** - Monitor online/offline hosts

### Reporting & Export
- **PDF Reports** - Generate professional detection reports
- **Saved Views** - Store custom filter configurations
- **Dashboard Statistics** - At-a-glance metrics
- **Hash Summary Reports** - Markdown export for analysis

---

## 🏗️ Architecture

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
```

### Technology Stack

**Frontend:**
- React 18+ (Single Page Application)
- Lucide Icons
- Modern responsive UI
- Session-based authentication

**Backend:**
- Python 3.8+ with Flask 3.0
- CrowdStrike FalconPy SDK 1.4+
- Flask-CORS for API access
- ReportLab for PDF generation
- Gunicorn WSGI server

**Infrastructure:**
- Google Kubernetes Engine (GKE Autopilot)
- Cloudflare CDN with Full (Strict) TLS
- Google Artifact Registry
- Docker containerization
- Nginx reverse proxy

**CLI Tools:**
- Python 3.8+ with FalconPy
- Tabulate for formatted output
- Colorama for terminal colors
- TQDM for progress bars

---

## 📁 Project Structure

```
falconpy/
├── README.md                          # This file - Project overview
├── CLOUDFLARE_TLS_SETUP.md           # TLS/HTTPS setup guide
├── SETUP_GUIDE.md                    # CLI tools setup
├── QUICK_REFERENCE.md                # CLI command reference
├── SCRIPTS_REFERENCE.md              # Script documentation
├── TROUBLESHOOTING.md                # Problem solving guide
├── CHANGES_2025-11-24.md             # Recent changes
├── falcon_pro_README.md              # Web app features
│
├── Dockerfile                        # Frontend container
├── nginx.conf                        # Nginx reverse proxy config
├── k8s-backend.yaml                  # Backend K8s deployment
├── k8s-frontend.yaml                 # Frontend K8s deployment
├── k8s-ingress.yaml                  # Ingress with TLS
├── cloudflare-origin-secret.yaml     # TLS certificate secret
├── deploy-tls.sh                     # Deployment script
│
├── backend/                          # Flask API Backend
│   ├── app.py                       # Main Flask application (1,100 lines)
│   ├── Dockerfile                   # Backend container
│   └── requirements.txt             # Python dependencies
│
├── src/                              # React Frontend
│   ├── App.js                       # Main React component (1,431 lines)
│   ├── index.js                     # React entry point
│   └── ...
│
├── public/                           # Static assets
│   └── index.html                   # HTML template
│
├── lib/                              # CLI Tools Library
│   └── falcon_utils.py              # Core utility functions
│
├── scripts/                          # CLI Scripts
│   ├── hash_summary.py              # Hash analysis & reporting
│   ├── query_detections.py          # Search detections
│   ├── close_by_hash.py             # Bulk close by hash
│   ├── bulk_close_detections.py     # Bulk close operations
│   └── create_ioc_exclusion.py      # IOC management
│
├── venv/                             # Python virtual environment
├── node_modules/                     # Node.js dependencies
│
├── .env                              # API credentials (secret!)
├── .env.example                      # Credentials template
└── .gitignore                        # Protects secrets & certificates
```

---

## 🚀 Quick Start

### Option 1: Access Production Web App

Visit: **https://falconmanagerpro.com**

1. Enter your CrowdStrike API credentials
2. Start managing detections through the web interface

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

### 🔒 Deploy Infrastructure
1. Read: [CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md)
2. Deploy: K8s configurations to GKE
3. Configure: DNS and SSL/TLS in Cloudflare

---

## 🔐 Security

### Authentication
- **API Credentials**: Stored securely in `.env` (never committed)
- **Session-based**: Web app uses session storage
- **OAuth2**: CrowdStrike API authentication

### Encryption
- **TLS 1.2+**: End-to-end encryption
- **Cloudflare Full (Strict)**: Origin certificate validation
- **Certificate Validity**: 15 years (expires 2040-11-20)

### API Scopes Required
- **Detections**: Read, Write
- **Hosts**: Read, Write
- **IOC**: Read, Write
- **Custom IOC**: Read, Write
- **Incidents**: Read, Write (optional)
- **Event Streams**: Read (optional)

### Protected Files (.gitignore)
```
.env
*.pem
cloudflare-origin-secret.yaml
```

---

## 🌐 Production Deployment

### GCP Infrastructure
- **Project**: falconmanagerpro
- **Region**: us-central1
- **Cluster**: falcon-autopilot (GKE Autopilot)
- **Static IP**: 136.110.230.236 (falcon-ui-ip)

### Container Registries
- **falcon-manager**: Backend API images (52+ versions)
- **app-repo**: Frontend UI images (10+ versions)

### Domain & CDN
- **Domain**: falconmanagerpro.com
- **DNS**: Cloudflare (nameservers transferred from GoDaddy)
- **SSL/TLS**: Full (strict) mode
- **CDN**: Cloudflare with DDoS protection

### Deployment Process

```bash
# Build & push backend
cd backend
docker build -t us-central1-docker.pkg.dev/falconmanagerpro/falcon-manager/falcon-api:v1 .
docker push us-central1-docker.pkg.dev/falconmanagerpro/falcon-manager/falcon-api:v1

# Build & push frontend
docker build -t us-central1-docker.pkg.dev/falconmanagerpro/app-repo/falcon-ui:v1 .
docker push us-central1-docker.pkg.dev/falconmanagerpro/app-repo/falcon-ui:v1

# Apply K8s configurations
kubectl apply -f k8s-backend.yaml
kubectl apply -f k8s-frontend.yaml
kubectl apply -f k8s-ingress.yaml
kubectl apply -f cloudflare-origin-secret.yaml
```

See [CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md) for complete deployment guide.

---

## 🔑 Key Concepts

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
- `closed` - Resolved (use this for benign)
- `reopened` - Reopened after closure
- ❌ **NOT VALID:** "resolved" (use "closed" instead)

---

## 🛡️ Safety Features

### CLI Tools Include:
- ✅ **Dry-run mode** - Preview before making changes
- ✅ **Confirmation prompts** - Prevents accidental execution
- ✅ **Batch processing** - Handles large volumes safely
- ✅ **Rate limiting** - Prevents API throttling
- ✅ **Progress tracking** - Shows what's happening
- ✅ **Error handling** - Graceful failure recovery

### Best Practices:
1. **Always dry-run first**
2. **Start with small batches**
3. **Include meaningful comments**
4. **Review hash summaries before closing**
5. **Test with one hash before bulk operations**
6. **Keep API credentials secure**

---

## 📊 Version History

### v1.1 - 2025-11-24 (Infrastructure & Security Update)
**New Features:**
- ✅ Kubernetes deployment configuration (GKE)
- ✅ Cloudflare Full (Strict) TLS setup
- ✅ Kubernetes Ingress with origin certificates
- ✅ React frontend with Flask backend architecture
- ✅ Nginx reverse proxy configuration
- ✅ Automated deployment scripts
- ✅ Comprehensive TLS setup documentation

**Infrastructure:**
- ✅ GKE cluster: falcon-autopilot (us-central1)
- ✅ Static IP: 136.110.230.236 (falcon-ui-ip)
- ✅ Domain: falconmanagerpro.com
- ✅ Cloudflare CDN with Full (Strict) TLS
- ✅ Docker containerization (52+ backend, 10+ frontend versions)

**Security:**
- ✅ End-to-end TLS encryption
- ✅ Cloudflare origin certificates (15-year validity)
- ✅ Certificate management via K8s secrets
- ✅ Updated .gitignore for certificate protection

### v1.0 - 2025-10-31 (Initial Release)
**Features:**
- ✅ Alerts API integration (migrated from deprecated Detects API)
- ✅ Hash summary reporting
- ✅ Search by hash (XDR + ODS)
- ✅ Close by hash
- ✅ Bulk operations
- ✅ IOC exclusions
- ✅ Multi-customer support
- ✅ Comprehensive documentation

**Web Application:**
- ✅ React frontend (1,431 lines)
- ✅ Flask backend (1,100 lines)
- ✅ Real-time detection monitoring
- ✅ Advanced FQL search
- ✅ Automated response playbooks
- ✅ PDF report generation
- ✅ Host management & containment

**Tested:**
- ✅ Connection to CrowdStrike API
- ✅ Query 10,000+ detections
- ✅ Close detections successfully
- ✅ Generate and export reports
- ✅ Production deployment on GKE

---

## 📈 Statistics

### Codebase
- **Backend**: 1,100 lines (Python/Flask)
- **Frontend**: 1,431 lines (React/JavaScript)
- **CLI Scripts**: 5 Python scripts
- **Documentation**: 8 comprehensive guides
- **Container Images**: 62+ versions deployed
- **Registry Size**: 2.2 GB across 2 repositories

### Infrastructure
- **Cluster Nodes**: 2 (GKE Autopilot)
- **Services**: 2 (falcon-api, falcon-ui)
- **Ingress**: 1 with TLS termination
- **Static IPs**: 1 reserved
- **Domains**: 1 (falconmanagerpro.com)

---

## 🔧 Maintenance

### Daily
- Monitor detection dashboard
- Review and close false positives
- Check system health at `/api/health`

### Weekly
- Check for FalconPy updates: `pip list --outdated`
- Review API usage in CrowdStrike console
- Monitor container image sizes

### Monthly
- Review closed detections accuracy
- Archive old reports
- Update documentation if workflow changes
- Check GKE cluster health

### Quarterly
- Rotate API credentials
- Review and update API scopes
- Test disaster recovery (redeployment)
- Audit security configurations

### Certificate Renewal
- **Next renewal**: November 2040
- **Reminder set**: November 2040
- **Process**: [CLOUDFLARE_TLS_SETUP.md](CLOUDFLARE_TLS_SETUP.md) → Certificate Renewal

---

## 🆘 Support & Resources

### Documentation
- All guides available in project root
- Inline code comments
- API examples in scripts

### External Resources
- **FalconPy Docs**: https://falconpy.io/
- **CrowdStrike API**: https://falcon.crowdstrike.com/documentation/
- **CrowdStrike Support**: https://supportportal.crowdstrike.com/
- **GKE Documentation**: https://cloud.google.com/kubernetes-engine/docs
- **Cloudflare SSL**: https://developers.cloudflare.com/ssl/

### Diagnostic Commands

```bash
# Test API connection
python scripts/query_detections.py --test-connection

# Check backend health
curl https://falconmanagerpro.com/api/health

# View K8s status
kubectl get all
kubectl describe ingress falcon-ingress

# Check certificates
kubectl describe managedcertificate falcon-managed-cert
```

---

## 👨‍💻 Project Information

**Project Location:**
`/home/kthompson/Development/Projects/falconpy`

**Primary User:**
Kyle Thompson (kthompson@tachtech.net)

**Production URL:**
https://falconmanagerpro.com

**GCP Project:**
falconmanagerpro

**Last Updated:**
2025-11-24

---

## 📄 License & Usage

**This project uses:**
- **FalconPy:** Public Domain (Unlicense)
- **Project Scripts:** Internal use
- **Flask/React:** MIT License

**Proprietary & Confidential:**
- API credentials (`.env` files)
- TLS certificates (`.pem` files)
- Customer data

---

## 🎉 Acknowledgments

**Built Using:**
- Python 3.x
- React 18
- CrowdStrike FalconPy SDK 1.4+
- Flask 3.0
- Google Kubernetes Engine
- Cloudflare CDN

**Special Thanks:**
- CrowdStrike for FalconPy SDK
- CrowdStrike Support for API documentation
- Google Cloud Platform
- Cloudflare

---

**🚀 Production-Ready Enterprise Detection Management Platform**

*For questions about this documentation, refer to the individual guide files listed above.*
