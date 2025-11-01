# FalconPy Setup Guide

Complete setup instructions for the CrowdStrike FalconPy Detection Management project.

## Initial Setup (First Time Only)

### 1. Project Structure
```
falconpy/
├── .env                          # Your API credentials
├── .env.example                  # Template
├── .gitignore                    # Protects sensitive files
├── requirements.txt              # Python dependencies
├── lib/
│   └── falcon_utils.py          # Core library
├── scripts/
│   ├── hash_summary.py          # Hash analysis
│   ├── close_by_hash.py         # Close by hash
│   ├── bulk_close_detections.py # Bulk operations
│   ├── query_detections.py      # Search
│   └── create_ioc_exclusion.py  # IOC management
└── venv/                        # Virtual environment
```

### 2. Create Virtual Environment
```bash
cd /home/kthompson/Development/Projects/falconpy

# Create virtual environment
python3 -m venv venv

# Activate (if needed for manual work)
source venv/bin/activate
```

### 3. Install Dependencies
```bash
# Install all required packages
venv/bin/pip install -r requirements.txt

# Verify installation
venv/bin/python -c "import falconpy; print(f'FalconPy: {falconpy.__version__}')"
```

**Expected output:** `FalconPy: 1.5.4`

### 4. Configure API Credentials

#### A. Create API Client in CrowdStrike
1. Log into CrowdStrike Falcon: https://falcon.crowdstrike.com
2. Navigate to: **Support and resources** → **API Clients and Keys**
3. Click **Add new API client**
4. Configure:
   - **Client Name:** `SOC Automation - Bulk Detection Management` (or similar)
   - **Description:** `API client for FalconPy bulk detection closure scripts`
   - **API Scopes:**
     - ✅ **Alerts: READ**
     - ✅ **Alerts: WRITE**
     - ✅ **IOC Management: WRITE** (optional)
5. Click **Add**
6. **IMPORTANT:** Copy the Client ID and Secret (shown only once!)

#### B. Create .env File
```bash
# Copy template
cp .env.example .env

# Edit with your credentials
nano .env
```

**Add your credentials:**
```bash
FALCON_CLIENT_ID=your_client_id_here
FALCON_CLIENT_SECRET=your_client_secret_here
FALCON_BASE_URL=https://api.crowdstrike.com
```

**Cloud Region URLs:**
- **US-1:** `https://api.crowdstrike.com` (default)
- **US-2:** `https://api.us-2.crowdstrike.com`
- **EU-1:** `https://api.eu-1.crowdstrike.com`
- **US-GOV-1:** `https://api.laggar.gcw.crowdstrike.com`

#### C. Secure the .env File
```bash
# Restrict permissions (important!)
chmod 600 .env

# Verify .gitignore protects it
cat .gitignore | grep .env
```

### 5. Test Connection
```bash
venv/bin/python scripts/query_detections.py --test-connection
```

**Expected output:**
```
Initializing CrowdStrike Falcon client...
✓ Successfully connected to CrowdStrike Falcon API
```

---

## Multi-Customer Setup

### For Multiple Customers
```bash
# Create separate .env files
cp .env.example customer1.env
cp .env.example customer2.env
cp .env.example customer3.env

# Edit each with customer's credentials
nano customer1.env
nano customer2.env
nano customer3.env

# Secure all files
chmod 600 *.env
```

### Switching Between Customers
```bash
# Method 1: Copy customer file to .env
cp customer1.env .env
venv/bin/python scripts/hash_summary.py -o customer1_report.md

# Method 2: Keep separate and rename as needed
cp customer2.env .env
venv/bin/python scripts/query_detections.py --filter 'status:"new"' --details
```

---

## Understanding the Architecture

### API Migration (Important!)
**The old Detects API was decommissioned by CrowdStrike.**

- ❌ **OLD:** Detects API (`/detects/entities/detects/v2`) - **DEPRECATED**
- ✅ **NEW:** Alerts API (`/alerts/entities/alerts/v2`) - **Current**

**What this means:**
- "Endpoint Detections" in the GUI = Alerts API on the backend
- Scripts use Alerts API methods (`query_alerts_v2`, `update_alerts_v3`)
- Status values: `new`, `in_progress`, `closed`, `reopened`
- ❌ There is NO "resolved" status (use `closed`)

### Detection Types

#### 1. XDR Detections (Behavioral)
- **Product:** `xdr`
- **Type:** `xdr/xdr`
- **Hash field:** `entities.sha256`
- **Examples:** Scheduled tasks, AutoHotKey execution, privilege escalation

#### 2. ODS Detections (On-Demand Scans)
- **Product:** `epp`
- **Type:** `epp/ods`
- **Hash field:** `sha256` (different from XDR!)
- **Examples:** PUP/Adware found in scans

#### 3. IDP Detections (Identity Protection)
- **Product:** `idp`
- **Type:** `idp/idp-session-source-user-endpoint-target-info`
- **Hash field:** None (identity-based, no files)
- **Examples:** Suspicious logins, anomalous endpoint usage

#### 4. EPP Detections (Endpoint Protection)
- **Product:** `epp`
- **Type:** `epp/ldt`
- **Examples:** IOC matches, malware detections

### Why Hash Searches Need Both Fields

Scripts search **both** hash fields because:
```python
# XDR detections use:
entities.sha256:"HASH"

# ODS detections use:
sha256:"HASH"
```

This is automatically handled by `close_by_hash.py` and `query_detections.py`.

---

## Required API Scopes Explained

### Alerts: READ
- Query detections: `query_alerts_v2()`
- Get detection details: `get_alerts_v2()`
- Search by hash, status, filter

### Alerts: WRITE
- Update detection status: `update_alerts_v3()`
- Close/resolve detections
- Add comments
- Assign detections

### IOC Management: WRITE (Optional)
- Create hash exclusions
- Prevent future false positives
- Only needed for `create_ioc_exclusion.py`

---

## Troubleshooting Setup

### Problem: "Module not found: falconpy"
**Solution:**
```bash
# Reinstall dependencies
venv/bin/pip install -r requirements.txt

# Verify
venv/bin/python -c "import falconpy; print(falconpy.__version__)"
```

### Problem: "Connection failed: 403 authorization failed"
**Causes:**
1. Wrong API scopes - Need **Alerts: READ** and **Alerts: WRITE**
2. Incorrect credentials in `.env`
3. Wrong cloud region URL

**Solution:**
```bash
# Check credentials
cat .env

# Verify API client scopes in CrowdStrike console
# Regenerate API credentials if needed
```

### Problem: "Connection failed: 404 API endpoint decommissioned"
**Cause:** Script is using old Detects API (shouldn't happen with current scripts)

**Solution:** Scripts are already updated to use Alerts API. If you see this:
```bash
# Verify you're using the latest scripts
ls -lh scripts/
cat lib/falcon_utils.py | grep "from falconpy import"
```
Should show: `from falconpy import Alerts, IOC`

### Problem: ".env file permissions too open"
**Solution:**
```bash
chmod 600 .env
```

### Problem: "No detections found" but GUI shows detections
**Causes:**
1. Wrong status filter
2. API pagination limit (10k max)
3. Detections in different product/type

**Solution:**
```bash
# Remove status filter to see all
venv/bin/python scripts/query_detections.py --filter '' --limit 100 --details

# Check specific products
venv/bin/python scripts/query_detections.py --filter 'product:"xdr"' --details
venv/bin/python scripts/query_detections.py --filter 'product:"epp"' --details
```

---

## Updating the Project

### Update Dependencies
```bash
# Update all packages
venv/bin/pip install --upgrade -r requirements.txt

# Update specific package
venv/bin/pip install --upgrade crowdstrike-falconpy
```

### Get Latest Scripts
If scripts are updated (stored in git repository):
```bash
git pull origin main
```

### Verify After Updates
```bash
# Test connection
venv/bin/python scripts/query_detections.py --test-connection

# Run a small query
venv/bin/python scripts/query_detections.py --filter 'status:"new"' --limit 5 --details
```

---

## Security Best Practices

### 1. Protect Credentials
```bash
# Never commit .env to version control
# .gitignore should contain:
.env
*.env
!.env.example

# Verify
git status  # .env should NOT appear
```

### 2. Rotate API Keys Regularly
- Rotate every 90 days (or per security policy)
- Create new API client in CrowdStrike
- Update `.env` file
- Test connection
- Delete old API client

### 3. Use Service Accounts
- Don't use personal user credentials
- Create dedicated service account
- Apply least-privilege principle

### 4. Audit Trail
- All actions are logged in CrowdStrike
- Comments are attributed to API client
- Consider including operator name in comments:
  ```bash
  --comment "Closed by Kyle Thompson - SOC approved"
  ```

### 5. File Permissions
```bash
# Secure all credential files
chmod 600 .env
chmod 600 *.env

# Verify
ls -l .env
# Should show: -rw------- (600)
```

---

## Maintenance

### Weekly
- Check for FalconPy updates
- Review API usage in CrowdStrike console
- Verify no rate limiting issues

### Monthly
- Review closed detections accuracy
- Update documentation if workflow changes
- Archive old reports

### Quarterly
- Rotate API credentials
- Review API scopes (ensure least privilege)
- Test disaster recovery (redeployment)

---

## Getting Help

### Documentation
- **FalconPy Docs:** https://falconpy.io/
- **CrowdStrike API Docs:** https://falcon.crowdstrike.com/documentation/
- **Project README:** `/home/kthompson/Development/Projects/falconpy/README.md`

### Common Issues
- See: `TROUBLESHOOTING.md` (if exists)
- Check: `QUICK_REFERENCE.md` for command syntax

### Support
- CrowdStrike Support Portal
- FalconPy GitHub: https://github.com/CrowdStrike/falconpy

---

## Next Steps After Setup

1. **Generate first hash summary:**
   ```bash
   venv/bin/python scripts/hash_summary.py -o initial_report.md
   ```

2. **Review what you have:**
   ```bash
   venv/bin/python scripts/query_detections.py --filter 'status:"new"' --count-only
   ```

3. **Test closing one detection:**
   ```bash
   # Find a hash first
   venv/bin/python scripts/hash_summary.py

   # Dry-run close
   venv/bin/python scripts/close_by_hash.py --hash "HASH_HERE" --dry-run
   ```

4. **Start bulk operations when confident:**
   ```bash
   venv/bin/python scripts/bulk_close_detections.py --filter 'status:"new"' --dry-run
   ```
