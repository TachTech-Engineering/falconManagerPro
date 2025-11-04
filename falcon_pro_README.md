## Features

### Detection Management
- **Real-time Monitoring** - Auto-refresh every 30 seconds with live activity indicator
- **Advanced Search** - FQL (Falcon Query Language) filtering for complex queries
- **Bulk Operations** - Select and update multiple detections simultaneously
- **Comment Workflows** - Required comments before status changes
- **Severity Filtering** - Quick filter by Critical, High, Medium, Low
- **Assignment Management** - Assign detections to team members

### Hash-Based Operations
- **Close by Hash** - Bulk close all detections matching a SHA256 hash
  - Supports both XDR and ODS detection types
  - Dry-run mode to preview changes
  - Batch processing for thousands of detections
- **Hash Analysis** - Group and analyze detections by file hash
  - See which hashes appear most frequently
  - One-click bulk operations from analysis view
  - Identifies repetitive false positives

### IOC Management
- **Custom Indicators** - Create IPv4, Domain, MD5, and SHA256 IOCs
- **IOC Exclusions** - Whitelist known-good files to prevent future alerts
- **Severity Levels** - Assign criticality to each indicator
- **Policy Control** - Detect, prevent, or allow actions

### Automated Response
- **Response Playbooks** - Create automated workflows for common scenarios
- **Trigger Conditions** - Execute on critical detections, ransomware, etc.
- **Multi-Action Chains** - Contain host, create incident, close detection
- **Manual Execution** - Run playbooks on-demand

### Host Management
- **Endpoint Inventory** - View all managed hosts with status
- **Network Containment** - Isolate compromised systems
- **Agent Status** - Monitor online/offline hosts

### Reporting & Views
- **PDF Reports** - Generate professional detection reports
- **Saved Views** - Store custom filter configurations
- **Dashboard Statistics** - At-a-glance metrics

---

## Prerequisites

- **Python 3.8+**
- **Node.js 16+** and npm/yarn
- **CrowdStrike Falcon API credentials** with appropriate scopes
- **Network access** to CrowdStrike API endpoints

---

## Installation

### Step 1: Clone/Download the Project

```bash
cd C:\Source\FalconUtil
```

### Step 2: Backend Setup

1. **Create Python virtual environment (recommended)**
```bash
python -m venv venv
.\venv\Scripts\activate
```

2. **Install dependencies**
```bash
pip install crowdstrike-falconpy flask flask-cors reportlab
```

Or use `requirements.txt`:
```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
crowdstrike-falconpy>=1.3.0
flask>=3.0.0
flask-cors>=4.0.0
reportlab>=4.0.0
```

3. **Configure port (if needed)**

Open `falcon_backend.py` and set your desired port:
```python
if __name__ == '__main__':
    app.run(debug=True, port=5003, host='0.0.0.0')  # Change port here
```

**Note:** Port 5002 may conflict with Datadog agent. Use 5003 or higher.

### Step 3: Frontend Setup

1. **Install React dependencies**
```bash
cd falcon-ui
npm install
# or
yarn install
```

2. **Update API endpoint**

In `src/App.js`, update the API_BASE to match your backend port:
```javascript
const API_BASE = 'http://localhost:5003/api';  // Match backend port
```

### Step 4: CrowdStrike API Credentials

1. Log into [Falcon Console](https://falcon.crowdstrike.com)
2. Navigate to: **Support → API Clients and Keys**
3. Click **Add New API Client**
4. Enable these scopes:
   - **Detections**: Read, Write
   - **Hosts**: Read, Write  
   - **IOC**: Read, Write
   - **Custom IOC**: Read, Write
   - **Event Streams**: Read (optional)

5. Save your **Client ID** and **Client Secret**

---

## Quick Start

### 1. Start the Backend

```bash
cd C:\Source\FalconUtil
python falcon_backend.py
```

You should see:
```
* Running on http://127.0.0.1:5003
* Running on http://192.168.x.x:5003
```

**Verify it's working:**
```bash
curl http://localhost:5003/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "authenticated": false,
  "timestamp": "2025-11-04 ..."
}
```

### 2. Start the Frontend

```bash
cd falcon-ui
npm start
```

Opens automatically at: **http://localhost:3000**

### 3. Authenticate

1. Enter **API Base URL**: `https://api.crowdstrike.com` (or your region)
2. Enter your **Client ID**
3. Enter your **Client Secret**
4. Click **Connect to Falcon**

---

## Usage Guide

### Managing Detections

#### Single Detection Actions
1. Browse detections in the **Detections** tab
2. Click action buttons:
   - **Resolve** - Mark as true positive
   - **Close (FP)** - False positive
   - **Ignore** - Suppress alert
3. Add required comment
4. Detection updates immediately

#### Bulk Operations (Checkbox Method)
1. Check boxes next to detections you want to update
2. Click **Bulk Resolve** or **Bulk Close**
3. Enter comment for all selected
4. All selected detections update simultaneously

#### Close by Hash (Advanced)
**Use case:** Close all detections of a known false positive file

1. Click **Close by Hash** button (orange, top header)
2. Enter the SHA256 hash
3. Add comment (e.g., "Internal admin tool - approved by IT")
4. Select status (closed/resolved)
5. Optional: Check **Dry run** to preview impact
6. Click **Close Detections**

**Example:**
```
Hash: d41d8cd98f00b204e9800998ecf8427e
Comment: Legitimate system file - Approved by SecOps
Status: Closed
Result: 147 detections closed across 53 hosts
```

### Hash Analysis Workflow

**Use case:** Identify and triage repetitive detections

1. Click **Hash Analysis** button (teal, top header)
2. Review hash frequency report
3. For each hash:
   - **Close All** - Bulk close all detections
   - **Exclude** - Create IOC exclusion (whitelist)

**Example Report:**
```
Hash: abc123...  (87 detections)  [Close All] [Exclude]
Hash: def456...  (43 detections)  [Close All] [Exclude]
Hash: ghi789...  (12 detections)  [Close All] [Exclude]
```

### Advanced Search

**Use case:** Complex queries using Falcon Query Language

1. Click **Advanced Search** button (indigo, top header)
2. Enter FQL filter string
3. Click **Search**

**Example Queries:**
```
status:"new"
max_severity_displayname:"High"
device.hostname:"WORKSTATION-*"
first_behavior:>"now-24h"
behaviors.tactic:"Custom Intelligence"
```

### Creating IOC Exclusions

**Method 1: From Hash Analysis**
1. Hash Analysis → Click **Exclude** next to hash
2. Fill in description (required)
3. Choose scope (global or specific host groups)
4. Create exclusion

**Method 2: Manual Creation (IOC Tab)**
1. Go to **IOC Management** tab
2. Click **+ Add IOC**
3. Select hash type
4. Enter hash value
5. Set policy to **"none"** (allows/excludes)
6. Add description

**What it does:**
- Prevents future detections for this file
- Whitelists as approved/safe
- Requires business justification

### Creating Playbooks

1. Go to **Playbooks** tab
2. Click **+ Create Playbook**
3. Name: `"Ransomware Auto-Response"`
4. Trigger: `Ransomware Activity`
5. Actions:
   - Contain Host
   - Create Incident
6. Click **Create Playbook**

### Generating Reports

1. Click **Report** button (purple, top header)
2. PDF downloads automatically
3. Contains:
   - Executive summary
   - Detection statistics
   - Detailed tables

### Saving Dashboard Views

1. Set filters (severity, search, date range)
2. Click **Save View** button (blue, top header)
3. Name: `"Critical - Last 24h"`
4. Access later from **Saved Views** tab

---

## Troubleshooting

### Port Already in Use

**Symptom:** `OSError: [WinError 10048]` or `Address already in use`

**Solution:**
```powershell
# Check what's using the port
netstat -ano | findstr :5003

# If it's another process, kill it
taskkill /F /PID [process_id]

# Or use a different port in falcon_backend.py
app.run(debug=True, port=5004, host='0.0.0.0')
```

**Common conflicts:**
- Port 5002: Often used by Datadog agent
- Port 5000-5001: Often used by other Flask apps

### Backend 404 Errors

**Symptom:** `http://localhost:5003/api/health` returns 404

**Check:**
1. Is backend running? Look for `* Running on http://127.0.0.1:5003`
2. Correct port in frontend? Check `API_BASE` matches backend port
3. Try `http://127.0.0.1:5003/` - should show available endpoints

### Authentication Failures

**Symptom:** "Authentication failed" or 401 errors

**Check:**
1. API credentials are correct
2. API scopes are enabled (see Prerequisites)
3. Base URL matches your Falcon cloud instance:
   - US-1: `https://api.crowdstrike.com`
   - US-2: `https://api.us-2.crowdstrike.com`
   - EU-1: `https://api.eu-1.crowdstrike.com`
4. Network/firewall allows outbound HTTPS

### "Failed to fetch" Errors

**Symptom:** Connection errors in browser console

**Solution:**
```javascript
// Try using 127.0.0.1 instead of localhost
const API_BASE = 'http://127.0.0.1:5003/api';
```

**Check CORS:**
```python
# In falcon_backend.py, ensure CORS is enabled
CORS(app, resources={r"/api/*": {"origins": "*"}})
```

### Hash Summary 500 Error

**Symptom:** "Failed to fetch hash analysis" with 500 error

**Check backend logs** for full error traceback:
```bash
# Look in backend terminal for:
ERROR:__main__:Error getting hash summary: ...
```

**Common causes:**
- Session expired (re-authenticate)
- No detections in timeframe (expected behavior)
- FQL syntax error in filter

---

## Security Best Practices

### Production Deployment

1. **Use HTTPS**
```python
# Use production WSGI server
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5003 falcon_backend:app
```

2. **Environment Variables**
```bash
export FALCON_CLIENT_ID="your_client_id"
export FALCON_CLIENT_SECRET="your_client_secret"
```

```python
# In falcon_backend.py
import os
client_id = os.getenv('FALCON_CLIENT_ID')
client_secret = os.getenv('FALCON_CLIENT_SECRET')
```

3. **Restrict CORS**
```python
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://your-domain.com"],
        "methods": ["GET", "POST", "PATCH", "DELETE"]
    }
})
```

4. **Add Authentication**
```python
# Add JWT or session-based auth to Flask routes
from flask_jwt_extended import JWTManager
```

5. **Network Security**
- Use reverse proxy (nginx/Apache)
- Enable rate limiting
- Set up WAF rules

### Operational Security

- Never commit API credentials to git
- Use `.env` files (add to `.gitignore`)
- Rotate API keys regularly
- Use least-privilege API scopes
- Monitor audit logs
- Enable MFA on Falcon console

---

## API Endpoints Reference

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth` | Authenticate with Falcon |

### Detections
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/detections` | List detections (query params: hours, severity, status) |
| PATCH | `/api/detections/{id}/status` | Update single detection |
| POST | `/api/detections/bulk-update` | Bulk update multiple detections |
| POST | `/api/detections/close-by-hash` | Close all detections by SHA256 |
| GET | `/api/detections/hash-summary` | Get hash frequency analysis |
| POST | `/api/detections/advanced-search` | FQL-based search |

### IOCs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/iocs` | List custom IOCs |
| POST | `/api/iocs` | Create new IOC |
| DELETE | `/api/iocs/{id}` | Delete IOC |
| POST | `/api/iocs/create-exclusion` | Create whitelist exclusion |

### Hosts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/hosts` | List managed hosts |
| POST | `/api/hosts/{id}/contain` | Network isolate host |

### Playbooks
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/playbooks` | List playbooks |
| POST | `/api/playbooks` | Create playbook |
| POST | `/api/playbooks/{id}/execute` | Execute playbook |

### Views & Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/views` | List saved views |
| POST | `/api/views` | Save current view |
| DELETE | `/api/views/{id}` | Delete view |
| POST | `/api/reports/generate` | Generate PDF report |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/events/recent` | Recent events (polling) |

---

## Architecture

```
┌─────────────────┐
│  React Frontend │ (localhost:3000)
│  - Lucide Icons │
│  - Tailwind CSS │
└────────┬────────┘
         │ HTTP/REST
         │ Polling (30s)
         ▼
┌─────────────────┐
│  Flask Backend  │ (localhost:5003)
│  - FalconPy SDK │
│  - ReportLab    │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│ CrowdStrike API │
│  Falcon Cloud   │
└─────────────────┘
```

---

## Update & Refresh Strategy

The dashboard uses **polling** for near real-time updates:

- **Frontend polls every 30 seconds** for new detections and host changes
- **Manual refresh button** available for immediate updates
- **Green indicator** shows auto-refresh is active
- **Toast notifications** confirm successful actions

**Why polling instead of WebSockets?**
- Simpler deployment (no socket.io required)
- Works through corporate proxies
- Sufficient for most SOC workflows
- Easy to debug and maintain

---

## Integration Examples

### Slack Notifications

```python
# Add to falcon_backend.py
import requests

def send_slack_alert(detection):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    message = {
        "text": f"Critical Detection: {detection['name']}",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Host", "value": detection['host'], "short": True},
                {"title": "Severity", "value": detection['severity'], "short": True}
            ]
        }]
    }
    requests.post(webhook_url, json=message)
```

### Chronicle SIEM Forwarding

```python
# Forward to Google Chronicle
from google.oauth2 import service_account
from googleapiclient.discovery import build

def forward_to_chronicle(detection):
    credentials = service_account.Credentials.from_service_account_file(
        'chronicle-credentials.json'
    )
    # Send to Chronicle ingestion API
```

### Jira Ticket Creation

```python
from jira import JIRA

def create_jira_ticket(detection):
    jira = JIRA(server='https://your-domain.atlassian.net', 
                basic_auth=('email', 'api_token'))
    
    issue = jira.create_issue(
        project='SEC',
        summary=f"Falcon Alert: {detection['name']}",
        description=detection['description'],
        issuetype={'name': 'Bug'},
        priority={'name': 'High'}
    )
    return issue.key
```

---

## Deployment Options

### Docker

**Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY falcon_backend.py .

EXPOSE 5003

CMD ["python", "falcon_backend.py"]
```

**Build and run:**
```bash
docker build -t falcon-manager .
docker run -p 5003:5003 \
  -e FALCON_CLIENT_ID="your_id" \
  -e FALCON_CLIENT_SECRET="your_secret" \
  falcon-manager
```

### Kubernetes

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: falcon-manager
spec:
  replicas: 2
  selector:
    matchLabels:
      app: falcon-manager
  template:
    metadata:
      labels:
        app: falcon-manager
    spec:
      containers:
      - name: backend
        image: falcon-manager:latest
        ports:
        - containerPort: 5003
        env:
        - name: FALCON_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: falcon-credentials
              key: client-id
        - name: FALCON_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: falcon-credentials
              key: client-secret
```

---

## Known Issues & Limitations

1. **Hash auto-fill bug**: When clicking "Exclude" from Hash Analysis, the hash value doesn't auto-populate in the exclusion dialog. You need to copy/paste it manually.

2. **Polling delay**: Updates appear every 30 seconds. For instant updates, consider implementing WebSockets.

3. **Large datasets**: Hash analysis limited to 10,000 detections. For larger datasets, increase the limit parameter.

4. **Session timeout**: API sessions expire after ~30 minutes. You'll need to re-authenticate.

---

## Changelog

### Version 1.0.0 (Current)
- Core detection management
- Hash-based bulk operations
- IOC management and exclusions
- Advanced FQL search
- Automated playbooks
- PDF report generation
- Saved dashboard views
- 30-second auto-refresh

---

## Roadmap

- [ ] WebSocket support for real-time updates
- [ ] Email notifications
- [ ] Custom report templates
- [ ] Detection correlation engine
- [ ] MITRE ATT&CK mapping
- [ ] Multi-tenant support
- [ ] Role-based access control
- [ ] Detection statistics and trending
- [ ] Integration with SOAR platforms
- [ ] Mobile-responsive design

---

## License

This is a custom implementation for CrowdStrike Falcon management. Ensure compliance with your CrowdStrike licensing agreement and internal security policies.

---

## Support & Resources

- **FalconPy Documentation**: https://www.falconpy.io/
- **CrowdStrike API Docs**: https://falcon.crowdstrike.com/documentation
- **GitHub Issues**: Report bugs and request features
- **Backend Logs**: Check Flask console for detailed error traces

---

## Contributing

Contributions welcome! Areas of interest:
- Additional bulk operations
- More playbook triggers and actions
- Enhanced reporting capabilities
- Integration with other security tools
- Performance optimizations

---

**Built for Security Operations Teams**