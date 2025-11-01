# CrowdStrike FalconPy - Bulk Detection Management

Python project for managing CrowdStrike Falcon detections at scale using the FalconPy SDK.

## Project Structure

```
falconpy/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── scripts/
│   ├── bulk_close_detections.py
│   ├── query_detections.py
│   └── create_ioc_exclusion.py
└── lib/
    └── falcon_utils.py
```

## Setup

### 1. Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

### 2. Configure API Credentials

```bash
cp .env.example .env
# Edit .env with your CrowdStrike API credentials
chmod 600 .env
```

### 3. Verify API Connection

```bash
python scripts/query_detections.py --test-connection
```

## Usage

### Query Detections

```bash
# Query detections by filter
python scripts/query_detections.py --filter 'status:"new"' --limit 100

# Query by hash
python scripts/query_detections.py --hash "0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bcc6f01b9"
```

### Bulk Close Detections

```bash
# Close detections matching a filter
python scripts/bulk_close_detections.py \
  --filter 'behaviors.tactic:"Custom Intelligence"+status:"new"' \
  --status "false_positive" \
  --comment "Bulk closure - confirmed FP" \
  --batch-size 1000 \
  --max-detections 10000

# Dry-run mode (preview only, no changes)
python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --dry-run
```

### Create IOC Exclusion

```bash
# Create SHA256 exclusion to prevent future FPs
python scripts/create_ioc_exclusion.py \
  --hash "0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bcc6f01b9" \
  --description "False positive - internal tool" \
  --applied-globally
```

## Required API Scopes

- **Alerts: READ** - Query and retrieve alerts
- **Alerts: WRITE** - Update alert status
- **IOC Management: WRITE** - Create exclusions (optional)

**Note:** The Detections API has been decommissioned. This project now uses the Alerts API.

## Safety Features

- Dry-run mode for previewing changes
- Batch size limits (max 1000 per API call)
- Rate limiting and retry logic
- Progress tracking and logging
- Confirmation prompts for bulk operations

## Security Notes

- Never commit `.env` file to version control
- Use restrictive file permissions (600) on credential files
- Rotate API credentials regularly
- Use service accounts with least-privilege scopes

## Support

CrowdStrike FalconPy Documentation: https://falconpy.io/
API Documentation: https://falcon.crowdstrike.com/documentation/
