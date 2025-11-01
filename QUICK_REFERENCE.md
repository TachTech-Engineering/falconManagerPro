# FalconPy Quick Reference Guide

**Last Updated:** 2025-10-31

## Daily Commands

### 1. Hash Summary Report (Most Common)
```bash
# Generate hash summary and save to file
venv/bin/python scripts/hash_summary.py -o report_$(date +%y%m%d).md

# Custom filter
venv/bin/python scripts/hash_summary.py --filter 'status:"new"' -o report.md
```

### 2. Close Detections by Hash
```bash
# Dry-run first (safe preview)
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH_HERE" \
  --dry-run

# Actually close
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH_HERE" \
  --comment "Benign - SOC approved"
```

### 3. Query/Search Detections
```bash
# Search by hash
venv/bin/python scripts/query_detections.py \
  --hash "YOUR_HASH_HERE" \
  --details

# Search by filter
venv/bin/python scripts/query_detections.py \
  --filter 'status:"new"' \
  --limit 10 \
  --details

# Count only
venv/bin/python scripts/query_detections.py \
  --filter 'status:"new"' \
  --count-only

# Test connection
venv/bin/python scripts/query_detections.py --test-connection
```

### 4. Bulk Close Detections
```bash
# Dry-run first (ALWAYS!)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --status closed \
  --comment "Bulk closure - SOC review" \
  --dry-run

# Actually close (with confirmation prompt)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --status closed \
  --comment "Bulk closure - SOC review"

# Skip confirmation (dangerous!)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --status closed \
  --no-confirm
```

---

## Common FQL Filters

### Status Filters
```bash
# New detections
--filter 'status:"new"'

# Closed detections
--filter 'status:"closed"'

# In progress
--filter 'status:"in_progress"'
```

### Detection Type Filters
```bash
# IOC detections (hash-based)
--filter 'display_name:*"IOC"*+status:"new"'

# Specific IOC type
--filter 'display_name:"CloudDetect-CustomerIOC-SHA256-High"+status:"new"'

# IDP (Identity Protection) detections
--filter 'product:"idp"+status:"new"'

# XDR detections
--filter 'product:"xdr"+status:"new"'

# ODS (On-Demand Scan) detections
--filter 'product:"epp"+type:"ods"'
```

### Host Filters
```bash
# Specific host
--filter 'device.hostname:"MSI"+status:"new"'

# Multiple conditions (use + for AND)
--filter 'device.hostname:"MSI"+status:"new"+severity:"High"'
```

### Hash Filters
```bash
# XDR detections with specific hash
--filter 'entities.sha256:"HASH_HERE"'

# ODS detections with specific hash
--filter 'sha256:"HASH_HERE"'
```

### Time-based Filters
```bash
# Last 24 hours
--filter 'created_timestamp:>="now-24h"'

# Specific date range
--filter 'created_timestamp:>"2025-10-01T00:00:00Z"'
```

---

## Multi-Customer Workflow

### Setup
```bash
# Create separate .env files for each customer
cp .env customer1.env
cp .env customer2.env

# Edit each with customer's API credentials
nano customer1.env
nano customer2.env
```

### Usage
```bash
# Switch customer by copying their .env
cp customer1.env .env
venv/bin/python scripts/hash_summary.py -o customer1_report.md

# Switch to another customer
cp customer2.env .env
venv/bin/python scripts/hash_summary.py -o customer2_report.md
```

---

## Important Notes

### Detection Types
- **XDR detections:** Behavioral detections, use `entities.sha256` for hash search
- **ODS detections:** On-Demand Scan results, use `sha256` for hash search
- **IDP detections:** Identity Protection alerts (no hashes)
- **EPP detections:** Endpoint Protection, often IOC-based

### API Limits
- **Query limit:** 10,000 detections per query
- **Batch update limit:** 1,000 detections per API call (automatically handled)
- **Rate limiting:** 0.5s delay between batches (automatic)

### Status Values
Valid status values for closing detections:
- `new` - New/unreviewed
- `in_progress` - Under investigation
- `closed` - Resolved/closed
- `reopened` - Reopened after closure

**Note:** "resolved" is NOT a valid status. Use `closed` instead.

### Best Practices
1. **Always dry-run first** before bulk operations
2. **Include meaningful comments** when closing detections
3. **Use specific filters** to avoid closing wrong detections
4. **Review hash summaries** before bulk closing
5. **Test with small batches** first (--max-detections 10)

---

## Troubleshooting

### Connection Issues
```bash
# Test API connection
venv/bin/python scripts/query_detections.py --test-connection

# Check credentials
cat .env | grep FALCON_CLIENT_ID
```

### No Results Found
- Verify the hash exists: Use `hash_summary.py` first
- Check if using correct hash field (XDR vs ODS)
- Ensure filter syntax is correct (use quotes around values)

### Permission Errors
Required API scopes:
- **Alerts: READ** - Query and retrieve alerts
- **Alerts: WRITE** - Update alert status
- **IOC Management: WRITE** - Create exclusions (optional)

### Rate Limiting
If you hit rate limits:
- Reduce batch size: `--batch-size 500`
- Increase delay in code (lib/falcon_utils.py line 206)
- Process in smaller chunks

---

## File Locations

```
falconpy/
├── .env                          # API credentials (NEVER commit!)
├── .env.example                  # Template for credentials
├── cintas_251031.md             # Generated reports
├── lib/
│   └── falcon_utils.py          # Core library
├── scripts/
│   ├── hash_summary.py          # Generate hash reports
│   ├── close_by_hash.py         # Close by SHA256
│   ├── bulk_close_detections.py # Bulk operations
│   ├── query_detections.py      # Search detections
│   └── create_ioc_exclusion.py  # Create IOC exclusions
└── venv/                        # Python virtual environment
```

---

## Quick Diagnostics

```bash
# Check Python version
venv/bin/python --version

# Check FalconPy version
venv/bin/python -c "import falconpy; print(falconpy.__version__)"

# List all scripts
ls -lh scripts/

# Test API connection
venv/bin/python scripts/query_detections.py --test-connection
```
