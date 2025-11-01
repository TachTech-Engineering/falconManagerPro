# Troubleshooting Guide

Common issues and solutions for the FalconPy Detection Management project.

---

## Connection Issues

### Error: "403 authorization failed"

**Symptoms:**
```
✗ Connection failed: [{'code': 403, 'message': 'access denied, authorization failed'}]
```

**Causes & Solutions:**

1. **Missing or incorrect API scopes**
   ```bash
   # Solution: Verify in CrowdStrike console
   # Required scopes:
   # - Alerts: READ
   # - Alerts: WRITE
   ```

2. **Wrong API credentials**
   ```bash
   # Verify credentials
   cat .env | grep FALCON_CLIENT_ID
   cat .env | grep FALCON_CLIENT_SECRET

   # Test with known good credentials
   # Regenerate API client if needed
   ```

3. **Incorrect cloud region**
   ```bash
   # Check your region in .env
   cat .env | grep FALCON_BASE_URL

   # Common regions:
   # US-1: https://api.crowdstrike.com
   # US-2: https://api.us-2.crowdstrike.com
   # EU-1: https://api.eu-1.crowdstrike.com
   ```

---

### Error: "404 API endpoint has been decommissioned"

**Symptoms:**
```
✗ Connection failed: [{'code': 404, 'message': 'API endpoint has been decommissioned as per TA: ...'}]
```

**Cause:** Using old Detects API instead of Alerts API

**Solution:**
```bash
# Check lib/falcon_utils.py
cat lib/falcon_utils.py | grep "from falconpy import"

# Should show:
from falconpy import Alerts, IOC

# NOT:
from falconpy import Detects, IOC

# If incorrect, pull latest version from repository
git pull origin main
```

---

### Error: "Connection error: Name or service not known"

**Symptoms:**
```
✗ Connection error: [Errno -2] Name or service not known
```

**Causes & Solutions:**

1. **Network connectivity**
   ```bash
   # Test internet connection
   ping api.crowdstrike.com

   # Test DNS resolution
   nslookup api.crowdstrike.com
   ```

2. **Firewall blocking**
   ```bash
   # Test HTTPS connectivity
   curl https://api.crowdstrike.com

   # Check proxy settings
   echo $http_proxy
   echo $https_proxy
   ```

3. **Wrong base URL**
   ```bash
   # Verify URL in .env
   cat .env | grep FALCON_BASE_URL

   # Should be a valid CrowdStrike API URL
   ```

---

### Error: "SSL: CERTIFICATE_VERIFY_FAILED"

**Symptoms:**
```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solution:**
```bash
# Update CA certificates
sudo apt-get update
sudo apt-get install ca-certificates

# Update certifi package
venv/bin/pip install --upgrade certifi

# Verify
venv/bin/python -c "import certifi; print(certifi.where())"
```

---

## Query/Search Issues

### Problem: "No detections found" but GUI shows detections

**Possible Causes:**

1. **Wrong status filter**
   ```bash
   # Try without status filter
   venv/bin/python scripts/query_detections.py --filter '' --limit 100

   # Check specific status
   venv/bin/python scripts/query_detections.py --filter 'status:"new"'
   venv/bin/python scripts/query_detections.py --filter 'status:"closed"'
   ```

2. **Hit 10k query limit**
   ```bash
   # Pagination not implemented yet
   # Workaround: Add more specific filters
   venv/bin/python scripts/query_detections.py \
     --filter 'status:"new"+product:"xdr"' \
     --limit 10000
   ```

3. **Wrong product/type**
   ```bash
   # Check different products
   venv/bin/python scripts/query_detections.py --filter 'product:"xdr"'
   venv/bin/python scripts/query_detections.py --filter 'product:"epp"'
   venv/bin/python scripts/query_detections.py --filter 'product:"idp"'
   ```

---

### Problem: Hash not found

**Symptoms:**
```
Searching for alerts with SHA256: YOUR_HASH
  XDR detections: 0
  ODS detections: 0
No alerts found with hash: YOUR_HASH
```

**Solutions:**

1. **Verify hash exists in environment**
   ```bash
   # Generate hash summary first
   venv/bin/python scripts/hash_summary.py

   # Look for your hash in the output
   ```

2. **Check if hash is uppercase/lowercase**
   ```bash
   # CrowdStrike stores lowercase
   # Convert to lowercase
   echo "YOUR_HASH" | tr '[:upper:]' '[:lower:]'
   ```

3. **Detection might be closed already**
   ```bash
   # Search all statuses
   venv/bin/python scripts/query_detections.py \
     --hash "YOUR_HASH" \
     --filter '' \
     --details
   ```

4. **Detection might be in Incidents, not Alerts**
   ```bash
   # Currently not supported - Alerts API only
   # Check GUI to confirm it's in "Endpoint Detections"
   ```

---

## Closure/Update Issues

### Error: "invalid status for update_status action param"

**Symptoms:**
```
Update failed: [{'code': 400, 'message': 'invalid status for update_status action param. must be one of ["new", "in_progress", "reopened", "closed"]'}]
```

**Cause:** Using invalid status value (e.g., "resolved")

**Solution:**
```bash
# Use valid status values only:
--status closed        # For resolved/benign detections
--status in_progress   # For under investigation
--status new           # Reopen to new
--status reopened      # Reopen from closed
```

---

### Error: "Argument composite_ids must be specified"

**Symptoms:**
```
Update failed: [{'message': 'Argument composite_ids must be specified.', 'code': 400}]
```

**Cause:** Using old `ids` parameter instead of `composite_ids`

**Solution:** Update scripts (should already be fixed):
```python
# Correct:
response = self.alerts.update_alerts_v3(composite_ids=detection_ids, ...)

# Incorrect:
response = self.alerts.update_alerts_v3(ids=detection_ids, ...)
```

---

### Problem: Detections close but still show in GUI

**Explanation:**
- Detections are closed (`status: closed`)
- `show_in_ui` may still be `True` for ODS detections
- This is normal behavior for certain detection types

**Verification:**
```bash
# Verify detection is actually closed
venv/bin/python scripts/query_detections.py \
  --hash "YOUR_HASH" \
  --details

# Look for: Status: closed
```

**GUI Refresh:**
- CrowdStrike GUI may cache results
- Try: Refresh browser (Ctrl+F5)
- Try: Clear filter and re-apply
- Wait: Can take a few minutes to update

---

## Script Execution Issues

### Error: "unrecognized arguments"

**Symptoms:**
```bash
$ venv/bin/python scripts/hash_summary.py >> file name.md
usage: hash_summary.py [-h] ...
hash_summary.py: error: unrecognized arguments: name.md
```

**Cause:** Space in filename or extra spaces after `\`

**Solutions:**
```bash
# Option 1: Remove spaces from filename
venv/bin/python scripts/hash_summary.py > filename.md

# Option 2: Use quotes
venv/bin/python scripts/hash_summary.py > "file name.md"

# Option 3: Use --output flag (recommended)
venv/bin/python scripts/hash_summary.py -o "file name.md"

# Option 4: Use tee
venv/bin/python scripts/hash_summary.py | tee output.md
```

---

### Error: "ModuleNotFoundError: No module named 'falconpy'"

**Symptoms:**
```
ModuleNotFoundError: No module named 'falconpy'
```

**Cause:** Using system Python instead of venv Python

**Solutions:**
```bash
# Always use venv/bin/python, NOT just python
venv/bin/python scripts/hash_summary.py

# If that doesn't work, reinstall dependencies
venv/bin/pip install -r requirements.txt

# Verify installation
venv/bin/python -c "import falconpy; print(falconpy.__version__)"
```

---

### Error: "Permission denied"

**Symptoms:**
```bash
$ python scripts/hash_summary.py
bash: scripts/hash_summary.py: Permission denied
```

**Cause:** Missing execute permissions (not actually needed with Python)

**Solution:**
```bash
# Don't execute directly, use Python interpreter
venv/bin/python scripts/hash_summary.py

# Or add execute permission
chmod +x scripts/hash_summary.py
./scripts/hash_summary.py  # Then can run directly (still needs venv)
```

---

## Environment Issues

### Problem: Virtual environment not activated

**Symptoms:**
- Commands work inconsistently
- "Module not found" errors
- Using system Python

**Solution:**
```bash
# Don't rely on activation - use full paths
venv/bin/python scripts/hash_summary.py

# If you prefer to activate:
source venv/bin/activate
python scripts/hash_summary.py
deactivate  # When done
```

---

### Problem: ".env file not found"

**Symptoms:**
```
ERROR: Missing FALCON_CLIENT_ID or FALCON_CLIENT_SECRET in .env file
```

**Solutions:**
```bash
# Check if .env exists
ls -la .env

# Create from template if missing
cp .env.example .env
nano .env

# Verify contents
cat .env | grep FALCON_CLIENT_ID
```

---

### Problem: Wrong working directory

**Symptoms:**
```
FileNotFoundError: [Errno 2] No such file or directory: '.env'
```

**Solution:**
```bash
# Always run from project root
cd /home/kthompson/Development/Projects/falconpy
venv/bin/python scripts/hash_summary.py

# Verify you're in the right place
pwd
ls -la .env
```

---

## Performance Issues

### Problem: Queries are slow

**Possible Causes:**

1. **Large result sets**
   ```bash
   # Reduce limit
   venv/bin/python scripts/query_detections.py \
     --filter 'status:"new"' \
     --limit 1000  # Instead of 10000
   ```

2. **Network latency**
   ```bash
   # Test API response time
   time venv/bin/python scripts/query_detections.py \
     --filter 'status:"new"' \
     --limit 10 \
     --count-only
   ```

3. **Rate limiting**
   - CrowdStrike may throttle requests
   - Built-in 0.5s delay between batches
   - No solution needed - this is normal

---

### Problem: Bulk operations take too long

**Expected Times:**
- 1,000 detections: ~10 minutes
- 10,000 detections: ~100 minutes
- 100,000 detections: ~17 hours

**Optimization:**
```bash
# Process in smaller batches
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --max-detections 10000  # Limit total

# Or reduce batch size (not recommended - already optimal)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --batch-size 500  # Default: 1000
```

---

## Data/Output Issues

### Problem: Report file is empty

**Causes & Solutions:**

1. **Script error occurred**
   ```bash
   # Check for errors in output
   venv/bin/python scripts/hash_summary.py -o report.md

   # Look for error messages before "✓ Results saved"
   ```

2. **File permissions**
   ```bash
   # Check if you can write to directory
   touch test.txt
   rm test.txt

   # Try different location
   venv/bin/python scripts/hash_summary.py -o /tmp/report.md
   ```

---

### Problem: Output formatting is broken

**Symptoms:**
- Markdown tables not aligned
- Special characters appear

**Cause:** Terminal encoding issues

**Solution:**
```bash
# Set UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Then run script
venv/bin/python scripts/hash_summary.py -o report.md
```

---

## Multi-Customer Issues

### Problem: Wrong customer data

**Symptoms:**
- Seeing another customer's detections
- API credentials mismatch

**Solution:**
```bash
# Verify which .env is active
cat .env | head -5

# Verify client ID matches expectation
cat .env | grep FALCON_CLIENT_ID

# Switch to correct customer
cp customer1.env .env
cat .env | grep FALCON_CLIENT_ID  # Verify change
```

---

## Diagnostic Commands

### Quick Health Check
```bash
# 1. Check Python version
venv/bin/python --version

# 2. Check FalconPy version
venv/bin/python -c "import falconpy; print(f'FalconPy: {falconpy.__version__}')"

# 3. Check environment
cat .env | grep FALCON_CLIENT_ID
cat .env | grep FALCON_BASE_URL

# 4. Test API connection
venv/bin/python scripts/query_detections.py --test-connection

# 5. Quick query
venv/bin/python scripts/query_detections.py \
  --filter 'status:"new"' \
  --limit 5 \
  --count-only
```

### Full Diagnostic
```bash
#!/bin/bash
# diagnostic.sh

echo "=== FalconPy Diagnostic ==="
echo ""

echo "1. Python Version:"
venv/bin/python --version
echo ""

echo "2. FalconPy Version:"
venv/bin/python -c "import falconpy; print(f'FalconPy: {falconpy.__version__}')"
echo ""

echo "3. Working Directory:"
pwd
echo ""

echo "4. .env File:"
if [ -f .env ]; then
    echo "  ✓ .env exists"
    cat .env | grep FALCON_CLIENT_ID | cut -d'=' -f1
    cat .env | grep FALCON_BASE_URL
else
    echo "  ✗ .env not found"
fi
echo ""

echo "5. Scripts:"
ls -1 scripts/*.py
echo ""

echo "6. API Connection Test:"
venv/bin/python scripts/query_detections.py --test-connection
echo ""

echo "=== End Diagnostic ==="
```

---

## Getting Help

### Before Opening a Support Ticket

1. **Run diagnostics** (see above)
2. **Check this troubleshooting guide**
3. **Review logs** for error messages
4. **Try with a simple test case**
5. **Document steps to reproduce**

### Information to Provide

```
Environment:
- Python version: [venv/bin/python --version]
- FalconPy version: [...]
- OS: [uname -a]
- CrowdStrike region: [US-1, US-2, EU-1, etc.]

Issue:
- What were you trying to do?
- What command did you run?
- What error did you see?
- What did you expect to happen?

Steps to Reproduce:
1. [...]
2. [...]
3. [...]

Logs/Output:
[Paste error messages]
```

### Resources

- **FalconPy Docs:** https://falconpy.io/
- **CrowdStrike API Docs:** https://falcon.crowdstrike.com/documentation/
- **FalconPy GitHub Issues:** https://github.com/CrowdStrike/falconpy/issues
- **CrowdStrike Support:** https://supportportal.crowdstrike.com/

---

## Known Issues

### 1. Query Pagination
**Issue:** Can only query 10,000 detections maximum

**Status:** Limitation of current implementation

**Workaround:** Use more specific filters to reduce result set

**Future Fix:** Implement pagination in query_detections() function

---

### 2. ODS show_in_ui Behavior
**Issue:** ODS detections remain `show_in_ui: True` even when closed

**Status:** Expected behavior (different from XDR detections)

**Workaround:** Verify status is "closed" instead of checking show_in_ui

---

### 3. API Client ID in Comments
**Issue:** Comments show API client ID instead of human name

**Status:** Expected behavior when using API credentials

**Workaround:** Include operator name in comment text

---

## Quick Fixes Summary

| Problem | Quick Fix |
|---------|-----------|
| 403 error | Check API scopes in CrowdStrike console |
| 404 error | Update to use Alerts API (not Detects) |
| No results | Try without status filter |
| Hash not found | Generate hash summary first |
| Invalid status | Use "closed" not "resolved" |
| Module not found | Use venv/bin/python, not python |
| File not found | Check working directory (pwd) |
| Slow performance | Reduce batch size or limit |
| Wrong customer | Verify .env file (cat .env) |

---

**Last Updated:** 2025-10-31
