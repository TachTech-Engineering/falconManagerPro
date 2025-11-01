# Scripts Reference Guide

Complete reference for all scripts in the FalconPy Detection Management project.

---

## Overview

| Script | Purpose | Modifies Data? |
|--------|---------|----------------|
| `hash_summary.py` | Generate SHA256 hash reports | No |
| `query_detections.py` | Search and view detections | No |
| `close_by_hash.py` | Close detections by SHA256 | Yes |
| `bulk_close_detections.py` | Bulk close by filter | Yes |
| `create_ioc_exclusion.py` | Create hash exclusions | Yes |

---

## 1. hash_summary.py

**Purpose:** Analyze which SHA256 hashes are involved in detections and generate reports.

### Features
- Counts detections per hash
- Sorts by frequency (most common first)
- Outputs to both terminal AND file
- Timestamp in report
- Supports custom filters

### Usage
```bash
# Basic usage (new detections)
venv/bin/python scripts/hash_summary.py

# Save to file (terminal + file)
venv/bin/python scripts/hash_summary.py -o report.md

# Custom filter
venv/bin/python scripts/hash_summary.py \
  --filter 'product:"xdr"+status:"new"' \
  -o xdr_report.md

# Limit results
venv/bin/python scripts/hash_summary.py \
  --limit 5000 \
  -o quick_report.md
```

### Parameters
| Parameter | Short | Required | Default | Description |
|-----------|-------|----------|---------|-------------|
| `--filter` | | No | `status:"new"` | FQL filter string |
| `--limit` | | No | `10000` | Max detections to analyze |
| `--output` | `-o` | No | None | Output file (markdown) |

### Output Format
```
================================================================================
SHA256 HASH SUMMARY
Generated: 2025-10-31 17:31:22
================================================================================

Querying detections with filter: status:"new"
Total detections found: 10000
Fetching details...

================================================================================
UNIQUE SHA256 HASHES: 29
================================================================================

Hash                                                             | Count
--------------------------------------------------------------------------------
0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46 |    18
...

================================================================================
SUMMARY
================================================================================
Total detections analyzed: 10000
Detections with SHA256 hashes: 98
Unique SHA256 hashes: 29
Most common hash: 18 detections
  0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46
================================================================================
```

### Examples
```bash
# Daily report
venv/bin/python scripts/hash_summary.py -o daily_$(date +%Y%m%d).md

# Specific product
venv/bin/python scripts/hash_summary.py \
  --filter 'product:"epp"+type:"ods"' \
  -o ods_hashes.md

# Closed detections (historical analysis)
venv/bin/python scripts/hash_summary.py \
  --filter 'status:"closed"' \
  -o closed_analysis.md
```

### Exit Codes
- `0` - Success
- `1` - Error occurred
- `130` - Cancelled by user (Ctrl+C)

---

## 2. query_detections.py

**Purpose:** Search for detections and display details.

### Features
- Search by hash or FQL filter
- Both XDR and ODS hash search
- Detailed or summary view
- Count-only mode
- Connection testing
- Pagination support

### Usage
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

### Parameters
| Parameter | Short | Required | Default | Description |
|-----------|-------|----------|---------|-------------|
| `--filter` | | No* | None | FQL filter string |
| `--hash` | | No* | None | SHA256 hash to search |
| `--limit` | | No | `100` | Max results (max: 10000) |
| `--offset` | | No | `0` | Starting offset (pagination) |
| `--details` | | No | False | Show full details |
| `--count-only` | | No | False | Only show count |
| `--test-connection` | | No | False | Test API and exit |

*Either `--filter` or `--hash` must be specified (unless using `--test-connection`)

### Output Modes

#### 1. Count Only (`--count-only`)
```
Found 69 detection(s).
```

#### 2. ID List (default)
```
Found 69 detection(s).

Detection IDs:
  1610a73617594125905b40c367121684:ind:1610a73617594125905b40c367121684:xdr|4114d...
  1610a73617594125905b40c367121684:ind:1610a73617594125905b40c367121684:xdr|dd833...
  ...
```

#### 3. Detailed View (`--details`)
```
Found 1 alert(s):

Alert ID: 1610a73617594125905b40c367121684:ods:...
  Status: closed
  Score: N/A
  Host: OnDemandScanPupAdwareHash
  Created: 2025-10-14T19:01:35.242931467Z
  Type: epp/ods
  MITRE ATT&CK Techniques:
    - Malware: PUP (CST0013)
```

### Hash Search Behavior
When using `--hash`, the script automatically searches both:
1. **XDR detections:** `entities.sha256:"HASH"`
2. **ODS detections:** `sha256:"HASH"`

Output shows breakdown:
```
Searching for alerts with SHA256: YOUR_HASH
  XDR detections: 0
  ODS detections: 1
Found 1 detection(s).
```

### Examples
```bash
# Find all high severity new detections
venv/bin/python scripts/query_detections.py \
  --filter 'status:"new"+severity:"High"' \
  --details

# Find detections on specific host
venv/bin/python scripts/query_detections.py \
  --filter 'device.hostname:"MSI"+status:"new"' \
  --details

# Pagination
venv/bin/python scripts/query_detections.py \
  --filter 'status:"new"' \
  --limit 100 \
  --offset 100  # Page 2
```

### Exit Codes
- `0` - Success
- `1` - Error occurred
- `130` - Cancelled by user

---

## 3. close_by_hash.py

**Purpose:** Close all detections associated with a specific SHA256 hash.

⚠️ **WARNING:** Modifies detections. Always use `--dry-run` first!

### Features
- Searches both XDR and ODS detections
- Dry-run mode (safe preview)
- Confirmation prompt
- Batch processing
- Progress tracking
- Comment support

### Usage
```bash
# Dry-run (safe preview)
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH" \
  --dry-run

# Actually close (with confirmation)
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH" \
  --comment "Benign - SOC approved"

# Custom status
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH" \
  --status in_progress \
  --comment "Under investigation"
```

### Parameters
| Parameter | Short | Required | Default | Description |
|-----------|-------|----------|---------|-------------|
| `--hash` | | **Yes** | None | SHA256 hash to search |
| `--comment` | | No | `Closed - benign file` | Comment to add |
| `--status` | | No | `closed` | Status to set |
| `--dry-run` | | No | False | Preview only, no changes |

### Valid Status Values
- `closed` - Mark as resolved (recommended)
- `in_progress` - Mark as under investigation
- `resolved` - Alias for "closed" (auto-converted)

### Workflow
```
1. Search for hash in both XDR and ODS detections
2. Display preview of detections found
3. If --dry-run: Exit (no changes)
4. Prompt for confirmation: "Proceed? (yes/no)"
5. If confirmed: Close detections in batches
6. Display results
```

### Output Example
```
Initializing CrowdStrike Falcon client...

Searching for alerts with SHA256: 71de08d14b90196b02293ddca105dc367837280bee2224815e35ff7f17363c48
  XDR detections: 0
  ODS detections: 1
Found 1 alert(s) with this hash

Fetching alert details...

Found 1 alert(s):

Alert ID: 1610a73617594125905b40c367121684:ods:...
  Status: new
  Score: N/A
  Host: OnDemandScanPupAdwareHash
  Created: 2025-10-14T19:01:35.242931467Z
  Type: epp/ods
  MITRE ATT&CK Techniques:
    - Malware: PUP (CST0013)


============================================================
CONFIRMATION REQUIRED
============================================================
Hash: 71de08d14b90196b02293ddca105dc367837280bee2224815e35ff7f17363c48
Alerts to close: 1
New status: closed
Comment: Benign - SOC approved
============================================================

Proceed? (yes/no): yes

Closing alerts...
Updating 1 alerts in batches of 1000...
Processing batch 1/1 (1 alerts)... ✓

============================================================
COMPLETE
============================================================
Total: 1
Success: 1
Failed: 0
============================================================
```

### Examples
```bash
# Close with detailed comment
venv/bin/python scripts/close_by_hash.py \
  --hash "0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46" \
  --comment "Benign - internal tool (approved by Kyle Thompson)"

# Mark as under investigation
venv/bin/python scripts/close_by_hash.py \
  --hash "YOUR_HASH" \
  --status in_progress \
  --comment "Investigating - ticket INC-12345"
```

### Exit Codes
- `0` - Success (all updated)
- `1` - Failure (some/all updates failed)
- `130` - Cancelled by user

---

## 4. bulk_close_detections.py

**Purpose:** Close large numbers of detections matching a filter.

⚠️ **WARNING:** Powerful tool! Can close thousands of detections. Always use `--dry-run` first!

### Features
- FQL filter support
- Dry-run mode
- Confirmation prompts (skippable)
- Batch processing (1000 per batch)
- Rate limiting (0.5s between batches)
- Progress tracking
- Max detection limits
- Sample preview

### Usage
```bash
# Dry-run first (ALWAYS!)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --status closed \
  --comment "Bulk closure - SOC review" \
  --dry-run

# Actually close (with confirmation)
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

### Parameters
| Parameter | Short | Required | Default | Description |
|-----------|-------|----------|---------|-------------|
| `--filter` | | **Yes** | None | FQL filter string |
| `--status` | | No | `closed` | Status to set |
| `--comment` | | No | None | Comment to add |
| `--batch-size` | | No | `1000` | Detections per batch (max: 1000) |
| `--max-detections` | | No | Unlimited | Maximum to process |
| `--dry-run` | | No | False | Preview only, no changes |
| `--no-confirm` | | No | False | Skip confirmation prompt |
| `--test-connection` | | No | False | Test API and exit |

### Valid Status Values
- `closed` - Mark as resolved
- `in_progress` - Mark as under investigation
- `new` - Reopen
- `reopened` - Reopen from closed
- `false_positive` - Alias for "closed" (auto-converted)
- `true_positive` - Alias for "closed" (auto-converted)
- `ignored` - Alias for "closed" (auto-converted)
- `resolved` - Alias for "closed" (auto-converted)

### Workflow
```
1. Query detections matching filter (up to max-detections)
2. Display count and sample (first 5)
3. If --dry-run: Exit (no changes)
4. If not --no-confirm: Prompt for confirmation
5. Close detections in batches of 1000
6. 0.5s delay between batches (rate limiting)
7. Display results
```

### Output Example
```
Initializing CrowdStrike Falcon client...

Querying detections with filter: status:"new"
Found 10000 detection(s) matching filter.

Fetching sample detection details...

Found 5 alert(s):
[... sample detections displayed ...]

============================================================
CONFIRMATION REQUIRED
============================================================
Filter: status:"new"
Detections to update: 10000
New status: closed
Comment: Bulk closure - SOC review
============================================================

Proceed with bulk update? (yes/no): yes

Starting bulk update...
Updating 10000 alerts in batches of 1000...
Processing batch 1/10 (1000 alerts)... ✓
Processing batch 2/10 (1000 alerts)... ✓
Processing batch 3/10 (1000 alerts)... ✓
...
Processing batch 10/10 (1000 alerts)... ✓

============================================================
BULK UPDATE COMPLETE
============================================================
Total detections: 10000
Successfully updated: 10000
Failed: 0
============================================================
```

### Examples
```bash
# Close all IOC detections
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'display_name:*"IOC"*+status:"new"' \
  --status closed \
  --comment "IOC detections - SOC reviewed" \
  --dry-run

# Close detections from specific host
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'device.hostname:"MSI"+status:"new"' \
  --status closed

# Limit to 1000 detections
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'status:"new"' \
  --max-detections 1000 \
  --status closed
```

### Performance
| Detections | Batches | Est. Time |
|------------|---------|-----------|
| 1,000 | 1 | ~10 seconds |
| 10,000 | 10 | ~100 seconds |
| 100,000 | 100 | ~17 minutes |

### Exit Codes
- `0` - Success (all updated)
- `1` - Failure (some/all updates failed)
- `130` - Cancelled by user

---

## 5. create_ioc_exclusion.py

**Purpose:** Create SHA256 hash exclusions to prevent future false positive detections.

⚠️ **WARNING:** Creates permanent exclusions. Use carefully!

### Features
- SHA256, SHA1, MD5 support
- Global or host-group scoping
- Confirmation prompt
- Detailed validation

### Usage
```bash
# Create global exclusion
venv/bin/python scripts/create_ioc_exclusion.py \
  --hash "YOUR_HASH" \
  --description "Internal tool - false positive" \
  --applied-globally

# Create for specific host groups
venv/bin/python scripts/create_ioc_exclusion.py \
  --hash "YOUR_HASH" \
  --description "Legacy backup utility" \
  --host-groups "Servers,Workstations"

# MD5 hash
venv/bin/python scripts/create_ioc_exclusion.py \
  --hash "5d41402abc4b2a76b9719d911017c592" \
  --type md5 \
  --description "Known good file" \
  --applied-globally
```

### Parameters
| Parameter | Short | Required | Default | Description |
|-----------|-------|----------|---------|-------------|
| `--hash` | | **Yes** | None | Hash value to exclude |
| `--type` | | No | `sha256` | Hash type (sha256, sha1, md5) |
| `--description` | | **Yes** | None | Reason for exclusion |
| `--applied-globally` | | No* | False | Apply to all hosts |
| `--host-groups` | | No* | None | Comma-separated groups |
| `--severity` | | No | `informational` | Severity if detected |
| `--test-connection` | | No | False | Test API and exit |

*Either `--applied-globally` or `--host-groups` must be specified

### Valid Severity Values
- `informational` (default)
- `low`
- `medium`
- `high`
- `critical`

### Workflow
```
1. Validate parameters
2. Display confirmation prompt
3. Create IOC indicator with policy="none" (exclusion)
4. Display created indicator ID
```

### Output Example
```
Initializing CrowdStrike Falcon client...

============================================================
CONFIRMATION REQUIRED
============================================================
Creating IOC exclusion will PREVENT future detections
Hash: 0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bc66f01b9
Type: sha256
Scope: Global (all hosts)
============================================================

Proceed with creating exclusion? (yes/no): yes

Creating SHA256 exclusion...
Hash: 0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bc66f01b9
Description: Internal tool - false positive

✓ Exclusion created successfully!

Indicator ID: abc123...
Type: sha256
Value: 0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bc66f01b9
Applied globally: True
```

### Examples
```bash
# Exclude internal tool globally
venv/bin/python scripts/create_ioc_exclusion.py \
  --hash "abc123..." \
  --description "Internal monitoring tool - CompanyXYZ" \
  --applied-globally

# Exclude for test environment only
venv/bin/python scripts/create_ioc_exclusion.py \
  --hash "def456..." \
  --description "Test environment utility" \
  --host-groups "Test,Dev"
```

### Exit Codes
- `0` - Success
- `1` - Failure
- `130` - Cancelled by user

---

## Common Patterns

### Daily Workflow
```bash
# 1. Generate report
venv/bin/python scripts/hash_summary.py -o daily_$(date +%Y%m%d).md

# 2. Review report, identify hashes to close

# 3. Close specific hash (dry-run first)
venv/bin/python scripts/close_by_hash.py --hash "HASH" --dry-run
venv/bin/python scripts/close_by_hash.py --hash "HASH" --comment "SOC approved"

# 4. Generate follow-up report to verify
venv/bin/python scripts/hash_summary.py -o followup_$(date +%Y%m%d).md
```

### Bulk Operations Workflow
```bash
# 1. Count what would be affected
venv/bin/python scripts/query_detections.py \
  --filter 'YOUR_FILTER' \
  --count-only

# 2. Review sample
venv/bin/python scripts/query_detections.py \
  --filter 'YOUR_FILTER' \
  --limit 10 \
  --details

# 3. Dry-run bulk close
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'YOUR_FILTER' \
  --dry-run

# 4. Actually close (start small!)
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'YOUR_FILTER' \
  --max-detections 100 \
  --comment "Test batch"

# 5. If successful, process all
venv/bin/python scripts/bulk_close_detections.py \
  --filter 'YOUR_FILTER' \
  --comment "Bulk closure"
```

---

## Environment Variables

All scripts support these environment variables from `.env`:

```bash
FALCON_CLIENT_ID=your_client_id
FALCON_CLIENT_SECRET=your_client_secret
FALCON_BASE_URL=https://api.crowdstrike.com
```

---

## Error Handling

All scripts include:
- ✅ Try-catch blocks for API errors
- ✅ Graceful Ctrl+C handling (exit code 130)
- ✅ Descriptive error messages
- ✅ Non-zero exit codes on failure

---

## Logging

Currently no log files are created. Output goes to:
- stdout (terminal)
- Optional: file output (hash_summary.py)

---

**Last Updated:** 2025-10-31
