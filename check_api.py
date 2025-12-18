#!/usr/bin/env python3
"""
Compare what CrowdStrike API returns vs what's in the database
Run this to find missing detections
"""

import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from falconpy import OAuth2, Alerts
from collections import defaultdict

load_dotenv()

# Your CrowdStrike credentials
CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID")
CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET")
BASE_URL = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

print("=" * 80)
print("CROWDSTRIKE API DIAGNOSTIC TOOL")
print("=" * 80)

# Authenticate
auth = OAuth2(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, base_url=BASE_URL)
if not auth.token():
    print("❌ Authentication failed!")
    exit(1)

alerts = Alerts(auth_object=auth)

# Query for Dec 9-12
start = "2025-12-09T00:00:00Z"
end = "2025-12-12T00:00:00Z"

print(f"\n📅 Querying CrowdStrike for: {start} to {end}")
print("-" * 80)

# Method 1: Query with pagination (what your backfill uses)
print("\n🔍 METHOD 1: Paginated Query (current backfill method)")
filter_str = f"created_timestamp:>='{start}',created_timestamp:<'{end}'"

all_ids_paginated = []
offset = None
page = 0

while True:
    page += 1
    response = alerts.query_alerts(
        filter=filter_str,
        limit=5000,
        sort="created_timestamp.asc",
        offset=offset
    )
    
    if response.get("status_code") != 200:
        print(f"❌ Query failed: {response.get('status_code')}")
        print(f"   Error: {response.get('body')}")
        break
    
    body = response.get("body", {})
    ids = body.get("resources", [])
    
    if not ids:
        break
    
    all_ids_paginated.extend(ids)
    print(f"   Page {page}: {len(ids)} IDs | Running total: {len(all_ids_paginated)}")
    
    # Check for next page
    meta = body.get("meta", {})
    pagination = meta.get("pagination", {})
    next_offset = pagination.get("offset")
    
    print(f"   Next offset: {next_offset}")
    
    if not next_offset or next_offset == offset:
        break
    
    offset = next_offset
    
    # Safety brake
    if page > 50:
        print("⚠️  Stopping at 50 pages to prevent infinite loop")
        break

unique_paginated = list(set(all_ids_paginated))
print(f"\n📊 PAGINATED RESULTS:")
print(f"   Total IDs returned: {len(all_ids_paginated)}")
print(f"   Unique IDs: {len(unique_paginated)}")
print(f"   Duplicates: {len(all_ids_paginated) - len(unique_paginated)}")

# Method 2: Try different filter syntax
print("\n🔍 METHOD 2: Alternative Filter Syntax")
filter_str2 = f"created_timestamp:>'{start}'+created_timestamp:<'{end}'"

response2 = alerts.query_alerts(
    filter=filter_str2,
    limit=5000,
    sort="created_timestamp.asc"
)

if response2.get("status_code") == 200:
    ids2 = response2.get("body", {}).get("resources", [])
    print(f"   First page: {len(ids2)} IDs")
else:
    print(f"❌ Alternative filter failed: {response2.get('status_code')}")

# Method 3: Query without date filter to get total
print("\n🔍 METHOD 3: Count All Recent Detections")
response3 = alerts.query_alerts(
    filter="",
    limit=1,
    sort="created_timestamp.desc"
)

if response3.get("status_code") == 200:
    meta = response3.get("body", {}).get("meta", {})
    pagination = meta.get("pagination", {})
    total = pagination.get("total", 0)
    print(f"   Total detections in your environment: {total}")

# Analyze by hour
print("\n📈 HOURLY BREAKDOWN (from API):")
print("-" * 80)

# Fetch details for a sample to see timestamps
sample_ids = unique_paginated[:1000]  # First 1000
details = alerts.get_alerts(ids=sample_ids)

if details.get("status_code") == 200:
    hourly_counts = defaultdict(int)
    
    for det in details.get("body", {}).get("resources", []):
        ts = det.get("created_timestamp", "")
        if ts:
            # Extract hour
            hour = ts[:13]  # "2025-12-09T00"
            hourly_counts[hour] += 1
    
    for hour in sorted(hourly_counts.keys()):
        print(f"   {hour}: {hourly_counts[hour]} detections")

print("\n" + "=" * 80)
print("RECOMMENDATIONS:")
print("=" * 80)

if len(unique_paginated) < 2000:
    print("⚠️  Only found {0} detections in 3-day window".format(len(unique_paginated)))
    print("   This seems LOW for a typical environment")
    print("   Possible issues:")
    print("   - Date filter not working correctly")
    print("   - Pagination stopped early")
    print("   - You may need different API credentials")
    print("\n   Check CrowdStrike console to see actual count for this period")

if len(all_ids_paginated) - len(unique_paginated) > len(unique_paginated) * 0.5:
    print("\n⚠️  More than 50% duplicates in API response!")
    print("   This indicates pagination is returning same data multiple times")
    print("   Your backfill pagination logic may have a bug")

print("\n✅ NEXT STEPS:")
print("1. Compare these numbers with your database count (should be 1,239)")
print("2. Check CrowdStrike console for actual detection count Dec 9-12")
print("3. If numbers don't match, we'll fix the pagination/filter logic")
print("\nRun this command to see what's in your database:")
print("SELECT COUNT(*) FROM detections WHERE timestamp >= '2025-12-09' AND timestamp < '2025-12-12';")