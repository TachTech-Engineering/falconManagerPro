# backend/run_backfill.py
"""
Standalone script to backfill 30 days of detections for all active tenants.
Run this separately from the main application.
"""

import os
import sys
import logging
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment before importing app modules
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_backfill():
    """Run the backfill process with proper error handling"""
    try:
        # Import after environment is loaded
        from database import db, tenant_dao, detection_dao
        from falconpy import OAuth2, Alerts
        
        logger.info("=" * 80)
        logger.info("STARTING 30-DAY DETECTION BACKFILL")
        logger.info("=" * 80)
        
        # ✅ FIXED: Match the main app's normalize_detection() exactly
        def _map_numeric_severity(num):
            """Map Falcon numeric severity into buckets"""
            try:
                n = int(num)
            except (TypeError, ValueError):
                return None
            
            if n <= 19:
                return 'informational'
            if n <= 39:
                return 'low'
            if n <= 59:
                return 'medium'
            if n <= 79:
                return 'high'
            return 'critical'
        
        def normalize_detection(det):
            """
            ✅ FIXED: Now returns the EXACT field names expected by the database
            """
            behaviors = det.get('behaviors') or []
            first_behavior = behaviors[0] if behaviors else {}
            device = det.get('device') or {}
            entities = det.get('entities') or {}
            has_hash = bool(entities.get('sha256') or entities.get('md5') or entities.get('sha1'))
            
            # Derive severity robustly
            severity = None
            
            # 1) Try string display-name style fields first
            for key in ('max_severity_displayname', 'severity_name'):
                val = det.get(key)
                if isinstance(val, str) and val.strip():
                    severity = val.lower()
                    break
            
            # 2) Try detection-level numeric or string severities
            if severity is None:
                for key in ('max_severity', 'severity'):
                    val = det.get(key)
                    if isinstance(val, str) and val.strip():
                        severity = val.lower()
                        break
                    mapped = _map_numeric_severity(val)
                    if mapped:
                        severity = mapped
                        break
            
            # 3) Fallback to behavior severity
            if severity is None and first_behavior:
                val = first_behavior.get('severity_name')
                if isinstance(val, str) and val.strip():
                    severity = val.lower()
                else:
                    bnum = first_behavior.get('severity')
                    mapped = _map_numeric_severity(bnum)
                    if mapped:
                        severity = mapped
            
            # 4) Final fallback
            if severity is None:
                severity = 'unknown'
            
            # ✅ CRITICAL FIX: Use correct field names matching database schema
            return {
                'id': det.get('detection_id') or det.get('id'),  # ✅ 'id' is correct for DAO
                'severity': severity,
                'status': det.get('status', 'new'),
                'timestamp': det.get('created_timestamp') or det.get('timestamp'),
                'host': device.get('hostname', 'Unknown'),  # ✅ 'host' is correct for DAO
                'host_id': device.get('device_id'),
                'tactic': first_behavior.get('tactic', 'Unknown'),
                'technique': first_behavior.get('technique', ''),
                'description': first_behavior.get('description', ''),
                'has_hash': has_hash,
                'behavior': first_behavior.get('tactic', 'Unknown'),
                'assigned_to': det.get('assigned_to_name', 'Unassigned'),
                'cs_raw': det  # ✅ CRITICAL: Include raw data for database
            }
        
        # Load all active tenants from database
        logger.info("Loading active tenants from database...")
        with db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT
                    id,
                    name,
                    crowdstrike_client_id,
                    crowdstrike_client_secret,
                    COALESCE(crowdstrike_base_url, 'https://api.crowdstrike.com') AS crowdstrike_base_url
                FROM tenants
                WHERE is_active = true
                  AND deleted_at IS NULL
                  AND crowdstrike_client_id IS NOT NULL
                  AND crowdstrike_client_secret IS NOT NULL
            """)
            tenants = cursor.fetchall()
        
        if not tenants:
            logger.warning("No active tenants with valid credentials found. Exiting.")
            return
        
        logger.info(f"Found {len(tenants)} active tenant(s) with valid credentials")
        
        # Process each tenant
        total_detections_synced = 0
        
        for tenant in tenants:
            # Handle both dict and tuple row formats
            if isinstance(tenant, dict):
                tenant_id = tenant['id']
                tenant_name = tenant['name']
                client_id = tenant['crowdstrike_client_id']
                client_secret = tenant['crowdstrike_client_secret']
                base_url = tenant['crowdstrike_base_url']
            else:
                tenant_id = tenant[0]
                tenant_name = tenant[1]
                client_id = tenant[2]
                client_secret = tenant[3]
                base_url = tenant[4]
            
            logger.info("-" * 80)
            logger.info(f"Processing Tenant: {tenant_name} (ID: {tenant_id})")
            
            try:
                # Create CrowdStrike auth
                falcon_auth = OAuth2(
                    client_id=client_id,
                    client_secret=client_secret,
                    base_url=base_url
                )
                
                # Verify authentication works
                token = falcon_auth.token()
                if not token:
                    logger.error(f"Failed to authenticate for tenant {tenant_name}")
                    continue
                
                alerts = Alerts(auth_object=falcon_auth)
                
                # ✅ FIXED: Use timezone-aware datetime
                start_utc_env = os.getenv("BACKFILL_START_UTC")
                end_utc_env = os.getenv("BACKFILL_END_UTC")
                
                if start_utc_env and end_utc_env:
                    logger.info(f"Using explicit backfill window: {start_utc_env} → {end_utc_env}")
                    # CrowdStrike expects naive UTC timestamps
                    # Use updated_timestamp to capture status changes
                    filter_str = (
                        f"updated_timestamp:>='{start_utc_env}',"
                        f"updated_timestamp:<'{end_utc_env}'"
                    )
                else:
                    # Default 30-day window
                    now_utc = datetime.now(timezone.utc)
                    start_time = now_utc - timedelta(days=30)
                    # Remove timezone for CrowdStrike API
                    start_naive = start_time.replace(tzinfo=None)
                    logger.info(f"Using default 30-day window: since {start_naive.isoformat()}Z")
                    # Use updated_timestamp to capture status changes
                    filter_str = f"updated_timestamp:>='{start_naive.isoformat()}Z'"

                # Query all detection IDs with pagination
                all_ids = []
                offset = None

                logger.info("Querying detection IDs from CrowdStrike...")
                while True:
                    query = alerts.query_alerts(
                        filter=filter_str,
                        limit=5000,
                        sort="updated_timestamp.asc",
                        offset=offset
                    )
                    
                    if query.get("status_code") != 200:
                        logger.error(f"Query failed with status {query.get('status_code')}")
                        break
                    
                    body = query.get("body") or {}
                    page_ids = body.get("resources", []) or []
                    
                    if not page_ids:
                        break
                    
                    all_ids.extend(page_ids)
                    logger.info(f"Collected {len(all_ids)} detection IDs so far...")
                    
                    # Check for next page
                    meta = body.get("meta") or {}
                    pagination = meta.get("pagination") or {}
                    next_offset = pagination.get("offset")
                    
                    if not next_offset or next_offset == offset or next_offset == "":
                        break

                    # Also check the 'total' field in meta
                    meta = body.get("meta", {})
                    pagination = meta.get("pagination", {})
                    total_available = pagination.get("total", 0)

                    if len(all_ids) >= total_available:
                        print(f"Collected all {total_available} detections")
                        break
                    offset = next_offset
                
                logger.info(f"Total detection IDs found: {len(all_ids)}")
                
                if not all_ids:
                    logger.warning(f"No detections found for tenant {tenant_name}")
                    continue
                
                # Fetch details in batches and save to database
                detections_synced = 0
                total_batches = (len(all_ids) + 499) // 500
                
                for i in range(0, len(all_ids), 500):
                    batch = all_ids[i:i+500]
                    batch_num = (i // 500) + 1
                    
                    logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} detections)...")
                    
                    detail = alerts.get_alerts(ids=batch)
                    if detail.get('status_code') != 200:
                        logger.error(f"Failed to fetch batch {batch_num} details")
                        continue
                    
                    resources = (detail.get("body") or {}).get("resources", []) or []
                    
                    # ✅ FIXED: Use bulk_create_or_update for better performance
                    detections_to_store = []
                    for det in resources:
                        try:
                            normalized = normalize_detection(det)
                            detections_to_store.append(normalized)
                        except Exception as e:
                            logger.error(f"Failed to normalize detection: {e}")
                    
                    # Bulk insert
                    if detections_to_store:
                        try:
                            count = detection_dao.bulk_create_or_update(tenant_id, detections_to_store)
                            detections_synced += count
                            logger.info(f"Batch {batch_num} complete - {count} detections saved ({detections_synced} total)")
                        except Exception as e:
                            logger.error(f"Failed to bulk insert batch {batch_num}: {e}")
                
                total_detections_synced += detections_synced
                logger.info(f"✅ Tenant {tenant_name}: {detections_synced} detections backfilled")
                
            except Exception as e:
                logger.error(f"❌ Failed to process tenant {tenant_name}: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        logger.info("=" * 80)
        logger.info(f"BACKFILL COMPLETE - Total detections synced: {total_detections_synced}")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Fatal error during backfill: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_backfill()