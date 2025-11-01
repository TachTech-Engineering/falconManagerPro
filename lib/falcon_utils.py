"""
Falcon Utility Library
Common functions for interacting with CrowdStrike Falcon API
"""

import os
import sys
import time
from typing import List, Dict, Optional
from dotenv import load_dotenv
from falconpy import Alerts, IOC


class FalconClient:
    """Wrapper for CrowdStrike Falcon API interactions"""

    def __init__(self, env_file: Optional[str] = None):
        """Initialize Falcon client with credentials from environment

        Args:
            env_file: Optional path to .env file (defaults to .env in current directory)
        """
        if env_file:
            load_dotenv(dotenv_path=env_file)
        else:
            load_dotenv()
        
        self.client_id = os.getenv('FALCON_CLIENT_ID')
        self.client_secret = os.getenv('FALCON_CLIENT_SECRET')
        self.base_url = os.getenv('FALCON_BASE_URL', 'https://api.crowdstrike.com')
        
        if not self.client_id or not self.client_secret:
            print("ERROR: Missing FALCON_CLIENT_ID or FALCON_CLIENT_SECRET in .env file")
            sys.exit(1)

        self.alerts = Alerts(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url
        )

        self.ioc = IOC(
            client_id=self.client_id,
            client_secret=self.client_secret,
            base_url=self.base_url
        )
    
    def test_connection(self) -> bool:
        """Test API connection and credentials"""
        try:
            response = self.alerts.query_alerts_v2(limit=1)
            if response['status_code'] == 200:
                print("✓ Successfully connected to CrowdStrike Falcon API")
                return True
            else:
                print(f"✗ Connection failed: {response['body']['errors']}")
                return False
        except Exception as e:
            print(f"✗ Connection error: {str(e)}")
            return False
    
    def query_detections(self, filter_string: str, limit: int = 100, offset: int = 0) -> List[str]:
        """
        Query alert IDs by filter

        Args:
            filter_string: FQL filter string
            limit: Maximum number of results (max 10000)
            offset: Starting offset for pagination

        Returns:
            List of alert IDs
        """
        try:
            response = self.alerts.query_alerts_v2(
                filter=filter_string,
                limit=min(limit, 10000),
                offset=offset
            )

            if response['status_code'] == 200:
                return response['body']['resources']
            else:
                print(f"Query failed: {response['body'].get('errors', 'Unknown error')}")
                return []
        except Exception as e:
            print(f"Query error: {str(e)}")
            return []
    
    def get_detection_details(self, detection_ids: List[str]) -> Dict:
        """
        Get detailed information for alert IDs

        Args:
            detection_ids: List of alert composite IDs (max 1000)

        Returns:
            Alert details
        """
        try:
            response = self.alerts.get_alerts_v2(composite_ids=detection_ids[:1000])

            if response['status_code'] == 200:
                return response['body']['resources']
            else:
                print(f"Failed to get details: {response['body'].get('errors', 'Unknown error')}")
                return {}
        except Exception as e:
            print(f"Error getting details: {str(e)}")
            return {}
    
    def update_detections(self, detection_ids: List[str], status: str,
                         comment: Optional[str] = None, assigned_to: Optional[str] = None) -> bool:
        """
        Update alert status in batches

        Args:
            detection_ids: List of alert composite IDs (max 1000 per call)
            status: New status (new, in_progress, closed, reopened)
                    For backwards compatibility also accepts: false_positive, true_positive, ignored, resolved
            comment: Optional comment
            assigned_to: Optional user to assign to

        Returns:
            True if successful
        """
        if len(detection_ids) > 1000:
            print(f"WARNING: Can only update 1000 alerts per call. Truncating to first 1000.")
            detection_ids = detection_ids[:1000]

        # Map old status values to correct Alerts API v3 status values
        # For benign detections, use 'closed' status (resolved is not a valid status)
        status_mapping = {
            'false_positive': 'closed',
            'true_positive': 'closed',
            'ignored': 'closed',
            'resolved': 'closed',  # Common terminology but maps to 'closed'
            'closed': 'closed',
            'in_progress': 'in_progress',
            'new': 'new',
            'reopened': 'reopened'
        }

        mapped_status = status_mapping.get(status, status)

        try:
            params = {
                'composite_ids': detection_ids,
                'update_status': mapped_status
            }

            if comment:
                params['append_comment'] = comment
            if assigned_to:
                params['assign_to_name'] = assigned_to

            response = self.alerts.update_alerts_v3(**params)

            if response['status_code'] == 200:
                return True
            else:
                print(f"Update failed: {response['body'].get('errors', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"Update error: {str(e)}")
            return False
    
    def bulk_update_detections(self, detection_ids: List[str], status: str,
                              comment: Optional[str] = None, batch_size: int = 1000,
                              delay: float = 0.5) -> Dict[str, int]:
        """
        Update alerts in batches with rate limiting

        Args:
            detection_ids: List of all alert composite IDs to update
            status: New status (new, in_progress, closed, reopened)
            comment: Optional comment
            batch_size: Number of alerts per batch (max 1000)
            delay: Delay between batches in seconds

        Returns:
            Dictionary with success and failure counts
        """
        batch_size = min(batch_size, 1000)
        total = len(detection_ids)
        success_count = 0
        failure_count = 0

        print(f"Updating {total} alerts in batches of {batch_size}...")

        for i in range(0, total, batch_size):
            batch = detection_ids[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total + batch_size - 1) // batch_size

            print(f"Processing batch {batch_num}/{total_batches} ({len(batch)} alerts)...", end=' ')

            if self.update_detections(batch, status, comment):
                success_count += len(batch)
                print("✓")
            else:
                failure_count += len(batch)
                print("✗")

            if i + batch_size < total:
                time.sleep(delay)

        return {
            'total': total,
            'success': success_count,
            'failure': failure_count
        }


def format_detection_summary(detections: List[Dict]) -> None:
    """Pretty print alert summary"""
    if not detections:
        print("No alerts found.")
        return

    print(f"\nFound {len(detections)} alert(s):\n")

    for alert in detections:
        print(f"Alert ID: {alert.get('composite_id', 'N/A')}")
        print(f"  Status: {alert.get('status', 'N/A')}")

        # Score/Severity
        incident = alert.get('incident', {})
        score = incident.get('highest_score', incident.get('score', 'N/A'))
        print(f"  Score: {score}")

        # Hostname
        hostname = alert.get('name', 'N/A')
        print(f"  Host: {hostname}")

        # Timestamps
        created = alert.get('created_timestamp', 'N/A')
        print(f"  Created: {created}")

        # Product/Type
        product = alert.get('product', 'N/A')
        alert_type = alert.get('type', 'N/A')
        print(f"  Type: {product}/{alert_type}")

        # MITRE ATT&CK
        mitre = alert.get('mitre_attack', [])
        if mitre:
            print(f"  MITRE ATT&CK Techniques:")
            for technique in mitre[:3]:  # Show first 3
                tactic = technique.get('tactic', 'N/A')
                tech = technique.get('technique', 'N/A')
                tech_id = technique.get('technique_id', '')
                print(f"    - {tactic}: {tech} ({tech_id})")

        # SHA256 hashes if present
        sha256s = alert.get('entities', {}).get('sha256', [])
        if sha256s:
            print(f"  SHA256: {sha256s[0]}")
            if len(sha256s) > 1:
                print(f"    (+{len(sha256s)-1} more)")

        print()
