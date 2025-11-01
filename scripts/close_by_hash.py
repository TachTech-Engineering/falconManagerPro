#!/usr/bin/env python3
"""
Close CrowdStrike Alerts by SHA256 Hash

Quick script to close all alerts associated with a specific SHA256 hash.
"""

import sys
import argparse
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from falcon_utils import FalconClient, format_detection_summary


def main():
    parser = argparse.ArgumentParser(
        description='Close all alerts for a specific SHA256 hash',
        epilog='''
Examples:
  # Dry-run to preview (safe - no changes)
  %(prog)s --hash "89eadbfac6d094cd86214fe6f340e3499f19119a43861d7dfe40cabb10f9a793" --dry-run

  # Actually close the alerts
  %(prog)s --hash "89eadbfac6d094cd86214fe6f340e3499f19119a43861d7dfe40cabb10f9a793" \\
           --comment "Benign - approved by SOC"
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--hash', required=True, help='SHA256 hash to search for')
    parser.add_argument('--comment', default='Resolved - benign file (SOC approved via API)', help='Comment to add')
    parser.add_argument('--dry-run', action='store_true', help='Preview only, no changes')
    parser.add_argument('--status', default='closed', choices=['closed', 'in_progress', 'resolved'],
                       help='Status to set (default: closed, benign detections)')
    
    args = parser.parse_args()
    
    # Initialize client
    print("Initializing CrowdStrike Falcon client...")
    falcon = FalconClient()
    
    # Search for alerts with this hash (both XDR and ODS detections)
    print(f"\nSearching for alerts with SHA256: {args.hash}")

    # Try XDR detections (entities.sha256)
    filter_xdr = f'entities.sha256:"{args.hash}"'
    alert_ids_xdr = falcon.query_detections(filter_string=filter_xdr, limit=10000)

    # Try ODS detections (sha256)
    filter_ods = f'sha256:"{args.hash}"'
    alert_ids_ods = falcon.query_detections(filter_string=filter_ods, limit=10000)

    # Combine results
    alert_ids = list(set(alert_ids_xdr + alert_ids_ods))
    print(f"  XDR detections: {len(alert_ids_xdr)}")
    print(f"  ODS detections: {len(alert_ids_ods)}")
    
    if not alert_ids:
        print(f"No alerts found with hash: {args.hash}")
        return 0
    
    print(f"Found {len(alert_ids)} alert(s) with this hash")
    
    # Get details
    print("\nFetching alert details...")
    details = falcon.get_detection_details(alert_ids)
    format_detection_summary(details)
    
    # Dry-run mode
    if args.dry_run:
        print("=" * 60)
        print("DRY-RUN MODE - No changes will be made")
        print("=" * 60)
        print(f"Would close {len(alert_ids)} alert(s)")
        print(f"Comment: {args.comment}")
        return 0
    
    # Confirm
    print("\n" + "=" * 60)
    print("CONFIRMATION REQUIRED")
    print("=" * 60)
    print(f"Hash: {args.hash}")
    print(f"Alerts to close: {len(alert_ids)}")
    print(f"New status: {args.status}")
    print(f"Comment: {args.comment}")
    print("=" * 60)
    
    response = input("\nProceed? (yes/no): ").strip().lower()
    if response != 'yes':
        print("\nCancelled.")
        return 0
    
    # Close alerts
    print("\nClosing alerts...")
    results = falcon.bulk_update_detections(
        detection_ids=alert_ids,
        status=args.status,
        comment=args.comment
    )
    
    # Results
    print("\n" + "=" * 60)
    print("COMPLETE")
    print("=" * 60)
    print(f"Total: {results['total']}")
    print(f"Success: {results['success']}")
    print(f"Failed: {results['failure']}")
    print("=" * 60)
    
    return 0 if results['failure'] == 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nCancelled (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        sys.exit(1)
