#!/usr/bin/env python3
"""
Bulk Close CrowdStrike Detections

Close large numbers of detections matching a filter in batches.
Includes dry-run mode and safety confirmations.
"""

import sys
import argparse
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from falcon_utils import FalconClient, format_detection_summary


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Bulk close CrowdStrike Falcon detections',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Close all new detections from Custom Intelligence (with confirmation)
  %(prog)s --filter 'behaviors.tactic:"Custom Intelligence"+status:"new"' \\
           --status false_positive \\
           --comment "Bulk closure - confirmed FP"

  # Dry-run to preview what would be closed
  %(prog)s --filter 'status:"new"' --dry-run

  # Close maximum 10,000 detections
  %(prog)s --filter 'status:"new"' --max-detections 10000 --no-confirm

Filter Examples:
  status:"new"
  status:"new"+max_severity_displayname:"High"
  behaviors.tactic:"Custom Intelligence"
  device.hostname:"WORKSTATION-01"
  first_behavior:>"2025-10-01T00:00:00Z"
        """
    )
    
    parser.add_argument(
        '--filter',
        required=True,
        help='FQL filter string to match detections'
    )
    
    parser.add_argument(
        '--status',
        default='closed',
        choices=['closed', 'in_progress', 'new', 'reopened', 'false_positive', 'true_positive', 'ignored', 'resolved'],
        help='Status to set (default: closed). Legacy values (false_positive, true_positive, ignored, resolved) map to "closed"'
    )
    
    parser.add_argument(
        '--comment',
        help='Comment to add to detections'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Number of detections per batch (max 1000, default: 1000)'
    )
    
    parser.add_argument(
        '--max-detections',
        type=int,
        help='Maximum number of detections to process (default: unlimited)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview detections without making changes'
    )
    
    parser.add_argument(
        '--no-confirm',
        action='store_true',
        help='Skip confirmation prompt (dangerous!)'
    )
    
    parser.add_argument(
        '--test-connection',
        action='store_true',
        help='Test API connection and exit'
    )
    
    return parser.parse_args()


def confirm_action(detection_count: int, status: str, filter_string: str) -> bool:
    """Prompt user to confirm bulk action"""
    print("\n" + "="*60)
    print("CONFIRMATION REQUIRED")
    print("="*60)
    print(f"Filter: {filter_string}")
    print(f"Detections to update: {detection_count}")
    print(f"New status: {status}")
    print("="*60)
    
    response = input("\nProceed with bulk update? (yes/no): ").strip().lower()
    return response == 'yes'


def main():
    """Main execution function"""
    args = parse_args()
    
    # Initialize Falcon client
    print("Initializing CrowdStrike Falcon client...")
    falcon = FalconClient()
    
    # Test connection if requested
    if args.test_connection:
        sys.exit(0 if falcon.test_connection() else 1)
    
    # Query detections
    print(f"\nQuerying detections with filter: {args.filter}")
    
    # First, get count
    detection_ids = falcon.query_detections(
        filter_string=args.filter,
        limit=10000 if not args.max_detections else min(args.max_detections, 10000)
    )
    
    if not detection_ids:
        print("No detections found matching filter.")
        return 0
    
    # If max_detections specified, truncate
    if args.max_detections and len(detection_ids) > args.max_detections:
        print(f"Limiting to first {args.max_detections} detections...")
        detection_ids = detection_ids[:args.max_detections]
    
    print(f"Found {len(detection_ids)} detection(s) matching filter.")
    
    # Get sample details
    print("\nFetching sample detection details...")
    sample_details = falcon.get_detection_details(detection_ids[:5])
    format_detection_summary(sample_details)
    
    # Dry-run mode
    if args.dry_run:
        print("="*60)
        print("DRY-RUN MODE - No changes will be made")
        print("="*60)
        print(f"Would update {len(detection_ids)} detection(s) to status: {args.status}")
        if args.comment:
            print(f"With comment: {args.comment}")
        return 0
    
    # Confirmation
    if not args.no_confirm:
        if not confirm_action(len(detection_ids), args.status, args.filter):
            print("\nOperation cancelled by user.")
            return 0
    
    # Perform bulk update
    print("\nStarting bulk update...")
    results = falcon.bulk_update_detections(
        detection_ids=detection_ids,
        status=args.status,
        comment=args.comment,
        batch_size=args.batch_size
    )
    
    # Print results
    print("\n" + "="*60)
    print("BULK UPDATE COMPLETE")
    print("="*60)
    print(f"Total detections: {results['total']}")
    print(f"Successfully updated: {results['success']}")
    print(f"Failed: {results['failure']}")
    print("="*60)
    
    return 0 if results['failure'] == 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        sys.exit(1)
