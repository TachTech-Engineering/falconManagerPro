#!/usr/bin/env python3
"""
Query CrowdStrike Detections

Search and display detection information from CrowdStrike Falcon.
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
        description='Query CrowdStrike Falcon detections',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Query new detections
  %(prog)s --filter 'status:"new"' --limit 10

  # Query by specific hash
  %(prog)s --hash "0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bcc6f01b9"

  # Query high severity detections from last 24 hours
  %(prog)s --filter 'max_severity_displayname:"High"+first_behavior:>"now-24h"'

  # Test API connection
  %(prog)s --test-connection
        """
    )
    
    parser.add_argument(
        '--filter',
        help='FQL filter string to match detections'
    )
    
    parser.add_argument(
        '--hash',
        help='SHA256 hash to search for in detections'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum number of detections to return (default: 100, max: 10000)'
    )
    
    parser.add_argument(
        '--offset',
        type=int,
        default=0,
        help='Starting offset for pagination (default: 0)'
    )
    
    parser.add_argument(
        '--details',
        action='store_true',
        help='Fetch and display detailed information'
    )
    
    parser.add_argument(
        '--count-only',
        action='store_true',
        help='Only display count of matching detections'
    )
    
    parser.add_argument(
        '--test-connection',
        action='store_true',
        help='Test API connection and exit'
    )
    
    return parser.parse_args()


def main():
    """Main execution function"""
    args = parse_args()
    
    # Initialize Falcon client
    print("Initializing CrowdStrike Falcon client...")
    falcon = FalconClient()
    
    # Test connection if requested
    if args.test_connection:
        sys.exit(0 if falcon.test_connection() else 1)
    
    # Build filter string
    if args.hash:
        # Search for hash in both XDR and ODS detections
        print(f"\nSearching for alerts with SHA256: {args.hash}")

        # Try XDR detections first (entities.sha256)
        filter_string_xdr = f'entities.sha256:"{args.hash}"'
        detection_ids_xdr = falcon.query_detections(
            filter_string=filter_string_xdr,
            limit=args.limit,
            offset=args.offset
        )

        # Try ODS detections (sha256)
        filter_string_ods = f'sha256:"{args.hash}"'
        detection_ids_ods = falcon.query_detections(
            filter_string=filter_string_ods,
            limit=args.limit,
            offset=args.offset
        )

        # Combine results (remove duplicates)
        detection_ids = list(set(detection_ids_xdr + detection_ids_ods))
        print(f"  XDR detections: {len(detection_ids_xdr)}")
        print(f"  ODS detections: {len(detection_ids_ods)}")
    elif args.filter:
        filter_string = args.filter
        print(f"\nQuerying detections with filter: {filter_string}")

        # Query detections
        detection_ids = falcon.query_detections(
            filter_string=filter_string,
            limit=args.limit,
            offset=args.offset
        )
    else:
        print("ERROR: Must specify either --filter or --hash")
        return 1
    
    if not detection_ids:
        print("No detections found matching criteria.")
        return 0
    
    print(f"Found {len(detection_ids)} detection(s).")
    
    # Count-only mode
    if args.count_only:
        return 0
    
    # Display detection IDs
    if not args.details:
        print("\nDetection IDs:")
        for det_id in detection_ids:
            print(f"  {det_id}")
        return 0
    
    # Fetch and display details
    print("\nFetching detection details...")
    details = falcon.get_detection_details(detection_ids)
    format_detection_summary(details)
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        sys.exit(1)
