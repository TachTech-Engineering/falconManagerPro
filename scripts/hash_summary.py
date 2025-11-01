#!/usr/bin/env python3
"""
SHA256 Hash Summary for New Detections

Quick script to analyze which hashes are involved in new detections.
"""

import sys
import argparse
from pathlib import Path
from collections import Counter
from datetime import datetime

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from falcon_utils import FalconClient


class TeeOutput:
    """Write to both stdout and a file"""
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.file = open(filename, 'w')

    def write(self, message):
        self.terminal.write(message)
        self.file.write(message)

    def flush(self):
        self.terminal.flush()
        self.file.flush()

    def close(self):
        self.file.close()


def main():
    parser = argparse.ArgumentParser(
        description='Analyze SHA256 hashes in detections',
        epilog='''
Examples:
  # Summary of new detections
  %(prog)s --filter 'status:"new"'

  # Summary of all detections
  %(prog)s --filter ''

  # Summary from specific host
  %(prog)s --filter 'device.hostname:"MSI"+status:"new"'
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--filter', default='status:"new"',
                       help='FQL filter (default: status:"new")')
    parser.add_argument('--limit', type=int, default=10000,
                       help='Max detections to analyze (default: 10000)')
    parser.add_argument('--output', '-o', metavar='FILE',
                       help='Output to both terminal and markdown file')

    args = parser.parse_args()

    # Setup output (terminal + file if specified)
    tee = None
    if args.output:
        tee = TeeOutput(args.output)
        sys.stdout = tee

    # Initialize client
    print("Initializing CrowdStrike Falcon client...")
    falcon = FalconClient()

    print('='*80)
    print('SHA256 HASH SUMMARY')
    print(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('='*80)

    # Get detections
    print(f'\nQuerying detections with filter: {args.filter}')
    ids = falcon.query_detections(filter_string=args.filter, limit=args.limit)
    print(f'Total detections found: {len(ids)}')

    if not ids:
        print('No detections found.')
        return 0

    # Get details
    print('Fetching details...\n')
    details = falcon.get_detection_details(ids)

    # Collect all hashes with counts
    hash_detections = Counter()

    for alert in details:
        sha256_list = alert.get('entities', {}).get('sha256', [])
        sha256_values = alert.get('entity_values', {}).get('sha256s', [])
        all_hashes = set(sha256_list + sha256_values)

        for hash_val in all_hashes:
            hash_detections[hash_val] += 1

    print('='*80)
    print(f'UNIQUE SHA256 HASHES: {len(hash_detections)}')
    print('='*80)

    if hash_detections:
        print(f'\n{"Hash":64s} | Count')
        print('-'*80)
        for hash_val, count in hash_detections.most_common():
            print(f'{hash_val:64s} | {count:5d}')
    else:
        print('\nNo SHA256 hashes found in these detections.')

    print('\n' + '='*80)
    print('SUMMARY')
    print('='*80)
    print(f'Total detections analyzed: {len(ids)}')
    print(f'Detections with SHA256 hashes: {sum(hash_detections.values())}')
    print(f'Unique SHA256 hashes: {len(hash_detections)}')
    if hash_detections:
        top_hash, top_count = hash_detections.most_common(1)[0]
        print(f'Most common hash: {top_count} detections')
        print(f'  {top_hash}')
    print('='*80)

    # Cleanup
    if tee:
        sys.stdout = tee.terminal
        tee.close()
        print(f"\n✓ Results saved to: {args.output}")

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nCancelled (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        sys.exit(1)
