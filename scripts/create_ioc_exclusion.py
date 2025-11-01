#!/usr/bin/env python3
"""
Create CrowdStrike IOC Exclusions

Create hash-based exclusions to prevent future false positive detections.
"""

import sys
import argparse
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from falcon_utils import FalconClient


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Create CrowdStrike IOC exclusions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create SHA256 exclusion applied globally
  %(prog)s --hash "0740b4a681b320f966b57f51c87c11f897e8605064b6aee2d03e177bcc6f01b9" \\
           --description "Internal monitoring tool" \\
           --applied-globally

  # Create MD5 exclusion for specific host groups
  %(prog)s --hash "5d41402abc4b2a76b9719d911017c592" \\
           --type md5 \\
           --description "Legacy backup utility" \\
           --host-groups "Servers,Workstations"
        """
    )
    
    parser.add_argument(
        '--hash',
        required=True,
        help='Hash value to exclude'
    )
    
    parser.add_argument(
        '--type',
        default='sha256',
        choices=['sha256', 'sha1', 'md5'],
        help='Hash type (default: sha256)'
    )
    
    parser.add_argument(
        '--description',
        required=True,
        help='Description of why this exclusion is needed'
    )
    
    parser.add_argument(
        '--applied-globally',
        action='store_true',
        help='Apply exclusion to all hosts'
    )
    
    parser.add_argument(
        '--host-groups',
        help='Comma-separated list of host group names to apply exclusion to'
    )
    
    parser.add_argument(
        '--severity',
        default='informational',
        choices=['informational', 'low', 'medium', 'high', 'critical'],
        help='Severity level if detected (default: informational)'
    )
    
    parser.add_argument(
        '--test-connection',
        action='store_true',
        help='Test API connection and exit'
    )
    
    return parser.parse_args()


def create_exclusion(falcon: FalconClient, args) -> bool:
    """
    Create IOC exclusion
    
    Args:
        falcon: FalconClient instance
        args: Parsed command line arguments
        
    Returns:
        True if successful
    """
    print(f"\nCreating {args.type.upper()} exclusion...")
    print(f"Hash: {args.hash}")
    print(f"Description: {args.description}")
    
    try:
        # Prepare IOC indicator body
        indicator_body = {
            'indicators': [{
                'type': args.type,
                'value': args.hash,
                'policy': 'none',  # 'none' means allow/exclude
                'description': args.description,
                'severity': args.severity,
                'applied_globally': args.applied_globally
            }]
        }
        
        # Add host groups if specified
        if args.host_groups and not args.applied_globally:
            groups = [g.strip() for g in args.host_groups.split(',')]
            indicator_body['indicators'][0]['host_groups'] = groups
            print(f"Host groups: {', '.join(groups)}")
        
        # Create the indicator
        response = falcon.ioc.indicator_create(body=indicator_body)
        
        if response['status_code'] == 201:
            print("\n✓ Exclusion created successfully!")
            
            # Display created indicator details
            if 'resources' in response['body']:
                for resource in response['body']['resources']:
                    print(f"\nIndicator ID: {resource.get('id', 'N/A')}")
                    print(f"Type: {resource.get('type', 'N/A')}")
                    print(f"Value: {resource.get('value', 'N/A')}")
                    print(f"Applied globally: {resource.get('applied_globally', False)}")
            
            return True
        else:
            print(f"\n✗ Failed to create exclusion:")
            print(f"Status: {response['status_code']}")
            print(f"Errors: {response['body'].get('errors', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"\n✗ Error creating exclusion: {str(e)}")
        return False


def main():
    """Main execution function"""
    args = parse_args()
    
    # Initialize Falcon client
    print("Initializing CrowdStrike Falcon client...")
    falcon = FalconClient()
    
    # Test connection if requested
    if args.test_connection:
        sys.exit(0 if falcon.test_connection() else 1)
    
    # Validate arguments
    if not args.applied_globally and not args.host_groups:
        print("ERROR: Must specify either --applied-globally or --host-groups")
        return 1
    
    # Confirm action
    print("\n" + "="*60)
    print("CONFIRMATION REQUIRED")
    print("="*60)
    print(f"Creating IOC exclusion will PREVENT future detections")
    print(f"Hash: {args.hash}")
    print(f"Type: {args.type}")
    print(f"Scope: {'Global (all hosts)' if args.applied_globally else args.host_groups}")
    print("="*60)
    
    response = input("\nProceed with creating exclusion? (yes/no): ").strip().lower()
    if response != 'yes':
        print("\nOperation cancelled by user.")
        return 0
    
    # Create exclusion
    success = create_exclusion(falcon, args)
    
    return 0 if success else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user (Ctrl+C)")
        sys.exit(130)
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        sys.exit(1)
