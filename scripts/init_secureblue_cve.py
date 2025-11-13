#!/usr/bin/env python3
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from cve_tracker.storage import CVEStorage

def main():
    parser = argparse.ArgumentParser(description='Initialize or update secureblue CVE data')
    parser.add_argument('package', help='Package name')
    parser.add_argument('cve_id', help='CVE ID (e.g., CVE-2024-39134)')
    parser.add_argument('--status', default='unverified', choices=['open', 'resolved', 'not affected', 'unverified'])
    parser.add_argument('--mitigated', action='store_true', help='Mark as mitigated')
    parser.add_argument('--comment', default='', help='Comment in HTML format')

    args = parser.parse_args()

    storage = CVEStorage()

    debian_data = storage.load_debian_cve(args.package, args.cve_id)
    if not debian_data:
        print(f'Error : debian.json not found for {args.package}/{args.cve_id}')
        print("Make sure to run 'python -m cve_tracker.cli update' first")
        sys.exit(1)

    storage.update_secureblue_cve(args.package, args.cve_id, args.status, args.mitigated, args.comment)
    print(f'Updated secureblue.json for {args.package}/{args.cve_id}')
    print(f'  Status : {args.status}')
    print(f'  Mitigated : {args.mitigated}')
    if args.comment:
        print(f'  Comment : {args.comment[:50]}...')

if __name__ == '__main__':
    main()