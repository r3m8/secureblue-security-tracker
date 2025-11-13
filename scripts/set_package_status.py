#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cve_tracker.storage import CVEStorage

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize or update package-level secureblue.json (overrides ALL CVEs in package)"
    )
    parser.add_argument("package", help="Package name")
    parser.add_argument(
        "--status",
        default="unverified",
        choices=["open", "resolved", "not affected", "unverified"],
        help="Status to apply to all CVEs in this package",
    )
    parser.add_argument("--mitigated", action="store_true", help="Mark as mitigated")
    parser.add_argument(
        "--comment",
        default="",
        help="Comment in HTML format explaining the package-level status",
    )
    return parser.parse_args()

def run(package: str, status: str, mitigated: bool, comment: str) -> None:
    storage = CVEStorage()
    storage.update_package_secureblue(package, status, mitigated, comment)

    print(f"Created/updated package-level secureblue.json for {package}")
    print(f"  Status : {status}")
    print(f"  Mitigated : {mitigated}")
    if comment:
        print(f"  Comment : {comment[:60]}...")
    print(f"  Location : packages/{package}/secureblue.json")

def main() -> None:
    args = parse_args()
    try:
        run(args.package, args.status, args.mitigated, args.comment)
    except Exception as exc:
        print(f"Error : {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()