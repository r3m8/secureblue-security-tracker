import argparse
import sys
from typing import List

from .updater import CVEUpdater
from .comparator import CVEComparator
from .storage import CVEStorage

def parse_years(year_str: str) -> List[int]:
    years_str = year_str.strip()
    if "-" in years_str:
        start_str, end_str = [p.strip() for p in years_str.split("-", 1)]
        start, end = int(start_str), int(end_str)
        if start > end:
            start, end = end, start
        return list(range(start, end + 1))
    if "," in years_str:
        return [int(y.strip()) for y in years_str.split(",") if y.strip()]
    return [int(years_str)]

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secureblue security tracker CLI"
    )
    parser.add_argument(
        "command",
        choices=["update", "compare", "report", "set-package-status"],
        help="Command to run",
    )
    parser.add_argument(
        "--year",
        type=str,
        default="2020-2025",
        help=(
            "CVE year to filter : single year (2024), range (2020-2025), "
            "or list (2023,2024,2025) (default : 2020-2025)"
        ),
    )
    parser.add_argument(
        "--output",
        default="index.html",
        help="Output file for reports (default : index.html)",
    )
    parser.add_argument(
        "package",
        nargs="?",
        help="Package name (required for set-package-status)",
    )
    parser.add_argument(
        "--status",
        choices=["open", "resolved", "not affected", "unverified"],
        help="Status for package (required for set-package-status)",
    )
    parser.add_argument(
        "--mitigated",
        action="store_true",
        help="Mark as mitigated (for set-package-status)",
    )
    parser.add_argument(
        "--comment",
        default="",
        help="Comment in HTML format (for set-package-status)",
    )

    args = parser.parse_args()

    if args.command == "update":
        updater = CVEUpdater()
        years = parse_years(args.year)
        updater.update_debian_cves(years)

    elif args.command == "compare":
        storage = CVEStorage()
        comparator = CVEComparator(storage)
        results = comparator.compare_all_cves()
        print(f"Found {len(results)} CVEs to compare")
        for result in results:
            print(f"Package : {result['package']}, CVE : {result['cve_id']}")

    elif args.command == "report":
        storage = CVEStorage()
        comparator = CVEComparator(storage)
        comparator.generate_json_data()
        comparator.generate_html_report(args.output)

    elif args.command == "set-package-status":
        if not args.package:
            print("Error : --package is required for set-package-status command")
            sys.exit(1)
        if not args.status:
            print("Error : --status is required for set-package-status command")
            sys.exit(1)

        storage = CVEStorage()
        storage.update_package_secureblue(
            args.package,
            args.status,
            args.mitigated,
            args.comment,
        )
        print(f"Updated package-level secureblue.json for {args.package}")
        print(f"  Status : {args.status}")
        print(f"  Mitigated : {args.mitigated}")
        if args.comment:
            preview = args.comment.replace("\n", " ")[:50]
            print(f"  Comment : {preview}...")

if __name__ == "__main__":
    main()