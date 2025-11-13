#!/bin/bash
set -e

case "${1:-help}" in
  update)
    python3 -m cve_tracker.cli update "$@"
    ;;
  compare)
    python3 -m cve_tracker.cli compare "$@"
    ;;
  report)
    python3 -m cve_tracker.cli report "$@"
    ;;
  package-status)
    python3 -m cve_tracker.cli set-package-status "$@"
    ;;
  cve-status)
    python3 scripts/init_secureblue_cve.py "$@"
    ;;
  full)
    echo "Update CVEs and generate report"
    echo "Step 1/2 : Downloading CVEs ..."
    python3 -m cve_tracker.cli update --year 2020-2025
    echo "Step 2/2 : Generating report ..."
    python3 -m cve_tracker.cli report
    echo "Full update complete"
    ;;
  *)
    cat <<'EOF'
Secureblue security tracker management script

Usage : ./scripts/run.sh COMMAND [OPTIONS]

Commands :
  update [year]      Download CVEs from debian (default year : 2020-2025)
  compare            Show all CVEs in packages/
  report             Generate index.html + data.json
  package-status     Set status for all CVEs in a package
  cve-status         Set status for a specific CVE
  full               Update CVEs + regenerate report

Examples :
  ./scripts/run.sh update --year 2024
  ./scripts/run.sh package-status asterisk --status "not affected"
  ./scripts/run.sh cve-status apache2 CVE-2025-1234 --status open --mitigated
  ./scripts/run.sh full
EOF
    ;;
esac