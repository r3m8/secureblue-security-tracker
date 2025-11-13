# Secureblue security tracker

Tracks Secureblue CVEs based on Debian with community-contributed status annotations. Automatic update every hour with Github Actions.

This project is NOT official and NOT affiliated to Secureblue. Please report real issues [here](https://github.com/secureblue/secureblue/issues).

## Architecture

**Storage hierarchy (priority order)**:
1. `packages/{package}/secureblue.json` - Package level override (applies to ALL CVEs)
2. `packages/{package}/{CVE}/secureblue.json` - CVE-specific override
3. Default - `status=unverified`, `mitigated=false` (no file created)

**Files never auto-created** : only `debian.json` is auto-generated during CVE updates.

## Project structure

```
packages/                      # CVE storage (31,000+ entries)
└── {package-name}/
    ├── secureblue.json        # Optional : Package level status
    └── {CVE-ID}/
        ├── debian.json        # Automatically generated from Debian
        └── secureblue.json    # Optional : CVE-specific status

data.json                      # Generated : All CVE data (gziped by CVE ID numerical order)
index.html                     # Generated : Static HTML report
```

### packages/{package-name}/secureblue.json

```json
{
  "CVE-2025-1234": {
    "releases": {
      "stream": {
        "status": "open|resolved|not affected|unverified",
        "mitigated": true|false,
        "comment": "HTML explanation, can contain href"
      }
    }
  }
}
```

### packages/{package-name}/{CVE-ID}/secureblue.json

```json
{
  "ALL": {
    "releases": {
      "stream": {
        "status": "not affected",
        "mitigated": false,
        "comment": "Secureblue use sandboxing with flatpak, excluding this issue."
      }
    }
  }
}
```

## Commands

### cli.py

```bash
usage: cli.py [-h] [--year YEAR] [--output OUTPUT] [--status {open,resolved,not affected,unverified}] [--mitigated] [--comment COMMENT] {update,compare,report,set-package-status} [package]

Secureblue security tracker CLI

positional arguments:
  {update,compare,report,set-package-status}
                        Command to run
  package               Package name (required for set-package-status)

options:
  -h, --help            show this help message and exit
  --year YEAR           CVE year to filter : single year (2024), range (2020-2025), or list (2023,2024,2025) (default : 2020-2025)
  --output OUTPUT       Output file for reports (default : index.html)
  --status {open,resolved,not affected,unverified}
                        Status for package (required for set-package-status)
  --mitigated           Mark as mitigated (for set-package-status)
  --comment COMMENT     Comment in HTML format (for set-package-status)
```

### run.sh

```bash
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
```

## Contributing

**For single CVE analysis :**
1. Navigate to `packages/{package}/{CVE-ID}/`
2. Create/edit `secureblue.json` with status, mitigated flag, and comment

**For entire package (e.g., package not in Secureblue) :**
1. Navigate to `packages/{package}/`
2. Create `secureblue.json` with `"ALL"` key (see schema above)