import json
import re
from typing import Dict
import urllib.error
import urllib.request

class CNVDDownloader:
    @staticmethod
    def download_debian_cve(url: str = "https://security-tracker.debian.org/tracker/data/json") -> Dict:
        try:
            print(f"Downloading debian CVE data from : {url}")
            with urllib.request.urlopen(url) as response:
                data = response.read()
                return json.loads(data)
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            print(f"Error downloading debian data : {e}")
            return {}

    @staticmethod
    def filter_by_year(cve_data: Dict, year: int) -> Dict:
        pattern = re.compile(rf"CVE-{year}-\d+")
        filtered: Dict = {}

        for package_name, package_cves in cve_data.items():
            cves_for_year = {
                cve_id: info
                for cve_id, info in package_cves.items()
                if pattern.match(cve_id)
            }
            if cves_for_year:
                filtered[package_name] = cves_for_year

        return filtered