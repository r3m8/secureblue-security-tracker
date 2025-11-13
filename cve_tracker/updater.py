from .downloader import CNVDDownloader
from .storage import CVEStorage

class CVEUpdater:
    def __init__(self, storage_path: str = "packages") -> None:
        self.downloader = CNVDDownloader()
        self.storage = CVEStorage(storage_path)

    def update_debian_cves(self, years: list[int] = [2025]) -> None:
        print("Fetching debian CVE data : start")
        all_debian_data = self.downloader.download_debian_cve()

        if not all_debian_data:
            print("No data downloaded !")
            return

        if isinstance(years, int):
            years = [years]

        total_cves = 0
        all_packages = set()

        for year in years:
            print(f"Filtering CVEs for year : {year}")
            filtered = self.downloader.filter_by_year(all_debian_data, year)

            year_cves = sum(len(cves) for cves in filtered.values())
            total_cves += year_cves
            all_packages.update(filtered.keys())

            print(f"Year : {year} - found {year_cves} CVEs across {len(filtered)} packages")
            print(f"Storing CVE data for : {year}")

            for package_name, package_cves in filtered.items():
                for cve_id, cve_info in package_cves.items():
                    self.storage.save_package_cve(package_name, cve_id, cve_info)

        print(f"Update complete : total {total_cves} CVEs across {len(all_packages)} packages")