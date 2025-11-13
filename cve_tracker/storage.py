import json
import os
from typing import Any, Dict, Optional

class CVEStorage:
    def __init__(self, base_path: str = "packages"):
        self.base_path = base_path
        os.makedirs(self.base_path, exist_ok=True)

    def _pkg_dir(self, package_name: str) -> str:
        return os.path.join(self.base_path, package_name)

    def _cve_dir(self, package_name: str, cve_id: str) -> str:
        return os.path.join(self._pkg_dir(package_name), cve_id)

    def _read_json(self, file_path: str) -> Optional[Dict[str, Any]]:
        if not os.path.exists(file_path):
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write_json(self, file_path: str, data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_package_cve(self, package_name: str, cve_id: str, debian_data: Dict[str, Any]) -> None:
        package_dir = self._cve_dir(package_name, cve_id)
        os.makedirs(package_dir, exist_ok=True)
        debian_file = os.path.join(package_dir, "debian.json")
        self._write_json(debian_file, debian_data)

    def load_debian_cve(self, package_name: str, cve_id: str) -> Optional[Dict[str, Any]]:
        file_path = os.path.join(self._cve_dir(package_name, cve_id), "debian.json")
        return self._read_json(file_path)

    def load_package_secureblue(self, package_name: str) -> Optional[Dict[str, Any]]:
        file_path = os.path.join(self._pkg_dir(package_name), "secureblue.json")
        return self._read_json(file_path)

    def load_secureblue_cve(self, package_name: str, cve_id: str) -> Optional[Dict[str, Any]]:
        file_path = os.path.join(self._cve_dir(package_name, cve_id), "secureblue.json")
        return self._read_json(file_path)

    def update_package_secureblue(self, package_name: str, status: str, mitigated: bool, comment: str) -> None:
        file_path = os.path.join(self._pkg_dir(package_name), "secureblue.json")
        data = {
            "ALL": {
                "releases": {
                    "stream": {
                        "status": status,
                        "mitigated": mitigated,
                        "comment": comment,
                    }
                }
            }
        }
        self._write_json(file_path, data)

    def update_secureblue_cve(self, package_name: str, cve_id: str, status: str, mitigated: bool, comment: str) -> None:
        file_path = os.path.join(self._cve_dir(package_name, cve_id), "secureblue.json")
        data = self._read_json(file_path)
        if data is None:
            return
        if (
            cve_id in data
            and "releases" in data[cve_id]
            and "stream" in data[cve_id]["releases"]
        ):
            data[cve_id]["releases"]["stream"]["status"] = status
            data[cve_id]["releases"]["stream"]["mitigated"] = mitigated
            data[cve_id]["releases"]["stream"]["comment"] = comment
        self._write_json(file_path, data)