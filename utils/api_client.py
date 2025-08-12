import requests

class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    
    def check_cve(self, software_name: str):
        response = requests.get(f"{self.BASE_URL}?keyword={software_name}")
        return response.json() if response.status_code == 200 else None