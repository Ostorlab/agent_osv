"""module responsible for retrieving the risk rating of a vulnerability"""

import requests
import json

CVE_MITRE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"


def get_cve_risk_rating(cve_id: str) -> str | None:
    """
    Given a CVE ID, retrieve the risk rating from the MITRE CVE API.
    Returns None if the CVE ID is not found.
    """
    url = f"{CVE_MITRE_BASE_URL}{cve_id}"
    response = requests.get(url)
    data = json.loads(response.text)
    if "error" in data:
        return None
    risk = data["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"][
        "baseSeverity"
    ]
    return risk
