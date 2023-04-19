"""module responsible for retrieving the risk rating of a vulnerability"""
import requests
import json

CVE_MITRE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
REQUEST_TIMEOUT = 10


def get_cve_risk_rating(cve_id: str) -> str | None:
    """Given a CVE ID, retrieve the risk rating from the MITRE CVE API.
    Args:
        cve_id
    Returns:
        None if the CVE ID is not found.
    """
    url = f"{CVE_MITRE_BASE_URL}{cve_id}"

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()  # raises a HTTPError if response code is not 2XX
        data = json.loads(response.text)

        risk: str | None = data["result"]["CVE_Items"][0]["impact"]["baseMetricV3"][
            "cvssV3"
        ]["baseSeverity"]
        return risk

    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return None
