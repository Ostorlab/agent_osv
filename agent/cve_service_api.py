"""module responsible for retrieving the risk rating of a vulnerability"""
import dataclasses

import requests
import json

CVE_MITRE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
REQUEST_TIMEOUT = 60


@dataclasses.dataclass
class CVE:
    risk: str
    description: str
    cvss_v3_vector: str | None


def get_cve_data_from_api(cve_id: str) -> CVE:
    """Given a CVE ID, retrieve the risk rating from the MITRE CVE API.
    Args:
        cve_id: the cve id to obtain its details
    Returns:
        CVE object.
    """
    url = f"{CVE_MITRE_BASE_URL}{cve_id}"

    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()  # raises a HTTPError if response code is not 2XX
    data = json.loads(response.text)

    return CVE(
        risk=data.get("result", {})
        .get("CVE_Items", {})[0]
        .get("impact", {})
        .get("baseMetricV3", {})
        .get("cvssV3", {})
        .get("baseSeverity"),
        description=data.get("result", {})
        .get("CVE_Items", [{}])[0]
        .get("cve", {})
        .get("description", {})
        .get("description_data", [{}])[0]
        .get("value"),
        cvss_v3_vector=data.get("result", {})
        .get("CVE_Items", [{}])[0]
        .get("impact", {})
        .get("baseMetricV3", {})
        .get("cvssV3", {})
        .get("vectorString"),
    )
