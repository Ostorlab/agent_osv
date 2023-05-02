"""module responsible for retrieving the risk rating of a vulnerability"""
import dataclasses

import requests
import json
import tenacity

CVE_MITRE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
REQUEST_TIMEOUT = 60


@dataclasses.dataclass
class CVE:
    risk: str
    description: str
    fixed_version: str | None
    cvss_v3_vector: str | None


default_cve = CVE(risk="UNKNOWN", description="", fixed_version="", cvss_v3_vector="")


@tenacity.retry(
    stop=tenacity.stop_after_attempt(3),
    retry=tenacity.retry_if_exception_type(
        (requests.ConnectionError, requests.HTTPError)
    ),
    retry_error_callback=lambda retry_state: default_cve,
)
def get_cve_data_from_api(cve_id: str) -> CVE:
    """Given a CVE ID, retrieve the risk rating from the MITRE CVE API.
    Args:
        cve_id: the cve id to obtain its details
    Returns:
        CVE object.
    """
    url = f"{CVE_MITRE_BASE_URL}{cve_id}"

    response = requests.get(url, timeout=REQUEST_TIMEOUT)
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
        fixed_version=data.get("result", {})
        .get("CVE_Items", [{}])[0]
        .get("configurations", {})
        .get("nodes", [{}])[0]
        .get("cpe_match", [{}])[-1]
        .get("versionEndExcluding", ""),
        cvss_v3_vector=data.get("result", {})
        .get("CVE_Items", [{}])[0]
        .get("impact", {})
        .get("baseMetricV3", {})
        .get("cvssV3", {})
        .get("vectorString"),
    )
