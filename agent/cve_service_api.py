"""module responsible for retrieving the risk rating of a vulnerability"""

import dataclasses
import json

import requests
import tenacity
from tenacity import stop
from tenacity import wait


CVE_MITRE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
REQUEST_TIMEOUT = 60


@dataclasses.dataclass
class CVE:
    risk: str
    description: str
    fixed_version: str | None
    cvss_v3_vector: str | None


default_cve = CVE(
    risk="POTENTIALLY", description="", fixed_version="", cvss_v3_vector=""
)


@tenacity.retry(
    stop=stop.stop_after_attempt(10),
    # wait for 30 seconds before retrying
    wait=wait.wait_fixed(30),
    retry=tenacity.retry_if_exception_type(
        (requests.ConnectionError, requests.HTTPError, json.JSONDecodeError)
    ),
    retry_error_callback=lambda retry_state: default_cve,
)
def get_cve_data_from_api(cve_id: str, api_key: str | None = None) -> CVE:
    """Given a CVE ID, retrieve the risk rating from the MITRE CVE API.
    Args:
        cve_id: the cve id to obtain its details
    Returns:
        CVE object.
    """
    url = f"{CVE_MITRE_BASE_URL}{cve_id}"
    headers = {
        "Content-Type": "application/json",
    }
    if api_key is not None:
        headers["apiKey"] = api_key
    response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    data = json.loads(response.text)
    cve_items = data.get("vulnerabilities", {})
    if len(cve_items) > 0:
        first_cve_item = cve_items[0]
        try:
            fixed_version = (
                first_cve_item.get("cve", {})
                .get("configurations", [{}])[0]
                .get("nodes", [{}])[0]
                .get("cpeMatch", [{}])[-1]
                .get("versionEndExcluding", "")
            )
        except IndexError:
            fixed_version = ""
        try:
            descriptions = first_cve_item.get("cve", {}).get("descriptions")
            description = next(
                item["value"] for item in descriptions if item["lang"] == "en"
            )
        except IndexError:
            description = ""

        risk = (
            first_cve_item.get("cve", {})
            .get("metrics", {})
            .get("cvssMetricV31", [{}])[0]
            .get("cvssData", {})
            .get("baseSeverity", "")
        )
        cvss_v3_vector = (
            first_cve_item.get("cve", {})
            .get("metrics", {})
            .get("cvssMetricV31", [{}])[0]
            .get("cvssData", {})
            .get("vectorString", "")
        )
        return CVE(
            risk=risk,
            description=description,
            fixed_version=fixed_version,
            cvss_v3_vector=cvss_v3_vector,
        )
    return default_cve
