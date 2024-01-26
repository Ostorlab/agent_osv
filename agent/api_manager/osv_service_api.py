import dataclasses
import json
import logging
from typing import Optional, Iterator

import requests
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import cve_service_api
from agent import osv_output_handler

logger = logging.getLogger(__name__)

OSV_ENDPOINT = "https://api.osv.dev/v1/query"

RISK_RATING_MAPPING = {
    "POTENTIALLY": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "MODERATE": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
    "CRITICAL": agent_report_vulnerability_mixin.RiskRating.CRITICAL,
}


@dataclasses.dataclass
class VulnData:
    risk: str
    description: str
    summary: str
    fixed_version: str | None
    cvss_v3_vector: str | None
    references: list[dict[str, str]]
    cves: list[str]


def query_osv_api(
    package_name: str | None, version: str | None, ecosystem: str | None
) -> Optional[str]:
    """Query the OSv API with the specified version, package name, and ecosystem.
    Args:
        version: The version to query.
        package_name: The name of the package to query.
        ecosystem: The ecosystem of the package e.g., javascript.
    Returns:
        The API response text if successful, None otherwise.
    """
    if version is None:
        logger.error("Error: Version must not be None.")
        return None
    if package_name is None:
        logger.error("Error: Package name must not be None.")
        return None

    data = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(OSV_ENDPOINT, data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        return response.text
    else:
        logger.error(f"Error: Request failed with status code {response.status_code}")
        return None


def parse_output(
    api_response: Optional[str], api_key: str | None = None
) -> list[VulnData]:
    """Parse the OSv API response to extract vulnerabilities.
    Args:
        api_response: The API response text.
    Returns:
        Parsed output.
    """
    if api_response is None:
        logger.error("Error: API response must not be None.")
        return []

    try:
        response_data = json.loads(api_response)
        vulnerabilities = response_data.get("vulns", [])

        parsed_vulns = []
        for vulnerability in vulnerabilities:
            risk = vulnerability.get("database_specific", {}).get("severity")
            filtered_cves = [
                alias for alias in vulnerability.get("aliases", []) if "CVE" in alias
            ]
            if risk is None:
                risk_ratings = []
                for cve in filtered_cves:
                    cve_data = cve_service_api.get_cve_data_from_api(cve, api_key)
                    risk_ratings.append(cve_data.risk)
                risk = osv_output_handler.calculate_risk_rating(risk_ratings)
            elif risk == "MODERATE":
                risk = "MEDIUM"

            description = vulnerability.get("details", "")
            summary = vulnerability.get("summary", "")
            fixed_version = _get_fixed_version(vulnerability.get("affected"))
            cvss_v3_vector = _get_cvss_v3_vector(vulnerability.get("severity"))
            references = []
            for reference in vulnerability.get("references"):
                references.append(reference.get("url"))
            vuln = VulnData(
                risk=risk,
                description=description,
                summary=summary,
                fixed_version=fixed_version,
                cvss_v3_vector=cvss_v3_vector,
                references=vulnerability.get("references"),
                cves=filtered_cves,
            )
            parsed_vulns.append(vuln)

        return parsed_vulns

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON: {e}")
        return []


def construct_vuln(
    parsed_vulns: list[VulnData], package_name: str | None, package_version: str | None
) -> Iterator[osv_output_handler.Vulnerability]:
    """Construct Vulneravilities from the parse output.
    Args:
        parsed_vulns: list of VulnData.
        package_name: The package name.
        package_version: The package version.
    Yields:
        Vulnerability entry.
    """
    for vuln in parsed_vulns:
        description = (
            f"Dependency `{package_name}` with version `{package_version}`"
            f"has a security issue.\nThe issue is identified by CVEs: `{', '.join(vuln.cves)}`."
        )
        recommendation = (
            f"We recommend updating `{package_name}` to the latest available version."
        )
        yield osv_output_handler.Vulnerability(
            entry=kb.Entry(
                title=f"Use of Outdated Vulnerable Component: "
                f"{package_name}@{package_version}: {', '.join(vuln.cves)}",
                risk_rating=vuln.risk,
                short_description=vuln.summary,
                description=description,
                references=osv_output_handler.build_references(vuln.references),
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False,
                recommendation=recommendation,
            ),
            technical_detail=f"{vuln.description} \n#### CVEs:\n {', '.join(vuln.cves)}",
            risk_rating=RISK_RATING_MAPPING[vuln.risk],
        )


def _get_fixed_version(
    affected_data: list[dict[str, list[dict[str, list[dict[str, str]]]]]],
) -> str:
    fixed_version = ""
    if affected_data is not None:
        try:
            ranges_data: list[dict[str, list[dict[str, str]]]] = affected_data[0].get(
                "ranges", []
            )
            if ranges_data:
                events_data = ranges_data[0].get("events", [])
                if len(events_data) > 1:
                    fixed_version = events_data[1].get("fixed", "")
        except IndexError:
            logger.warning("Can't get the fixed version.")

    return fixed_version


def _get_cvss_v3_vector(severity_data: list[dict[str, str]]) -> str:
    cvss_v3_vector = ""
    if severity_data:
        try:
            cvss_data = severity_data[0].get("score", "")
            cvss_v3_vector = cvss_data if isinstance(cvss_data, str) else ""
        except IndexError:
            logger.warning("Can't get the cvss v3 vector.")
    return cvss_v3_vector
