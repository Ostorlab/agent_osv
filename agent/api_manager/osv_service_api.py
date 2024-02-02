"""This module provides utility functions to query the OSV API for vulnerability information
related to a specific package version."""
import dataclasses
import json
import logging
from typing import Iterator, Any

import requests
import tenacity
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import cve_service_api
from agent import osv_output_handler

logger = logging.getLogger(__name__)

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
NUMBER_RETRIES = 3
WAIT_BETWEEN_RETRIES = 2


@dataclasses.dataclass
class VulnData:
    risk: str
    description: str
    summary: str
    fixed_version: str | None
    cvss_v3_vector: str | None
    references: list[dict[str, str]]
    cves: list[str]


@tenacity.retry(
    stop=tenacity.stop_after_attempt(NUMBER_RETRIES),
    wait=tenacity.wait_fixed(WAIT_BETWEEN_RETRIES),
    retry=tenacity.retry_if_exception_type(),
    retry_error_callback=lambda retry_state: retry_state.outcome.result()
    if retry_state.outcome is not None
    else None,
)
def query_osv_api(
    package_name: str, version: str, ecosystem: str | None = None
) -> dict[str, Any] | None:
    """Query the OSV API with the specified version, package name, and ecosystem.
    Args:
        version: The version to query.
        package_name: The name of the package to query.
        ecosystem: The ecosystem of the package e.g., javascript.
    Returns:
        The API response text if successful, None otherwise.
    """
    if ecosystem is not None:
        data = {
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem},
        }
    else:
        data = {
            "version": version,
            "package": {"name": package_name},
        }

    response = requests.post(OSV_ENDPOINT, json=data)

    if response.status_code == 200:
        resp: dict[str, Any] = response.json()
        return resp

    return None


def parse_output(
    api_response: dict[str, Any], api_key: str | None = None
) -> list[VulnData]:
    """Parse the OSV API response to extract vulnerabilities.
    Args:
        api_response: The API response json.
        api_key: The API key.
    Returns:
        Parsed output.
    """
    try:
        vulnerabilities = api_response.get("vulns", [])

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
            vuln = VulnData(
                risk=risk,
                description=description,
                summary=summary,
                fixed_version=fixed_version,
                cvss_v3_vector=cvss_v3_vector,
                references=vulnerability.get("references", {}),
                cves=filtered_cves,
            )
            parsed_vulns.append(vuln)

        return parsed_vulns

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON: {e}")
        return []


def construct_vuln(
    parsed_vulns: list[VulnData], package_name: str, package_version: str
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
            f"Dependency `{package_name}` with version `{vuln.fixed_version}`"
            f"has a security issue.\nThe issue is identified by CVEs: `{', '.join(vuln.cves)}`."
        )
        recommendation = (
            f"We recommend updating `{package_name}` to the latest available version."
        )
        yield osv_output_handler.Vulnerability(
            entry=kb.Entry(
                title=f"Use of Outdated Vulnerable Component: "
                f"{package_name}@{vuln.fixed_version}: {', '.join(vuln.cves)}",
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
            risk_rating=agent_report_vulnerability_mixin.RiskRating[vuln.risk.upper()],
        )


def _get_fixed_version(
    affected_data: list[dict[str, Any]],
) -> str:
    fixed_version = ""
    if affected_data is not None:
        ranges_data: list[dict[str, Any]] = affected_data[0].get("ranges", [])
        if ranges_data is not None and len(ranges_data) > 0:
            events_data = ranges_data[0].get("events", [])
            if len(events_data) > 1:
                fixed_version = events_data[1].get("fixed", "")

    return fixed_version


def _get_cvss_v3_vector(severity_data: list[dict[str, str]]) -> str:
    if severity_data is not None and len(severity_data) > 0:
        return severity_data[0].get("score", "")

    return ""
