"""OSV Wrapper responsible for dealing with the agent output and constructing its information."""
import dataclasses
import json
import logging
import pathlib
from typing import Iterator, Any, Tuple, List, Dict
import re


from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import cve_service_api

CVE_MITRE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
RISK_RATING_MAPPING = {
    "POTENTIALLY": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}
CVE_PATTERN = r".*/(CVE-[0-9]+-[0-9]+)"

RISK_RATINGS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "POTENTIALLY"]

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating


@dataclasses.dataclass
class VulnData:
    package_name: str | None
    package_version: str | None
    risk: str
    description: str
    summary: str
    fixed_version: str | None
    cvss_v3_vector: str | None
    references: list[dict[str, str]]
    cves: list[str]
    file_type: str | None = None
    file_name: str | None = None


def read_output_file_as_dict(output_file_path: str) -> dict[str, Any]:
    """Read the OSV scanner output from json file and return dict
    Args:
        output_file_path: the OSV scanner output file
    returns:
        Dict representation of the json object
    """
    with open(output_file_path, "r", encoding="utf-8") as of:
        data: dict[str, Any] = json.load(of)

    return data


def build_references(references: list[dict[str, str]]) -> dict[str, str]:
    """Build references from the OSV output
    Args:
        references: references from OSV output
    Returns:
        references list as object with name, url as key-value.
    """
    references_list = {}
    for reference in references:
        references_list[reference.get("url", "")] = reference.get("url", "")
    return references_list


def parse_osv_output(output: str, api_key: str | None = None) -> list[VulnData]:
    """Parses JSON generated OSV results and yield vulnerability entries.
    Args:
        output: OSV json output file path.
    Yields:
        Vulnerability entry.
    """

    data = json.loads(output, strict=False)
    if data.get("results") is None:
        logger.info("Osv returns null result.")
        return []

    results: dict[Any, Any] = data.get("results", [])
    parsed_vulns = []
    for result in results:
        packages = result.get("packages", [{}])
        file_type = result.get("source", {}).get("type", "")
        file_name = pathlib.Path(result.get("source", {}).get("path", "")).name
        for package in packages:
            parsed_vulns.extend(
                parse_vulnerabilities(
                    output=package,
                    api_key=api_key,
                    file_type=file_type,
                    file_name=file_name,
                )
            )

    return parsed_vulns


def parse_vulnerabilities(
    output: dict[str, Any],
    package_name: str | None = None,
    package_version: str | None = None,
    api_key: str | None = None,
    file_type: str | None = None,
    file_name: str | None = None,
) -> list[VulnData]:
    """Parse the OSV API response to extract vulnerabilities.
    Args:
        output: The API response json.
        package_name: The package name.
        package_version: The package version.
        api_key: The NVD API key.
        file_type: The package file type.
        file_name: The package file name.
    Returns:
        Parsed output.
    """
    try:
        vulnerabilities = output.get("vulns") or output.get("vulnerabilities") or []
        package_name = output.get("package", {}).get("name") or package_name
        package_version = output.get("package", {}).get("version") or package_version
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
                risk = calculate_risk_rating(risk_ratings)
            elif risk == "MODERATE":
                risk = "MEDIUM"

            description = vulnerability.get("details", "")
            summary = vulnerability.get("summary", "")
            fixed_version = _get_fixed_version(vulnerability.get("affected"))
            cvss_v3_vector = _get_cvss_v3_vector(vulnerability.get("severity"))
            vuln = VulnData(
                package_name=package_name,
                package_version=package_version,
                risk=risk,
                description=description,
                summary=summary,
                fixed_version=fixed_version,
                cvss_v3_vector=cvss_v3_vector,
                references=vulnerability.get("references", {}),
                cves=filtered_cves,
                file_name=file_name,
                file_type=file_type,
            )
            parsed_vulns.append(vuln)

        return parsed_vulns

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON: {e}")
        return []


def _aggregate_cves(cve_ids: list[str], api_key: str | None = None) -> Tuple[str, str]:
    """Generate the description for the vulnerability from all the related CVEs."""
    risk_ratings = []
    cve_list_details = ""
    for cve_id in cve_ids:
        cve_list_details += f"- [{cve_id}]({CVE_MITRE_URL}{cve_id}) "
        cve_data = cve_service_api.get_cve_data_from_api(cve_id, api_key)
        if cve_data.description is not None and cve_data.description != "":
            cve_list_details += f": {cve_data.description}"
        if cve_data.fixed_version is not None and cve_data.fixed_version != "":
            cve_list_details += (
                f"The issue was fixed in version `{cve_data.fixed_version}`. \n "
            )
        risk_ratings.append(cve_data.risk)
    risk_rating = calculate_risk_rating(risk_ratings)
    return risk_rating, cve_list_details


def calculate_risk_rating(risk_ratings: list[str]) -> str:
    """Calculate the risk rating of a given cve ids of a vulnerability
    Args:
        risk_ratings: list of risk ratings
    Returns:
        Risk rating of a vulnerability
    """
    priority_levels = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "POTENTIALLY": 4}
    risk_ratings = [risk_rating.upper() for risk_rating in risk_ratings]
    sorted_ratings = sorted(
        risk_ratings, key=lambda x: priority_levels.get(x, 4), reverse=False
    )

    for rating in sorted_ratings:
        if rating in priority_levels:
            return rating
    return "POTENTIALLY"


def _extract_cve_reference_advisory(
    references: List[Dict[str, str]],
) -> str | List[str]:
    for reference in references:
        if reference["type"] == "ADVISORY":
            cve_match = re.match(CVE_PATTERN, reference["url"], re.IGNORECASE)
            if cve_match is not None:
                return [cve_match.group(1)]
    return ""


def _get_fixed_version(
    affected_data: list[dict[str, Any]] | None,
) -> str:
    fixed_version = ""
    if affected_data is None:
        return fixed_version

    ranges_data: list[dict[str, Any]] = affected_data[0].get("ranges", [])
    if len(ranges_data) > 0:
        events_data = ranges_data[0].get("events", [])
        if len(events_data) > 1:
            fixed_version = events_data[1].get("fixed", "")

    return fixed_version


def _get_cvss_v3_vector(severity_data: list[dict[str, str]]) -> str:
    if severity_data is not None and len(severity_data) > 0:
        return severity_data[0].get("score", "")

    return ""


def construct_vuln(parsed_vulns: list[VulnData]) -> Iterator[Vulnerability]:
    """Construct Vulneravilities from the parse output.
    Args:
        parsed_vulns: list of VulnData.
    Yields:
        Vulnerability entry.
    """
    for vuln in parsed_vulns:
        if vuln.fixed_version != "":
            recommendation = (
                f"We recommend updating `{vuln.package_name}` to a version greater than or equal to "
                f"`{vuln.fixed_version}`."
            )
        else:
            recommendation = f"We recommend updating `{vuln.package_name}` to the latest available version."

        if len(vuln.cves) == 0:
            if vuln.file_type is not None and vuln.file_name is not None:
                description = (
                    f"Dependency `{vuln.package_name}` with version `{vuln.package_version}`"
                    f" found in the `{vuln.file_type}` `{vuln.file_name}` "
                    f"has a security issue."
                )
            else:
                description = (
                    f"Dependency `{vuln.package_name}` with version `{vuln.package_version}`"
                    f"has a security issue."
                )
            title = f"Use of Outdated Vulnerable Component: {vuln.package_name}@{vuln.package_version}"
            technical_detail = f"```{vuln.description}```"
        else:
            title = f"Use of Outdated Vulnerable Component: {vuln.package_name}@{vuln.package_version}: {', '.join(vuln.cves)}"
            technical_detail = (
                f"```{vuln.description}``` \n#### CVEs:\n {', '.join(vuln.cves)}"
            )

            if vuln.file_type is not None and vuln.file_name is not None:
                description = (
                    f"Dependency `{vuln.package_name}` with version `{vuln.package_version}`"
                    f" found in the `{vuln.file_type}` `{vuln.file_name}` "
                    f"has a security issue.\nThe issue is identified by CVEs: `{', '.join(vuln.cves)}`."
                )
            else:
                description = (
                    f"Dependency `{vuln.package_name}` with version `{vuln.package_version}`"
                    f"has a security issue.\nThe issue is identified by CVEs: `{', '.join(vuln.cves)}`."
                )
        yield Vulnerability(
            entry=kb.Entry(
                title=title,
                risk_rating=vuln.risk,
                short_description=vuln.summary,
                description=description,
                references=build_references(vuln.references),
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False,
                recommendation=recommendation,
            ),
            technical_detail=technical_detail,
            risk_rating=agent_report_vulnerability_mixin.RiskRating[
                vuln.risk.upper()
                if vuln.risk.upper() in RISK_RATINGS
                else "POTENTIALLY"
            ],
        )
