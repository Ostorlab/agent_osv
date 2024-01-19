"""OSV Wrapper responsible for dealing with the agent output and constructing its information."""
import dataclasses
import json
import logging
import pathlib
from typing import Iterator, Any, Tuple, List, Dict
import re


from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging

from agent import cve_service_api

CVE_MITRE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
RISK_RATING_MAPPING = {
    "POTENTIALLY": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}
CVE_PATTERN = r".*/(CVE-[0-9]+-[0-9]+)"

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating


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


def _build_references(references: list[dict[str, str]]) -> dict[str, str]:
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


def parse_results(output: str, api_key: str | None = None) -> Iterator[Vulnerability]:
    """Parses JSON generated OSV results and yield vulnerability entries.
    Args:
        output: OSV json output file path.
    Yields:
        Vulnerability entry.
    """

    data = json.loads(output, strict=False)
    if data.get("results") is None:
        logger.info("Osv returns null result.")
        return

    results: dict[Any, Any] = data.get("results", [])
    for result in results:
        packages = result.get("packages", [{}])
        file_type = result.get("source", {}).get("type", "")
        file_name = pathlib.Path(result.get("source", {}).get("path", "")).name
        for package in packages:
            package_name = package.get("package", {}).get("name", "")
            package_version = package.get("package", {}).get("version", "")
            for vuln in package.get("vulnerabilities", []):
                cve_ids = vuln.get("aliases", "")
                if cve_ids == "" and vuln.get("references") is not None:
                    cve_ids = _extract_cve_reference_advisory(vuln["references"])
                risk_rating, cve_list_details = _aggregate_cves(
                    cve_ids=cve_ids, api_key=api_key
                )
                description = (
                    f"Dependency `{package_name}` with version `{package_version}`"
                    f" found in the `{file_type}` `{file_name}` "
                    f"has a security issue.\nThe issue is identified by CVEs: `{', '.join(cve_ids)}`."
                )
                recommendation = f"We recommend updating `{package_name}` to the latest available version."
                yield Vulnerability(
                    entry=kb.Entry(
                        title=f"Use of Outdated Vulnerable Component: "
                        f"{package_name}@{package_version}: {', '.join(cve_ids)}",
                        risk_rating=risk_rating.upper(),
                        short_description=vuln.get("summary", ""),
                        description=description,
                        references=_build_references(vuln.get("references", [])),
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                        recommendation=recommendation,
                    ),
                    technical_detail=f"{vuln.get('details')} \n#### CVEs:\n {cve_list_details}",
                    risk_rating=RISK_RATING_MAPPING[risk_rating.upper()],
                )


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
    references: List[Dict[str, str]]
) -> str | List[str]:
    for reference in references:
        if reference["type"] == "ADVISORY":
            cve_match = re.match(CVE_PATTERN, reference["url"], re.IGNORECASE)
            if cve_match is not None:
                return [cve_match.group(1)]
    return ""
