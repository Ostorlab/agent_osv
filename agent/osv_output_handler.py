"""OSV Wrapper responsible for dealing with the agent output and constructing its information."""
import dataclasses
import json
import logging
from typing import Iterator, Any

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import file
from rich import logging as rich_logging
from agent import cve_service_api

RISK_RATING_MAPPING = {
    "POTENTIALLY": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}

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
    vulnerability_location: agent_report_vulnerability_mixin.VulnerabilityLocation


def construct_technical_detail(
    package_name: str,
    package_version: str,
    file_type: str,
    vuln_aliases: list[str],
    fixed_version: str | None,
) -> str:
    """construct the technical detail
    Args:
        package_name: the vulnerable package name
        package_version: the vulnerable package version
        file_type: lock file type
        vuln_aliases: Vulnerability CVEs
        fixed_version: The version when the issue is fixed
    Returns:
        technical detail
    """
    if fixed_version is not None:
        technical_detail = f"""The file `{file_type}` has a security issue in package `{package_name}` with version
        `{package_version}`. The issue is identified by CVE
        `{",".join(vuln_aliases)}`. We recommend updating `{package_name}` to the latest available version since
         this issue is fixed in version `{fixed_version}`."""
    else:
        technical_detail = f"""The file `{file_type}` has a security issue in package `{package_name}` with version
        `{package_version}`. The issue is identified by CVE
        `{",".join(vuln_aliases)}`. We recommend updating `{package_name}` to the latest available version."""

    return technical_detail


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


def parse_results(output: str) -> Iterator[Vulnerability]:
    """Parses JSON generated OSV results and yield vulnerability entries.
    Args:
        output_file_path: OSV json output file path.
    Yields:
        Vulnerability entry.
    """

    data = json.loads(output, strict=False)
    if data.get("results") is None:
        logger.info("Osv returns null result.")
        return

    results: dict[Any, Any] = data.get("results", [])
    for result in results:
        file_type = result.get("source", {}).get("type", "")
        file_path = result.get("source", {}).get("path", "")
        packages = result.get("packages", [{}])
        for package in packages:
            package_name = package.get("package", {}).get("name", "")
            package_version = package.get("package", {}).get("version", "")
            for vuln in package.get("vulnerabilities", []):
                vuln_aliases = vuln.get("aliases", "")
                summary = vuln.get("summary", "")
                cve_data = get_cve_data_summary(vuln_aliases)
                technical_detail = construct_technical_detail(
                    package_name,
                    package_version,
                    file_type,
                    vuln_aliases,
                    cve_data.fixed_version,
                )
                vuln_location = agent_report_vulnerability_mixin.VulnerabilityLocation(
                    asset=file.File(),
                    metadata=[
                        agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                            metadata_type=agent_report_vulnerability_mixin.MetadataType.FILE_PATH,
                            value=file_path,
                        )
                    ],
                )
                yield Vulnerability(
                    entry=kb.Entry(
                        title=summary,
                        risk_rating=cve_data.risk.upper(),
                        short_description=summary,
                        description=cve_data.description,
                        references=vuln.get("references")[0],
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                    ),
                    technical_detail=technical_detail,
                    risk_rating=RISK_RATING_MAPPING[cve_data.risk.upper()],
                    vulnerability_location=vuln_location,
                )


def get_cve_data_summary(cve_ids: list[str]) -> cve_service_api.CVE:
    """Set cve summary including risk rating, description and cvss v3 vector
    Args:
        cve_ids: cve ids of a vulnerability
    Returns:
        CVE of cve information
    """
    risk_ratings = []
    description = ""
    cvss_v3_vector = ""
    fixed_version = ""

    for cve_id in cve_ids:
        cve_data = cve_service_api.get_cve_data_from_api(cve_id)
        risk_ratings.append(cve_data.risk)
        if cve_data.description is not None and cve_data.description != "":
            description = cve_data.description
        if cve_data.cvss_v3_vector is not None and cve_data.cvss_v3_vector != "":
            cvss_v3_vector = cve_data.cvss_v3_vector
        if cve_data.fixed_version is not None and cve_data.fixed_version != "":
            fixed_version = cve_data.fixed_version
    risk_rating = calculate_risk_rating(risk_ratings)

    return cve_service_api.CVE(
        risk=risk_rating,
        description=description,
        fixed_version=fixed_version,
        cvss_v3_vector=cvss_v3_vector,
    )


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
