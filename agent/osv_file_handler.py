"""OSV Wrapper responsible for running OSV Scanner on the appropriate file"""
import dataclasses
import json
import logging
import mimetypes
import os
from typing import Optional, Iterator, Any

import magic
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import file
from rich import logging as rich_logging

from agent import cve_service_api

RISK_RATING_MAPPING = {
    "UNKNOWN": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating
    vulnerability_location: agent_report_vulnerability_mixin.VulnerabilityLocation


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


class OSVFileHandler:
    """OSV Wrapper responsible for running OSV on the appropriate file"""

    def __init__(self, content: bytes | None, path: str | None):
        self.content = content
        self.path = path
        self.extension: str | None = ""

    def set_extension_and_check_if_valid_lock_file(self) -> bool:
        """check whether the file is valid lock file or not
        Returns:
            Boolean whether the file is valid
        """
        if self.content is None or self.content == b"":
            logger.error("Received empty content.")
            return False

        self.extension = self.get_file_type()
        if self.extension not in LOCK_FILES_EXTENSIONS:
            logger.error("This type of file not supported.")
            return False

        return True

    def get_file_type(self) -> str | None:
        """Get the file extension
        Returns:
            The file extension
        """
        if self.path is not None and len(os.path.splitext(self.path)[1]) >= 2:
            return os.path.splitext(self.path)[1]
        if self.content is not None:
            mime = magic.from_buffer(self.content, mime=True)
            return mimetypes.guess_extension(mime)
        return None

    def write_content_to_file(self) -> str | None:
        """Write the file content to a file
        Returns:
            The file path
        """
        if self.content is None or self.content != b"":
            return None

        decoded_content = self.content.decode("utf-8")
        file_path = f"/tmp/lock_file{self.extension}"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(decoded_content)
        return file_path

    def build_putput(self, output: Optional[bytes]) -> None:
        raise NotImplementedError


def construct_technical_detail(
    package_name: str,
    package_version: str,
    package_framework: str,
    file_type: str,
    vuln_aliases: list[str],
    vuln_id: str,
) -> str:
    """construct the technical detail
    Args:
        package_name: the vulnerable package name
        package_version: the vulnerable package version
        package_framework: the package ecosystem
        file_type: lock file type
        vuln_aliases: Vulnerability CVEs
        vuln_id: vulnerability id
    Returns:
        technical detail
    """
    technical_detail = f"""The file `{file_type}` has a security issue at the package `{package_name}`,
    version `{package_version}`, framework {package_framework}.
    The issue ID `{vuln_id}`, CVE `{",".join(vuln_aliases)}`."""

    return technical_detail


def read_output_file(output_file_path: str) -> dict[str, Any]:
    """Read the OSV scanner output from json file and return dict
    Args:
        output_file_path: the OSV scanner output file
    returns:
        Dict representation of the json object
    """
    with open(output_file_path, "r", encoding="utf-8") as of:
        data: dict[str, Any] = json.load(of)

    return data


def parse_results(output_file_path: str) -> Iterator[Vulnerability]:
    """Parses JSON generated OSV results and yield vulnerability entries.
    Args:
        output_file_path: OSV json output file path.
    Yields:
        Vulnerability entry.
    """

    data = read_output_file(output_file_path)
    results: dict[Any, Any] = data.get("results", [])
    for result in results:
        file_type = result.get("source", {}).get("type", "")
        file_path = result.get("source", {}).get("path", "")
        packages = result.get("packages", [{}])
        for package in packages:
            package_name = package.get("package", {}).get("name", "")
            package_version = package.get("package", {}).get("version", "")
            package_framework = package.get("package", {}).get("ecosystem", "")
            for vuln in package.get("vulnerabilities", []):
                vuln_id = vuln.get("id")
                vuln_aliases = vuln.get("aliases")
                summary = vuln.get("summary")
                technical_detail = construct_technical_detail(
                    package_name,
                    package_version,
                    package_framework,
                    file_type,
                    vuln_aliases,
                    vuln_id,
                )
                cve_data = get_cve_data_summary(vuln_aliases)
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

    for cve_id in cve_ids:
        cve_data = cve_service_api.get_cve_data_from_api(cve_id)
        risk_ratings.append(cve_data.risk)
        if cve_data.description is not None and cve_data.description != "":
            description = cve_data.description
        if cve_data.cvss_v3_vector is not None and cve_data.cvss_v3_vector != "":
            cvss_v3_vector = cve_data.cvss_v3_vector
    risk_rating = calculate_risk_rating(risk_ratings)

    return cve_service_api.CVE(
        risk=risk_rating, description=description, cvss_v3_vector=cvss_v3_vector
    )


def calculate_risk_rating(risk_ratings: list[str]) -> str:
    """Calculate the risk rating of a given cve ids of a vulnerability
    Args:
        risk_ratings: list of risk ratings
    Returns:
        Risk rating of a vulnerability
    """
    priority_levels = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_ratings = sorted(
        risk_ratings, key=lambda x: priority_levels.get(x) or "UNKNOWN", reverse=False
    )

    for rating in sorted_ratings:
        if rating in priority_levels:
            return rating
    return "UNKNOWN"
