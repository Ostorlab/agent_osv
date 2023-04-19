"""OSV Wrapper responsible for running OSV Scanner on the appropriate file"""
import dataclasses
import json
import logging
import mimetypes
import os
import re
from typing import Optional

from agent import cve_service_api
import magic
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import file
from rich import logging as rich_logging

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

LOCK_FILES_EXTENSIONS = [".lockfile", ".lock", ".json", ".yaml", ".xml", ".txt"]


class OSVWrapper:
    """OSV Wrapper responsible for running OSV on the appropriate file"""

    def __init__(self, content: bytes | None, path: str | None):
        self.content = content
        self.path = path
        self.extension: str | None = ""

    def is_valid_file(self) -> bool:
        """check whether the file is valid lock file or not
        Args:
            content: the file content
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
        Args:
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
        Args:
        Returns:
            The file path
        """
        if self.content is None or self.content != b"":
            return None

        decoded_content = self.content.decode("utf-8")
        logger.info("null path")
        file_path = f"/tmp/lock_file{self.extension}"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(decoded_content)
        return file_path

    def build_putput(self, output: Optional[bytes]) -> None:
        raise NotImplementedError


def construct_technical_detail(
    package_name, package_version, package_framework, file_type, vuln_aliases, vuln_id
) -> str:
    technical_detail = f"""The file `{file_type}` has a security issue at the package `{package_name}`, version 
    `{package_version}`, framework {package_framework}.
    The issue ID `{vuln_id}`, CVE `{",".join(vuln_aliases)}`."""

    return technical_detail


def read_output_file(output_file_path: str) -> dict[str, str]:
    """Read the OSV scanner output from json file and return dict
    Args:
        output_file_path: the OSV scanner output file
    returns:
        Dict representation of the json object
    """
    with open(output_file_path, "r") as of:
        data = json.load(of)

    return data


def parse_results(output_file_path: str):
    """Parses JSON generated OSV results and yield vulnerability entries.
    Args:
        output_file_path: OSV json output file path.
    Yields:
        Vulnerability entry.
    """

    data = read_output_file(output_file_path)

    for result in data.get("results", []):
        file_type = result.get("source", {}).get("type", "")
        file_path = result.get("source", {}).get("path", "")
        packages = result.get("packages", {})
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
                risk_rating = calculate_risk_rating(vuln_aliases)
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
                        risk_rating=RISK_RATING_MAPPING[risk_rating.upper()],
                        short_description=summary,
                        description="",
                        references=vuln.get("references")[0],
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False,
                    ),
                    technical_detail=technical_detail,
                    risk_rating=RISK_RATING_MAPPING[risk_rating.upper()],
                    vulnerability_location=vuln_location,
                )


def calculate_risk_rating(cve_ids: list[str]) -> str:
    risk_ratings = []
    priority_levels = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for cve_id in cve_ids:
        risk_ratings.append(cve_service_api.get_cve_risk_rating(cve_id))

    sorted_ratings = sorted(
        risk_ratings, key=lambda x: priority_levels.get(x, 0), reverse=False
    )

    for rating in sorted_ratings:
        if rating in priority_levels:
            return rating
    return "UNKNOWN"
