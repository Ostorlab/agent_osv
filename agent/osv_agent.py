"""OSV agent implementation"""

import json
import logging
import pathlib
import subprocess
import typing

import requests
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import osv_output_handler
from agent.api_manager import osv_service_api

SUPPORTED_OSV_FILE_NAMES = [
    "buildscript-gradle.lockfile",
    "Cargo.lock",
    "composer.lock",
    "conan.lock",
    "Gemfile.lock",
    "go.mod",
    "gradle.lockfile",
    "mix.lock",
    "Pipfile.lock",
    "package-lock.json",
    "packages.lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pubspec.lock",
    "requirements.txt",
    "yarn.lock",
]
OSV_ECOSYSTEM_MAPPING = {
    "JAVASCRIPT_LIBRARY": "npm",
    "JAVA_LIBRARY": "Maven",
    "FLUTTER_FRAMEWORK": "Pub",
    "CORDOVA_LIBRARY": "npm",
    "DOTNET_FRAMEWORK": "NuGet",
    "IOS_FRAMEWORK": "SwiftURL",
}

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


def _get_content(message: m.Message) -> bytes | None:
    """Get the content of the file from the message.
    Args:
        message: The message containing the file content.
    Returns:
        The content of the file.
    """
    content = message.data.get("content")
    if content is not None:
        casted_content = typing.cast(bytes, content)
        return casted_content
    content_url = message.data.get("content_url")
    if content_url is not None:
        return requests.get(content_url, timeout=60).content
    return None


def _construct_commands(file_path: str) -> list[list[str]]:
    """Constructs OSV command, for both lockfile and sbomfile."""
    return [
        [
            "/usr/local/bin/osv-scanner",
            "--format",
            "json",
            "--lockfile",
            file_path,
        ],
        [
            "/usr/local/bin/osv-scanner",
            "--format",
            "json",
            "--sbom",
            file_path,
        ],
    ]


def _run_osv(path: str, content: bytes) -> str | None:
    """Perform the osv scan with two flags with --sbom and --lockfile,  letting OSV validate the file
     instead of guessing the file format.
    Args:
        path: The file path.
        content: Scanned file content
    """
    decoded_content = content.decode("utf-8", errors="ignore")
    file_name = pathlib.Path(path)
    file_name.write_text(decoded_content, encoding="utf-8")
    for command in _construct_commands(file_name.name):
        output = _run_command(command)
        if output is not None:
            return output
    return None


class OSVAgent(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """OSV agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        super().__init__(agent_definition, agent_settings)
        self.api_key = self.args.get("nvd_api_key", None)

    def process(self, message: m.Message) -> None:
        """Process messages of type v3.asset.file and scan dependencies against vulnerabilities.
        Once the scan is completed, it emits messages of type : `v3.report.vulnerability`
        """
        logger.info("processing message of selector : %s", message.selector)
        if message.selector.startswith("v3.asset.file") is True:
            self._process_asset_file(message)

        elif message.selector.startswith("v3.fingerprint.file") is True:
            self._process_fingerprint_file(message)

    def _emit_vulnerabilities(
        self, output: list[osv_output_handler.VulnData], path: str | None = None
    ) -> None:
        vulnz = osv_output_handler.construct_vuln(output, path)
        for vuln in vulnz:
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                dna=vuln.dna,
                risk_rating=vuln.risk_rating,
            )

    def _process_asset_file(self, message: m.Message) -> None:
        """Process message of type v3.asset.file."""
        content = _get_content(message)
        if content is None or content == b"":
            logger.warning("Message file content is empty.")
            return
        for file_name in SUPPORTED_OSV_FILE_NAMES:
            scan_results = _run_osv(file_name, content)
            if scan_results is not None:
                logger.info("Found valid name for file: %s", file_name)
                parsed_output = osv_output_handler.parse_osv_output(
                    scan_results, self.api_key
                )
                if len(parsed_output) > 0:
                    self._emit_vulnerabilities(output=parsed_output)
                break

    def _process_fingerprint_file(self, message: m.Message) -> None:
        """Process message of type v3.fingerprint.file."""
        package_name = message.data.get("library_name")
        package_version = message.data.get("library_version")
        package_type = message.data.get("library_type")
        path = message.data.get("path")

        if package_version is None:
            logger.error("Error: Version must not be None.")
            return None
        if package_name is None:
            logger.error("Error: Package name must not be None.")
            return None

        api_result = osv_service_api.query_osv_api(
            package_name=package_name,
            version=package_version,
            ecosystem=OSV_ECOSYSTEM_MAPPING.get(str(package_type)),
        )
        if api_result is None or api_result == {}:
            return None

        parsed_osv_output = osv_output_handler.parse_vulnerabilities_osv_api(
            output=api_result,
            package_name=package_name,
            package_version=package_version,
            api_key=self.api_key,
        )

        if parsed_osv_output is None:
            return None

        if len(parsed_osv_output) == 0:
            return None

        self._emit_vulnerabilities(output=parsed_osv_output, path=path)


def _is_valid_osv_result(results: str | None) -> bool:
    """Check if the results are valid."""
    if results is None:
        return False

    if results == "":
        return False

    try:
        if json.loads(results) == {"results": []}:
            return False
    except json.JSONDecodeError:
        return False

    return True


def _run_command(command: list[str] | str) -> str | None:
    """Run OSV command on the provided file
    Args:
        command to run
    """
    try:
        output = subprocess.run(command, capture_output=True, text=True, check=False)
    except (subprocess.CalledProcessError, UnicodeDecodeError) as e:
        logger.error(
            "An error occurred while running the command. Error message: %s", e
        )
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Timeout occurred while running command")
        return None
    results = output.stdout
    if _is_valid_osv_result(results) is False:
        logger.warning("OSV scan returned no results for command %s", command)
        return None
    return results


if __name__ == "__main__":
    logger.info("starting agent ...")
    OSVAgent.main()
