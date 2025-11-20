"""OSV agent implementation"""

import json
import logging
import pathlib
import subprocess
import typing
import os
import mimetypes
from agent import hotpatch
from urllib import parse

import requests
import magic
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import osv_output_handler
from agent.api_manager import osv_service_api
from ostorlab.assets import ios_store
from ostorlab.assets import android_store
from ostorlab.assets import domain_name
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin


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
    "pdm.lock",
    "pom.xml",
    "pubspec.lock",
    "requirements.txt",
    "renv.lock",
    "yarn.lock",
    "verification-metadata.xml",
]

OSV_ECOSYSTEM_MAPPING = {
    "JAVASCRIPT_LIBRARY": ["npm"],
    "JAVA_LIBRARY": ["Maven"],
    "FLUTTER_FRAMEWORK": ["Pub"],
    "CORDOVA_FRAMEWORK": ["npm"],
    "DOTNET_FRAMEWORK": ["NuGet"],
    "IOS_FRAMEWORK": ["SwiftURL"],
    "ELF_LIBRARY": ["OSS-Fuzz", "Alpine", "Debian", "Linux", "Bitnami"],
    "MACHO_LIBRARY": ["OSS-Fuzz", "Alpine", "Debian", "Linux", "Bitnami", "SwiftURL"],
}

FILE_TYPE_BLACKLIST = (
    ".car",
    ".dex",
    ".dylib",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mobileprovision",
    ".nib",
    ".pdf",
    ".plist",
    ".png",
    ".psd",
    ".so",
    ".strings",
    ".svg",
    ".symbols",
    ".ttf",
    ".woff",
    ".woff2",
    ".zip",
)

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


def _get_content_url(message: m.Message) -> bytes | None:
    url = message.data.get("url")
    if url is None:
        return None
    parsed_url = parse.urlparse(url)
    filename = os.path.basename(parsed_url.path)
    if filename.lower() in [
        support_lock.lower() for support_lock in SUPPORTED_OSV_FILE_NAMES
    ]:
        logger.debug("Found matching path %s", url)
        response = requests.get(url, timeout=60)
        logger.debug("Collected response %s", response.text)
        return response.text.encode()
    return None


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
    content_url = _get_content_url(message)
    if content_url is not None:
        return content_url
    return None


def _get_path(message: m.Message) -> str | None:
    path: str | None = message.data.get("path")
    if path is not None:
        return path
    url: str | None = message.data.get("url")
    if url is not None:
        parsed_url = parse.urlparse(url)
        filename = os.path.basename(parsed_url.path)
        return filename
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
    patched_path, patched_content = hotpatch.hotpatch(path, content)
    decoded_content = patched_content.decode("utf-8", errors="ignore")
    file_name = pathlib.Path(patched_path)
    file_name.write_text(decoded_content, encoding="utf-8")
    for command in _construct_commands(file_name.name):
        logger.debug("Running command %s", command)
        output = _run_command(command)
        logger.debug("Output: %s", output)
        if output is not None:
            return output
    return None


def _run_osv_directory(original_path: str, content: bytes) -> str | None:
    """Perform OSV scan on a directory (for Go projects) to preserve context.

    Args:
        original_path: Original file path (e.g., "/workspace/go.mod")
        content: File content as bytes

    Returns:
        OSV scan results as JSON string, or None if scan fails
    """
    try:
        original_path_obj = pathlib.Path(original_path)
        module_dir = original_path_obj.parent.resolve()

        # Write file to module directory
        patched_path, patched_content = hotpatch.hotpatch(
            original_path_obj.name, content
        )
        file_path = module_dir / original_path_obj.name
        file_path.write_text(
            patched_content.decode("utf-8", errors="ignore"), encoding="utf-8"
        )

        # Scan directory instead of just the file
        command = ["/usr/local/bin/osv-scanner", "--format", "json", str(module_dir)]
        output = subprocess.run(
            command, cwd=module_dir, capture_output=True, text=True, check=False
        )

        if _is_valid_osv_result(output.stdout):
            return output.stdout
        return None
    except (OSError, UnicodeDecodeError, ValueError) as e:
        logger.error("Error during directory scan: %s", e, exc_info=True)
        return None


def _get_file_type(content: bytes, path: str | None) -> str:
    if path is None:
        mime = magic.from_buffer(content, mime=True)
        file_type = mimetypes.guess_extension(mime)
        return str(file_type)
    else:
        file_split = os.path.splitext(path)[1]
        # Check the result hase the base name and the file extension
        if len(file_split) < 2:
            return _get_file_type(content, None)
        return file_split


def _prepare_vulnerability_location(
    message: m.Message,
) -> vuln_mixin.VulnerabilityLocation | None:
    """
    Prepare the vulnerability location based on the message data.

    Args:
        message: The message containing the data to prepare the vulnerability location.

    Returns:
        VulnerabilityLocation if asset is found, None otherwise.
    """
    asset: (
        domain_name.DomainName | ios_store.IOSStore | android_store.AndroidStore | None
    ) = None
    metadata = []
    if message.selector == "v3.asset.link":
        url = message.data.get("url")
        url_netloc = parse.urlparse(url).netloc
        asset = domain_name.DomainName(name=str(url_netloc))
        if url is not None:
            metadata.append(
                vuln_mixin.VulnerabilityLocationMetadata(
                    metadata_type=vuln_mixin.MetadataType.URL,
                    value=url,
                )
            )

    else:
        package_name = message.data.get("android_metadata", {}).get("package_name")
        bundle_id = message.data.get("ios_metadata", {}).get("bundle_id")
        if bundle_id is not None:
            asset = ios_store.IOSStore(bundle_id=bundle_id)
        elif package_name is not None:
            asset = android_store.AndroidStore(package_name=package_name)
        metadata.append(
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.FILE_PATH,
                value=message.data.get("path") or "",
            )
        )

    if asset is None:
        return None

    return vuln_mixin.VulnerabilityLocation(
        asset=asset,
        metadata=metadata,
    )


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
        if message.selector.startswith("v3.asset") is True:
            self._process_asset(message)

        elif message.selector.startswith("v3.fingerprint.file") is True:
            self._process_fingerprint_file(message)

    def _emit_vulnerabilities(
        self,
        output: list[osv_output_handler.VulnData],
        vulnerability_location: vuln_mixin.VulnerabilityLocation | None,
        path: str | None = None,
    ) -> None:
        vulnz = osv_output_handler.construct_vuln(output, path)
        for vuln in vulnz:
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                dna=vuln.dna,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vulnerability_location,
            )

    def _process_asset(self, message: m.Message) -> None:
        """Process message of type v3.asset.file."""
        content = _get_content(message)
        path = _get_path(message)
        if content is None or content == b"":
            logger.warning("Message file content is empty.")
            return
        file_type = _get_file_type(content, path)
        logger.debug("Analyzing file `%s` with type `%s`.", path, file_type)

        if file_type in FILE_TYPE_BLACKLIST:
            logger.debug("File type is blacklisted.")
            return

        # Special handling for Go module files to preserve directory context
        if path is not None and path.endswith(("go.mod", "go.sum")) is True:
            scan_results = _run_osv_directory(path, content)
            if scan_results is not None:
                parsed_output = osv_output_handler.parse_osv_output(
                    scan_results, self.api_key
                )
                if len(parsed_output) > 0:
                    vulnerability_location = _prepare_vulnerability_location(message)
                    self._emit_vulnerabilities(
                        output=parsed_output,
                        vulnerability_location=vulnerability_location,
                    )
            return

        for file_name in SUPPORTED_OSV_FILE_NAMES:
            scan_results = _run_osv(file_name, content)
            if scan_results is not None:
                logger.info(
                    "Found valid name for file: %s in path: %s", file_name, path
                )
                parsed_output = osv_output_handler.parse_osv_output(
                    scan_results, self.api_key
                )
                if len(parsed_output) > 0:
                    vulnerability_location = _prepare_vulnerability_location(message)
                    self._emit_vulnerabilities(
                        output=parsed_output,
                        vulnerability_location=vulnerability_location,
                    )

    def _process_fingerprint_file(self, message: m.Message) -> None:
        """Process message of type v3.fingerprint.file."""
        package_name = message.data.get("library_name")
        package_version = message.data.get("library_version")
        package_type = message.data.get("library_type")
        path = message.data.get("path")

        if package_version is None:
            return None
        if package_name is None:
            logger.warning("Error: Package name must not be None.")
            return None

        ecosystems = OSV_ECOSYSTEM_MAPPING.get(str(package_type), [])
        whitelisted_ecosystems = None
        ecosystem = None
        if len(ecosystems) == 1:
            ecosystem = ecosystems[0]
        elif len(ecosystems) > 1:
            whitelisted_ecosystems = ecosystems

        api_result = osv_service_api.query_osv_api(
            package_name=package_name,
            version=package_version,
            ecosystem=ecosystem,
        )

        if api_result is None or api_result == {}:
            api_result = osv_service_api.query_osv_api(
                package_name=package_name.lower(),
                version=package_version,
                ecosystem=ecosystem,
            )

        if api_result is None or api_result == {}:
            return None

        parsed_osv_output = osv_output_handler.parse_vulnerabilities_osv_api(
            output=api_result,
            package_name=package_name,
            package_version=package_version,
            api_key=self.api_key,
            whitelisted_ecosystems=whitelisted_ecosystems,
        )
        if parsed_osv_output is None:
            return None

        if len(parsed_osv_output) == 0:
            return None
        vulnerability_location = _prepare_vulnerability_location(message)
        self._emit_vulnerabilities(
            output=parsed_osv_output,
            path=path,
            vulnerability_location=vulnerability_location,
        )


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
