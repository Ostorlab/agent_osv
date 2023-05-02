"""OSV agent implementation"""
import logging
import subprocess
import tempfile

from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging

from agent import osv_file_handler

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)


class OSVAgent(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
    agent_persist_mixin.AgentPersistMixin,
):
    """OSV agent."""

    def process(self, message: m.Message) -> None:
        """Process messages of type v3.asset.file and scan dependencies against vulnerabilities.
        Once the scan is completed, it emits messages of type : `v3.report.vulnerability`
        """
        self._osv_file_handler: osv_file_handler.OSVFileHandler
        logger.info("processing message of selector : %s", message.selector)
        content = message.data.get("content")
        path = message.data.get("path")
        if content is None or content == b"":
            logger.warning("Message file content is empty.")
            return
        self._osv_file_handler = osv_file_handler.OSVFileHandler(
            content=content, path=path
        )

        self._run_osv(content)

    def _run_osv(self, content: bytes) -> None:
        """Perform the osv scan with two flags with --sbom and --lockfile,  letting OSV validate the file
         instead of guessing the file format.
        Args:
            content: Scanned file content
        """
        extension = self._osv_file_handler.get_file_type()
        decoded_content = content.decode("utf-8")
        with tempfile.NamedTemporaryFile(mode="w", suffix=extension) as file_path:
            file_path.write(decoded_content)
            sbom_output = self._run_sbom_command(file_path.name)
            lockfile_output = self._run_lockfile_command(file_path.name)

            if sbom_output is not None:
                self._emit_results(sbom_output)
            if lockfile_output is not None:
                self._emit_results(lockfile_output)

    def _run_sbom_command(self, file_path: str) -> str | None:
        """build the sbom command and run it
        Args:
            file_path: the sbom file path
        """
        command = self._construct_command(sbomfile_path=file_path)
        if command is not None:
            return _run_command(command)
        return None

    def _run_lockfile_command(self, file_path: str) -> str | None:
        """build the lockfile command and run it
        Args:
            file_path: the lockfile file path
        """
        command = self._construct_command(lockfile_path=file_path)
        if command is not None:
            return _run_command(command)
        return None

    def _construct_command(
        self, lockfile_path: str | None = None, sbomfile_path: str | None = None
    ) -> list[str] | None:
        """Constructs OSV command with correct flag based on the input.
        Args:
            lockfile_path: Path to the lockfile to be scanned.
            sbomfile_path: Path to the sbom file to be scanned.
        Returns:
            A list containing the constructed command based on the input parameters..
        """
        if lockfile_path is not None:
            return [
                "/usr/local/bin/osv-scanner",
                "--format",
                "json",
                "--lockfile",
                lockfile_path,
            ]
        if sbomfile_path is not None:
            return [
                "/usr/local/bin/osv-scanner",
                "--format",
                "json",
                "--sbom",
                sbomfile_path,
            ]

        logger.warning("Can't construct command")
        return None

    def _emit_results(self, output: str) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in osv_file_handler.parse_results(output):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )


def _run_command(command: list[str] | str) -> str | None:
    """Run OSV command on the provided file
    Args:
        command to run
    """
    try:
        output = subprocess.run(command, capture_output=True, text=True, check=False)
    except subprocess.CalledProcessError as e:
        logger.error(
            "An error occurred while running the command. Error message: %s", e
        )
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Timeout occurred while running command")
        return None

    return output.stdout


if __name__ == "__main__":
    logger.info("starting agent ...")
    OSVAgent.main()
