"""OSV agent implementation"""
import logging
import subprocess
import tempfile

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
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

SBOM_OUTPUT_PATH = "/tmp/sbom_osv_output.json"
LOCKFILE_OUTPUT_PATH = "/tmp/lockfile_osv_output.json"


class OSVAgent(
    agent.Agent,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
    agent_persist_mixin.AgentPersistMixin,
):
    """OSV agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        agent_report_vulnerability_mixin.AgentReportVulnMixin.__init__(self)
        self._osv_file_handler: osv_file_handler.OSVFileHandler
        self._command: list[str] = [
            "/usr/local/bin/osv-scanner",
            "--format",
            "json",
        ]

    def process(self, message: m.Message) -> None:
        """Process messages of type v3.asset.file and scan dependencies against vulnerabilities.
        Once the scan is completed, it emits messages of type : `v3.report.vulnerability`
        """

        logger.info("processing message of selector : %s", message.selector)
        content = message.data.get("content")
        path = message.data.get("path")
        if content is None or content == b"":
            return
        self._osv_file_handler = osv_file_handler.OSVFileHandler(
            content=content, path=path
        )

        self._run_osv(content)

    def _run_osv(self, content: bytes) -> None:
        """perform the scan on the file
        Args:
            content: file content
        """
        extension = self._osv_file_handler.get_file_type()
        decoded_content = content.decode("utf-8")
        with tempfile.NamedTemporaryFile(mode="w", suffix=extension) as file_path:
            file_path.write(decoded_content)
            self._run_sbom_command(file_path.name)
            self._run_lockfile_command(file_path.name)
            self._emit_results()

    def _run_sbom_command(self, file_path: str) -> None:
        """build the sbom command and run it
        Args:
            file_path: the sbom file path
        """
        self._command.append("--sbom=")
        self._command.append(file_path)
        self._command.append(">")
        self._command.append(SBOM_OUTPUT_PATH)
        _run_command(self._command)

    def _run_lockfile_command(self, file_path: str) -> None:
        """build the lockfile command and run it
        Args:
            file_path: the lockfile file path
        """
        self._command.append("--lockfile")
        self._command.append(file_path)
        self._command.append(">")
        self._command.append(LOCKFILE_OUTPUT_PATH)
        _run_command(self._command)

    def _emit_results(self) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in osv_file_handler.parse_results(SBOM_OUTPUT_PATH):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )

        for vuln in osv_file_handler.parse_results(LOCKFILE_OUTPUT_PATH):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )


def _run_command(command: list[str] | str) -> bytes | None:
    """Run OSV command on the provided file
    Args:
        command to run
    """
    try:
        output = subprocess.run(command, capture_output=True, check=True)
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
