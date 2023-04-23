"""OSV agent implementation"""
import logging
import subprocess

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import osv_wrapper

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)

OSV_COMMAND = [
    "/usr/local/bin/osv-scanner",
    "--format",
    "json",
    "--sbom=",
]

OUTPUT_PATH = "/tmp/osv_output.json"


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
        self.osv_wrapper: osv_wrapper.OSVWrapper | None = None

    def start(self) -> None:
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        """Process messages of type v3.asset.file and scan dependencies against vulnerabilities.
        Once the scan is completed, it emits messages of type : `v3.report.vulnerability`
        """
        if message.selector != "v3.asset.file":
            return

        logger.info("processing message of selector : %s", message.selector)
        content = message.data.get("content")
        path = message.data.get("path")
        if content is None or content == b"":
            return
        self.osv_wrapper = osv_wrapper.OSVWrapper(content=content, path=path)
        try:
            if (
                self.osv_wrapper is not None
                and self.osv_wrapper.validate_and_set_lock_file_extension() is False
            ):
                logger.info("Invalid file: %s", path)
                return
        except NotImplementedError:
            logger.info("the check of file validity not implemented yet")

        self._run_osv(path, content)

    def _run_osv(self, file_path: str | None, content: bytes | None) -> None:
        """perform the scan on the file
        Args:
            file_path: the path to the file
            content: file content
        """
        if content is None or content == b"":
            return

        if self.osv_wrapper is not None and file_path is None:
            file_path = self.osv_wrapper.write_content_to_file()

        if file_path is None:
            logger.info("The file path is empty")
            return
        OSV_COMMAND.append(file_path)
        OSV_COMMAND.append(">")
        OSV_COMMAND.append(OUTPUT_PATH)
        run_command(OSV_COMMAND)
        self._emit_results()

    def _emit_results(self) -> None:
        """Parses results and emits vulnerabilities."""
        for vuln in osv_wrapper.parse_results(OUTPUT_PATH):
            self.report_vulnerability(
                entry=vuln.entry,
                technical_detail=vuln.technical_detail,
                risk_rating=vuln.risk_rating,
                vulnerability_location=vuln.vulnerability_location,
            )


def run_command(command: list[str] | str) -> bytes | None:
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
