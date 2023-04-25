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
            "--sbom=",
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
        try:
            if self._osv_file_handler.is_valid_file() is False:
                logger.error("Invalid file: %s", path)
                return
        except NotImplementedError:
            logger.info("The check of file validity not implemented yet")

        self._run_osv()

    def _run_osv(self) -> None:
        """Perform the scan on the file"""
        file_path: str | None = None
        try:
            file_path = self._osv_file_handler.write_content_to_file()
            if file_path is None:
                logger.info("The file path is empty")
                return
        except NotImplementedError:
            logger.info("Write_content_to_file not implemented yet")

        if file_path is not None:
            self._command.append(file_path)
        _run_command(self._command)

    def _emit_results(self, json_output: str) -> NotImplementedError:
        raise NotImplementedError


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
