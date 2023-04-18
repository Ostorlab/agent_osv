"""OSV agent implementation"""
import logging

from rich import logging as rich_logging
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


class OSVAgent(agent.Agent):
    """OSV agent."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def start(self) -> None:
        """TODO (author): add your description here."""
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        logger.info("processing message of selector : %s", message.selector)
        content = message.data.get("content")
        path = message.data.get("path")
        content_url = message.data.get("content_url")

    def _is_lock_file(self, content: bytes) -> bool:
        """check whether the file is valid lock file or not
        Args:
            content: the file content
        Returns:
            Boolean whether the file is valid
        """
        pass

    def _is_sbom_file(self, content: bytes) -> bool:
        """check whether the file is valid sbom file or not
        Args:
            content: the file content
        Returns:
            Boolean whether the file is valid
        """

    def _run_osv(self, file_path: str) -> bytes | None:
        """perform the scan on the file"""
        pass


if __name__ == "__main__":
    logger.info("starting agent ...")
    OSVAgent.main()
