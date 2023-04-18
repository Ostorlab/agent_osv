"""OSV agent implementation"""
import json
import logging
import subprocess
from typing import Optional

from rich import logging as rich_logging
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin

from agent import utils

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")

LOCK_FILES_EXTENSIONS = ["lockfile", "lock", "json", "yaml", "xml", "txt"]


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
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        logger.info("processing message of selector : %s", message.selector)
        content = message.data.get("content")
        path = message.data.get("path")
        content_url = message.data.get("content_url")

        if self._is_valid_file(content, path) is False:
            logger.info("Invalid file")
            return
        self._run_osv(path)

    def _is_valid_file(self, content: Optional[bytes], path: Optional[str]) -> bool:
        """check whether the file is valid lock file or not
        Args:
            content: the file content
        Returns:
            Boolean whether the file is valid
        """
        if content is None:
            logger.error("Received empty file.")
            return False

        extension = utils.get_file_type(content, path)
        if extension not in LOCK_FILES_EXTENSIONS:
            logger.error("This type of file not supported.")
            return False

        return True

    def _run_osv(self, file_path: str):
        """perform the scan on the file"""
        command = ["/usr/local/bin/osv-scanner", f"--sbom={file_path}", "--format", "json", "/tmp"]
        output = self._run_command(command, self.args.get("timeout"))
        data = self._build_putput(output)

    def _build_putput(self, output: Optional[bytes]):
        if isinstance(output, bytes):
            return json.loads(output)
        else:
            logger.error("Process completed with errors")

    def _run_command(self, command: list[str] | str, timeout: Optional[int] = None):
        try:
            output = subprocess.run(
                command, capture_output=True, check=True, timeout=timeout
            )
        except subprocess.CalledProcessError as e:
            logger.error(
                "An error occurred while running the command. Error message: %s", e
            )
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Timeout occurred while running command")
            return None

        return output.stdout

    def _emit_results(self, json_output):
        return NotImplemented




if __name__ == "__main__":
    logger.info("starting agent ...")
    OSVAgent.main()
