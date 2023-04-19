"""OSV agent implementation"""
import logging
import mimetypes
import os
import subprocess
from typing import Optional

import magic
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)

LOCK_FILES_EXTENSIONS = [".lockfile", ".lock", ".json", ".yaml", ".xml", ".txt"]


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
        self.osv_wrapper: OSVWrapper | None = None

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
        self.osv_wrapper = OSVWrapper(content=content, path=path)
        if self.osv_wrapper is not None and self.osv_wrapper.is_valid_file() is False:
            logger.info("Invalid file")
            return

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

        command = [
            "/usr/local/bin/osv-scanner",
            "--format",
            "json",
            f"--sbom={file_path}",
        ]
        run_command(command)

    def _emit_results(self, json_output: str) -> None:
        raise NotImplementedError


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
