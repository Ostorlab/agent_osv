"""OSV agent implementation"""
import logging
from typing import Union

from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from rich import logging as rich_logging

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

    def start(self) -> None:
        """TODO (author): add your description here."""
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        logger.info("processing message of selector : %s", message.selector)

    def _is_lock_file(self, content: bytes) -> bool:
        """check whether the file is valid lock file or not
        Args:
            content: the file content
        Returns:
            Boolean whether the file is valid
        """
        return NotImplemented

    def _is_sbom_file(self, content: bytes) -> bool:
        """check whether the file is valid sbom file or not
        Args:
            content: the file content
        Returns:
            Boolean whether the file is valid
        """
        return NotImplemented

    def _run_osv(self, file_path: str) -> str:
        """perform the scan on the file"""
        return NotImplemented


if __name__ == "__main__":
    logger.info("starting agent ...")
    OSVAgent.main()
