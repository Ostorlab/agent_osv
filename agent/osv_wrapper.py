"""OSV Wrapper responsible for running OSV Scanner on the appropriate file"""
import logging
from typing import Optional

from rich import logging as rich_logging

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)

LOCK_FILES_EXTENSIONS = [".lockfile", ".lock", ".json", ".yaml", ".xml", ".txt", ".mod"]


class OSVFileHandler:
    """OSV Wrapper responsible for running OSV on the appropriate file"""

    def __init__(self, content: bytes | None, path: str | None):
        self.content = content
        self.path = path
        self.extension: str | None = ""

    def is_valid_file(self) -> bool:
        raise NotImplementedError

    def get_file_type(self) -> str | None:
        raise NotImplementedError

    def write_content_to_file(self) -> str | None:
        raise NotImplementedError

    def build_putput(self, output: Optional[bytes]) -> None:
        raise NotImplementedError
