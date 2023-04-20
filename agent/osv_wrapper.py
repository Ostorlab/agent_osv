"""OSV Wrapper responsible for running OSV Scanner on the appropriate file"""
import logging
import mimetypes
import os
from typing import Optional

import magic
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
