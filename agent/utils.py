"""Utilities for resolving asset extraction directories in multi-asset scans."""

import logging
import os
from urllib import parse

logger = logging.getLogger(__name__)


def build_repository_asset_directory(repository_url: str, commit_hash: str) -> str:
    """Build the repository extraction folder name used in multi-asset scans.

    Args:
        repository_url: URL of the repository asset.
        commit_hash: Commit hash checked out for the repository asset.

    Returns:
        Folder name composed from the repository name and commit hash.
    """
    parsed_url: parse.ParseResult = parse.urlparse(repository_url)
    repository_path: str = parsed_url.path
    if len(repository_path) == 0:
        repository_path = repository_url

    repository_name: str = os.path.basename(repository_path.rstrip("/"))
    if repository_name.endswith(".git") is True:
        repository_name = repository_name[: -len(".git")]
    return f"{repository_name}_{commit_hash}"


def build_repository_archive_asset_directory(content_url: str) -> str:
    """Build the archive extraction folder name from its uploaded content URL.

    Args:
        content_url: URL of the uploaded repository archive.

    Returns:
        Last path segment of the archive content URL, ignoring query parameters.
    """
    parsed_url: parse.ParseResult = parse.urlparse(content_url)
    return os.path.basename(parsed_url.path.rstrip("/"))
