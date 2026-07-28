"""Utilities for resolving asset extraction directories in multi-asset scans."""

import os
from urllib import parse


def construct_repository_asset_directory_name(
    repository_url: str, commit_hash: str
) -> str:
    """Construct the repository extraction directory name used in multi-asset scans.

    Args:
        repository_url: URL of the repository asset.
        commit_hash: Commit hash checked out for the repository asset.

    Returns:
        Directory name composed from the repository name and commit hash.
    """
    parsed_url: parse.ParseResult = parse.urlparse(repository_url)
    repository_name: str = os.path.basename(parsed_url.path.rstrip("/"))
    if repository_name.endswith(".git") is True:
        repository_name = repository_name[: -len(".git")]
    return f"{repository_name}_{commit_hash}"


def construct_repository_archive_asset_directory_name(content_url: str) -> str:
    """Construct the archive extraction directory name from its uploaded content URL.

    Repository archive uploads are expected to follow the upload shape
    ``.../uploads/<uuid>``. The upload UUID immediately after the ``uploads``
    segment is returned and used as the extraction directory name.

    Args:
        content_url: URL of the uploaded repository archive.

    Returns:
        The upload UUID segment immediately after ``uploads``.

    Raises:
        ValueError: If ``content_url`` does not contain an ``uploads/<uuid>``
            segment, since any deviation from the expected upload shape must
            surface rather than silently scan an ambiguous directory.
    """
    parsed_url: parse.ParseResult = parse.urlparse(content_url)
    path_segments: list[str] = [
        segment for segment in parsed_url.path.split("/") if len(segment) > 0
    ]
    try:
        uploads_index: int = path_segments.index("uploads")
    except ValueError as e:
        raise ValueError(
            f"Repository archive content_url has no `uploads` segment: {content_url!r}"
        ) from e
    if uploads_index + 1 >= len(path_segments):
        raise ValueError(
            f"Repository archive content_url has no upload id after `uploads`: "
            f"{content_url!r}"
        )
    return path_segments[uploads_index + 1]
