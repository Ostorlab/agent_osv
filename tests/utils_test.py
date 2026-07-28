"""Unittests for the asset directory utils."""

import pytest

from agent import utils


def testConstructRepositoryAssetDirectoryName_whenGitUrl_returnsNameAndCommitHash() -> (
    None
):
    """A .git URL produces a `<repo>_<commit>` directory name."""
    directory = utils.construct_repository_asset_directory_name(
        "https://github.com/org/repo.git",
        "a1a10cdbc6551ba359169a3033f193b7f8c1b95d",
    )

    assert directory == "repo_a1a10cdbc6551ba359169a3033f193b7f8c1b95d"


def testConstructRepositoryAssetDirectoryName_whenNoGitSuffix_returnsNameAndCommitHash() -> (
    None
):
    """A URL without a .git suffix keeps the full repository name."""
    directory = utils.construct_repository_asset_directory_name(
        "https://github.com/org/another-repo",
        "abc123",
    )

    assert directory == "another-repo_abc123"


@pytest.mark.parametrize(
    ("repository_url", "expected_repository_name"),
    [
        ("https://github.com/example-org/juice-shop-private", "juice-shop-private"),
        ("https://gitlab.com/example-user/juice-shop-private", "juice-shop-private"),
        ("https://bitbucket.org/example-user/juice-shop", "juice-shop"),
        (
            "https://example-org@dev.azure.com/example-org/test-project/_git/juice-shop",
            "juice-shop",
        ),
        ("git://git.example.com/example-org/juice-shop.git", "juice-shop"),
    ],
)
def testConstructRepositoryAssetDirectoryName_whenProviderUrlShapes_returnsNameAndCommitHash(
    repository_url: str, expected_repository_name: str
) -> None:
    """Supported repository provider URL shapes yield `<repository_name>_<commit_hash>`."""
    directory = utils.construct_repository_asset_directory_name(repository_url, "abc123")

    assert directory == f"{expected_repository_name}_abc123"


def testConstructRepositoryArchiveAssetDirectoryName_returnsSegmentAfterUploads() -> (
    None
):
    """The archive directory is the path segment immediately after `uploads`."""
    directory = utils.construct_repository_archive_asset_directory_name(
        "https://example.com/uploads/62f54a92-6d5f-4ce8-848e-adf13ff79fee"
    )

    assert directory == "62f54a92-6d5f-4ce8-848e-adf13ff79fee"


def testConstructRepositoryArchiveAssetDirectoryName_whenQueryParamsPresent_ignoresQuery() -> (
    None
):
    """Query parameters of the content url are ignored when building the directory."""
    directory = utils.construct_repository_archive_asset_directory_name(
        "https://example.com/uploads/cc3714/archive/main.zip?token=secret&expires=1"
    )

    assert directory == "cc3714"


@pytest.mark.parametrize(
    "content_url",
    [
        "https://example.com/archive/main.zip",
        "https://example.com/uploads",
        "https://example.com/uploads/",
    ],
)
def testConstructRepositoryArchiveAssetDirectoryName_whenInvalidUrl_raisesValueError(
    content_url: str,
) -> None:
    """Archive content URLs without `uploads/<id>` cannot identify the asset."""
    with pytest.raises(ValueError):
        utils.construct_repository_archive_asset_directory_name(content_url)
