"""Unittests for the asset directory utils."""

from agent import utils


def testBuildRepositoryAssetDirectory_whenGitUrl_returnsNameAndCommitHash() -> None:
    """A .git URL produces a `<repo>_<commit>` directory name."""
    directory = utils.build_repository_asset_directory(
        "https://github.com/org/repo.git",
        "a1a10cdbc6551ba359169a3033f193b7f8c1b95d",
    )

    assert directory == "repo_a1a10cdbc6551ba359169a3033f193b7f8c1b95d"


def testBuildRepositoryAssetDirectory_whenNoGitSuffix_returnsNameAndCommitHash() -> (
    None
):
    """A URL without a .git suffix keeps the full repository name."""
    directory = utils.build_repository_asset_directory(
        "https://github.com/org/another-repo",
        "abc123",
    )

    assert directory == "another-repo_abc123"


def testBuildRepositoryArchiveAssetDirectory_returnsLastPathSegment() -> None:
    """The archive directory is the last path segment of the content url."""
    directory = utils.build_repository_archive_asset_directory(
        "https://storage.googleapis.com/ostorlabapps/uploads/"
        "62f54a92-6d5f-4ce8-848e-adf13ff79fee"
    )

    assert directory == "62f54a92-6d5f-4ce8-848e-adf13ff79fee"


def testBuildRepositoryArchiveAssetDirectory_whenQueryParamsPresent_ignoresQuery() -> (
    None
):
    """Query parameters of the content url are ignored when building the directory."""
    directory = utils.build_repository_archive_asset_directory(
        "https://storage.googleapis.com/ostorlabapps/uploads/"
        "62f54a92-6d5f-4ce8-848e-adf13ff79fee?token=secret&expires=1"
    )

    assert directory == "62f54a92-6d5f-4ce8-848e-adf13ff79fee"
