"""Implementation of hotpatch due to known issues in OSV."""

import re


def hotpatch(path: str, content: bytes) -> tuple[str, bytes]:
    """Fix content to address known issues in OSV.

    Args:
        path: File path.
        content: File Content.

    Returns:
        Patched content and path.
    """
    # Link to issue https://github.com/google/osv-scanner/issues/1138.
    if path.lower() == "composer.lock":
        # Regex pattern to find "version": followed by a number and a comma
        pattern = rb'"version": (\d+),'

        # Replacement pattern with the number captured in quotes
        replacement = rb'"version": "\1",'
        content = re.sub(pattern, replacement, content)

    return path, content
