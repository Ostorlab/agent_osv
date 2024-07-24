import pathlib
from agent import hotpatch


def testHotPatch_whenComposerHasIntVersion_replacesWithString() -> None:
    content = (
        pathlib.Path(__file__).parent.parent / "tests/files/composer.lock"
    ).read_bytes()

    _, patch_content = hotpatch.hotpatch("composer.lock", content)
    assert b'"version": "20190220",' in patch_content
