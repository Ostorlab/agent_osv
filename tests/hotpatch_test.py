import pathlib
from agent import hotpatch


def testHotPatch_whenComposerHasIntVersion_replacesWithString():
    content = pathlib.Path("files/composer.lock").read_bytes()

    _, patch_content = hotpatch.hotpatch("composer.lock", content)
    assert b'"version": "20190220",' in patch_content
