import mimetypes
import os

import magic


def get_file_type(content: bytes, path: str | None) -> str:
    if path is not None and len(os.path.splitext(path)[1]) >= 2:
        return os.path.splitext(path)[1]

    mime = magic.from_buffer(content, mime=True)
    return mimetypes.guess_extension(mime)
