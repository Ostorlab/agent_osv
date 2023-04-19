"""Unittests for OSV wrapper."""
import json

import pytest
from pytest_mock import plugin

from agent import osv_wrapper


def testOSVWrapper_withValidLockFile_returnTrue(valid_lock_file_content: bytes) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(valid_lock_file_content, None)
    assert osv_scanner_wrapper.is_valid_file() is True


def testOSVWrapper_withEmptyLockFile_returnFalse(
    invalid_lock_file_content: bytes,
) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(invalid_lock_file_content, None)
    assert osv_scanner_wrapper.is_valid_file() is False


def testOSVWrapper_withInvalidLockFile_returnFalse() -> None:
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(
        b"invalid_lock_file_content", "/invalid/lock/file/path.foo"
    )
    assert osv_scanner_wrapper.is_valid_file() is False


def testOSVWrapper_withLockFilePath_returnFileType(
    mocker: plugin.MockerFixture, valid_lock_file_path: str
) -> None:
    mock_splitext = mocker.patch("agent.osv_wrapper.os.path.splitext")
    mock_splitext.return_value = ("path", ".lock")
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(None, valid_lock_file_path)
    assert osv_scanner_wrapper.get_file_type() == ".lock"


def testOSVWrapper_withLockFileContent_returnFileType(
    mocker: plugin.MockerFixture, valid_lock_file_content: bytes
) -> None:
    from_buffer_mock = mocker.patch("agent.osv_wrapper.magic.from_buffer")
    from_buffer_mock.return_value = "text/plain"
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(valid_lock_file_content, None)
    assert osv_scanner_wrapper.get_file_type() == ".txt"


def testReadOutputFile_withValidFile_returnData(output_file):
    """Test read_output_file with a valid file"""
    data = osv_wrapper.read_output_file(output_file)
    assert data == {"key": "value"}


def testReadOutputFile_withMissingFile_raiseFileNotFoundError():
    """Test read_output_file with a missing file"""
    with pytest.raises(FileNotFoundError):
        osv_wrapper.read_output_file("nonexistent_file.json")


def testReadOutputFile_withInvalidFile_raiseJSONDecodeError(output_file):
    """Test read_output_file with a file containing invalid JSON"""
    with open(output_file, "w") as f:
        f.write("not JSON")
    with pytest.raises(json.JSONDecodeError):
        osv_wrapper.read_output_file(output_file)
