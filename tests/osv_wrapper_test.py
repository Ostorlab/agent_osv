"""Unittests for OSV wrapper."""
import json
import pathlib

import pytest
from pytest_mock import plugin

from agent import osv_wrapper


def testOSVWrapper_withValidLockFile_returnTrue(valid_lock_file_content: bytes) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(valid_lock_file_content, None)
    assert osv_scanner_wrapper.validate_and_set_lock_file_extension() is True


def testOSVWrapper_withEmptyLockFile_returnFalse(
    invalid_lock_file_content: bytes,
) -> None:
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(invalid_lock_file_content, None)
    assert osv_scanner_wrapper.validate_and_set_lock_file_extension() is False


def testOSVWrapper_withInvalidLockFile_returnFalse() -> None:
    osv_scanner_wrapper = osv_wrapper.OSVWrapper(
        b"invalid_lock_file_content", "/invalid/lock/file/path.foo"
    )
    assert osv_scanner_wrapper.validate_and_set_lock_file_extension() is False


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


def testReadOutputFile_withValidFile_returnData(output_file: str) -> None:
    """Test read_output_file with a valid file"""
    data = osv_wrapper.read_output_file(output_file)
    assert data == {"key": "value"}


def testReadOutputFile_withMissingFile_raiseFileNotFoundError() -> None:
    """Test read_output_file with a missing file"""
    with pytest.raises(FileNotFoundError):
        osv_wrapper.read_output_file("nonexistent_file.json")


def testReadOutputFile_withInvalidFile_raiseJSONDecodeError(output_file: str) -> None:
    """Test read_output_file with a file containing invalid JSON"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("not JSON")
    with pytest.raises(json.JSONDecodeError):
        osv_wrapper.read_output_file(output_file)


def testParseResults_withValidFile_returnData() -> None:
    parsed_data = osv_wrapper.parse_results(
        f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_output.json"
    )

    parsed_data_list = list(parsed_data)

    assert parsed_data_list[0].risk_rating.name == "HIGH"
    assert "has a security issue at the package" in parsed_data_list[0].technical_detail
    assert "protobuf" in parsed_data_list[0].technical_detail
    assert "version `3.20.1`" in parsed_data_list[0].technical_detail
    assert "The issue ID `GHSA-8gq9-2x98-w8hf`" in parsed_data_list[0].technical_detail
