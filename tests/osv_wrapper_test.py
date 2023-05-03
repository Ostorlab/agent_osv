"""Unittests for OSV wrapper."""
import json

import pytest
from pytest_mock import plugin

from agent import osv_file_handler


def testGetFileType_withLockFilePath_returnFileType(valid_lock_file_path: str) -> None:
    osv_scanner_wrapper = osv_file_handler.OSVFileHandler(None, valid_lock_file_path)
    assert osv_scanner_wrapper.get_file_type() == ".lock"


def testGetFileType_withLockFileContent_returnFileType(
    mocker: plugin.MockerFixture, valid_lock_file_content: bytes
) -> None:
    from_buffer_mock = mocker.patch("agent.osv_file_handler.magic.from_buffer")
    from_buffer_mock.return_value = "text/plain"
    osv_scanner_wrapper = osv_file_handler.OSVFileHandler(valid_lock_file_content, None)
    assert osv_scanner_wrapper.get_file_type() == ".txt"


def testReadOutputFile_withValidFile_returnData(output_file: str) -> None:
    """Test read_output_file with a valid file"""
    data = osv_file_handler.read_output_file_as_dict(output_file)
    assert data == {"key": "value"}


def testReadOutputFile_withMissingFile_raiseFileNotFoundError() -> None:
    """Test read_output_file with a missing file"""
    with pytest.raises(FileNotFoundError):
        osv_file_handler.read_output_file_as_dict("nonexistent_file.json")


def testReadOutputFile_withInvalidFile_raiseJSONDecodeError(output_file: str) -> None:
    """Test read_output_file with a file containing invalid JSON"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("not JSON")
    with pytest.raises(json.JSONDecodeError):
        osv_file_handler.read_output_file_as_dict(output_file)


def testParseResults_withValidFile_returnData(osv_output: str) -> None:
    parsed_data = osv_file_handler.parse_results(osv_output)

    parsed_data_list = list(parsed_data)

    assert parsed_data_list[0].risk_rating.name == "HIGH"
    assert (
        "has a security issue in package `protobuf`"
        in parsed_data_list[0].technical_detail
    )
    assert "version `3.18.3`" in parsed_data_list[0].technical_detail


def testConstructTechnicalDetail_whenAllArgs_returnTechniclalDetail() -> None:
    package_name = "example-package"
    package_version = "1.0.0"
    file_type = "requirements.txt"
    vuln_aliases = ["CVE-2022-1234"]
    vuln_id = "VULN-123"

    expected_output = """The file `requirements.txt` has a security issue in package `example-package` with version
        `1.0.0`. The issue is identified by CVE
        `CVE-2022-1234`. We recommend updating `example-package` to the latest available version since
         this issue is fixed in version `VULN-123`."""

    technical_detail = osv_file_handler.construct_technical_detail(
        package_name,
        package_version,
        file_type,
        vuln_aliases,
        vuln_id,
    )

    assert technical_detail == expected_output
