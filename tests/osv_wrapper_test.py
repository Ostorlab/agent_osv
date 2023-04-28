"""Unittests for OSV wrapper."""
import json
import pathlib

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


def testParseResults_withValidFile_returnData() -> None:
    parsed_data = osv_file_handler.parse_results(
        f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_output.json"
    )

    parsed_data_list = list(parsed_data)

    assert parsed_data_list[0].risk_rating.name == "HIGH"
    assert "has a security issue at the package" in parsed_data_list[0].technical_detail
    assert "protobuf" in parsed_data_list[0].technical_detail
    assert "version `3.20.1`" in parsed_data_list[0].technical_detail
    assert "The issue ID `GHSA-8gq9-2x98-w8hf`" in parsed_data_list[0].technical_detail


def testConstructTechnicalDetail_whenAllArgs_returnTechniclalDetail() -> None:
    package_name = "example-package"
    package_version = "1.0.0"
    package_framework = "example-framework"
    file_type = "requirements.txt"
    vuln_aliases = ["CVE-2022-1234"]
    vuln_id = "VULN-123"

    expected_output = (
        "The file `requirements.txt` has a security issue at the package "
        "`example-package`,\n"
        "    version `1.0.0`, framework example-framework.\n"
        "    The issue ID `VULN-123`, CVE `CVE-2022-1234`."
    )
    assert (
        osv_file_handler.construct_technical_detail(
            package_name,
            package_version,
            package_framework,
            file_type,
            vuln_aliases,
            vuln_id,
        )
        == expected_output
    )
