"""Unittests for OSV wrapper."""
import json

import pytest

from agent import osv_output_handler


def testReadOutputFile_withValidFile_returnData(output_file: str) -> None:
    """Test read_output_file with a valid file"""
    data = osv_output_handler.read_output_file_as_dict(output_file)
    assert data == {"key": "value"}


def testReadOutputFile_withMissingFile_raiseFileNotFoundError() -> None:
    """Test read_output_file with a missing file"""
    with pytest.raises(FileNotFoundError):
        osv_output_handler.read_output_file_as_dict("nonexistent_file.json")


def testReadOutputFile_withInvalidFile_raiseJSONDecodeError(
    output_file: str,
) -> None:
    """Test read_output_file with a file containing invalid JSON"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("not JSON")
    with pytest.raises(json.JSONDecodeError):
        osv_output_handler.read_output_file_as_dict(output_file)


def testParseResults_withValidFile_returnData(fake_osv_output: str) -> None:
    parsed_data = osv_output_handler.parse_results(fake_osv_output)

    parsed_data_list = list(parsed_data)

    assert parsed_data_list[0].risk_rating.name == "HIGH"
    assert (
        "Dependency `protobuf` with version `3.20.1` found in `lockfile` has a "
        "security issue. The issue `protobuf-cpp and protobuf-python have potential "
        "Denial of Service issue` is identified by CVE `CVE-2022-1941`.\n"
        " The issue was fixed in version `3.18.3`."
    ) in parsed_data_list[0].technical_detail
    assert "version `3.18.3`" in parsed_data_list[0].technical_detail


def testConstructTechnicalDetail_whenAllArgs_returnTechnicalDetail() -> None:
    package_name = "example-package"
    package_version = "1.0.0"
    file_type = "requirements.txt"
    vuln_aliases = ["CVE-2022-1234"]
    vuln_id = "VULN-123"

    expected_output = (
        "Dependency `example-package` with version `1.0.0` found in "
        "`requirements.txt` has a security issue. The issue `Summary of the issue` is "
        "identified by CVE `CVE-2022-1234`.\n"
        " The issue was fixed in version `VULN-123`."
    )

    technical_detail = osv_output_handler.construct_technical_detail(
        package_name,
        package_version,
        file_type,
        vuln_aliases,
        vuln_id,
        summary="Summary of the issue",
    )

    assert technical_detail == expected_output
