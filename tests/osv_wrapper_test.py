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
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1941"
        in parsed_data_list[0].technical_detail
    )
    assert (
        "We recommend upgrading to versions 3.18.3, 3.19.5, 3.20.2, 3.21.6"
        in parsed_data_list[0].technical_detail
    )
    assert len(parsed_data_list[0].entry.references) == 7
    assert (
        "https://nvd.nist.gov/vuln/detail/CVE-2022-1941"
        in parsed_data_list[0].entry.references
    )
    assert (
        "We recommend updating `protobuf` to the latest available version."
        in parsed_data_list[0].entry.recommendation
    )


def testParseResults_withFileMissingCVE_returnData(
    fake_osv_output_missing_cve: str,
) -> None:
    parsed_data = osv_output_handler.parse_results(fake_osv_output_missing_cve)
    parsed_data_list = list(parsed_data)

    assert len(parsed_data_list) == 2
    assert parsed_data_list[0].risk_rating.name == "HIGH"
    assert (
        "Use of Outdated Vulnerable Component: dio@4.0.6: CVE-2021-31402"
        in parsed_data_list[0].entry.title
    )
    assert "4.0.0" in parsed_data_list[0].technical_detail
    assert len(parsed_data_list[0].entry.references) == 7
    assert (
        "https://nvd.nist.gov/vuln/detail/CVE-2021-31402"
        in parsed_data_list[0].entry.references
    )
    assert (
        "We recommend updating `dio` to the latest available version."
        in parsed_data_list[0].entry.recommendation
    )
    assert (
        "Use of Outdated Vulnerable Component: dio@4.0.6: CVE-2021-31402"
        in parsed_data_list[1].entry.title
    )
    assert "5.0.0" in parsed_data_list[1].technical_detail
