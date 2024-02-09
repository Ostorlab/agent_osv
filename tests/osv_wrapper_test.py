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
    parsed_data = osv_output_handler.parse_osv_output(fake_osv_output)
    parsed_data_list = list(parsed_data)

    assert parsed_data_list[0].risk == "HIGH"
    assert len(parsed_data_list[0].references) == 7
    assert parsed_data_list[0].cves == ["CVE-2022-1941"]
    assert (
        "A message parsing and memory management vulnerability in ProtocolBuffer’s C++ and Python implementations can trigger an out of memory (OOM) failure when processing a specially crafted message"
        in parsed_data_list[0].description
    )
    assert parsed_data_list[0].fixed_version == "3.18.3"
    assert parsed_data_list[0].package_version == "3.20.1"
    assert parsed_data_list[0].package_name == "protobuf"
    assert (
        parsed_data_list[0].summary
        == "protobuf-cpp and protobuf-python have potential Denial of Service issue"
    )


def testParseResults_withFileMissingCVE_returnData(
    fake_osv_output_missing_cve: str,
) -> None:
    parsed_data = osv_output_handler.parse_osv_output(fake_osv_output_missing_cve)
    parsed_data_list = list(parsed_data)

    assert parsed_data_list[0].risk == "HIGH"
    assert len(parsed_data_list[0].references) == 7
    assert parsed_data_list[0].cves == ["CVE-2021-31402"]
    assert (
        "The dio package 4.0.0 for Dart allows CRLF injection if the attacker controls the HTTP method string, a different vulnerability than CVE-2020-35669."
        in parsed_data_list[0].description
    )
    assert parsed_data_list[0].fixed_version == "5.0.0"
    assert parsed_data_list[0].package_version == "4.0.6"
    assert parsed_data_list[0].package_name == "dio"
    assert (
        parsed_data_list[0].summary
        == "dio vulnerable to CRLF injection with HTTP method string"
    )
