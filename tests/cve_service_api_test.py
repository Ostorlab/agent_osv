"""Unittests for CVE service api."""
import re

import requests_mock as rq_mock
from pytest_mock import plugin

from agent import cve_service_api


def testGetCveData_withResponse_returnRiskRating() -> None:
    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-31402")

    assert cve_data.risk == "HIGH"
    assert (
        cve_data.description
        == "The dio package 4.0.0 for Dart allows CRLF injection if the attacker controls the HTTP method string, "
        "a different vulnerability than CVE-2020-35669."
    )
    assert cve_data.fixed_version == "5.0.0"
    assert cve_data.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def testGetCveData_whenException_returnDefaultValue(
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text="<html><body><h1>503 Service Unavailable</h1>"
        "\nNo server is available to handle this request.\n</body></html>\n",
    )
    mocker.patch("time.sleep")

    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-1234")

    assert cve_data.risk == "POTENTIALLY"


def testGetCveData_whenRateLimitException_waitFixedBeforeRetry(
    mocker: plugin.MockerFixture,
    requests_mock: rq_mock.mocker.Mocker,
) -> None:
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text="<html><body><h1>503 Service Unavailable</h1>"
        "\nNo server is available to handle this request.\n</body></html>\n",
    )
    time_mocked = mocker.patch("time.sleep")

    cve_service_api.get_cve_data_from_api("CVE-2021-1234")

    assert requests_mock.call_count == 10
    assert time_mocked.call_count == 9
    assert time_mocked.call_args_list[0][0][0] == 30.0


def testGetCveData_whenJsonDataIsMissingItems_ReturnDefault(
    requests_mock: rq_mock.mocker.Mocker,
    nvd_output: str,
) -> None:
    requests_mock.get(
        re.compile("https://services.nvd.nist.gov/.*"),
        text=nvd_output,
    )

    cve = cve_service_api.get_cve_data_from_api("CVE-2021-37713")

    assert requests_mock.call_count == 1
    assert cve.risk == "HIGH"
    assert cve.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
