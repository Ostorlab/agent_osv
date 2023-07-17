"""Unittests for CVE service api."""
import re

import requests
import requests_mock as rq_mock
from pytest_mock import plugin

from agent import cve_service_api


def testGetCveData_withResponse_returnRiskRating(
        mocker: plugin.MockerFixture,
) -> None:
    cve_data = cve_service_api.CVE(
        risk="HIGH", description="description", fixed_version="2", cvss_v3_vector=None
    )

    mocker.patch("agent.cve_service_api.requests.get")
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-12345")
    assert cve_data.risk == "HIGH"


def testGetCveData_whenException_returnDefaultValue(
        mocker: plugin.MockerFixture,
) -> None:
    mocker.patch(
        "agent.cve_service_api.requests.get", side_effect=requests.ConnectionError
    )
    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-1234")
    assert cve_data.risk == "POTENTIALLY"


def testGetCveData_whenRateLimitException_waitFixedBeforeRetry(
        mocker: plugin.MockerFixture,
        requests_mock: rq_mock.mocker.Mocker,
) -> None:
    # mock all https://services.nvd.nist.gov/* requests
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
