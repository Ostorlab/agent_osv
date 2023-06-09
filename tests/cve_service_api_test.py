"""Unittests for CVE service api."""
import requests
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


def testGetCveData_whenException_retrunDefaultValue(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch(
        "agent.cve_service_api.requests.get", side_effect=requests.ConnectionError
    )
    cve_data = cve_service_api.get_cve_data_from_api("CVE-2021-1234")
    assert cve_data.risk == "POTENTIALLY"
