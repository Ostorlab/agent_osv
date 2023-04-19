"""Unittests for CVE service api."""

import requests

from agent import cve_service_api
from pytest_mock import plugin


def testGetCveRiskRating_withResponse_returnRiskRating(
    mocker: plugin.MockerFixture,
) -> None:
    cve_data = {
        "result": {
            "CVE_Items": [
                {"impact": {"baseMetricV3": {"cvssV3": {"baseSeverity": "HIGH"}}}}
            ]
        }
    }

    mocker.patch("agent.cve_service_api.requests.get")
    mocker.patch("agent.cve_service_api.json.loads", return_value=cve_data)

    assert cve_service_api.get_cve_risk_rating("CVE-2021-12345") == "HIGH"


def testGetCveRiskRating_withoutResponseError_returnRiskRating(
    mocker: plugin.MockerFixture,
) -> None:
    with mocker.patch(
        "agent.cve_service_api.requests.get",
        side_effect=requests.exceptions.RequestException,
    ):
        assert cve_service_api.get_cve_risk_rating("CVE-2021-12345") is None
