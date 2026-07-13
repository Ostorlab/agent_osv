"""Unit tests for OSV service api."""

from unittest import mock

from pytest_mock import plugin

from agent.api_manager import osv_service_api


def testQueryOSVOutput_withPackage_returnListOfVulnerabilities(
    mocker: plugin.MockerFixture,
) -> None:
    """Send request to osv and get the vulnerabilities."""
    expected_output = {
        "vulns": [
            {
                "id": "GHSA-462w-v97r-4m45",
                "summary": "Jinja2 sandbox escape via string formatting",
            }
        ]
    }
    post_mock = mocker.patch(
        "agent.api_manager.osv_service_api.requests.post",
        return_value=mock.Mock(
            status_code=200, json=mock.Mock(return_value=expected_output)
        ),
    )

    osv_output = osv_service_api.query_osv_api(
        package_name="jinja2", version="2.4.1", ecosystem="PyPI"
    )

    assert osv_output == expected_output
    post_mock.assert_called_once_with(
        osv_service_api.OSV_ENDPOINT,
        json={"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}},
    )
    assert (
        any(
            "Jinja2 sandbox escape via string formatting" in vuln["summary"]
            for vuln in osv_output["vulns"]
        )
        is True
    )
