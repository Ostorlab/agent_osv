"""Unit tests for OSV service api."""
from typing import Any

from agent.api_manager import osv_service_api


def testQueryOSVOutput_withPackage_returnListOfVulnerabilities() -> None:
    """Send request to osv and get the vulnerabilities."""
    osv_output = osv_service_api.query_osv_api(
        package_name="jinja2", version="2.4.1", ecosystem="PyPI"
    )

    assert osv_output is not None
    assert isinstance(osv_output, dict) is True
    assert len(osv_output["vulns"]) == 11
    assert any(
        "Jinja2 sandbox escape via string formatting" in vuln["summary"]
        for vuln in osv_output["vulns"]
    )


def testPasrseOSVOutput_withValidResponse_returnListOfVulnzData(
    osv_api_output: dict[str, Any],
) -> None:
    """Parse the output of osv api call."""
    cves_data = osv_service_api.parse_output(osv_api_output)

    assert len(cves_data) == 7
    assert cves_data[0].risk == "LOW"
    assert cves_data[0].fixed_version == "4.17.5"
    assert (
        "Versions of `lodash` before 4.17.5 are vulnerable to prototype pollution. "
        in cves_data[0].description
    )
    assert cves_data[1].risk == "HIGH"
    assert cves_data[1].fixed_version == "4.17.11"
    assert cves_data[6].risk == "HIGH"
    assert (
        cves_data[6].description
        == "`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function."
    )
