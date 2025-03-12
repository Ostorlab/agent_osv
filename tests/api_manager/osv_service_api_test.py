"""Unit tests for OSV service api."""

from agent.api_manager import osv_service_api


def testQueryOSVOutput_withPackage_returnListOfVulnerabilities() -> None:
    """Send request to osv and get the vulnerabilities."""
    osv_output = osv_service_api.query_osv_api(
        package_name="jinja2", version="2.4.1", ecosystem="PyPI"
    )

    assert osv_output is not None
    assert isinstance(osv_output, dict) is True
    assert len(osv_output["vulns"]) == 14
    assert (
        any(
            "Jinja2 sandbox escape via string formatting" in vuln["summary"]
            for vuln in osv_output["vulns"]
        )
        is True
    )
