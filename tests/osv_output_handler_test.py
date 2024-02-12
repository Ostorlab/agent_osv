from typing import Any

from agent import osv_output_handler


def testBuildReferences_always_returnReferencesFromTheOsvOutput() -> None:
    """Test that the references are built correctly."""
    references = [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-3721"},
        {
            "type": "WEB",
            "url": "https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a",
        },
        {"type": "WEB", "url": "https://hackerone.com/reports/310443"},
        {
            "type": "ADVISORY",
            "url": "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
        },
        {
            "type": "WEB",
            "url": "https://security.netapp.com/advisory/ntap-20190919-0004/",
        },
        {"type": "WEB", "url": "https://www.npmjs.com/advisories/577"},
    ]

    built_references = osv_output_handler.build_references(references)

    assert built_references == {
        "https://nvd.nist.gov/vuln/detail/CVE-2018-3721": "https://nvd.nist.gov/vuln/detail/CVE-2018-3721",
        "https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a": "https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a",
        "https://hackerone.com/reports/310443": "https://hackerone.com/reports/310443",
        "https://github.com/advisories/GHSA-fvqr-27wr-82fm": "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
        "https://security.netapp.com/advisory/ntap-20190919-0004/": "https://security.netapp.com/advisory/ntap-20190919-0004/",
        "https://www.npmjs.com/advisories/577": "https://www.npmjs.com/advisories/577",
    }


def testPasrseOSVOutput_withValidResponse_returnListOfVulnzData(
    osv_api_output: dict[str, Any],
) -> None:
    """Parse the output of osv api call."""
    cves_data = osv_output_handler.parse_api_vulnerabilities(
        osv_api_output, package_name="lodash", package_version="4.10.0"
    )

    assert len(cves_data) == 1
    assert cves_data[0].risk == "CRITICAL"
    assert cves_data[0].fixed_version == "4.17.21"
    assert (
        """- [CVE-2018-3721](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3721) : Versions of `lodash` before 4.17.5 are vulnerable to prototype pollution. 

The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith' which allow a malicious user to modify the prototype of `Object` via `__proto__` causing the addition or modification of an existing property that will exist on all objects.
"""
        in cves_data[0].description
    )
