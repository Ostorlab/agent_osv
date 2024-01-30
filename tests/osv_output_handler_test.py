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
