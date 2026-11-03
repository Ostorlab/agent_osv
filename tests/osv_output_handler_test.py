from typing import Any

from pytest_mock import plugin

from agent import cve_service_api, osv_output_handler


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
    cves_data = osv_output_handler.parse_vulnerabilities_osv_api(
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


def testParseVulnerabilitiesOsvBinary_withMultipleAdvisories_returnOneVulnData(
    mocker: plugin.MockerFixture,
) -> None:
    """Combine all advisories affecting one package into one vulnerability."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "package": {"name": "flatted", "version": "3.3.3"},
        "vulnerabilities": [
            {
                "aliases": ["CVE-2026-32141"],
                "database_specific": {"severity": "MODERATE"},
                "summary": "Moderate advisory",
                "severity": [{"score": "CVSS:3.1/AV:L"}],
                "affected": [{"ranges": [{"events": [{}, {"fixed": "3.4.0"}]}]}],
                "references": [{"type": "WEB", "url": "https://example.com/1"}],
            },
            {
                "aliases": ["CVE-2026-32141", "CVE-2026-33228"],
                "database_specific": {"severity": "HIGH"},
                "summary": "High advisory",
                "severity": [{"score": "CVSS:3.1/AV:N"}],
                "affected": [{"ranges": [{"events": [{}, {"fixed": "3.5.0"}]}]}],
                "references": [{"type": "WEB", "url": "https://example.com/2"}],
            },
        ],
    }

    parsed_vulnerabilities = osv_output_handler.parse_vulnerabilities_osv_binary(
        output,
        file_type="npm",
        file_name="package-lock.json",
    )

    assert len(parsed_vulnerabilities) == 1
    vulnerability = parsed_vulnerabilities[0]
    assert vulnerability.package_name == "flatted"
    assert vulnerability.package_version == "3.3.3"
    assert vulnerability.cves == ["CVE-2026-32141", "CVE-2026-33228"]
    assert vulnerability.risk == "HIGH"
    assert vulnerability.summary == "High advisory"
    assert vulnerability.cvss_v3_vector == "CVSS:3.1/AV:N"
    assert vulnerability.fixed_version == "3.5.0"
    assert vulnerability.references == [
        {"type": "WEB", "url": "https://example.com/1"},
        {"type": "WEB", "url": "https://example.com/2"},
    ]
    assert "CVE-2026-32141" in vulnerability.description
    assert "CVE-2026-33228" in vulnerability.description
    assert vulnerability.description.count("- [CVE-2026-32141]") == 1
    assert "CVE description\n- [CVE-2026-33228]" in vulnerability.description
    assert vulnerability.file_type == "npm"
    assert vulnerability.file_name == "package-lock.json"


def testParseVulnerabilitiesOsvBinary_withCveLessAdvisory_includeItsDetails(
    mocker: plugin.MockerFixture,
) -> None:
    """Explain an advisory when it determines risk but has no CVE alias."""
    cve_data = cve_service_api.CVE(
        risk="LOW",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "package": {"name": "example", "version": "1.0.0"},
        "vulnerabilities": [
            {
                "aliases": ["CVE-2026-10000"],
                "database_specific": {"severity": "LOW"},
                "summary": "Low CVE",
            },
            {
                "id": "GHSA-1111-2222-3333",
                "details": "Advisory without a CVE alias.",
                "database_specific": {"severity": "HIGH"},
                "summary": "High GHSA",
            },
        ],
    }

    vulnerability = osv_output_handler.parse_vulnerabilities_osv_binary(output)[0]

    assert vulnerability.risk == "HIGH"
    assert vulnerability.summary == "High GHSA"
    assert (
        "- GHSA-1111-2222-3333 : Advisory without a CVE alias."
        in vulnerability.description
    )


def testParseVulnerabilitiesOsvBinary_withInvalidFixedVersion_keepValidVersions(
    mocker: plugin.MockerFixture,
) -> None:
    """Ignore unparseable fixes without discarding valid semantic versions."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "package": {"name": "example", "version": "1.0.0"},
        "vulnerabilities": [
            {
                "aliases": ["CVE-2026-10000"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{}, {"fixed": "3.5.0"}]}]}],
            },
            {
                "aliases": ["CVE-2026-20000"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{}, {"fixed": "release-4"}]}]}],
            },
        ],
    }

    vulnerability = osv_output_handler.parse_vulnerabilities_osv_binary(output)[0]

    assert vulnerability.fixed_version == "3.5.0"


def testParseVulnerabilitiesOsvBinary_withoutFixedVersions_doesNotLogError(
    mocker: plugin.MockerFixture,
) -> None:
    """Treat the absence of a published fix as a routine condition."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    logger_error_mock = mocker.patch("agent.osv_output_handler.logger.error")
    output = {
        "package": {"name": "example", "version": "1.0.0"},
        "vulnerabilities": [
            {
                "aliases": ["CVE-2026-10000"],
                "database_specific": {"severity": "HIGH"},
            }
        ],
    }

    vulnerability = osv_output_handler.parse_vulnerabilities_osv_binary(output)[0]

    assert vulnerability.fixed_version == ""
    logger_error_mock.assert_not_called()


def testParseVulnerabilitiesOsvApi_whenAffectedListsForeignPackages_usesQueriedPackage(
    mocker: plugin.MockerFixture,
) -> None:
    """A record's first affected entry can describe another package (a distro
    build of a bundled framework); only the queried package's endpoints feed
    the recommendation.

    Reproduced from the live OSV no-ecosystem response for opencv: the
    UBUNTU-CVE-2020-11022 record lists ``drupal7`` before ``jquery``, and the
    old first-entry reader fed the drupal7 distro version into jquery's
    aggregate."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "vulns": [
            {
                "aliases": ["CVE-2020-11022"],
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {
                            "ecosystem": "Ubuntu:Pro:14.04:LTS",
                            "name": "drupal7",
                        },
                        "ranges": [
                            {"events": [{"introduced": "0"}, {"fixed": "7.26-1"}]}
                        ],
                    },
                    {
                        "package": {"ecosystem": "npm", "name": "jquery"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "1.12.0"},
                                    {"fixed": "3.5.0"},
                                ],
                            }
                        ],
                    },
                ],
            }
        ]
    }

    parsed = osv_output_handler.parse_vulnerabilities_osv_api(
        output, package_name="jquery", package_version="2.2.0"
    )

    assert parsed[0].fixed_version == "3.5.0"


def testParseVulnerabilitiesOsvApi_whenAffectedHasSeveralRanges_collectsCoveringInterval(
    mocker: plugin.MockerFixture,
) -> None:
    """An advisory with two affected intervals names the fix of each branch;
    the recommendation must use the interval covering the detected version.

    Reproduced from GHSA-rmxg-73gg-4p98 (CVE-2015-9251, jquery): the npm
    entry carries [0, 1.12.2) and [1.12.3, 3.0.0). For a detected 2.2.0 only
    the second interval covers; the old first-range reader returned 1.12.2 —
    a version the installed 2.2.0 already exceeds, so the recommendation was
    satisfied by the vulnerable installation itself."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "vulns": [
            {
                "aliases": ["CVE-2015-9251"],
                "database_specific": {"severity": "MODERATE"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "jquery"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "1.12.2"},
                                    {"introduced": "1.12.3"},
                                    {"fixed": "3.0.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    parsed = osv_output_handler.parse_vulnerabilities_osv_api(
        output, package_name="jquery", package_version="2.2.0"
    )

    assert parsed[0].fixed_version == "3.0.0"


def testParseVulnerabilitiesOsvApi_whenDistroFormatFixedVersionsPresent_keepsSemverAggregate(
    mocker: plugin.MockerFixture,
) -> None:
    """A distro-format fixed version (3.4.6-6.el8, 3.1.1-2+deb9u2) must not
    wipe the recommendation for the whole package.

    The old aggregate was a single max() over semver.Version.parse that
    raised on the first distro string and degraded every CVE's
    recommendation to "latest available version" — the behaviour the live
    opencv query demonstrates."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "vulns": [
            {
                "aliases": ["CVE-2026-10001"],
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "AlmaLinux:8", "name": "opencv"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "3.4.6-6.el8"},
                                ],
                            }
                        ],
                    }
                ],
            },
            {
                "aliases": ["CVE-2019-10061"],
                "database_specific": {"severity": "CRITICAL"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "opencv"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "6.1.0"}],
                            }
                        ],
                    }
                ],
            },
        ]
    }

    parsed = osv_output_handler.parse_vulnerabilities_osv_api(
        output, package_name="opencv", package_version="3.4.0"
    )

    assert parsed[0].fixed_version == "6.1.0"


def testParseVulnerabilitiesOsvApi_whenCoveringIntervalClosesWithLastAffected_namesNoFix(
    mocker: plugin.MockerFixture,
) -> None:
    """A covering interval that closes with last_affected names no safe
    version: the recommendation must fall back to the latest available
    version rather than an endpoint that does not cover it."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "vulns": [
            {
                "aliases": ["CVE-2020-28500"],
                "database_specific": {"severity": "LOW"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash.trimend"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"last_affected": "4.5.1"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    parsed = osv_output_handler.parse_vulnerabilities_osv_api(
        output, package_name="lodash.trimend", package_version="4.5.0"
    )

    assert parsed[0].fixed_version == ""


def testParseVulnerabilitiesOsvApi_whenEcosystemGiven_ignoresOtherEcosystemEntries(
    mocker: plugin.MockerFixture,
) -> None:
    """The ecosystem the query was scoped to filters the affected entries:
    the same record's NuGet entry must not feed an npm query."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="CVE description",
        fixed_version=None,
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    output = {
        "vulns": [
            {
                "aliases": ["CVE-2015-9251"],
                "database_specific": {"severity": "MODERATE"},
                "affected": [
                    {
                        "package": {"ecosystem": "NuGet", "name": "jQuery"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "1.12.2"}],
                            },
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "1.12.3"},
                                    {"fixed": "3.0.0"},
                                ],
                            },
                        ],
                    },
                    {
                        "package": {"ecosystem": "npm", "name": "jquery"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "3.0.0"}],
                            }
                        ],
                    },
                ],
            }
        ]
    }

    parsed = osv_output_handler.parse_vulnerabilities_osv_api(
        output,
        package_name="jquery",
        package_version="2.2.0",
        ecosystem="npm",
    )

    assert parsed[0].fixed_version == "3.0.0"


def testWhitelistVulnz_whenMatchIsNotTheFirstAffectedEntry_keepsVuln() -> None:
    """A record whose first affected entry belongs to a non-whitelisted
    ecosystem but that also lists a whitelisted one must be kept: the old
    first-entry check dropped it.

    Reproduced from the live OSV response for a MACHO_LIBRARY-typed jquery
    fingerprint: the Debian entry of a record is rarely the first one."""
    vulnerabilities = [
        {
            "id": "GHSA-6c3j-c64m-qhgq",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "jquery"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.4.0"}]}],
                },
                {
                    "package": {"ecosystem": "Debian:11", "name": "jquery"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "3.5.1+dfsg-1"}]}
                    ],
                },
            ],
        }
    ]

    whitelisted = osv_output_handler._whitelist_vulnz_from_ecosystems(
        vulnerabilities, ["Debian:11"]
    )

    assert len(whitelisted) == 1
