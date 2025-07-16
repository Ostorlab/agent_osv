"""Unittests for OSV agent."""

import subprocess
from typing import Callable, Any

import requests_mock as rq_mock
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import cve_service_api
from agent import osv_agent
from agent.api_manager import osv_service_api


def testAgentOSV_whenAnalysisRunsWithoutPathWithContent_processMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
    osv_output_as_dict: dict[str, str],
    fake_osv_output: str,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="description",
        fixed_version="2",
        cvss_v3_vector=None,
    )

    subprocess_mock = mocker.patch(
        "agent.osv_agent._run_command", return_value=fake_osv_output
    )
    mocker.patch(
        "agent.osv_output_handler.read_output_file_as_dict",
        return_value=osv_output_as_dict,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")

    test_agent.process(scan_message_file)

    assert "/usr/local/bin/osv-scanner --format json --lockfile" in " ".join(
        subprocess_mock.call_args.args[0]
    )
    assert len(agent_mock) > 0
    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: protobuf@3.20.1: CVE-2022-1941"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: protobuf@3.20.1: CVE-2022-1941"
    )
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert agent_mock[0].data.get("vulnerability_location") is not None
    assert "package_lock.json" in agent_mock[0].data.get(
        "vulnerability_location", {}
    ).get("file", {}).get("path", "")


def testAgentOSV_whenAnalysisRunsWithoutURL_processMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_link: message.Message,
    mocker: plugin.MockerFixture,
    osv_output_as_dict: dict[str, str],
    fake_osv_output: str,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs with a link and without errors and yields vulnerabilities.
    """
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="description",
        fixed_version="2",
        cvss_v3_vector=None,
    )

    subprocess_mock = mocker.patch(
        "agent.osv_agent._run_command", return_value=fake_osv_output
    )
    mocker.patch(
        "agent.osv_output_handler.read_output_file_as_dict",
        return_value=osv_output_as_dict,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")

    test_agent.process(scan_message_link)

    assert "/usr/local/bin/osv-scanner --format json --lockfile" in " ".join(
        subprocess_mock.call_args.args[0]
    )
    assert len(agent_mock) > 0
    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: protobuf@3.20.1: CVE-2022-1941"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: protobuf@3.20.1: CVE-2022-1941"
    )
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert agent_mock[0].data.get("vulnerability_location") is not None
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("domain_name", {})
        .get("name")
        == "rexel.com"
    )


def testAgentOSV_whenAnalysisRunsWithBadFile_noCrash(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_bad_file: message.Message,
    mocker: plugin.MockerFixture,
    osv_output_as_dict: dict[str, str],
    fake_osv_output: str,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="description",
        fixed_version="2",
        cvss_v3_vector=None,
    )

    subprocess_mock = mocker.patch(
        "agent.osv_agent._run_command", return_value=fake_osv_output
    )
    mocker.patch(
        "agent.osv_output_handler.read_output_file_as_dict",
        return_value=osv_output_as_dict,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")

    test_agent.process(scan_message_bad_file)

    assert "/usr/local/bin/osv-scanner --format json --lockfile" in " ".join(
        subprocess_mock.call_args.args[0]
    )
    assert len(agent_mock) > 0


def testAgentOSV_whenAnalysisRunsWithoutPathWithoutContent_notProcessMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    empty_scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    subprocess_mock = mocker.patch("agent.osv_agent._run_command")
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")

    test_agent.process(empty_scan_message_file)

    assert subprocess_mock.call_count == 0
    assert len(agent_mock) == 0


def testAgentOSV_whenAnalysisRunsWithInvalidFile_notProcessMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    invalid_scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    subprocess_mock = mocker.patch("agent.osv_agent._run_command")
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")

    test_agent.process(invalid_scan_message_file)

    assert subprocess_mock.call_count == 0
    assert len(agent_mock) == 0


def testAgentOSV_whenAnalysisRunsWithBlackListedFile_notProcessMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    blacklisted_scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    subprocess_mock = mocker.patch("agent.osv_agent._run_command")

    test_agent.process(blacklisted_scan_message_file)

    assert subprocess_mock.call_count == 0
    assert len(agent_mock) == 0


def testAgentOSV_whenAnalysisRunsWithBlackListedContent_notProcessMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    blacklisted_scan_message_content: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    subprocess_mock = mocker.patch("agent.osv_agent._run_command")

    test_agent.process(blacklisted_scan_message_content)

    assert subprocess_mock.call_count == 0
    assert len(agent_mock) == 0


def testAgentOSV_whenAnalysisRunsWithNoFileName_shouldBruteForceTheName(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file_no_name: message.Message,
    mocker: plugin.MockerFixture,
    mocked_osv_scanner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    mocker.patch("time.sleep")
    mocker.patch("subprocess.run", mocked_osv_scanner)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")

    test_agent.process(scan_message_file_no_name)

    assert len(agent_mock) == 1


def testAgentOSV_withContentUrl_shouldDownloadFileContentAndBrutForceTheFileName(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    requests_mock: rq_mock.mocker.Mocker,
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_file_content_url: message.Message,
    mocker: plugin.MockerFixture,
    mocked_osv_scanner: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the osv analysis runs without a path provided and without errors and yields vulnerabilities.
    """
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="description",
        fixed_version="2",
        cvss_v3_vector=None,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    mocker.patch("subprocess.run", mocked_osv_scanner)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")
    mocked_requests = requests_mock.get(
        "https://ostorlab.co/requirements.txt", content=b"ostorlab"
    )
    test_agent.process(scan_message_file_content_url)

    assert len(agent_mock) == 1
    assert mocked_requests.call_count == 1


def testAgentOSV_whenFingerprintMessage_processMessage(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    osv_api_output: dict[str, Any],
) -> None:
    """Unit test for the full life cycle of the agent:
    case where the osv scan a package.
    """
    mocker.patch(
        "agent.api_manager.osv_service_api.query_osv_api", return_value=osv_api_output
    )
    selector = "v3.fingerprint.file.library"
    msg_data = {"library_name": "lodash", "library_version": "4.7.11"}
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, CVE-2019-10744, CVE-2019-1010266, CVE-2018-3721, CVE-2018-16487"
    )
    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2021-23337,CVE-2020-8203,CVE-2020-28500,CVE-2019-10744,CVE-2019-1010266,CVE-2018-3721,CVE-2018-16487"
    )


def testAgentOSV_whenRiskLowerCase_doesNotCrash(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    osv_api_output_risk_lower: dict[str, Any],
) -> None:
    """Ensure that the agent does not crash when the risk is in lowercase."""
    mocker.patch(
        "agent.api_manager.osv_service_api.query_osv_api",
        return_value=osv_api_output_risk_lower,
    )
    selector = "v3.fingerprint.file.library"
    msg_data = {"library_name": "lodash", "library_version": "4.7.11"}
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, CVE-2019-10744, CVE-2019-1010266, CVE-2018-3721, CVE-2018-16487"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2021-23337,CVE-2020-8203,CVE-2020-28500,CVE-2019-10744,CVE-2019-1010266,CVE-2018-3721,CVE-2018-16487"
    )

    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert (
        """- [CVE-2018-3721](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3721) : Versions of `lodash` before 4.17.5 are vulnerable to prototype pollution. 

The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith' which allow a malicious user to modify the prototype of `Object` via `__proto__` causing the addition or modification of an existing property that will exist on all objects.
"""
    ) in agent_mock[0].data["technical_detail"]

    assert (
        """Recommendation: Update to version 4.17.5 or later.
- [CVE-2018-16487](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16487) : Versions of `lodash` before 4.17.11 are vulnerable to prototype pollution. 

The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith' which allow a malicious user to modify the prototype of `Object` via `{constructor: {prototype: {...}}}` causing the addition or modification of an existing property that will exist on all objects."""
    ) in agent_mock[0].data["technical_detail"]
    assert agent_mock[0].data["short_description"] == "Prototype Pollution in lodash"
    assert agent_mock[0].data["description"] == (
        """Dependency `lodash` with version `4.7.11` has a security issue.
The issue is identified by CVEs: `CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, CVE-2019-10744, CVE-2019-1010266, CVE-2018-3721, CVE-2018-16487`."""
    )


def testAgentOSV_whenMultipleVulns_groupByFingerprint(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    osv_api_output_risk_missing: dict[str, Any],
) -> None:
    """Ensure that the agent does not crash when the risk is missing and default to potentially."""
    mocker.patch(
        "agent.api_manager.osv_service_api.query_osv_api",
        return_value=osv_api_output_risk_missing,
    )

    class MockCveData:
        risk = "CRITICAL"

        def __init__(self, cve_id: str, api_key: str | None = None):
            del cve_id
            del api_key
            pass

    mocker.patch("agent.cve_service_api.get_cve_data_from_api", side_effect=MockCveData)

    selector = "v3.fingerprint.file.library"
    msg_data = {"library_name": "lodash", "library_version": "4.7.11"}
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2021-23337, CVE-2020-8203, CVE-2020-28500, CVE-2019-10744, CVE-2019-1010266, CVE-2018-3721, CVE-2018-16487"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2021-23337,CVE-2020-8203,CVE-2020-28500,CVE-2019-10744,CVE-2019-1010266,CVE-2018-3721,CVE-2018-16487"
    )
    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert (
        """- [CVE-2018-3721](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3721) : Versions of `lodash` before 4.17.5 are vulnerable to prototype pollution. 

The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith' which allow a malicious user to modify the prototype of `Object` via `__proto__` causing the addition or modification of an existing property that will exist on all objects.


"""
    ) in agent_mock[0].data["technical_detail"]


def testAgentOSV_always_emitVulnWithValidTechnicalDetail(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> None:
    """Ensure that the agent always emits a vulnerability with a valid technical detail."""
    selector = "v3.fingerprint.file.library"
    msg_data = {
        "library_name": "opencv",
        "library_version": "6.0.0",
        "library_type": "JAVASCRIPT_LIBRARY",
    }
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: opencv@6.0.0: CVE-2019-10061"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: opencv@6.0.0: CVE-2019-10061"
    )
    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert (
        """- [CVE-2019-10061](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10061) : utils/find-opencv.js in node-opencv (aka OpenCV bindings for Node.js) prior to 6.1.0 is vulnerable to Command Injection. It does not validate user input allowing attackers to execute arbitrary commands.\n"""
        in agent_mock[0].data["technical_detail"]
    )
    assert (
        """- GHSA-f698-m2v9-5fh3 : Versions of `opencv`prior to 6.1.0 are vulnerable to Command Injection. The utils/ script find-opencv.js does not validate user input allowing attackers to execute arbitrary commands.\n\n\nRecommendation: Upgrade to version 6.1.0.\n\n"""
        in agent_mock[0].data["technical_detail"]
    )
    assert (
        agent_mock[0].data["recommendation"]
        == "We recommend updating `opencv` to a version greater than or equal to `6.1.0`."
    )


def testAgentOSV_whenRiskInvalid_defaultToPotentially(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    osv_api_output_risk_invalid: dict[str, Any],
) -> None:
    """Ensure that the agent does not crash when the risk is invalid and default to potentially."""
    mocker.patch(
        "agent.api_manager.osv_service_api.query_osv_api",
        return_value=osv_api_output_risk_invalid,
    )
    selector = "v3.fingerprint.file.library"
    msg_data = {"library_name": "lodash", "library_version": "4.7.11"}
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert all(
        agent_mock[i].data["risk_rating"] == "POTENTIALLY"
        for i in range(len(agent_mock))
    )


def testAgentOSV_whenUnicodeDecodeError_shouldNotCrash(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    scan_message_file: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that the agent does not crash when a UnicodeDecodeError is raised."""
    mocker.patch(
        "subprocess.run", side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "")
    )

    test_agent.process(scan_message_file)

    assert len(agent_mock) == 0


def testAgentOSV_whenNoFindingsFromTheApi_returnsNoVulnz(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> None:
    """Ensure that the agent does not detect vulnerabilities if the api returns no findings."""
    selector = "v3.fingerprint.file.library"
    msg_data = {"library_name": "jquery", "library_version": "3.6.0"}
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert len(agent_mock) == 0


def testAgentOSV_whenPathInMessage_technicalDetailShouldIncludeIt(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> None:
    """Ensure that the agent does not detect vulnerabilities if the api returns no findings."""
    selector = "v3.fingerprint.file.library"
    msg_data = {
        "library_name": "opencv",
        "library_version": "3.4.0",
        "path": "`lib/arm64-v8a/libBlinkID.so`",
    }
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: opencv@3.4.0: CVE-2019-10061"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: opencv@3.4.0: CVE-2019-10061 `lib/arm64-v8a/libBlinkID.so`"
    )
    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert agent_mock[0].data["technical_detail"] == (
        """#### Dependency `opencv`:
- **Version**: `3.4.0`
- **Location**: `lib/arm64-v8a/libBlinkID.so`
- **Description**:
- GHSA-f698-m2v9-5fh3 : Versions of `opencv`prior to 6.1.0 are vulnerable to Command Injection. The utils/ script find-opencv.js does not validate user input allowing attackers to execute arbitrary commands.\n

Recommendation: Upgrade to version 6.1.0.

- [CVE-2019-10061](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10061) : utils/find-opencv.js in node-opencv (aka OpenCV bindings for Node.js) prior to 6.1.0 is vulnerable to Command Injection. It does not validate user input allowing attackers to execute arbitrary commands.\n
"""
    )

    assert agent_mock[0].data["description"] == (
        """Dependency `opencv` with version `3.4.0` has a security issue.
The issue is identified by CVEs: `CVE-2019-10061`."""
    )

    assert (
        agent_mock[0].data["recommendation"]
        == "We recommend updating `opencv` to a version greater than or equal to `6.1.0`."
    )
    assert agent_mock[0].data.get("vulnerability_location") is not None
    assert "libBlinkID.so" in agent_mock[0].data.get("vulnerability_location", {}).get(
        "file", {}
    ).get("path")


def testAgentOSV_whenElfLibraryFingerprintMessage_shouldExcludeNpmEcosystemVulnz(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    elf_library_fingerprint_msg: message.Message,
) -> None:
    """For fingerprints of elf or macho files, we do not know the corresponding osv ecosystem.
    We use a list of accepted ecosystems.
    This unit test ensures no vulnz of excluded ecosystems are reported.
    """
    test_agent.process(elf_library_fingerprint_msg)

    assert len(agent_mock) == 1

    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: opencv@4.9.0"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: opencv@4.9.0: "
    )
    assert agent_mock[0].data["risk_rating"] == "POTENTIALLY"
    assert agent_mock[0].data["technical_detail"] == (
        """#### Dependency `opencv`:\n- **Version**: `4.9.0`\n- **Description**:\n```\n- OSV-2022-394 : OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47190\n\n```\nCrash type: Incorrect-function-pointer-type\nCrash state:\ncv::split\ncv::split\nTestSplitAndMerge\n```\n\n- OSV-2023-444 : OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=59450\n\n```\nCrash type: Heap-buffer-overflow READ 4\nCrash state:\nopj_jp2_apply_pclr\nopj_jp2_decode\ncv::detail::Jpeg2KOpjDecoderBase::readData\n```\n\n\n```"""
    )
    assert agent_mock[0].data["description"] == (
        """Dependency `opencv` with version `4.9.0` has a security issue."""
    )

    assert (
        agent_mock[0].data["recommendation"]
        == "We recommend updating `opencv` to the latest available version."
    )


def testAgentOSV_whenUpperCaseApiEmptyLowerIsNot_returnsVulnz(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that the agent does detect vulnerabilities if the api returns no findings for Uppercase packages but returns findings for lowercase."""
    selector = "v3.fingerprint.file.library"
    msg_data = {
        "library_name": "Wordpress",
        "library_version": "6.5.0",
    }
    query_osv_spy = mocker.spy(osv_service_api, "query_osv_api")
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert query_osv_spy.call_count == 2
    spy_return_list = query_osv_spy.spy_return_list
    assert spy_return_list[0] == {}
    assert len(spy_return_list[1].get("vulns")) > 0
    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: Wordpress@6.5.0: CVE-2024-6307, CVE-2024-4439, CVE-2024-32111, CVE-2024-31111"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: Wordpress@6.5.0: CVE-2024-6307,CVE-2024-4439,CVE-2024-32111,CVE-2024-31111"
    )
    assert agent_mock[0].data["risk_rating"] == "HIGH"
    assert agent_mock[0].data["technical_detail"] == (
        "#### Dependency `Wordpress`:\n"
        "- **Version**: `6.5.0`\n"
        "- **Description**:\n"
        "- "
        "[CVE-2024-4439](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-4439) "
        ": WordPress Core is vulnerable to Stored Cross-Site Scripting via user "
        "display names in the Avatar block in various versions up to 6.5.2 due to "
        "insufficient output escaping on the display name. This makes it possible for "
        "authenticated attackers, with contributor-level access and above, to inject "
        "arbitrary web scripts in pages that will execute whenever a user accesses an "
        "injected page. In addition, it also makes it possible for unauthenticated "
        "attackers to inject arbitrary web scripts in pages that have the comment "
        "block present and display the comment author's avatar.\n"
        "- "
        "[CVE-2024-31111](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-31111) "
        ": Improper Neutralization of Input During Web Page Generation (XSS or "
        "'Cross-site Scripting') vulnerability in Automattic WordPress allows Stored "
        "XSS.This issue affects WordPress: from 6.5 through 6.5.4, from 6.4 through "
        "6.4.4, from 6.3 through 6.3.4, from 6.2 through 6.2.5, from 6.1 through "
        "6.1.6, from 6.0 through 6.0.8, from 5.9 through 5.9.9.\n"
        "- "
        "[CVE-2024-32111](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32111) "
        ": Improper Limitation of a Pathname to a Restricted Directory ('Path "
        "Traversal') vulnerability in Automattic WordPress allows Relative Path "
        "Traversal.This issue affects WordPress: from 6.5 through 6.5.4, from 6.4 "
        "through 6.4.4, from 6.3 through 6.3.4, from 6.2 through 6.2.5, from 6.1 "
        "through 6.1.6, from 6.0 through 6.0.8, from 5.9 through 5.9.9, from 5.8 "
        "through 5.8.9, from 5.7 through 5.7.11, from 5.6 through 5.6.13, from 5.5 "
        "through 5.5.14, from 5.4 through 5.4.15, from 5.3 through 5.3.17, from 5.2 "
        "through 5.2.20, from 5.1 through 5.1.18, from 5.0 through 5.0.21, from 4.9 "
        "through 4.9.25, from 4.8 through 4.8.24, from 4.7 through 4.7.28, from 4.6 "
        "through 4.6.28, from 4.5 through 4.5.31, from 4.4 through 4.4.32, from 4.3 "
        "through 4.3.33, from 4.2 through 4.2.37, from 4.1 through 4.1.40.\n"
        "- "
        "[CVE-2024-6307](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6307) "
        ": WordPress Core is vulnerable to Stored Cross-Site Scripting via the HTML "
        "API in various versions prior to 6.5.5 due to insufficient input "
        "sanitization and output escaping on URLs. This makes it possible for "
        "authenticated attackers, with contributor-level access and above, to inject "
        "arbitrary web scripts in pages that will execute whenever a user accesses an "
        "injected page.\n"
        "\n"
    )
    assert agent_mock[0].data["description"] == (
        "Dependency `Wordpress` with version `6.5.0` has a security issue.\n"
        "The issue is identified by CVEs: `CVE-2024-6307, CVE-2024-4439, "
        "CVE-2024-32111, CVE-2024-31111`."
    )


def testAgentOSV_whenIosMetadataWithBundleId_prepareVulnerabilityLocation(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    fake_osv_output: str,
    osv_output_as_dict: dict[str, str],
) -> None:
    """Ensure that the agent prepares the vulnerability location correctly when ios_metadata is present."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="description",
        fixed_version="2",
        cvss_v3_vector=None,
    )
    mocker.patch("agent.osv_agent._run_command", return_value=fake_osv_output)
    mocker.patch(
        "agent.osv_output_handler.read_output_file_as_dict",
        return_value=osv_output_as_dict,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")
    selector = "v3.asset.file"
    msg_data = {
        "content": b"some file content",
        "path": "/tmp/path/file.txt",
        "ios_metadata": {"bundle_id": "com.example.app"},
    }
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert len(agent_mock) > 0
    assert agent_mock[0].data.get("vulnerability_location") is not None
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("ios_store", {})
        .get("bundle_id")
        == "com.example.app"
    )
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("metadata", [{}])[0]
        .get("type")
        == "FILE_PATH"
    )
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("metadata", [{}])[0]
        .get("value")
        == "/tmp/path/file.txt"
    )


def testAgentOSV_whenAndroidMetadataWithPackageName_prepareVulnerabilityLocation(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    fake_osv_output: str,
    osv_output_as_dict: dict[str, str],
) -> None:
    """Ensure that the agent prepares the vulnerability location correctly when android_metadata is present."""
    cve_data = cve_service_api.CVE(
        risk="HIGH",
        description="description",
        fixed_version="2",
        cvss_v3_vector=None,
    )
    mocker.patch("agent.osv_agent._run_command", return_value=fake_osv_output)
    mocker.patch(
        "agent.osv_output_handler.read_output_file_as_dict",
        return_value=osv_output_as_dict,
    )
    mocker.patch("agent.cve_service_api.get_cve_data_from_api", return_value=cve_data)
    mocker.patch("agent.osv_output_handler.calculate_risk_rating", return_value="HIGH")
    selector = "v3.asset.file"
    msg_data = {
        "content": b"some file content",
        "path": "/tmp/path/file.txt",
        "android_metadata": {"package_name": "com.example.app"},
    }
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert len(agent_mock) > 0
    assert agent_mock[0].data.get("vulnerability_location") is not None
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("android_store", {})
        .get("package_name")
        == "com.example.app"
    )
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("metadata", [{}])[0]
        .get("type")
        == "FILE_PATH"
    )
    assert (
        agent_mock[0]
        .data.get("vulnerability_location", {})
        .get("metadata", [{}])[0]
        .get("value")
        == "/tmp/path/file.txt"
    )
