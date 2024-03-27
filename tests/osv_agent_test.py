"""Unittests for OSV agent."""

import subprocess
from typing import Callable, Any

import requests_mock as rq_mock
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import cve_service_api
from agent import osv_agent


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
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337"
    )
    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337"
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
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337"
    )

    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert (
        """- [CVE-2018-3721](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3721) : Versions of `lodash` before 4.17.5 are vulnerable to prototype pollution. 

The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith' which allow a malicious user to modify the prototype of `Object` via `__proto__` causing the addition or modification of an existing property that will exist on all objects.
"""
    ) in agent_mock[0].data["technical_detail"]

    assert (
        """## Recommendation

Update to version 4.17.5 or later.
- [CVE-2018-16487](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-16487) : Versions of `lodash` before 4.17.11 are vulnerable to prototype pollution. 

The vulnerable functions are 'defaultsDeep', 'merge', and 'mergeWith' which allow a malicious user to modify the prototype of `Object` via `{constructor: {prototype: {...}}}` causing the addition or modification of an existing property that will exist on all objects."""
    ) in agent_mock[0].data["technical_detail"]
    assert agent_mock[0].data["short_description"] == "Prototype Pollution in lodash"
    assert agent_mock[0].data["description"] == (
        """Dependency `lodash` with version `4.7.11` has a security issue.
The issue is identified by CVEs: `CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337`."""
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
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337"
    )
    assert (
        agent_mock[0].data["dna"]
        == "Use of Outdated Vulnerable Component: lodash@4.7.11: CVE-2018-16487, CVE-2018-3721, CVE-2019-1010266, CVE-2019-10744, CVE-2020-28500, CVE-2020-8203, CVE-2021-23337"
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
        """- GHSA-f698-m2v9-5fh3 : Versions of `opencv`prior to 6.1.0 are vulnerable to Command Injection. The utils/ script find-opencv.js does not validate user input allowing attackers to execute arbitrary commands.\n\n\n## Recommendation\n\nUpgrade to version 6.1.0.\n\n"""
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
        == "Use of Outdated Vulnerable Component: opencv@3.4.0: CVE-2019-10061"
    )
    assert agent_mock[0].data["risk_rating"] == "CRITICAL"
    assert agent_mock[0].data["technical_detail"] == (
        """Dependency `opencv` Found in `lib/arm64-v8a/libBlinkID.so` has a security issue: 
- GHSA-f698-m2v9-5fh3 : Versions of `opencv`prior to 6.1.0 are vulnerable to Command Injection. The utils/ script find-opencv.js does not validate user input allowing attackers to execute arbitrary commands.\n\n\n## Recommendation\n\nUpgrade to version 6.1.0.\n
- [CVE-2019-10061](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10061) : utils/find-opencv.js in node-opencv (aka OpenCV bindings for Node.js) prior to 6.1.0 is vulnerable to Command Injection. It does not validate user input allowing attackers to execute arbitrary commands.
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
        == "Use of Outdated Vulnerable Component: opencv@4.9.0:"
    )
    assert agent_mock[0].data["risk_rating"] == "POTENTIALLY"
    assert agent_mock[0].data["technical_detail"] == (
        """```\n- OSV-2022-394 : OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47190\n\n```\nCrash type: Incorrect-function-pointer-type\nCrash state:\ncv::split\ncv::split\nTestSplitAndMerge\n```\n\n- OSV-2023-444 : OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=59450\n\n```\nCrash type: Heap-buffer-overflow READ 4\nCrash state:\nopj_jp2_apply_pclr\nopj_jp2_decode\ncv::detail::Jpeg2KOpjDecoderBase::readData\n```\n\n\n```"""
    )
    assert agent_mock[0].data["description"] == (
        """Dependency `opencv` with version `4.9.0` has a security issue."""
    )

    assert (
        agent_mock[0].data["recommendation"]
        == "We recommend updating `opencv` to the latest available version."
    )
