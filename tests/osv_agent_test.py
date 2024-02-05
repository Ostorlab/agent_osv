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
        == "Use of Outdated Vulnerable Component: lodash@4.17.5: CVE-2018-3721"
    )
    assert agent_mock[0].data["risk_rating"] == "LOW"
    assert (
        agent_mock[6].data["title"]
        == "Use of Outdated Vulnerable Component: lodash@4.17.21: CVE-2021-23337"
    )
    assert agent_mock[6].data["risk_rating"] == "HIGH"


def testAgentOSV_whenRiskLowerCase_doesNotCrash(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    osv_api_output_risk_lower: dict[str, Any],
) -> None:
    """Ensure that the agent does not crash when the risk is lower."""
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
        == "Use of Outdated Vulnerable Component: lodash@4.17.5: CVE-2018-3721"
    )
    assert agent_mock[0].data["risk_rating"] == "LOW"
    assert (
        agent_mock[6].data["title"]
        == "Use of Outdated Vulnerable Component: lodash@4.17.21: CVE-2021-23337"
    )
    assert agent_mock[6].data["risk_rating"] == "HIGH"


def testAgentOSV_whenRiskMissing_defaultToPotentially(
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
    selector = "v3.fingerprint.file.library"
    msg_data = {"library_name": "lodash", "library_version": "4.7.11"}
    msg = message.Message.from_data(selector, data=msg_data)

    test_agent.process(msg)

    assert (
        agent_mock[0].data["title"]
        == "Use of Outdated Vulnerable Component: lodash@4.17.5: CVE-2018-3721"
    )
    assert agent_mock[0].data["risk_rating"] == "POTENTIALLY"
    assert agent_mock[3].data["risk_rating"] == "POTENTIALLY"


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
