"""Pytest fixture for the osv agent."""
import json
import random
import pathlib
from typing import Dict

import pytest
from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import osv_agent


@pytest.fixture
def scan_message_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = f"{pathlib.Path(__file__).parent.parent}/tests/files/package_lock.json"
    with open(path, "rb") as lock_file:
        msg_data = {"content": lock_file.read(), "path": path}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def empty_scan_message_file() -> message.Message:
    """Creates empty message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    msg_data = {"content": b"", "path": ""}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def invalid_scan_message_file() -> message.Message:
    """Creates an invalid message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    msg_data = {"content": b"", "path": "test.java"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def test_agent(
    agent_persist_mock: Dict[str | bytes, str | bytes]
) -> osv_agent.OSVAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/semgrep",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        return osv_agent.OSVAgent(definition, settings)


@pytest.fixture
def valid_lock_file_content() -> bytes:
    return b"valid_lock_file_content"


@pytest.fixture
def invalid_lock_file_content() -> bytes:
    return b""


@pytest.fixture
def invalid_lock_file_path() -> str:
    return "/invalid/lock/file/path"


@pytest.fixture
def valid_lock_file_path() -> str:
    return "/valid/lock/file/path.lock"


@pytest.fixture
def osv_output() -> dict[str, str]:
    """Return a temporary file and write JSON data to it"""
    with open(
        f"{pathlib.Path.cwd().parent.resolve()}/files/osv_output.json",
        "r",
        encoding="utf-8",
    ) as of:
        data: dict[str, str] = json.load(of)
    return data


@pytest.fixture
def output_file(tmp_path: pathlib.Path) -> str:
    """Create a temporary file and write JSON data to it"""
    data = {"key": "value"}
    file_path = f"{tmp_path}/output.json"
    with open(str(file_path), "w", encoding="utf-8") as f:
        json.dump(data, f)
    return str(file_path)
