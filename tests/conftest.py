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
    path = "/home/oussama/Desktop/agent_osv/files/package_lock.json"
    with open(path, "rb") as lock_file:
        msg_data = {"content": lock_file.read(), "path": path}
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
