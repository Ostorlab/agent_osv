import random
import pathlib
from typing import Dict

import pytest
from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import osv_agent

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
