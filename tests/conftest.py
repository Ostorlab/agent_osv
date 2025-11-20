"""Pytest fixture for the osv agent."""

import json
import pathlib
import random
import subprocess
from typing import Dict, Callable, Any

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import osv_agent

SVG_CONTENT = b"""<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" stroke="black" stroke-width="3" fill="red" />
</svg>"""


@pytest.fixture
def scan_message_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = f"{pathlib.Path(__file__).parent.parent}/tests/files/package_lock.json"
    with open(path, "rb") as lock_file:
        msg_data = {"content": lock_file.read(), "path": path}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://rexel.com/composer.lock"}

    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_bad_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    path = f"{pathlib.Path(__file__).parent.parent}/tests/files/package_lock.json"
    msg_data = {"content": b"\xdd\xff\x00", "path": path}
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


@pytest.fixture
def blacklisted_scan_message_file() -> message.Message:
    """Creates an invalid message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    msg_data = {"content": b"2132154645645", "path": "test.dex"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def blacklisted_scan_message_content() -> message.Message:
    """Creates an invalid message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    msg_data = {"content": SVG_CONTENT, "path": ""}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def mocked_osv_scanner(
    fake_osv_output: str,
) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Creates a mocked osv scanner that returns a CompletedProcess object with the provided osv_output."""

    def scan(
        *popenargs: Any,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        if "package-lock.json" in popenargs[0]:
            return subprocess.CompletedProcess(popenargs, 0, fake_osv_output, None)

        return subprocess.CompletedProcess(popenargs, 0, """{"results":[]}""", None)

    return scan


@pytest.fixture
def scan_message_file_no_name() -> message.Message:
    """Creates a dummy message with no name `path`
    provided of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    msg_data = {"content": b"May the force be with you"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_file_content_url() -> message.Message:
    """Creates a dummy message with no name `path` provided of type v3.asset.file to be used
    by the agent for testing purposes."""
    selector = "v3.asset.file"
    msg_data = {
        "content_url": b"https://ostorlab.co/requirements.txt",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def test_agent(
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    return b""""unicode-match-property-ecmascript": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/unicode-match-property-ecmascript/-/unicode-match-property-ecmascript-1.0.4.tgz",
      "integrity": "sha512-L4Qoh15vTfntsn4P1zqnHulG0LdXgjSO035fEpdtp6YxXhMT51Q6vgM5lYdG/5X3MjS+k/Y9Xw4SFCY9IkR0rg==",
      "dev": true,
      "requires": {
        "unicode-canonical-property-names-ecmascript": "^1.0.4",
        "unicode-property-aliases-ecmascript": "^1.0.4"
      }
    }"""


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
def osv_output_as_dict() -> dict[str, str]:
    """Return a temporary file and write JSON data to it"""
    with open(
        f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_output.json",
        "r",
        encoding="utf-8",
    ) as of:
        data: dict[str, str] = json.load(of)
    return data


@pytest.fixture(name="fake_osv_output")
def osv_output() -> str:
    """Return a temporary file and write JSON data to it"""
    with open(
        f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_output.json",
        "r",
        encoding="utf-8",
    ) as of:
        data = of.read()
    return data


@pytest.fixture(name="fake_osv_output_missing_cve")
def osv_output_missing_cve() -> str:
    """Return a temporary file and write JSON data to it"""
    with open(
        f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_output_missing_cve.json",
        "r",
        encoding="utf-8",
    ) as of:
        data = of.read()
    return data


@pytest.fixture(name="nvd_output")
def nvd_output() -> str:
    """Return a temporary file and write JSON data to it"""
    with open(
        f"{pathlib.Path(__file__).parent.parent}/tests/files/nvd_output.json",
        "r",
        encoding="utf-8",
    ) as of:
        data = of.read()
    return data


@pytest.fixture
def output_file(tmp_path: pathlib.Path) -> str:
    """Create a temporary file and write JSON data to it"""
    data = {"key": "value"}
    file_path = f"{tmp_path}/output.json"
    with open(str(file_path), "w", encoding="utf-8") as f:
        json.dump(data, f)
    return str(file_path)


@pytest.fixture(name="osv_api_output")
def osv_api_output() -> dict[str, Any]:
    """Read and return the OSV API output from a file as a dict."""
    file_path = (
        f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_api_output.json"
    )
    data = pathlib.Path(file_path).read_text(encoding="utf-8")
    json_data: dict[str, Any] = json.loads(data)
    return json_data


@pytest.fixture(name="osv_api_output_risk_lower")
def osv_api_output_risk_lower() -> dict[str, Any]:
    """Read and return the OSV API output from a file as a dict."""
    file_path = f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_api_output_risk_lower.json"
    data = pathlib.Path(file_path).read_text(encoding="utf-8")
    json_data: dict[str, Any] = json.loads(data)
    return json_data


@pytest.fixture(name="osv_api_output_risk_missing")
def osv_api_output_risk_missing() -> dict[str, Any]:
    """Read and return the OSV API output from a file as a dict."""
    file_path = f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_api_output_risk_missing.json"
    data = pathlib.Path(file_path).read_text(encoding="utf-8")
    json_data: dict[str, Any] = json.loads(data)
    return json_data


@pytest.fixture(name="osv_api_output_risk_invalid")
def osv_api_output_risk_invalid() -> dict[str, Any]:
    """Read and return the OSV API output from a file as a dict."""
    file_path = f"{pathlib.Path(__file__).parent.parent}/tests/files/osv_api_output_risk_invalid.json"
    data = pathlib.Path(file_path).read_text(encoding="utf-8")
    json_data: dict[str, Any] = json.loads(data)
    return json_data


@pytest.fixture
def elf_library_fingerprint_msg() -> message.Message:
    selector = "v3.fingerprint.file.library"
    msg_data = {
        "library_name": "opencv",
        "library_version": "4.9.0",
        "library_type": "ELF_LIBRARY",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def go_mod_file_message() -> message.Message:
    """Creates a dummy message of type v3.asset.file for go.mod file."""
    selector = "v3.asset.file"
    go_mod_content = b"""module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
)
"""
    msg_data = {"content": go_mod_content, "path": "/workspace/go.mod"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def go_sum_file_message() -> message.Message:
    """Creates a dummy message of type v3.asset.file for go.sum file."""
    selector = "v3.asset.file"
    go_sum_content = b"""github.com/gin-gonic/gin v1.9.0 h1:test
github.com/gin-gonic/gin v1.9.0/go.mod h1:test
"""
    msg_data = {"content": go_sum_content, "path": "/workspace/go.sum"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def fake_go_osv_output() -> str:
    """Return fake OSV output for Go module scanning."""
    return json.dumps(
        {
            "results": [
                {
                    "source": {"path": "/workspace/go.mod", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "github.com/gin-gonic/gin",
                                "version": "1.9.0",
                                "ecosystem": "Go",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GO-2024-1234",
                                    "aliases": ["CVE-2024-1234"],
                                    "summary": "Test vulnerability in gin",
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
