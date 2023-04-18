"""Unittests for OSV agent."""
import subprocess
from typing import Union

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import osv_agent
from agent import utils

JSON_OUTPUT = b'''
{
  "results": [
    {
      "packageSource": {
        "path": "/absolute/path/to/go.mod",
        // One of: lockfile, sbom, git, docker
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "github.com/gogo/protobuf",
            "version": "1.3.1",
            "ecosystem": "Go"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-c3h9-896r-86jm",
              "aliases": [
                "CVE-2021-3121"
              ],
              // ... Full OSV
            },
            {
              "id": "GO-2021-0053",
              "aliases": [
                "CVE-2021-3121",
                "GHSA-c3h9-896r-86jm"
              ],
              // ... Full OSV
            }
          ],
          // Grouping based on aliases, if two vulnerability share the same alias, or alias each other,
          // they are considered the same vulnerability, and is grouped here under the id field.
          "groups": [
            {
              "ids": [
                "GHSA-c3h9-896r-86jm",
                "GO-2021-0053"
              ],
              // Call stack analysis is done using the `--experimental-call-analysis` flag
              // and result is matched against data provided by the advisory to check if
              // affected code is actually being executed.
              "experimentalAnalysis": {
                "GO-2021-0053": {
                  "called": false
                }
              }
            }
          ]
        }
      ]
    },
    {
      "packageSource": {
        "path": "/absolute/path/to/Cargo.lock",
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "regex",
            "version": "1.5.1",
            "ecosystem": "crates.io"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-m5pq-gvj9-9vr8",
              "aliases": [
                "CVE-2022-24713"
              ],
              // ... Full OSV
            },
            {
              "id": "RUSTSEC-2022-0013",
              "aliases": [
                "CVE-2022-24713"
              ],
              // ... Full OSV
            }
          ],
          "groups": [
            {
              "ids": [
                "GHSA-m5pq-gvj9-9vr8",
                "RUSTSEC-2022-0013"
              ]
            }
          ]
        }
      ]
    }
  ]
}
'''


def testAgentOSV_whenAnalysisRunsWithoutPathWithoutErrors_emitsBackVulnerability(
    test_agent: osv_agent.OSVAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[Union[str, bytes], Union[str, bytes]],
    scan_message_file: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Unittest for the full life cycle of the agent:
    case where the semgrep analysis runs without a path provided and without errors and yields vulnerabilities.
    """

    subprocess_mock = mocker.patch(
        "agent.osv_agent.OSVAgent._run_command",
        return_value=JSON_OUTPUT,
    )

    del scan_message_file.data["path"]

    test_agent.process(scan_message_file)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.report.vulnerability"
    assert agent_mock[0].data["risk_rating"] == "MEDIUM"
    assert (
        agent_mock[0].data["title"]
        == "Using CBC with PKCS5Padding is susceptible to padding oracle attacks"
    )
    assert len(agent_mock[0].data["references"]) >= 3
