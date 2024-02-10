"""This module provides utility functions to query the OSV API for vulnerability information
related to a specific package version."""
import dataclasses
import logging
from typing import Any

import requests
import tenacity

logger = logging.getLogger(__name__)

OSV_ENDPOINT = "https://api.osv.dev/v1/query"
NUMBER_RETRIES = 3
WAIT_BETWEEN_RETRIES = 2


@dataclasses.dataclass
class VulnData:
    risk: str
    description: str
    summary: str
    fixed_version: str | None
    cvss_v3_vector: str | None
    references: list[dict[str, str]]
    cves: list[str]


@tenacity.retry(
    stop=tenacity.stop_after_attempt(NUMBER_RETRIES),
    wait=tenacity.wait_fixed(WAIT_BETWEEN_RETRIES),
    retry=tenacity.retry_if_exception_type(),
    retry_error_callback=lambda retry_state: retry_state.outcome.result()
    if retry_state.outcome is not None
    else None,
)
def query_osv_api(
    package_name: str, version: str, ecosystem: str | None = None
) -> dict[str, Any] | None:
    """Query the OSV API with the specified version, package name, and ecosystem.
    Args:
        version: The version to query.
        package_name: The name of the package to query.
        ecosystem: The ecosystem of the package e.g., javascript.
    Returns:
        The API response text if successful, None otherwise.
    """
    if ecosystem is not None:
        data = {
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem},
        }
    else:
        data = {
            "version": version,
            "package": {"name": package_name},
        }

    response = requests.post(OSV_ENDPOINT, json=data)

    if response.status_code == 200:
        resp: dict[str, Any] = response.json()
        return resp

    return None
