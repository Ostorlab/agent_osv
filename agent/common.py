"""Common utilities for the exploits."""

import json
from typing import Any

from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import link as link_asset
from ostorlab.assets import file as file_asset


def build_vuln_location(
    file_path: str | None = None,
    content_url: str | None = None,
    package_name: str | None = None,
    package_version: str | None = None,
) -> agent_report_vulnerability_mixin.VulnerabilityLocation:
    """Build VulnerabilityLocation based on the asset.

    Args:
        file_path: The path of the file
        content_url: The content url of the file
        package_name: The package name
        package_version: The package version
    Returns:
        The vulnerability location object.
    """

    asset: file_asset.File | link_asset.Link
    metadata = []
    asset = file_asset.File(path=file_path, content_url=content_url)
    if file_path is not None:
        metadata.append(
            agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                metadata_type=agent_report_vulnerability_mixin.MetadataType.FILE_PATH,
                value=file_path,
            )
        )
    if package_name is not None:
        metadata.append(
            agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                metadata_type=agent_report_vulnerability_mixin.MetadataType.PACKAGE_NAME,
                value=package_name,
            )
        )
    if package_version is not None:
        metadata.append(
            agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                metadata_type=agent_report_vulnerability_mixin.MetadataType.VERSION,
                value=package_version,
            )
        )
    return agent_report_vulnerability_mixin.VulnerabilityLocation(
        asset=asset, metadata=metadata
    )


def compute_dna(
    vuln_title: str,
    vuln_location: agent_report_vulnerability_mixin.VulnerabilityLocation | None,
    package_name: str | None,
    package_version: str | None,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.

    Args:
        vuln_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.
        package_name: The package name
        package_version: The package version

    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {"title": vuln_title}

    if vuln_location is not None:
        location_dict: dict[str, Any] = vuln_location.to_dict()
        sorted_location_dict = sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    if package_name is not None:
        dna_data["package_name"] = package_name

    if package_version is not None:
        dna_data["package_version"] = package_version

    return json.dumps(dna_data, sort_keys=True)


def sort_dict(d: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.

    Args:
        d: The dictionary or list to sort.

    Returns:
        A sorted dictionary or list.
    """
    if isinstance(d, dict):
        return {k: sort_dict(v) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return sorted(
            d,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return d
