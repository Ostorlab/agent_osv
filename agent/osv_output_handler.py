"""OSV Wrapper responsible for dealing with the agent output and constructing its information."""

import dataclasses
import json
import logging
import pathlib
import re
from collections.abc import Iterator
from typing import Any

import semver
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

from agent import cve_service_api

CVE_MITRE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
RISK_RATING_MAPPING = {
    "POTENTIALLY": agent_report_vulnerability_mixin.RiskRating.POTENTIALLY,
    "LOW": agent_report_vulnerability_mixin.RiskRating.LOW,
    "MEDIUM": agent_report_vulnerability_mixin.RiskRating.MEDIUM,
    "HIGH": agent_report_vulnerability_mixin.RiskRating.HIGH,
}
CVE_PATTERN = r".*/(CVE-[0-9]+-[0-9]+)"

RISK_RATINGS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "POTENTIALLY"]

RISK_PRIORITY_LEVELS = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "POTENTIALLY": 5,
}

MAX_SHOWN_CVES = 10

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Vulnerability:
    """Vulnerability dataclass to pass to the emit method."""

    entry: kb.Entry
    dna: str
    technical_detail: str
    risk_rating: agent_report_vulnerability_mixin.RiskRating


@dataclasses.dataclass
class VulnData:
    package_name: str | None
    package_version: str | None
    risk: str
    description: str
    summary: str
    fixed_version: str | None
    cvss_v3_vector: str | None
    references: list[dict[str, str]]
    cves: list[str]
    file_type: str | None = None
    file_name: str | None = None


def read_output_file_as_dict(output_file_path: str) -> dict[str, Any]:
    """Read the OSV scanner output from json file and return dict
    Args:
        output_file_path: the OSV scanner output file
    returns:
        Dict representation of the json object
    """
    with open(output_file_path, "r", encoding="utf-8") as of:
        data: dict[str, Any] = json.load(of)

    return data


def build_references(references: list[dict[str, str]]) -> dict[str, str]:
    """Build references from the OSV output
    Args:
        references: references from OSV output
    Returns:
        references list as object with name, url as key-value.
    """
    references_list = {}
    for reference in references:
        references_list[reference.get("url", "")] = reference.get("url", "")
    return references_list


def parse_osv_output(output: str, api_key: str | None = None) -> list[VulnData]:
    """Parses JSON generated OSV results and yield vulnerability entries.
    Args:
        output: OSV json output file path.
    Yields:
        Vulnerability entry.
    """

    data = json.loads(output, strict=False)
    if data.get("results") is None:
        logger.info("Osv returns null result.")
        return []

    results: dict[Any, Any] = data.get("results", [])
    parsed_vulns = []
    for result in results:
        packages = result.get("packages", [{}])
        file_type = result.get("source", {}).get("type", "")
        file_name = pathlib.Path(result.get("source", {}).get("path", "")).name
        for package in packages:
            parsed_vulns.extend(
                parse_vulnerabilities_osv_binary(
                    output=package,
                    api_key=api_key,
                    file_type=file_type,
                    file_name=file_name,
                )
            )

    return parsed_vulns


def parse_vulnerabilities_osv_binary(
    output: dict[str, Any],
    api_key: str | None = None,
    file_type: str | None = None,
    file_name: str | None = None,
) -> list[VulnData]:
    """Parse the OSV binary response to extract vulnerabilities.
    Args:
        output: The API response json.
        api_key: The NVD API key.
        file_type: The package file type.
        file_name: The package file name.
    Returns:
        Parsed output.
    """
    try:
        vulnerabilities = output.get("vulns") or output.get("vulnerabilities") or []
        if len(vulnerabilities) == 0:
            return []

        package_name = output.get("package", {}).get("name")
        package_version = output.get("package", {}).get("version")
        cves: list[str] = []
        description_blocks: list[str] = []
        fixed_versions: list[str] = []
        has_unfixed_covering_interval = False
        references: list[dict[str, str]] = []
        reference_urls: set[str] = set()
        highest_risk_priority = len(RISK_PRIORITY_LEVELS) + 1
        highest_risk = "POTENTIALLY"
        highest_risk_summary = ""
        highest_risk_cvss_v3_vector = ""

        for vulnerability in vulnerabilities:
            filtered_cves = [
                alias for alias in vulnerability.get("aliases", []) if "CVE" in alias
            ]
            severity = vulnerability.get("database_specific", {}).get("severity")
            risk = _vuln_risk_rating(risk=severity, cves=filtered_cves, api_key=api_key)
            vulnerability_fixed_versions, has_unfixed_interval = _get_fixed_versions(
                vulnerability.get("affected"), package_name, package_version
            )
            fixed_versions.extend(vulnerability_fixed_versions)
            has_unfixed_covering_interval = (
                has_unfixed_covering_interval or has_unfixed_interval
            )
            risk_priority = RISK_PRIORITY_LEVELS.get(
                risk.upper(), RISK_PRIORITY_LEVELS["POTENTIALLY"]
            )
            if risk_priority < highest_risk_priority:
                highest_risk_priority = risk_priority
                highest_risk = (
                    risk.upper()
                    if risk.upper() in RISK_PRIORITY_LEVELS
                    else "POTENTIALLY"
                )
                highest_risk_summary = vulnerability.get("summary", "")
                highest_risk_cvss_v3_vector = _get_cvss_v3_vector(
                    vulnerability.get("severity")
                )

            new_cves = []
            for cve in filtered_cves:
                if cve not in cves:
                    cves.append(cve)
                    new_cves.append(cve)
            if len(new_cves) > 0:
                cve_description = _aggregate_cves(
                    cve_ids=new_cves, api_key=api_key
                ).strip()
                if cve_description != "":
                    description_blocks.append(cve_description)
            elif len(filtered_cves) == 0:
                advisory_id = vulnerability.get("id", "")
                advisory_details = vulnerability.get("details", "")
                if advisory_id != "" or advisory_details != "":
                    description_blocks.append(
                        f"- {advisory_id} : {advisory_details}".strip()
                    )
            for reference in vulnerability.get("references", []):
                reference_url = reference.get("url", "")
                if reference_url not in reference_urls:
                    references.append(reference)
                    reference_urls.add(reference_url)

        if has_unfixed_covering_interval:
            fixed_version = ""
        else:
            fixed_version = _get_highest_fixed_version(
                fixed_versions, package_name=package_name
            )
        return [
            VulnData(
                package_name=package_name,
                package_version=package_version,
                risk=highest_risk,
                description="\n".join(description_blocks),
                summary=highest_risk_summary,
                fixed_version=fixed_version,
                cvss_v3_vector=highest_risk_cvss_v3_vector,
                references=references,
                cves=cves,
                file_name=file_name,
                file_type=file_type,
            )
        ]

    except json.JSONDecodeError as e:
        logger.error("Error decoding JSON: %s", e)
        return []


def parse_vulnerabilities_osv_api(
    output: dict[str, Any],
    package_name: str,
    package_version: str,
    api_key: str | None = None,
    whitelisted_ecosystems: list[str] | None = None,
    ecosystem: str | None = None,
) -> list[VulnData]:
    """Parse the OSV API response to extract vulnerabilities.

    Args:
        output: The list of vulnerabilities raw from the API response .
        package_name: The package name.
        package_version: The package version.
        api_key: The NVD API key.
        whitelisted_ecosystems: The ecosystems to keep advisories for.
        ecosystem: The ecosystem the query was scoped to, when it was.

    Returns:
        Parsed output.
    """
    cves_list: list[str] = []
    risks_list: list[str] = []
    vulnerabilities = output.get("vulns", []) or output.get("vulnerabilities", [])
    fixed_versions: list[str] = []
    has_unfixed_covering_interval = False
    references: list[dict[str, Any]] = []
    description = ""
    highest_risk_vuln_info: dict[str, str] = {}
    if len(vulnerabilities) == 0:
        return []

    whitlisted_vulnerabilities = _whitelist_vulnz_from_ecosystems(
        vulnerabilities, whitelisted_ecosystems
    )
    for vulnerability in whitlisted_vulnerabilities:
        vulnerability_fixed_versions, has_unfixed_interval = _get_fixed_versions(
            vulnerability.get("affected"),
            package_name,
            package_version=package_version,
            ecosystem=ecosystem,
            whitelisted_ecosystems=whitelisted_ecosystems,
        )
        fixed_versions.extend(vulnerability_fixed_versions)
        has_unfixed_covering_interval = (
            has_unfixed_covering_interval or has_unfixed_interval
        )
        filtered_cves = [
            alias for alias in vulnerability.get("aliases", []) if "CVE" in alias
        ]

        if len(filtered_cves) > 0:
            for cve in filtered_cves:
                description += f"- [{cve}]({CVE_MITRE_URL}{cve}) : "
        else:
            description += f"- {vulnerability.get('id')} : "
        description += f"{vulnerability.get('details')}\n"

        severity = vulnerability.get("database_specific", {}).get("severity")
        risk = _vuln_risk_rating(risk=severity, cves=filtered_cves, api_key=api_key)
        # Keep the summary and the cvss_v3_vector of the vulnerability with the highest risk rating
        old_risk = RISK_PRIORITY_LEVELS.get(
            highest_risk_vuln_info.get("risk", "POTENTIALLY").upper()
        )
        new_risk = RISK_PRIORITY_LEVELS.get(risk.upper())
        if old_risk is not None and new_risk is not None and old_risk > new_risk:
            highest_risk_vuln_info["risk"] = risk
            highest_risk_vuln_info["cvss_v3_vector"] = _get_cvss_v3_vector(
                vulnerability.get("severity", [])
            )
            highest_risk_vuln_info["summary"] = vulnerability.get("summary", "")

        cves_list.extend(filtered_cves)
        risks_list.append(risk)
        references.extend(vulnerability.get("references", {}))

    if has_unfixed_covering_interval:
        # A covering interval closes with ``last_affected`` and names no safe
        # version: no endpoint can be recommended for this package.
        fixed_version = ""
    else:
        fixed_version = _get_highest_fixed_version(fixed_versions, package_name)
    return [
        VulnData(
            package_name=package_name,
            package_version=package_version,
            risk=highest_risk_vuln_info.get("risk", "POTENTIALLY"),
            description=description,
            summary=highest_risk_vuln_info.get("summary", ""),
            fixed_version=fixed_version,
            cvss_v3_vector=highest_risk_vuln_info.get("cvss_v3_vector"),
            references=references,
            cves=cves_list,
        )
    ]


def _whitelist_vulnz_from_ecosystems(
    vulnerabilities: list[dict[str, Any]],
    whitelisted_ecosystems: list[str] | None = None,
) -> list[dict[str, Any]]:
    if whitelisted_ecosystems is None or len(whitelisted_ecosystems) == 0:
        return vulnerabilities
    whitelisted_ecosystem_set = set(whitelisted_ecosystems)
    whitelisted = []
    for vuln in vulnerabilities:
        affected_data = vuln.get("affected", [])
        # A record is relevant when ANY of its affected entries names a
        # whitelisted ecosystem: OSV records list one entry per package, and
        # the entry matching the whitelist may not be the first one (reading
        # only ``affected[0]`` drops records whose first entry belongs to
        # another ecosystem).
        for affected in affected_data:
            ecosystem = (affected.get("package") or {}).get("ecosystem")
            if ecosystem in whitelisted_ecosystem_set:
                whitelisted.append(vuln)
                break
    return whitelisted


def _aggregate_cves(cve_ids: list[str], api_key: str | None = None) -> str:
    """Generate the description for the vulnerability from all the related CVEs."""
    cve_list_details = ""
    for cve_id in cve_ids:
        cve_list_details += f"- [{cve_id}]({CVE_MITRE_URL}{cve_id}) "
        cve_data = cve_service_api.get_cve_data_from_api(cve_id, api_key)
        if cve_data.description is not None and cve_data.description != "":
            cve_list_details += f": {cve_data.description}"
        if cve_data.fixed_version is not None and cve_data.fixed_version != "":
            cve_list_details += (
                f"The issue was fixed in version `{cve_data.fixed_version}`. \n "
            )
    return cve_list_details


def calculate_risk_rating(risk_ratings: list[str]) -> str:
    """Calculate the risk rating of a given cve ids of a vulnerability
    Args:
        risk_ratings: list of risk ratings
    Returns:
        Risk rating of a vulnerability
    """
    risk_ratings = [risk_rating.upper() for risk_rating in risk_ratings]
    sorted_ratings = sorted(
        risk_ratings, key=lambda x: RISK_PRIORITY_LEVELS.get(x, 5), reverse=False
    )

    for rating in sorted_ratings:
        if rating in RISK_PRIORITY_LEVELS:
            return rating
    return "POTENTIALLY"


def _extract_cve_reference_advisory(
    references: list[dict[str, str]],
) -> str | list[str]:
    for reference in references:
        if reference["type"] == "ADVISORY":
            cve_match = re.match(CVE_PATTERN, reference["url"], re.IGNORECASE)
            if cve_match is not None:
                return [cve_match.group(1)]
    return ""


def _parse_version_key(version: str) -> semver.Version | None:
    """The semver key of a version string, or None when it is not semver.

    Distros and some ecosystems use version formats semver cannot parse
    (``3.1.1-2+deb9u2``); a None key means "cannot compare", never "lower".
    """
    try:
        return semver.Version.parse(version)
    except ValueError:
        return None


# Ecosystems the OSV schema documents as distribution package namespaces:
# they version packages by the distribution's own scheme (``3.4.6-6.el8``,
# ``3.1.1-2+deb9u2``, ``3.5.1+dfsg-1``), optionally scoped with a release
# suffix (``Debian:11``, ``Alpine:v3.19``, ``SUSE:Server:15``,
# ``Root:Alpine:3.18``). Verified against the schema's ecosystem table
# (https://ossf.github.io/osv-schema/ #affectedpackage-schema): package
# managers and registries (npm, PyPI, Maven, NuGet, Go, crates.io, ...),
# project namespaces (Linux, OSS-Fuzz, Android, Bitnami, Kubernetes) and
# version/score namespaces (NVD, CNA, CVSS_*) are deliberately absent —
# only distributions re-version upstream packages in their own scheme.
_DISTRIBUTION_ECOSYSTEMS = frozenset(
    {
        "AlmaLinux",
        "Alpaquita",
        "Alpine",
        "Azure Linux",
        "BellSoft Hardened Containers",
        "Chainguard",
        "CleanStart",
        "Debian",
        "Docker Hardened Images",
        "FreeBSD",
        "Mageia",
        "MinimOS",
        "Photon OS",
        "Raspberry Pi OS",
        "Red Hat",
        "Red Hat Lightwell",
        "Rocky Linux",
        "Root",
        "SUSE",
        "TuxCare",
        "Ubuntu",
        "Wolfi",
        "openEuler",
        "openSUSE",
    }
)


def _is_distribution_ecosystem(ecosystem: str | None) -> bool:
    """Whether an affected entry's ecosystem is a distribution package
    namespace (bare or with a release suffix).

    The comparison is on the namespace before the first ``:`` so the release
    suffixes the schema documents (``Debian:11``, ``Ubuntu:24.04``,
    ``Alpine:v3.19``, ``openSUSE:Leap:15.5``) match their base distribution.
    """
    if ecosystem is None:
        return False
    namespace = ecosystem.split(":", 1)[0].strip()
    return namespace in _DISTRIBUTION_ECOSYSTEMS


def _covers_version(
    introduced: str | None,
    limit: str | None,
    version_key: semver.Version | None,
    limit_inclusive: bool = False,
) -> bool:
    """Whether the interval ``[introduced, limit]`` covers the detected version.

    The limit is exclusive for ``fixed`` (the fixed version itself is safe)
    and inclusive for ``last_affected`` (that version is still affected). An
    unparsable bound or an unparsable detected version is treated as covering
    (conservative inclusion): a bound we cannot compare must not silently
    drop a fixed version from the recommendation.
    """
    if version_key is None:
        return True
    if introduced is not None and introduced not in ("", "0"):
        introduced_key = _parse_version_key(introduced)
        if introduced_key is not None and version_key < introduced_key:
            return False
    if limit is not None:
        limit_key = _parse_version_key(limit)
        if limit_key is not None:
            if limit_inclusive:
                if version_key > limit_key:
                    return False
            elif version_key >= limit_key:
                return False
    return True


def _get_fixed_versions(
    affected_data: list[dict[str, Any]] | None,
    package_name: str | None,
    package_version: str | None = None,
    ecosystem: str | None = None,
    whitelisted_ecosystems: list[str] | None = None,
) -> tuple[list[str], bool]:
    """Collect the fixed-version endpoints of the affected intervals that
    cover the detected package version.

    OSV records are advisory-shaped: one record can list several packages
    (the queried library, the frameworks that bundle it, and distro builds of
    it), and one affected entry can carry several ranges — an advisory with
    several affected version intervals, one per maintained branch (e.g.
    protobuf's 3.18.3 / 3.19.5 / 3.20.2 / 4.21.6 for CVE-2022-1941). Reading
    only ``affected[0]`` / ``ranges[0]`` / ``events[1]`` picks whatever the
    record happened to list first — another package's fixed version (e.g. a
    distro build of a bundled framework), or the endpoint of an interval that
    does not cover the detected version, which yields recommendations the
    installed version already satisfies.

    Only the entries whose package name matches the queried package
    (case-insensitive; an entry without a package is treated as the queried
    package) and whose ecosystem matches, when one is given, are considered.
    For an **unscoped** query (neither ``ecosystem`` nor
    ``whitelisted_ecosystems``), distribution-namespace entries
    (``Debian:11``, ``AlmaLinux:8``, ... — see
    ``_is_distribution_ecosystem``) are skipped before collecting endpoints:
    a distro's fixed version is expressed in the distribution's own version
    scheme, is not actionable for an upstream consumer, and — when it happens
    to parse as semver (``3.5.1+dfsg-1`` parses as build metadata,
    ``3.4.6-6.el8`` as a pre-release) — can outrank the real ecosystem
    endpoint. Distro endpoints therefore never enter the recommendation
    through a query that did not target them; the semver aggregate's
    parse-drop remains as the net for anything whitelisted on purpose (the
    native-library pipeline whitelists distro ecosystems).
    For a **whitelisted** query, entry collection is additionally restricted
    to the whitelisted ecosystems: the record-level whitelist keeps a record
    when ANY of its entries matches, so a record mixing a whitelisted entry
    (``OSS-Fuzz``) with a non-whitelisted one for the same package name
    (``npm``) would otherwise contribute the non-whitelisted endpoint, which
    — being the highest semver — outranks the native fix in the aggregate.
    The whitelist matches the ecosystem's namespace before the first ``:``
    (case-insensitive), so release-suffixed forms of a whitelisted
    namespace (``Alpine:v3.19`` for ``Alpine``) stay collectible; an entry
    without an ecosystem fails open.
    Within the kept entries, every interval that covers the detected version
    contributes its ``fixed`` endpoint; the aggregate recommendation then
    takes the maximum, which names the branch the user can stay on.
    GIT ranges carry commit hashes, not versions, and are skipped for the
    version comparison.

    Returns the collected endpoints and whether any covering interval closes
    with ``last_affected`` instead of ``fixed`` — an advisory with no
    nameable safe version, for which the caller must fall back to
    recommending the latest available version rather than an endpoint that
    does not cover it.
    """
    if affected_data is None:
        return [], False
    version_key = (
        _parse_version_key(package_version) if package_version is not None else None
    )
    unscoped_query = ecosystem is None and not whitelisted_ecosystems
    whitelisted_namespaces = (
        {name.lower() for name in whitelisted_ecosystems}
        if whitelisted_ecosystems
        else None
    )
    fixed_versions: list[str] = []
    has_unfixed_covering_interval = False
    for affected in affected_data:
        package = affected.get("package") or {}
        entry_name = package.get("name")
        if (
            package_name is not None
            and entry_name is not None
            and entry_name.lower() != package_name.lower()
        ):
            continue
        entry_ecosystem = package.get("ecosystem")
        if (
            ecosystem is not None
            and entry_ecosystem is not None
            and entry_ecosystem != ecosystem
        ):
            continue
        if unscoped_query and _is_distribution_ecosystem(entry_ecosystem):
            continue
        if whitelisted_namespaces is not None and entry_ecosystem is not None:
            # A whitelisted query deliberately targets its whitelisted
            # ecosystems: a record passes the record-level whitelist when ANY
            # of its entries matches, so without this restriction its other
            # entries (e.g. an npm entry of the same package name) would
            # contribute endpoints that — being the highest semver — outrank
            # the native fix in the aggregate. The namespace before the
            # first ``:`` is matched case-insensitively because whitelist
            # entries are base namespaces (``Alpine``) while entries carry
            # release suffixes (``Alpine:v3.19``); an entry without an
            # ecosystem fails open, mirroring the ``ecosystem`` scope filter.
            entry_namespace = entry_ecosystem.split(":", 1)[0].strip().lower()
            if entry_namespace not in whitelisted_namespaces:
                continue
        for ranges_data in affected.get("ranges", []):
            if ranges_data.get("type") == "GIT":
                continue
            introduced: str | None = None
            for event in ranges_data.get("events", []):
                if "introduced" in event:
                    introduced = str(event["introduced"])
                    continue
                if "fixed" in event:
                    fixed_version = str(event["fixed"])
                    if _covers_version(introduced, fixed_version, version_key):
                        fixed_versions.append(fixed_version)
                    introduced = None
                    continue
                if "last_affected" in event:
                    if _covers_version(
                        introduced,
                        str(event["last_affected"]),
                        version_key,
                        limit_inclusive=True,
                    ):
                        # The affected interval ends at this version with no
                        # named safe point: no fixed version can cover the
                        # detected installation.
                        has_unfixed_covering_interval = True
                    introduced = None
    return fixed_versions, has_unfixed_covering_interval


def _get_highest_fixed_version(
    fixed_versions: list[str], package_name: str | None
) -> str:
    """Return the highest valid semantic fixed version.

    The emitted string is the parsed version's ``major.minor.patch`` — never
    the raw collected string — so an endpoint that slipped through the
    entry-level filters carrying a distribution suffix (``3.5.1+dfsg-1``)
    or pre-release segment (``3.4.6-6.el8``) is recommended in canonical
    semver form rather than verbatim. Dropping pre-release/build segments is
    conservative-safe for the "update to version >= X or later" semantics:
    ``3.5.0`` follows ``3.5.0-beta.1`` in semver precedence, so naming the
    release is always at-or-above the advisory's own first fixed version.
    """
    parsed_versions: list[semver.Version] = []
    for fixed_version in fixed_versions:
        try:
            parsed_versions.append(semver.Version.parse(fixed_version))
        except (TypeError, ValueError):
            logger.warning(
                "Ignoring invalid fixed version `%s` for %s package.",
                fixed_version,
                package_name,
            )

    if len(parsed_versions) == 0:
        return ""

    highest = max(parsed_versions)
    return f"{highest.major}.{highest.minor}.{highest.patch}"


def _get_cvss_v3_vector(severity_data: list[dict[str, str]]) -> str:
    if severity_data is not None and len(severity_data) > 0:
        return severity_data[0].get("score", "")

    return ""


def construct_vuln(
    parsed_vulns: list[VulnData], path: str | None = None
) -> Iterator[Vulnerability]:
    """Construct Vulnerabilities from the parse output.
    Args:
        parsed_vulns: list of VulnData.
        path: path of the dependency.
    Yields:
        Vulnerability entry.
    """
    for vuln in parsed_vulns:
        if len(vuln.cves) == 0:
            continue

        if vuln.fixed_version != "":
            recommendation = (
                f"We recommend updating `{vuln.package_name}` to a version greater than or equal to "
                f"`{vuln.fixed_version}`."
            )
        else:
            recommendation = f"We recommend updating `{vuln.package_name}` to the latest available version."

        vuln.cves.sort(reverse=True)
        title = f"Use of Outdated Vulnerable Component: {vuln.package_name}@{vuln.package_version}: {', '.join(vuln.cves[:MAX_SHOWN_CVES])}"

        if vuln.file_type is not None and vuln.file_name is not None:
            description = (
                f"Dependency `{vuln.package_name}` with version `{vuln.package_version}`"
                f" found in the `{vuln.file_type}` `{vuln.file_name}` "
                f"has a security issue.\nThe issue is identified by CVEs: `{', '.join(vuln.cves)}`."
            )
        else:
            description = (
                f"Dependency `{vuln.package_name}` with version `{vuln.package_version}`"
                f" has a security issue.\nThe issue is identified by CVEs: `{', '.join(vuln.cves)}`."
            )

        technical_detail = (
            f"#### Dependency `{vuln.package_name}`:\n"
            f"- **Version**: `{vuln.package_version}`\n"
        )
        if path is not None:
            technical_detail += f"- **Location**: {path}\n"
        osv_description = vuln.description.replace(
            "## Recommendation\n\n", "Recommendation: "
        )
        technical_detail += f"- **Description**:\n{osv_description}\n"

        short_description = f"Dependency `{vuln.package_name}` with version `{vuln.package_version}` has a security issue."

        yield Vulnerability(
            entry=kb.Entry(
                title=title,
                risk_rating=vuln.risk,
                short_description=short_description,
                description=description,
                references=build_references(vuln.references),
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False,
                recommendation=recommendation,
            ),
            dna=f"Use of Outdated Vulnerable Component: {vuln.package_name}@{vuln.package_version}{f': {path}' if path is not None else ''}",
            technical_detail=technical_detail,
            risk_rating=agent_report_vulnerability_mixin.RiskRating[
                vuln.risk.upper()
                if vuln.risk.upper() in RISK_RATINGS
                else "POTENTIALLY"
            ],
        )


def _vuln_risk_rating(
    risk: str | None, cves: list[str], api_key: str | None = None
) -> str:
    if risk is None:
        risk_ratings = [
            cve_service_api.get_cve_data_from_api(cve, api_key).risk for cve in cves
        ]
        return calculate_risk_rating(risk_ratings)

    elif risk == "MODERATE":
        return "MEDIUM"
    else:
        return risk
