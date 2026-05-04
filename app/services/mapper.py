"""
Maps Sonatype Guide API responses to Port entity payloads.

Verified API response shapes:

GET /components/detail → ComponentDetailDocument:
  format, namespace, name, version, registryLink,
  components[], licenses[], categories[], latestStable,
  versionScore (int), maxCvss (double), publishedDate,
  isMalware (bool), policyCompliance{},
  dts{ overall, age, license, popularity, releaseStability, security }

GET /components/vulnerabilities → paginated response:
  hits[]: { vulnId, cvssSeverity, sonatypeCvssSeverity, summary,
            cwes[], isMalware, kev, epss, source, publishedAt }
  total, offset, limit
  aggregations.bySeverity: { critical, high, medium, low }

POST /recommendations → { fromVersion, toVersions[] }
"""

import re
from datetime import datetime, timezone
from typing import Tuple, Optional


# ---------------------------------------------------------------------------
# Identifier sanitization
# ---------------------------------------------------------------------------

def sanitize_identifier(purl: str) -> str:
    s = purl
    s = s.replace("pkg:", "pkg-")
    s = s.replace("/", "-")
    s = s.replace("@", "-")
    s = s.replace("%40", "-")
    s = re.sub(r"[^a-zA-Z0-9._\-]", "-", s)
    return s


def base_purl(purl: str) -> str:
    return purl.split("@")[0]


def base_identifier(purl: str) -> str:
    return sanitize_identifier(base_purl(purl))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# DTS score → human-readable rating
# ---------------------------------------------------------------------------

def _dts_to_rating(score: Optional[int]) -> str:
    if score is None:
        return "Unknown"
    if score >= 75:
        return "Excellent"
    if score >= 50:
        return "Good"
    if score >= 25:
        return "Fair"
    return "Poor"


# ---------------------------------------------------------------------------
# Component → (package_entity, version_entity)
# ---------------------------------------------------------------------------

def map_component_to_entities(detail: dict, purl: str) -> Tuple[dict, dict]:
    package_entity = _map_package(detail, purl)
    version_entity = _map_version(detail, purl)
    return package_entity, version_entity


def _map_package(detail: dict, purl: str) -> dict:
    fmt = detail.get("format", "")
    namespace = detail.get("namespace", "")
    name = detail.get("name", "")

    if fmt == "maven" and namespace:
        title = f"{namespace}/{name}"
    elif fmt == "npm" and namespace:
        title = f"{namespace}/{name}".lstrip("/")
    else:
        title = name or base_purl(purl).split("/")[-1]

    return {
        "identifier": base_identifier(purl),
        "title": title,
        "properties": {
            "ecosystem": fmt,
            "name": name,
            "namespace": namespace,
            "basePurl": base_purl(purl),
            "guideUrl": detail.get("registryLink", ""),
            "latestTrackedVersion": detail.get("version", "unknown"),
        },
        "relations": {},
    }


def _map_version(detail: dict, purl: str) -> dict:
    vulns = detail.get("_vulnerabilities", {})

    # Use the pre-aggregated counts from the API response — no bucketing needed
    aggregations = vulns.get("aggregations", {}) if isinstance(vulns, dict) else {}
    by_severity = aggregations.get("bySeverity", {})
    hits = vulns.get("hits", []) if isinstance(vulns, dict) else []
    total = vulns.get("total", 0) if isinstance(vulns, dict) else 0

    critical_count = by_severity.get("critical", 0)
    high_count     = by_severity.get("high", 0)
    medium_count   = by_severity.get("medium", 0)
    low_count      = by_severity.get("low", 0)
    max_cvss       = detail.get("maxCvss", 0) or 0

    dts = detail.get("dts", {}) or {}

    # License — take first license name from the licenses array
    licenses = detail.get("licenses", []) or []
    license_name = licenses[0].get("licenseName", "Unknown") if licenses else "Unknown"

    return {
        "identifier": sanitize_identifier(purl),
        "title": f"{detail.get('name', '')} {detail.get('version', '')}".strip(),
        "properties": {
            "packageUrl": purl,
            "version": detail.get("version", "unknown"),
            "ecosystem": detail.get("format", ""),
            "displayName": f"{detail.get('name', '')} {detail.get('version', '')}".strip(),
            "hygieneRating": _dts_to_rating(dts.get("releaseStability")),
            "integrityRating": _dts_to_rating(dts.get("security")),
            "relativePopularity": dts.get("popularity", 0),
            "effectiveLicense": license_name,
            "catalogDate": detail.get("publishedDate"),
            "matchState": "exact",
            "securityIssueCount": total,
            "criticalCount": critical_count,
            "highCount": high_count,
            "mediumCount": medium_count,
            "lowCount": low_count,
            "maxCvssScore": max_cvss,
            "vulnerabilitySummary": _build_vuln_summary(hits),
            "guideUrl": detail.get("registryLink", ""),
            "lastSyncedAt": now_iso(),
        },
        "relations": {
            "package": base_identifier(purl),
        },
    }


def _build_vuln_summary(hits: list) -> str:
    if not hits:
        return "✅ No open security issues."

    sorted_hits = sorted(hits, key=lambda v: v.get("cvssSeverity") or 0, reverse=True)
    rows = ["| CVE / ID | CVSS | Source |", "|---|---|---|"]
    for v in sorted_hits:
        vuln_id  = v.get("vulnId", "N/A")
        cvss     = v.get("cvssSeverity", 0) or 0
        source   = v.get("source", "Unknown")
        rows.append(f"| {vuln_id} | {cvss} | {source} |")

    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Recommendations → remediation_entity
# POST /recommendations returns: { fromVersion, toVersions[] }
# ---------------------------------------------------------------------------

def map_remediation_to_entity(rec_data: dict, source_purl: str) -> dict:
    # fromVersion is an object: { version, developerTrustScore, maxSeverity, ... }
    from_version_obj = rec_data.get("fromVersion", {})
    from_version = (
        from_version_obj.get("version")
        if isinstance(from_version_obj, dict)
        else source_purl.split("@")[-1]
    )

    to_versions = rec_data.get("toVersions", [])
    if not to_versions:
        raise ValueError("No toVersions in recommendations response")

    # Pick the best recommendation — highest developerTrustScore with no vulnerable methods
    clean = [v for v in to_versions if not v.get("vulnerableMethods")]
    candidates = clean if clean else to_versions
    recommended = max(candidates, key=lambda v: v.get("developerTrustScore") or 0)

    rec_version = recommended.get("version", "unknown")
    rec_purl = base_purl(source_purl) + "@" + rec_version

    # Count remaining vulns in recommended version
    rec_vuln_count = len(recommended.get("vulnerableMethods", []))

    # Build reasons from fromVersion data
    from_vuln_count = len(from_version_obj.get("vulnerableMethods", [])) if isinstance(from_version_obj, dict) else 0
    from_severity = from_version_obj.get("maxSeverity", 0) if isinstance(from_version_obj, dict) else 0
    trust_score = recommended.get("developerTrustScore", 0) or 0

    reasons = (
        f"Upgrading from {from_version} (max CVSS: {from_severity}, {from_vuln_count} vulnerable methods) "
        f"to {rec_version} (developer trust score: {trust_score}, {rec_vuln_count} vulnerable methods remaining)."
    )

    return {
        "identifier": f"remediation-{sanitize_identifier(source_purl)}",
        "title": f"Remediation: {from_version} → {rec_version}",
        "properties": {
            "fromPackageUrl": source_purl,
            "fromVersion": from_version,
            "recommendedPackageUrl": rec_purl,
            "recommendedVersion": rec_version,
            "remediationType": "recommended",
            "reasons": reasons,
            "recommendedVulnCount": rec_vuln_count,
            "guideRemediationUrl": f"https://guide.sonatype.com/component/{_uri_encode(rec_purl)}",
            "fetchedAt": now_iso(),
        },
        "relations": {
            "sourceVersion": sanitize_identifier(source_purl),
        },
    }


def _uri_encode(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")
