"""
Sonatype Guide API client.
Base URL: https://api.guide.sonatype.com
Auth: Bearer token

Verified endpoints:
  GET  /components/detail          → metadata (versionScore, maxCvss, licenses, dts scores)
  GET  /components/vulnerabilities → CVE list
  POST /recommendations            → version upgrade recommendation
"""

import logging
from typing import Optional
from urllib.parse import quote

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def _parse_purl(purl: str) -> dict:
    """
    Parse a purl into coordinate query params for the Guide API.

    pkg:npm/lodash@4.17.20
      → format=npm, name=lodash, version=4.17.20

    pkg:maven/org.apache.struts/struts2-core@2.5.10
      → format=maven, namespace=org.apache.struts, name=struts2-core, version=2.5.10

    pkg:pypi/requests@2.31.0
      → format=pypi, name=requests, version=2.31.0
    """
    rest = purl.removeprefix("pkg:")
    rest, version = rest.rsplit("@", 1) if "@" in rest else (rest, "")
    parts = rest.split("/", 2)
    fmt = parts[0]

    if len(parts) == 3:
        namespace, name = parts[1], parts[2]
    elif len(parts) == 2:
        namespace, name = "", parts[1]
    else:
        namespace, name = "", parts[0]

    return {"format": fmt, "namespace": namespace, "name": name, "version": version}


class GuideClient:
    def __init__(self, http: httpx.AsyncClient, api_token: str):
        self._http = http
        self._headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._base = settings.sonatype_api_base_url

    def _coords(self, purl: str) -> dict:
        c = _parse_purl(purl)
        params = {
            "purl": purl,
            "format": c["format"],
            "name": c["name"],
            "version": c["version"],
        }
        if c["namespace"]:
            params["namespace"] = c["namespace"]
        return params

    async def get_component_details(self, purl: str) -> dict:
        """
        Calls GET /components/detail and GET /components/vulnerabilities,
        merges them into one dict for the mapper.

        Response shape from /components/detail:
          format, namespace, name, version, registryLink,
          components[], licenses[], categories[], latestStable,
          versionScore, maxCvss, publishedDate, isMalware,
          policyCompliance{}, dts{ overall, age, license, popularity, releaseStability, security }

        Vulnerabilities attached under _vulnerabilities[]:
          Each item has: refid, severity, isMalware
        """
        params = self._coords(purl)

        logger.info("Guide API → GET /components/detail purl=%s", purl)
        detail_resp = await self._http.get(
            f"{self._base}/components/detail",
            params=params,
            headers=self._headers,
        )
        detail_resp.raise_for_status()
        detail = detail_resp.json()

        logger.info("Guide API → GET /components/vulnerabilities purl=%s", purl)
        vuln_resp = await self._http.get(
            f"{self._base}/components/vulnerabilities",
            params=params,
            headers=self._headers,
        )
        vuln_resp.raise_for_status()
        vuln_data = vuln_resp.json()

        # Store the full paginated response — mapper reads hits, total, aggregations
        detail["_vulnerabilities"] = vuln_data

        return detail

    async def get_remediation(self, purl: str) -> Optional[dict]:
        """
        POST /recommendations
        Body: { "purl": "<purl>" }
        Returns { fromVersion, toVersions: [...] } or None if already optimal.
        """
        url = f"{self._base}/recommendations"

        logger.info("Guide API → POST /recommendations purl=%s", purl)
        resp = await self._http.post(
            url,
            json={"purl": purl},
            headers=self._headers,
        )

        if resp.status_code == 404:
            logger.info("No recommendation found for %s (404)", purl)
            return None

        resp.raise_for_status()
        data = resp.json()

        if not data.get("toVersions"):
            logger.info("No upgrade needed for %s — already optimal", purl)
            return None

        return data
