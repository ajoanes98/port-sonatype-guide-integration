"""
Port API client.
Handles auth token management, entity upserts, and action run lifecycle.
"""

import logging
import time
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_token_cache: dict = {"token": None, "expires_at": 0}


class PortClient:
    def __init__(self, http: httpx.AsyncClient, client_id: str, client_secret: str):
        self._http = http
        self._client_id = client_id
        self._client_secret = client_secret
        self._base = settings.port_api_base_url

    async def _get_token(self) -> str:
        """Fetch and cache a Port API access token."""
        now = time.time()
        if _token_cache["token"] and _token_cache["expires_at"] > now + 60:
            return _token_cache["token"]

        resp = await self._http.post(
            f"{self._base}/auth/access_token",
            json={"clientId": self._client_id, "clientSecret": self._client_secret},
        )
        resp.raise_for_status()
        data = resp.json()
        token = data["accessToken"]
        # Port tokens are valid for 1 hour; cache for 55 minutes to be safe
        _token_cache["token"] = token
        _token_cache["expires_at"] = now + 3300
        logger.info("Refreshed Port API token")
        return token

    async def _headers(self) -> dict:
        token = await self._get_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def upsert_entity(self, blueprint: str, entity: dict) -> dict:
        """
        Create or update a Port entity via PATCH (upsert semantics).
        """
        identifier = entity.get("identifier")
        url = f"{self._base}/blueprints/{blueprint}/entities"
        params = {"upsert": "true", "merge": "true"}

        logger.info("Port upsert → blueprint=%s identifier=%s", blueprint, identifier)
        resp = await self._http.post(
            url,
            json=entity,
            headers=await self._headers(),
            params=params,
        )

        if resp.status_code not in (200, 201):
            logger.error(
                "Port upsert failed blueprint=%s identifier=%s status=%s body=%s",
                blueprint, identifier, resp.status_code, resp.text,
            )
        resp.raise_for_status()
        return resp.json()

    async def log_run(self, run_id: Optional[str], message: str) -> None:
        """Append a log message to an action run."""
        if not run_id:
            return
        url = f"{self._base}/actions/runs/{run_id}/logs"
        resp = await self._http.post(
            url,
            json={"message": message},
            headers=await self._headers(),
        )
        if resp.status_code not in (200, 201):
            logger.warning("Failed to log run message run_id=%s: %s", run_id, resp.text)

    async def complete_run(self, run_id: Optional[str], message: str = "Completed") -> None:
        """Mark an action run as SUCCESS."""
        if not run_id:
            return
        url = f"{self._base}/actions/runs/{run_id}"
        resp = await self._http.patch(
            url,
            json={"status": "SUCCESS", "summary": message},
            headers=await self._headers(),
        )
        if resp.status_code not in (200, 201):
            logger.warning("Failed to complete run run_id=%s: %s", run_id, resp.text)

    async def fail_run(self, run_id: Optional[str], message: str = "Failed") -> None:
        """Mark an action run as FAILURE."""
        if not run_id:
            return
        url = f"{self._base}/actions/runs/{run_id}"
        resp = await self._http.patch(
            url,
            json={"status": "FAILURE", "summary": message},
            headers=await self._headers(),
        )
        if resp.status_code not in (200, 201):
            logger.warning("Failed to fail run run_id=%s: %s", run_id, resp.text)
