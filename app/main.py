"""
Sonatype Guide → Port Webhook Backend
Handles three self-service actions:
  - search_oss_component   (X-Port-Action: search_oss_component)
  - get_remediation        (X-Port-Action: get_remediation)
  - refresh_component      (X-Port-Action: refresh_component)
"""

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.services.guide import GuideClient
from app.services.port import PortClient
from app.services.mapper import map_component_to_entities, map_remediation_to_entity
from app.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(timeout=30)
    yield
    await app.state.http.aclose()


app = FastAPI(title="Sonatype Guide Webhook", lifespan=lifespan)


def get_clients(request: Request):
    guide = GuideClient(request.app.state.http, settings.sonatype_api_token)
    port = PortClient(request.app.state.http, settings.port_client_id, settings.port_client_secret)
    return guide, port


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_port_action: str = Header(..., alias="X-Port-Action"),
):
    body = await request.json()
    logger.info("Received action=%s payload=%s", x_port_action, body)

    guide, port = get_clients(request)
    run_id = body.get("portContext", {}).get("runId")

    try:
        if x_port_action == "search_oss_component":
            return await handle_search(body, guide, port, run_id)
        elif x_port_action == "get_remediation":
            return await handle_get_remediation(body, guide, port, run_id)
        elif x_port_action == "refresh_component":
            return await handle_refresh(body, guide, port, run_id)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {x_port_action}")

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unhandled error for action=%s", x_port_action)
        if run_id:
            await port.fail_run(run_id, str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------

async def handle_search(body: dict, guide: GuideClient, port: PortClient, run_id: str):
    package_url = body.get("packageUrl")
    fetch_remediation = body.get("fetchRemediation", True)
    # Port sends booleans as strings when templated
    if isinstance(fetch_remediation, str):
        fetch_remediation = fetch_remediation.lower() == "true"

    if not package_url:
        raise HTTPException(status_code=400, detail="packageUrl is required")

    await port.log_run(run_id, f"Querying Sonatype Guide for {package_url}...")

    component_data = await guide.get_component_details(package_url)
    package_entity, version_entity = map_component_to_entities(component_data, package_url)

    await port.upsert_entity("sonatype_guide_package", package_entity)
    await port.upsert_entity("sonatype_guide_package_version", version_entity)

    if fetch_remediation:
        await _fetch_and_upsert_remediation(package_url, guide, port, run_id)

    await port.complete_run(run_id, f"Component data retrieved and synced to Port for {package_url}")
    return JSONResponse({"status": "success", "packageUrl": package_url})


async def handle_get_remediation(body: dict, guide: GuideClient, port: PortClient, run_id: str):
    package_url = body.get("packageUrl")
    if not package_url:
        raise HTTPException(status_code=400, detail="packageUrl is required")

    await port.log_run(run_id, f"Fetching remediation recommendation for {package_url}...")
    await _fetch_and_upsert_remediation(package_url, guide, port, run_id)

    await port.complete_run(run_id, f"Remediation recommendation retrieved for {package_url}")
    return JSONResponse({"status": "success", "packageUrl": package_url})


async def handle_refresh(body: dict, guide: GuideClient, port: PortClient, run_id: str):
    package_url = body.get("packageUrl")
    if not package_url:
        raise HTTPException(status_code=400, detail="packageUrl is required")

    await port.log_run(run_id, f"Refreshing {package_url} from Sonatype Guide...")

    component_data = await guide.get_component_details(package_url)
    package_entity, version_entity = map_component_to_entities(component_data, package_url)

    await port.upsert_entity("sonatype_guide_package", package_entity)
    await port.upsert_entity("sonatype_guide_package_version", version_entity)
    await _fetch_and_upsert_remediation(package_url, guide, port, run_id)

    await port.complete_run(run_id, f"Refreshed {package_url} — security posture and ratings updated.")
    return JSONResponse({"status": "success", "packageUrl": package_url})


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

async def _fetch_and_upsert_remediation(
    package_url: str, guide: GuideClient, port: PortClient, run_id: str
):
    try:
        remediation_data = await guide.get_remediation(package_url)
        if remediation_data:
            remediation_entity = map_remediation_to_entity(remediation_data, package_url)
            await port.upsert_entity("sonatype_guide_remediation", remediation_entity)
        else:
            logger.info("No remediation available for %s", package_url)
            await port.log_run(run_id, f"No remediation recommendation available for {package_url}")
    except Exception as exc:
        # Remediation is best-effort — log but don't fail the whole action
        logger.warning("Remediation fetch failed for %s: %s", package_url, exc)
        await port.log_run(run_id, f"Note: Could not fetch remediation — {exc}")
