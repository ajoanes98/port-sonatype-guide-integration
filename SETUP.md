# Sonatype Guide × Port — Setup Guide

This guide walks you through installing the Sonatype Guide integration into your Port organization. The integration syncs OSS component intelligence — vulnerabilities, hygiene ratings, license data, and upgrade recommendations — directly into your Port catalog.

---

## What you'll get

- **OSS Package catalog** — every tracked dependency enriched with live Sonatype Guide data
- **Vulnerability visibility** — CVE counts by severity, CVSS scores, and a formatted vuln summary per component version
- **Remediation recommendations** — the safest version to upgrade to, surfaced directly in Port
- **Scorecard** — automatic security posture rating (Critical Risk → Trusted) per component
- **Three self-service actions** — Search, Refresh, and Get Remediation, triggerable by any developer from Port

---

## Prerequisites

Before you start you'll need:

| Requirement | Where to get it |
|---|---|
| Sonatype Guide API token | `guide.sonatype.com/settings/tokens` |
| Port Client ID + Secret | `app.port.io/organization/credentials` |
| Docker (for container deployment) | `docs.docker.com/get-docker` |
| Port GitHub App installed (for GitHub Actions deployment) | `app.port.io/settings/integrations` |

---

## Step 1 — Register blueprints in Port

Blueprints must be registered in this order (parent before child):

1. Go to **Port → Builder → + Blueprint → Edit JSON**
2. Paste and save each file in order:
   - `blueprints/sonatype_guide_package.json`
   - `blueprints/sonatype_guide_package_version.json`
   - `blueprints/sonatype_guide_remediation.json`

## Step 2 — Register the scorecard

1. In Builder, click on the **OSS Package Version** blueprint
2. Open the **Scorecards** tab → **+ Scorecard → Edit JSON**
3. Paste `scorecards/oss_component_security.json` and save

## Step 3 — Register the self-service actions

1. Go to **Port → Self-Service → + Action → Edit JSON**
2. Paste and save each file:
   - `actions/search_oss_component.json`
   - `actions/get_remediation.json`
   - `actions/refresh_component.json`

---

## Step 4 — Deploy the webhook backend

Choose the deployment approach that fits your setup:

---

### Option A — Docker container (recommended for most teams)

The webhook backend is a lightweight FastAPI service that bridges Port's self-service actions with the Sonatype Guide API.

**Pull the image:**
```bash
docker pull ajoanes98/sonatype-guide-port-integration:latest
```

**Run with environment variables:**
```bash
docker run -d \
  -e SONATYPE_API_TOKEN=your-guide-api-token \
  -e PORT_CLIENT_ID=your-port-client-id \
  -e PORT_CLIENT_SECRET=your-port-client-secret \
  -p 8000:8000 \
  ajoanes98/sonatype-guide-port-integration:latest
```

Or using docker-compose — copy `.env.example` to `.env`, fill in your credentials, then:
```bash
docker compose up -d
```

The service needs to be reachable from Port over HTTPS. Deploy it on any platform that gives you a public URL — Railway, Render, Fly.io, AWS ECS, or a VM with nginx in front. The container listens on port `8000` and exposes `POST /webhook`.

Verify it's running:
```bash
curl https://your-deployment-url/health
# {"status": "ok"}
```

---

### Option B — Port Agent (recommended for enterprise / private networks)

The Port Agent runs inside your network and proxies action invocations outbound — no public URL or open firewall rules needed. The container only needs outbound access to Port and Sonatype Guide.

**Install the Port Agent** following the [Port Agent docs](https://docs.port.io/actions-and-automations/setup-backend/webhook/port-execution-agent/usage/).

**Run the webhook container** on the same internal network as the agent — it does not need a public URL in this setup.

**Update each action's `invocationMethod`** — change `"agent": false` to `"agent": true` in all three action JSON files and re-register them in Port.

---

### Option C — GitHub Actions (coming soon)

A zero-infrastructure alternative where Port triggers GitHub Actions workflows directly instead of calling a webhook. No server required. See the `TODO` section in `INTEGRATION_DESIGN.md` for details — this path is planned but not yet implemented.

---

## Step 5 — Add the webhook URL as a Port secret

Once your backend is deployed and reachable:

1. Go to **Port → Organization Settings → Credentials → Secrets**
2. Click **+ Secret** and add:
   - **Name:** `SONATYPE_GUIDE_WEBHOOK_URL`
   - **Value:** `https://your-deployment-url/webhook`

> Note: The secret must be named exactly `SONATYPE_GUIDE_WEBHOOK_URL` — this is what the action JSON files reference via `{{.secrets.SONATYPE_GUIDE_WEBHOOK_URL}}`.

---

## Step 6 — Test the integration

Trigger the **Search OSS Component** action from Port's Self-Service page:

1. Go to **Self-Service → Search OSS Component → Execute**
2. Enter a package URL, e.g. `pkg:npm/lodash@4.17.20`
3. Set **Fetch Remediation** to `true`
4. Click **Execute**

After a successful run you should see:
- A new **OSS Package** entity for `lodash`
- A new **OSS Package Version** entity for `lodash 4.17.20` with vulnerability data populated
- A **Remediation** entity showing the recommended upgrade version
- The scorecard evaluated against the component's security posture

---

## Environment variables reference

| Variable | Required | Description |
|---|---|---|
| `SONATYPE_API_TOKEN` | ✅ | Your Sonatype Guide API token |
| `PORT_CLIENT_ID` | ✅ | Your Port organization client ID |
| `PORT_CLIENT_SECRET` | ✅ | Your Port organization client secret |
| `SONATYPE_API_BASE_URL` | Optional | Override Guide API base URL (default: `https://api.guide.sonatype.com`) |
| `PORT_API_BASE_URL` | Optional | Override for US region: `https://api.us.port.io/v1` |

---

## Supported package ecosystems

`maven` · `npm` · `pypi` · `golang` · `nuget` · `gem` · `cargo` · `composer` · `conan` · `conda`

---

## Troubleshooting

**Action fails with "Invalid input: expected string, received null at url"**
The `SONATYPE_GUIDE_WEBHOOK_URL` secret is missing or named incorrectly in Port. Check **Organization Settings → Credentials → Secrets**.

**401 Unauthorized from Sonatype Guide**
Your `SONATYPE_API_TOKEN` is invalid or expired. Regenerate it at `guide.sonatype.com/settings/tokens`.

**422 Unprocessable Entity when upserting to Port**
A required blueprint field is missing or has an invalid value. Check the container logs for the full error body from the Port API.

**502 Bad Gateway from ngrok (local testing)**
ngrok is not forwarding to the right port. Make sure you ran `ngrok http 8000` and your container is running on port 8000.

---

## File structure reference

```
port-sonatype-guide-integration/
├── app/                          ← Webhook backend (FastAPI)
│   ├── main.py                   ← Route handlers for all 3 actions
│   ├── config.py                 ← Environment variable settings
│   └── services/
│       ├── guide.py              ← Sonatype Guide API client
│       ├── port.py               ← Port API client
│       └── mapper.py             ← API response → Port entity mapping
├── blueprints/                   ← Port blueprint JSON files
├── actions/                      ← Port self-service action JSON files
├── scorecards/                   ← Port scorecard JSON files
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example                  ← Copy to .env and fill in credentials
```
