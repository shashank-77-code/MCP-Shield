# MCP Shield

MCP Shield is a local, fail-closed security gateway for MCP tool calls routed through it. It exposes a Streamable HTTP endpoint, validates tools against an operator-controlled manifest, evaluates deterministic policy before execution, forwards allowed calls to real downstream MCP servers, holds reviewable calls for authenticated approval, and records redacted audit events.

Shield only protects MCP traffic configured to use its endpoint. It does not prevent a client from connecting directly to a downstream server through another route.

## Start on Windows

Use Python 3.11 or later and double-click `run_mcp_shield.bat`. On first launch, the script creates `.venv` and installs the pinned dependencies. It uses the safe example manifest (which has no downstream servers configured), generates local client and approver tokens if you have not supplied them in the environment, starts the server on loopback, waits for its health endpoint, and opens the dashboard.

The default URLs are:

```text
Dashboard:     http://127.0.0.1:8765
MCP endpoint:  http://127.0.0.1:8765/mcp
```

If that port is occupied, the launcher checks through port 8775 and prints the selected URL. The generated tokens are displayed once in the launcher console, are not written to disk, and change on the next launch. Enter the approver token in the dashboard to unlock approval requests. Keep the launcher open while using Shield.

The example manifest starts with no downstream tools, so only the built-in Shield tools appear. To connect a server, copy `config/manifest.example.json` to `config/manifest.json`, set `SHIELD_MANIFEST` to that file, and add an explicit server/tool policy and authorization rule. Do not expose a downstream tool until its manifest metadata has been reviewed.

## Manual start

Set strong, independent tokens in the same PowerShell process that starts Uvicorn. The following generates random tokens for one launch:

```powershell
$clientBytes = [byte[]]::new(32)
$clientRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$clientRandom.GetBytes($clientBytes)
$clientRandom.Dispose()
$env:SHIELD_CLIENT_TOKEN = [Convert]::ToBase64String($clientBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

$approverBytes = [byte[]]::new(32)
$approverRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$approverRandom.GetBytes($approverBytes)
$approverRandom.Dispose()
$env:SHIELD_APPROVER_TOKEN = [Convert]::ToBase64String($approverBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$env:SHIELD_APPROVER_TOKENS = '{"local-admin":"' + $env:SHIELD_APPROVER_TOKEN + '"}'

py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

For an operator-configured manifest, also set `$env:SHIELD_MANIFEST` to its path. If `SHIELD_APPROVER_TOKENS` is not configured, REVIEW requests terminate safely without forwarding.

## Connect Codex CLI

The installed Codex CLI advertises `--bearer-token-env-var` for Streamable HTTP MCP servers. Set the same client token in the shell that launches Codex, then add the server:

```powershell
$env:SHIELD_CLIENT_TOKEN = '<copy SHIELD_CLIENT_TOKEN from the launcher>'
codex mcp add mcp_shield --url http://127.0.0.1:8765/mcp --bearer-token-env-var SHIELD_CLIENT_TOKEN
codex mcp list
```

Run `codex` from that PowerShell window so its process receives the token. If the launcher selected another port, substitute it. Codex manual forwarding and approval verification must still be performed separately; automated SDK tests do not prove the desktop client is configured.

## What is implemented

- Official MCP Python SDK Streamable HTTP server bound to loopback with bearer authentication.
- Application sessions bound to the authenticated client, with expiry and isolated confidentiality/integrity state.
- Operator manifest validation, namespaced downstream tool discovery, and real stdio MCP forwarding.
- Fail-closed deterministic policy evaluation, including path/repository boundaries, destination checks, and payload detectors.
- Authenticated approver API with request-bound, single-use grants and fresh revalidation.
- SDK-native progress notifications during approval waits and cancellation-safe pending calls.
- Redacted gateway audit events and separate tool-call, ALLOW, REVIEW, BLOCK, execution, rejection, timeout, cancellation, downstream-error, and audit-event metrics.
- Dashboard polling of real gateway events and metrics. Approval requests require an operator token typed into the page; it is kept in page memory and cleared when the page reloads or is locked.
- A separate legacy security simulation labelled **DEMO DATA**. It does not represent real gateway traffic or change the live gateway metrics.

Only the `tools` MCP capability is proxied. Resources, prompts, completions, and other downstream capabilities are not proxied.

## API

- `GET /api/health` — local readiness, downstream server count, and whether approvals are configured; no credentials returned.
- `GET /api/gateway/events` — redacted gateway audit events and metrics.
- `GET /api/gateway/metrics` — separate gateway outcome counters.
- `GET /api/gateway/approvals` — authenticated pending approval list; requires an approver bearer token.
- `POST /api/gateway/approvals/{request_id}` — authenticated `approve` or `reject` with a reason; same-origin checks protect browser actions.
- `POST /api/demo/run` — run the clearly labelled legacy **DEMO DATA** simulation.
- `POST /api/session/reset` — reset only the legacy demo session.
- `/mcp` — authenticated Streamable HTTP MCP endpoint.

## Limitations

- Sessions, approval requests/grants, and audit records are held in memory in this single-process prototype. They are lost on restart. Audit storage retains up to the configured limit (1,000 by default).
- Path validation cannot eliminate the race between Shield checking a path and a downstream server opening it. Run downstream servers with appropriate OS sandboxing and least privilege.
- Shield cannot protect traffic that bypasses the configured MCP endpoint.
- The Windows launcher generates ephemeral credentials by default; restart Codex with the matching bearer-token environment variable after each launch.
- Codex desktop UI behavior is marked `MANUAL-NOT-RUN` until separately tested with the actual desktop client.

## Tests

Run backend tests with:

```powershell
.\.venv\Scripts\python.exe -m pytest -vv
```

Run frontend module tests with Node.js:

```powershell
node --test tests/test_frontend.mjs
```
