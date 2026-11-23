# Connect Codex CLI to MCP Shield

Keep MCP Shield running. Its default endpoint is `http://127.0.0.1:8765/mcp`; the Windows launcher may choose another port between 8765 and 8775 when needed.

The installed Codex CLI help for `codex mcp add` was checked locally. It supports Streamable HTTP via `--url` and bearer authentication via `--bearer-token-env-var`.

In a PowerShell process where the MCP Shield launcher printed the client token, set the environment variable and add the endpoint:

```powershell
$env:SHIELD_CLIENT_TOKEN = '<copy SHIELD_CLIENT_TOKEN from the launcher>'
codex mcp add mcp_shield --url http://127.0.0.1:8765/mcp --bearer-token-env-var SHIELD_CLIENT_TOKEN
codex mcp list
```

Start Codex from that same PowerShell process so it inherits the token. If the server is already configured, update the existing `mcp_shield` entry instead of adding a duplicate. Codex reads the token from its process environment; Shield never returns it from its APIs.

The dashboard is at `http://127.0.0.1:8765`. Enter the separate `SHIELD_APPROVER_TOKEN` from the launcher in its approver field to view and resolve pending reviews. The dashboard keeps that token in page memory only and clears it when locked or reloaded.

The example manifest has no downstream servers, so initial tool listing includes built-in Shield tools only. Add a downstream server and explicit security metadata to a local manifest before expecting its tools to appear.

## Verify

1. Confirm the server is running and `GET /api/health` reports `status: ready`.
2. Run `codex mcp list` and confirm `mcp_shield` is enabled.
3. Ask Codex to list MCP tools and confirm `shield_status` appears.
4. Call `shield_status` and confirm it returns the real gateway status.
5. Add a local fixture downstream server to an operator manifest and verify one allowed call, one blocked call, and one review call.
6. Resolve the review through the authenticated dashboard and confirm the original MCP call returns the downstream result.

## Verification status

`MANUAL-VERIFIED (Codex CLI)`: a temporary command-line MCP configuration discovered Shield tools, read a harmless fixture, blocked an outside-root delete with P-001, held an in-root delete for P-006 review, and returned the real fixture response after authenticated approval. The out-of-band fixture counter and gateway audit confirmed the execution count and forwarding status. The user's Codex configuration was not changed.

`MANUAL-NOT-RUN (Codex desktop UI)`: the desktop app itself has not been tested against this server. Automated SDK tests and Codex CLI verification do not prove the desktop UI's behavior.
