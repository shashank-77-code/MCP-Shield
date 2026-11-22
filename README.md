# MCP Shield

MCP Shield is a local, explainable security gateway for Model Context Protocol tool calls. It inspects tool arguments before they leave the process, propagates taint across a session, applies deterministic policy, and makes high-impact calls wait for human approval.

## Run

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000`. The interface is intentionally self-contained: no node install or cloud account is required.

## What is implemented

- Request inspection with sensitive-data and prompt-injection taint sources
- Egress policy for untrusted, sensitive, and outbound data combinations
- Approval queue, allow/block actions, audit trail, and session reset
- A realistic attack simulation that streams events to the UI with WebSockets
- Attack-path graph and blast-radius metrics exposed through the API

## API

- `POST /api/inspect` - evaluate an MCP-like tool call
- `GET /api/events` - list the current audit feed
- `POST /api/approvals/{id}` - approve or deny a pending call
- `POST /api/demo/run` - run the safe adversarial demo
- `POST /api/session/reset` - reset session taint and the demo data

This is a local demonstration gateway, not a replacement for identity-aware authorization, secret storage, or a production security review.
