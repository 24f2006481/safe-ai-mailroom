# Safe AI Mailroom starter

FastAPI service for `ga5-mailroom-action-gate/v2`.

## Render settings
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
- Endpoint URL to submit: `https://YOUR-SERVICE.onrender.com/`

Health check: `GET /`. Grader operations use `POST /`.

## Important limitation
This starter includes request envelopes, persistent SQLite state, stable dossier caching, schema checks, proposal hashing, and Ed25519 receipt verification. The included fallback is conservative and rule-based; it is not a full AI decision engine and will not reliably score well on hidden cases. Before Check/Save, add an AI model integration and validate decisions against the assignment's action/evidence rules. Do not submit until the full propose/commit flow is tested.

Optional environment variable `DATABASE_PATH` sets the SQLite file path. On Render, local disk persistence requires a persistent disk; otherwise SQLite state may be lost on redeploy/restart.
