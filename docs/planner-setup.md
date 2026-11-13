# Planner readiness and local-only models

AUTO checks model configuration and engagement budget before launching its loop.
Missing keys, missing tariffs, exhausted budgets and unavailable local models now
produce specific persisted blocked reasons. The check makes no generation request
and consumes no model quota. Cloud credentials are checked locally for availability
and decryptability; remote credential validity is established only by an authorized
request. Actual requests still reserve budget against their full prompt immediately
before I/O, so a successful preflight is not a guarantee of later admission.

## Local-only setup

Provide a local OpenAI-compatible inference server exposing `GET /v1/models` and
`POST /v1/chat/completions`. It must support JSON-object responses and advertise
the exact installed model ID. Configure the deployment environment:

```dotenv
LLM_ROUTING=local
LOCAL_LLM_URL=http://127.0.0.1:11434/v1
LOCAL_LLM_MODEL=your-installed-model-id
```

Replace the model ID with one already installed on your server, then restart ARIA
through its normal service procedure. This change does not install a model, download
weights, change deployment secrets or modify the running service. No provider key
is needed for local mode. Only numeric loopback HTTP endpoints are accepted; outbound
proxy environment variables and redirects are disabled. The inference server itself
must run local weights without cloud forwarding. ARIA cannot attest to the server's
internal behavior.

Local mode routes all model tasks locally and never falls back to cloud providers.
Model calls still require ownership, engagement data-sharing consent where configured,
call/token limits and durable accounting. Local inference has zero reserved provider
cost and needs no tariff, while calls and tokens remain bounded. Electricity and
hardware cost are not measured. Default engagement limits allow up to 20 calls;
existing stricter limits remain authoritative. Review them in the Team budget controls.

For cloud mode, retain `LLM_ROUTING=cloud`, add an active provider key and configure
an engagement tariff for the exact selected provider/model. Preflight never probes
a cloud model or makes a paid test call. Task-specific model overrides in
`llm/pool_manager.py` also apply during preflight.

## Failure handling and verification

Configuration and authorization errors stop immediately. Temporary request failures
get at most three logical planning attempts; malformed JSON or rejected commands get
two corrective attempts. Plans require exactly one command with string `tool`,
`command`, `purpose` and `expected_evidence` fields. Server scope, capabilities,
approval and worker validation remain authoritative.

Status exposes `planning_attempts`. The compatibility field `model_calls` retains
its old logical-attempt meaning, with an explicit `model_calls_basis`. Physical
provider requests and their reservations are recorded in engagement model accounting.

Run offline verification:

```bash
DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
```

After configuring a real local model, use an authorized isolated engagement and
confirm an accepted proposal, worker job receipt and saved observation. Offline
transport tests establish the integration contract, not model quality or live
vulnerability discovery. No real local generation was performed during this change.
