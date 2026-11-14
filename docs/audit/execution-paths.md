# ARIA — Execution Paths (Phase A audit)

Audit date: 2026-11-13. Branch `autonoms_pentesters`, HEAD `2fd16db72406a41fc7370537b80d4cb7f7d71bac`.
Every path below was traced in source; `file:line` references are to that HEAD. Paths not traceable to code are labeled NOT DEMONSTRATED.

---

## 1. Interactive plan → proposal → approval → execution → analysis

```
POST /api/v8/input                     api/routers/pentest.py:110-125
  └─ get_accessible_session            api/session_access.py:10-21        (ownership or admin; sets engagement_context.owner)
  └─ intent_engine.parse               orchestrator/intent_engine.py      (special intents: status/findings/report/new-target/correlate/set-goal/set-mode)
  └─ coordinator_agent.decide_next_agent → agents/<specialist>.process    agents/coordinator_agent.py
       └─ BaseAgent checked wrapper    agents/base_agent.py:50-148        (evidence filter/select, worker capability probe, redaction, contract)
       └─ query_llm_smart              agents/base_agent.py:173-193
            └─ pool_manager.query_for_task   llm/pool_manager.py:272-294  (key refresh, secret redaction, task routing)
            └─ model_accounting.reserve/settle   llm/engagement_budget.py:107-258  (durable pre-I/O reservation, never refunded)
  └─ _filter_plan_commands             api/routers/pentest.py:128-173     (scope + live worker capability filter for display)

POST /api/execution/proposals          api/routers/pentest.py:539-544
  └─ worker_jobs.resume_session        memory/worker_jobs.py              (clears fence if jobs terminal)
  └─ execution_authorization.propose   memory/execution_authorization.py:138-145
       └─ _context → authoritative_context   :83-106                     (DB owner/admin, active status, scope_digest, auth_revision, worker_epoch, worker_blocked)
       └─ _validate → execution_policy.validate_command  orchestrator/execution_policy.py:86-205
            (allowlisted argv reconstruction; shell metacharacters refused; target ⊆ scope, ∉ exclusions)
       └─ store.add → DecisionLog row (durable Proposal)                  :45-52

POST /api/execution/{action_id}/decision  api/routers/pentest.py:547-552
  └─ execution_authorization.decide    memory/execution_authorization.py:155-167
       └─ _load (requester=False)      :147-153                           (scope-hash re-digest; expiry 600 s)
       └─ store.transition CAS         :60-80                             (compare-and-swap on metadata; concurrent change → 409)

POST /api/kali/execute                 api/routers/pentest.py:511-523
  └─ execution_authorization.execute   memory/execution_authorization.py:169-210
       ├─ _load (requester=True)       :175                               (proposer must be the caller)
       ├─ expected auth_revision / worker_epoch re-check                 :176-179
       ├─ command re-validated and must equal the proposal               :180-184
       ├─ red risk requires status == "approved"                          :183-184
       ├─ store.transition to "consumed" (CAS) BEFORE worker contact      :193-195  (a timeout cannot replay)
       ├─ program-policy requires jobs-v1 worker, no custom executor      :197-200
       └─ _worker → worker_jobs.execute :212-228
            └─ authorization_check() re-loads the consumed proposal and re-validates command/scope inside the worker call  :215-227
            └─ memory/worker_jobs.py:337-448: engagement row lock, ≤5 nonterminal jobs, capability match, POST /jobs (jobs-v1, Bearer, 16 KiB), poll, terminal receipt + output hashes

POST /api/tool-results                 api/routers/pentest.py:370-471
  └─ worker_jobs.verify_receipt        :376                               (receipt must match a terminal worker job)
  └─ orchestrator_agent.analyze_output agents/orchestrator_agent.py:311-462
       ├─ dispatch_parser (deterministic, BEFORE LLM)                     memory/parsers.py
       ├─ query_llm_smart task_type=output_analysis                       (tier-1 small model)
       └─ _validate_analysis (CVE_ACCURACY downgrades) → findings persisted
```

## 2. Bounded autonomous run (engine loop)

```
start: POST /api/pentest/{id}/autonomous/start      api/routers/pentest.py:1252-1270
       (owner-or-admin session access; campaign-active rejected; NO _campaign_owner — see architecture-review §5.0)
  └─ autonomous_engine.start         agents/autonomous_engine.py:260-368
       ├─ _context + "searchsploit scope-check" self-test                 :275-276
       ├─ goal allowlist {discovery, http_check}                          :304-307  (others → blocked unsupported_goal)
       ├─ worker capability probe (curl/nmap required)                    :309-322
       ├─ pool_manager.planner_preflight (read-only)                      :324-328
       ├─ knowledge_store.restore                                          :329-337
       └─ _run_loop as background asyncio task                            :360

loop (agents/autonomous_engine.py:890-1182):
  per iteration:
    1. _check_goal_achieved            :1523-1556   (completion ONLY from durable worker receipts: observation_job_ids)
    2. _plan_next_step                 :1188-1229   (≤3 corrective attempts; model-call budget MAX_MODEL_CALLS)
         └─ _validated_plan            :1231-1324
              ├─ orchestrator_agent.process (autonomous_mode=True)        agents/orchestrator_agent.py:160-163 → _bounded_assessment_plan :126-158
              │    └─ AssessmentPlan pydantic (ONE command, extra='forbid')  agents/orchestrator_agent.py:109-113
              └─ SERVER-SIDE re-validation of each planner command:
                   validate_worker_command            worker/policy.py:38-53   (curl/nmap only)
                   command_was_executed replay guard  autonomous_engine.py:91-94 (exact + digest)
                   tool ∈ worker capabilities         :1314
                   tool must satisfy a missing observation :1316-1319  (nmap→port_discovery, curl→http_response)
    3. execution_authorization.propose :942-947     (require_approval when red-risk or threshold not green_orange)
       └─ pending → ApprovalRequest; HARD BLOCK in _wait_for_approval :952-1015 (human approve/reject/modify; modify re-validated)
    4. state.run_state="executing"; last_action_id persisted BEFORE dispatch  :1019-1025  (crash-safety: restore can prove job existence)
    5. execution_authorization.execute :1575-1604
       └─ worker job → success requires exit_code 0 AND job_id AND non-empty stdout :1583
       └─ failure classification: worker_timeout / worker_cancelled / worker_exit_nonzero / worker_failed :1589-1600
    6. dispatch_parser (deterministic) → knowledge_store.record_observation  :1057-1093
       └─ bounded structured facts + SHA-256 evidence hashes only (raw output excluded)  memory/knowledge_store.py:1-8
    7. _write_decision_log (DecisionLog: auto_execute | approved_execute)     :1112-1121
    8. observation_completion          :108-124     → complete ⇒ specialist phase ⇒ completed; else repeat (STEP_DELAY 1.5 s)
  terminal reasons: step_budget_exhausted, model_call_budget, human_rejected, knowledge_persist_failed,
                    invalid_planner_output, worker_*, run_error, cancelled, run_interrupted
```

## 3. Durable campaign (SPEC-12 supervisor)

```
create: POST /api/pentest/{id}/campaign/start    api/routers/pentest.py:1314-1377
  └─ _campaign_owner (exact owner equality)       :1321
  └─ authoritative_context                        :1328    (scope_digest, auth_revision, worker_epoch captured)
  └─ campaign_supervisor.create → campaign_store.create   orchestrator/campaign_supervisor.py:252-258, memory/campaign_store.py

supervisor loop (orchestrator/campaign_supervisor.py:151-229):
  └─ _run → recover() once at startup (store.recover: lease takeover → scheduled + backoff)  :171-177
  └─ tick() every CAMPAIGN_TICK_SECONDS: store.due(now) → per-campaign correlation id → _process
       ├─ store.claim (PostgreSQL lease, CAMPAIGN_LEASE_SECONDS)            :197-202
       ├─ state dispatch: cancelling/pausing → finalize; starting/running → _supervise_running; scheduled → _run_scheduled
       ├─ _run_scheduled :426-539
       │    ├─ schedule window + daily runtime (max 28800 s/local day) + budget pre-checks   :431-458
       │    ├─ _preflight :901-984   (accounting consistency, budget, worker_resume, authoritative_context,
       │    │                          worker capabilities ⊇ required tools, pool_manager.planner_preflight)
       │    ├─ store.bind_session (one active campaign per engagement)      :477-492
       │    └─ engine.start (first) or engine.restore (resume) with campaign_supervisor_token  :986-1005
       └─ _supervise_running :577-688
            ├─ run status absent → supervisor_restart (recoverable)
            ├─ re-check ownership, scope_digest, auth_revision, worker_epoch, worker_blocked EVERY tick  :594-626 (any change → _abort_unsafe)
            ├─ accounting inconsistencies → stop                            :630-634
            ├─ window closed / daily runtime → _begin_pause (graceful stop) :647-659
            └─ durable progress clears retry streak                         :661-685
  retry: _recoverable_failure → scheduled + retry_next_action backoff (base 60 s → max 1800 s, count ≤ CAMPAIGN_MAX_RETRIES)  :809-850
  terminal: TERMINAL_REASONS (budget, authorization, scope, retry_exhausted, …) → failed  :74-88, :852-860
```

## 4. Specialist review phase (SPEC-13) — runs only inside a campaign-bound run

```
trigger: observation_completion complete (autonomous_engine.py:1126-1132)
  └─ _run_specialist_phase_guarded     agents/autonomous_engine.py:1393-1451
       └─ _verify_campaign_supervisor  :1349-1391  (fail closed without live lease; manual restore cannot run specialist work)
       └─ _run_specialist_phase        :1453-1511
            ├─ execution_authorization re-check (auth_revision, worker_epoch, scope_digest)  :1463-1479
            ├─ specialist_integration.candidates   orchestrator/specialist_integration.py:402-422
            │    └─ select_candidates :191-334
            │         ├─ investigation_capabilities from worker advertised versions + lab scope opt-ins  orchestrator/specialist_investigations.py
            │         ├─ exposure / authentication candidates from http_response receipts
            │         └─ authorization / input_validation / business_logic from application-map captures, identities, permissions, workflows
            ├─ specialist_integration.ensure        :424-574
            │    └─ deterministic task ids (uuid5 over campaign+scope+specialty+question+sources); evidence cataloged; duplicate suppression
            └─ specialist_integration.run_pending   :576-675
                 └─ team_coordinator.run            orchestrator/team_coordinator.py:54-136
                      ├─ _authorize_campaign_task (require_campaign_execution: live lease + state + digest + revisions)  :29-52, orchestrator/campaign_execution.py:50-161
                      ├─ team_store.claim (duplicate delivery NEVER calls the specialist twice)  :74-77
                      ├─ re-check lease AFTER claim, BEFORE model call                        :79-92
                      ├─ specialist = web_intel | vuln | correlation per specialty (ROLE_BY_SPECIALTY)
                      ├─ specialist.process with team evidence inputs (review-only objective; "no target request dispatched")
                      ├─ AgentResult contract; every observation/hypothesis stamped verified=False          :108-121
                      └─ team_store.collect → task state awaiting_review (human review required to progress)
```

## 5. Finding verification (SPEC-14 area) — human-driven, no autonomy

```
state machine: observation → hypothesis → tested → reproduced → reviewed → reportable   memory/finding_verification.py:9-19
routes: POST /api/team/{sid}/findings + POST .../findings/{fid}/review   api/routers/team.py:103-115
  └─ verification_store.create           memory/finding_verification.py:217-235
       └─ candidate must cite a collected specialist task's evidence     :219-222
  └─ verification_store.review → advance :237-268, :141-189
       ├─ tested/reproduced REQUIRE a recorded Validation (steps, positive evidence refs, negative-control refs, ownership refs, clean-state True literals)
       ├─ negative controls must come from SEPARATE source observations than positives  :162-167
       ├─ reproduction requires FRESH positive+negative sources vs the test run          :170-174
       ├─ observed_behavior must be "violation"                                            :168-169
       ├─ reviewed/reportable require content_verification for BOTH runs + human signoff  :180-188
       └─ every transition re-checks scope/evidence digests (current())                  :134-139, :146-148
reportable → ready_for_external_submission (view) but submission remains human-controlled (no external disclosure code path exists).
```

## 6. Worker job lifecycle (worker-side)

```
POST /jobs (worker/app.py:132-141)  [Bearer auth, 16 KiB body, strict UUIDs]
  └─ worker/service.submit :30-100 (single asyncio.Lock)
       ├─ fingerprint idempotency (same job_id+payload → stored snapshot; different payload → 409)  :32-36
       ├─ unresolved cancel fence per session  :38-39
       ├─ global capacity ≤4 active  :40-41
       ├─ program-policy rules (max_requests/concurrency/interval/overload) via orchestrator.program_scope.ExecutionRules  :44-56
       │    ⚠ see architecture-review §5.2: module missing from the shipped image copy list.
       ├─ authenticated HTTP: timeout ≤10 s, budget 1..20, spacing, overload  :57-70
       ├─ worker-side policy plan (curl/nmap or prepare_http)  :71-80   (scope ∩ ceiling; DNS resolve+pinned; port allowlist)
       ├─ durable save BEFORE container mutation  :88
       └─ runtime.create/start (Docker CLI, immutable sha256 image, --pull=never)  :89-93; failure → cancel, never auto-resubmit  :94-99

container: worker/container_entry.py (trusted)
  ├─ deadline re-check → 124 if expired  :16-17
  ├─ nftables firewall from plan (default-drop output; only approved dest×ports)  :19-24, worker/policy.py:113-125
  ├─ setpriv privilege drop: uid/gid 65534, clear groups, --bounding-set=-all, inh/ambient caps cleared, no-new-privs  :22-24
  ├─ argv execution (curl / nmap -sT) or http_runner (http.client, encrypted evidence)  :25-48
  └─ supervisor kills the full process group at deadline → exit 124  :37-48

status/poll: GET /jobs/{id} → service.status :158-195
  ├─ deadline exceeded → cancel
  ├─ container missing → cancel
  ├─ exited → docker logs → rm container → terminal receipt (state/exit_code/stdout/stderr bounded)
  └─ authenticated HTTP: stdout JSON parsed; status 000/429/≥500 → overloaded=True (engagement-wide stop); stderr cleared from model-facing receipts  :183-191

cancel: POST /jobs/{id}/cancel → service.cancel :119-130
  ├─ intent persisted FIRST (cancel_requested)  :102-109
  ├─ runtime.stop: kill --signal=KILL → rm → absence verified  worker/runtime.py:117-134
  └─ confirmed removal ⇒ cancelled/terminated:true; ambiguous ⇒ unresolved (API never fabricates termination)
```

## 7. Model call path (accounting focus)

```
query_for_task            llm/pool_manager.py:272-294
  ├─ per-user asyncio.Lock
  ├─ refresh_user_keys (DB re-read)
  ├─ redact(prompt, deployment_secrets + decrypted provider keys + known KB credentials)  :278-289  (wrapped in <untrusted_engagement_data>)
  └─ _query_for_task        :333-488
       ├─ local routing: LocalClient (loopback only) + validation_budget
       ├─ cloud: pass-1 preferred providers → pass-2 any provider
       ├─ _reserve_key (DB row CAS on quota)  :261-270
       ├─ model_accounting.reserve  llm/engagement_budget.py:107-192
       │    ├─ owner-bound engagement (ContextVar), tariff required for provider/model
       │    ├─ reservation ceiling = byte-length(prompt+system) + 8192 (conservative)  :55-58
       │    ├─ engagement budget + campaign budget + task budget checked in ONE transaction  :148-176
       │    └─ DecisionLog model_attempt row committed BEFORE provider I/O  :184-191
       ├─ provider client query (httpx; groq/gemini/openrouter adapters)
       └─ model_accounting.settle  :194-258
            ├─ reported vs reserved: overrun → stopped/provider_overrun
            ├─ success without token usage → stopped/unknown_usage
            └─ campaign usage applied in same transaction; accounting inconsistency stops further calls
No prompt caching exists anywhere in this path (verified by grep across llm/).
```

## 8. Restart/recovery paths (verified in code)

| Event | Mechanism | File:line |
| --- | --- | --- |
| API restart with live campaigns | supervisor `recover()` at first tick: lease takeover → `scheduled` + backoff; full preflight before anything runs | `campaign_supervisor.py:171-177`; `campaign_store.recover` |
| API crash mid-dispatch | proposal consumed before worker contact; run state + last_action_id persisted before dispatch; restore proves job existence, never replays | `execution_authorization.py:193-195`; `autonomous_engine.py:1019-1025,696-714` |
| Worker restart with live jobs | `WorkerService.recover()` cancels all active jobs; never resumes/replays | `worker/service.py:197-201` |
| Provider crash mid-call | reservation remains charged (never refunded); settlement on next call path; unknown usage → stopped | `engagement_budget.py:194-258` |
| Unresolved cancellation | engagement fenced (`worker_blocked` metadata); only owner/admin explicit resume clears it; pre-stop approvals invalidated by worker_epoch bump | `worker_jobs.py` (resume_session, epoch) |
| Checkpoint restore | scope digest, owner, auth_revision, worker_epoch, completion criteria, capabilities, budgets, receipts all revalidated; pending approvals never restored | `autonomous_engine.py:616-800` |
| Duplicate specialist dispatch | deterministic task/run ids; `team_store.claim` duplicate → returns claim, never calls model twice | `team_coordinator.py:74-77` |

## 9. Paths NOT DEMONSTRATED (no code path exists)

- Any autonomous verification/reproduction of a candidate finding (verification is human-driven by construction — §5).
- Any execution of tools other than curl / nmap TCP / aria-http through the isolated worker.
- Any exploitation/post-exploitation goal (`initial_access`, `dump_creds`, `privilege_escalation`, `full_compromise`): recognized by `_check_goal_achieved` but rejected at start (`autonomous_engine.py:304-307`).
- External vulnerability disclosure: no submission code exists; `reportable` state is a local ledger status only.
- Eight-hour wall-clock soak: only accelerated synthetic harnesses exist (`docs/spec15-endurance-status.md`).
- Browser-based testing in the worker container: browser mapping is API-side Playwright rendering of saved evidence only.
