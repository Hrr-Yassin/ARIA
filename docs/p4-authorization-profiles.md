# P4 operational authorization profiles (2026-11-22)

## Audit findings at entry

| Area | Finding |
| --- | --- |
| Engagement mode | `PentestSession.attack_mode` (`lab`, `red_team`, `bug_bounty`) could be changed **from chat**. A regex intent (`SET_MODE`, `needs_confirmation=False`) updated the session, and `authoritative_context` adds `mode=bug_bounty` to the scope, which typed adapters enforce. Chat could therefore loosen authorization from bug bounty to lab. |
| Bug bounty | `memory/program_policy.py` already implements source-linked rule review, explicit activation, suspension on source change, and request, concurrency and interval budgets enforced at the worker. It was reused, not duplicated. |
| Central path | Every worker dispatch goes through `ExecutionAuthorization.execute`, and `worker_jobs.execute` re-runs `_validate` just before submit. Approvals bind a digest of the authoritative context, including the scope. |
| Capability restrictions | Owner blocks are enforced in authorization (`security_tools/restrictions.py`). |
| Model sharing | Governed by the application-map data policy (`provider_sharing`). |
| Missing | No per-engagement authorization record for lab, CTF or pentest; no validity windows, schedules, approval levels or hourly limits; no profile audit trail; `scope.engagement_profile` was not protected at session creation; program activation would have erased any extra scope keys. |

## Model

`memory/engagement_profiles.py`: four validated profiles. All of them declare:

- targets and optional ports;
- exclusions;
- permitted capabilities (allowlist) and prohibited capabilities;
- approval level (`red_only`, `sensitive` or `all`);
- validity window and weekly UTC schedule;
- hourly operation limit and timeout cap;
- evidence retention days;
- model sharing (`deny` or `redacted_metadata`).

| Profile | Additional required documentation | Constraints |
| --- | --- | --- |
| Private Lab | Ownership statement; lab inventory; isolation (`network_isolated: true` plus description) | Targets ⊆ inventory; private or lab-reserved assets only |
| CTF | Challenge name, scope, rules text and rules source | `valid_until` required |
| Authorized Pentest | Authorization reference, authorizer, authorization document SHA-256, rules of engagement, `exclusions_reviewed: true` | `valid_from` and `valid_until` required; approval at least `sensitive` |
| Bug Bounty | Program snapshot ID, testing restrictions, `exclusions_reviewed: true` | Named snapshot must be the **active, reviewed** program policy; targets ⊆ program assets; approval at least `sensitive`; rules provenance (snapshot, review, content SHA-256, activation) recorded |

Authorization is never inferred from reachability. Every asset is declared; wildcards, `any`, and ranges broader than /16 (IPv4) or /48 (IPv6) are refused.

## Enforcement

All enforcement is in `ExecutionAuthorization`:

- **Capability checks.** Prohibited or unpermitted capabilities, validity window, schedule and the bug-bounty program match are checked in `_validate`. That one function runs at proposal, at decision, at execution and at the dispatch-time recheck.
- **Approval.** A profile-required approval forces `pending` at proposal, and `execute` refuses `authorized` (unapproved) proposals with `profile_approval_required`.
- **Hourly limit.** `execute` refuses with `profile_rate_limited` when the trailing-hour count of claimed dispatches reaches the limit. The timeout is capped by the profile.
- **Approval invalidation.** A profile change rewrites the scope, so every approval bound to the previous scope digest is rejected. The worker epoch is also bumped.
- **Change guard.** A profile change is refused while worker jobs or web replays are active, and when the expected revision is stale.
- **Audit.** Each change writes `engagement_profile_change` (revision, previous and new kind, reason, actor, scope digests before and after). Each profile or capability denial writes `policy_denied` (stage, reason, command hash).
- **No model control.** Chat `SET_MODE` no longer changes the session. A client-supplied scope cannot inject `engagement_profile`. Program activation preserves the profile; a snapshot change then denies bug-bounty execution until the profile names it.
- **Model sharing: most restrictive wins.** A profile with `deny` blocks provider calls in `reserve` and reports `profile_model_sharing_denied` in status. `redacted_metadata` never relaxes the application data policy. The existing sharing policy is unchanged.
- **Unprofiled engagements** keep the legacy scope behaviour, and the operator view says so explicitly.

## API and operator interface

**API**, owner-authenticated (`api/routers/engagement_profiles.py`):

- `GET /api/engagements/profile-kinds`: requirements from the same models the backend validates with;
- `GET /api/engagements/{sid}/profile`: profile, enforced restrictions, policy changes and denied operations;
- `PUT` or `POST /api/engagements/{sid}/profile`: update.

**Mission Control** (`web/mission-control/src/profiles.ts`): an "Authorization profile" section in Settings. It provides:

- a profile type selector and the required documentation for each type;
- a JSON definition editor seeded from the current profile or a template, with server-side validation errors shown verbatim;
- a recorded reason for every change;
- the enforced-restrictions list, taken from the backend description;
- denied operations and policy history.

Approvals stay in Operations → Pending proposals.

**Deployment.** The production build was verified into `.local-lab/p4-ui-build`. The served bundle (`web/static/mission`) and the running API were **not** changed or restarted, because the running API lacks the new routes until an owner-approved restart.

## Acceptance

| Check | Result |
| --- | --- |
| Unit and policy scenarios | `tests/test_engagement_profiles.py`: 15 tests. They cover documentation requirements, reachability refusal, approval floors, capability, validity, schedule and program checks, approve-then-dispatch with a timeout cap, rejection before dispatch with audit, approval invalidation, repeated denial, the hourly limit, legacy behaviour, the chat mode change and profile injection at creation. |
| Dispatch-time recheck | A profile tightened between approval and dispatch → 403; the worker never submits. |
| UI/backend consistency | `tests/test_profile_ui_contract.py`: the panel's endpoints and methods exist; its kinds equal the backend's; the fields it reads are the ones the backend returns. TypeScript `tsc --noEmit` is clean and the production build succeeds. |
| Disposable PostgreSQL (`python -m integration.profiles_postgres`, fresh rootless postgres:16.6, two processes, tripwire worker) | Profile persisted across restart (revision 2). Proposal `pending` under the sensitive profile. Stale revision → 409. Approval from revision 1 → 403 after the change. Prohibited capability → 403 on both retries after restart. Out-of-scope target → 403. Bug bounty without an active program → 409. Change during active execution → 409. Two audited changes with differing digests. Denials audited at propose and execute and listed in the operator view. Worker epoch 2. Tripwire never reached. |
| Regression | Full offline suite 995/996; the one failure is the known pre-existing `test_team_tasks` correlation-prompt test. |
| Pyright | 0 errors in P4 files; 0 findings on changed lines of the pre-existing modified files. |

No security tool was run and no external target was contacted.

## Limitations and gaps

- **Unprofiled engagements still execute under the legacy scope.** Requiring a profile for all execution is a policy decision for the owner and would change existing workflows.
- **`retention_days` is recorded and displayed** but no automatic evidence deletion runs.
- **The hourly limit counts claimed dispatches** per engagement. Concurrency limits exist only through the bug-bounty program policy.
- **The Mission Control editor is JSON-based.** Structured form fields per profile type are a usability follow-up.
- **The UI was verified by type-check, build and contract tests,** not by a browser run against a deployed API.
