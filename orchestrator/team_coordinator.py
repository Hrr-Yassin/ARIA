"""Durable specialist delegation. This coordinator never dispatches tools."""
import asyncio
import uuid
from fastapi import HTTPException
from agents.result_contract import AgentResult, professional_result
from llm.engagement_budget import engagement_context, task_context
from memory.evidence_context import review_evidence_context, select_evidence
from memory.team_tasks import (
    INTERNAL_REVIEW_LIMIT, PriorReviewClaim, public, saved_review_challenge, task_id_for_request, team_store,
)
from orchestrator.campaign_execution import (
    CampaignExecutionDenied,
    require_campaign_execution,
)


class TeamCoordinator:
    def __init__(self, *, campaign_loader=None, context_loader=None):
        # Injectable for offline tests; production uses the durable stores.
        self.campaign_loader = campaign_loader
        self.context_loader = context_loader
        self._internal_runs: dict[tuple[str, str, str], asyncio.Task] = {}

    def cancel_internal(self, sid: str, owner: str, task_id: str) -> None:
        runner = self._internal_runs.get((sid, owner, task_id))
        if runner is not None:
            runner.cancel()

    async def run_internal(self, sid: str, owner: str, task_ids: list[str]) -> dict:
        """Drive only explicitly selected saved-evidence reviews and their challenges."""
        requested = list(dict.fromkeys(task_ids))
        if not 1 <= len(requested) <= 8:
            raise HTTPException(422, 'Select one to eight internal review tasks')
        pending = dict.fromkeys(requested)
        attempted = set()
        errors = {}

        async def dispatch(task: dict) -> None:
            task_id = task['id']
            key = (sid, owner, task_id)
            if key in self._internal_runs:
                return
            self._internal_runs[key] = asyncio.current_task()
            try:
                run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-internal-run:{task_id}:{task["attempts"] + 1}'))
                await self.run(sid, owner, task_id, run_id, 'intermediate', internal_batch=True)
            except HTTPException as error:
                errors[task_id] = error.detail
            finally:
                self._internal_runs.pop(key, None)

        running = set()
        try:
            while True:
                view = await team_store.view(sid, owner)
                tasks = {task['id']: task for task in view['tasks']}
                if any(not tasks.get(task_id, {}).get('internal_review') for task_id in pending):
                    raise HTTPException(422, 'Batch accepts only internal review tasks')
                for task_id in requested:
                    if task_id in errors:
                        continue
                    proposal = saved_review_challenge(tasks[task_id])
                    if proposal is None:
                        continue
                    child_id = task_id_for_request(sid, proposal.request_id)
                    child = tasks.get(child_id)
                    if child is None:
                        # An explicitly started batch can also resume analysis saved before
                        # the result and queued challenge were recorded together.
                        try:
                            event = await team_store.create(sid, owner, proposal)
                        except HTTPException as error:
                            errors[task_id] = error.detail
                            continue
                        tasks[child_id] = event['data']
                    elif (child.get('internal_review') != 'challenge' or child['dependencies'] != proposal.task.dependencies
                          or child['evidence_inputs'] != proposal.task.evidence_inputs
                          or child.get('require_all_evidence', False) != proposal.task.require_all_evidence
                          or child['objective'] != proposal.task.objective or child['budget'] != proposal.task.budget.model_dump()):
                        errors[task_id] = 'Follow-up identity conflicts with an existing task'
                        continue
                    pending[child_id] = None
                ready = [tasks[task_id] for task_id in pending if task_id not in attempted
                         and tasks[task_id]['state'] == 'queued'
                         and all(tasks[ref]['state'] in {'analyzed', 'completed'}
                                 for ref in tasks[task_id]['dependencies'])]
                for task in ready[:INTERNAL_REVIEW_LIMIT - len(running)]:
                    attempted.add(task['id'])
                    running.add(asyncio.create_task(dispatch(task)))
                if not running:
                    return {'states': {task_id: tasks[task_id]['state'] for task_id in pending}, 'errors': errors}
                finished, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
                for runner in finished:
                    running.remove(runner)
                    if not runner.cancelled():
                        runner.result()
        finally:
            for runner in running:
                runner.cancel()
            if running:
                await asyncio.gather(*running, return_exceptions=True)

    async def _review_saved(self, sid: str, owner: str, task: dict, run_id: str, view: dict) -> dict:
        from agents.correlation_agent import correlation_agent

        assigned = set(task['evidence_inputs'])
        owned = [entry for entry in view['evidence'] if entry['id'] in assigned
                 and entry.get('owner_id') == owner and entry.get('session_id') == sid]
        evidence = select_evidence(owned, session_id=sid, owner_id=owner, query=task['objective']).items
        selected = {entry['id'] for entry in evidence}
        readable = {entry['id'] for entry in evidence if entry['summary']}
        incomplete = task.get('require_all_evidence') and readable != assigned
        claims = []
        claim_refs = []
        challenge = task['internal_review'] == 'challenge'
        snapshot = {entry['task_id']: entry for entry in task['dependencies_at_claim']}
        for producer in (view['tasks'] if challenge and not incomplete else ()):
            dependency = snapshot.get(producer['id'])
            if (not dependency or not producer.get('internal_review') or producer['revision'] != dependency['revision']
                    or not producer.get('run_id') or producer['run_id'] != dependency.get('run_id')):
                continue
            for index, claim in enumerate((producer.get('result') or {}).get('hypotheses', [])):
                refs = claim['evidence_references']
                if refs and selected.issuperset(refs):
                    claims.append({'task_id': producer['id'], 'run_id': producer['run_id'],
                                   'description': str(claim['description'])[:500], 'evidence_references': refs,
                                   'disposition': claim.get('disposition', 'inconclusive')})
                    claim_refs.append(PriorReviewClaim(task_id=producer['id'], run_id=producer['run_id'],
                                                       revision=producer['revision'], hypothesis_index=index))
                if len(claims) == 10:
                    break
            if len(claims) == 10:
                break
        if incomplete:
            result = {'rejections': [{
                'code': 'comparison_evidence_incomplete',
                'detail': f'{len(readable)} of {len(assigned)} assigned observations had readable summaries in context. '
                          'Check the missing records or select a smaller comparison set.',
            }]}
        elif evidence:
            result = await correlation_agent.review_saved(owner, task['objective'], evidence, public(claims),
                                                          challenge=challenge)
        else:
            result = {'rejections': [{'code': 'missing_evidence', 'detail': 'No owned evidence was prepared'}]}
        contract = professional_result('correlation', {'objective': task['objective']}, result, {}, evidence, set())
        for hypothesis, claim in zip(contract.hypotheses, result.get('correlations', []), strict=True):
            hypothesis['disposition'] = (claim['disposition'] if hypothesis['evidence_references']
                                         else 'inconclusive')
            hypothesis['uncertainty'] = claim['uncertainty']
            if claim.get('prior_claim_indices') and hypothesis['evidence_references']:
                hypothesis['prior_claim_indices'] = claim['prior_claim_indices']
        contract.uncertainty.append('Internal analysis is unverified and does not authorize any operation.')
        return await team_store.collect(sid, owner, task['id'], run_id, contract,
                                        prepared_review_evidence=sorted(selected), prepared_review_claims=claim_refs)

    def specialists(self) -> dict:
        from agents.recon_agent import recon_agent
        from agents.scan_agent import scan_agent
        from agents.vuln_agent import vuln_agent
        from agents.web_intel_agent import web_intel_agent
        from agents.correlation_agent import correlation_agent
        from agents.report_agent import report_agent
        return {'recon': recon_agent, 'scan': scan_agent, 'vuln': vuln_agent,
                'web_intel': web_intel_agent, 'correlation': correlation_agent, 'report': report_agent}

    async def _authorize_campaign_task(
            self, *, sid: str, owner: str, task: dict, campaign_id: str,
            campaign_supervisor_token: str, scope_digest: str,
            auth_revision: int | None, worker_epoch: int | None) -> None:
        """Deny campaign-bound work without a live supervisor lease.

        This runs before a claim for a task already visible in the ledger, and
        again after the claim but before any specialist model call.  The second
        check closes the race where a task becomes visible between the read and
        the claim, and bounds a lease or authorization change to no dispatch.
        """
        bound = task.get('campaign_id') if isinstance(task, dict) else None
        if not bound:
            return
        if (not isinstance(bound, str) or not isinstance(campaign_id, str)
                or not campaign_id or campaign_id != bound):
            raise CampaignExecutionDenied(
                'campaign_supervisor_required',
                'Campaign-bound task requires its campaign supervisor')
        await require_campaign_execution(
            campaign_id=bound, token=campaign_supervisor_token,
            session_id=sid, owner_id=owner, scope_digest=scope_digest,
            auth_revision=auth_revision, worker_epoch=worker_epoch,
            loader=self.campaign_loader, context_loader=self.context_loader)

    async def run(self, sid: str, owner: str, task_id: str, request_id: str,
                  skill: str, *, campaign_id: str = '',
                  campaign_supervisor_token: str = '',
                  scope_digest: str = '',
                  auth_revision: int | None = None,
                  worker_epoch: int | None = None, internal_batch: bool = False) -> dict:
        campaign_args = dict(
            sid=sid, owner=owner, campaign_id=campaign_id,
            campaign_supervisor_token=campaign_supervisor_token,
            scope_digest=scope_digest, auth_revision=auth_revision,
            worker_epoch=worker_epoch)
        # The manual team API reaches this method without a supervisor token.
        # Reading the immutable task first lets it fail before claiming state.
        preview = await team_store.view(sid, owner)
        visible = next((task for task in preview.get('tasks', [])
                        if task.get('id') == task_id), None)
        if visible is not None:
            if visible.get('internal_review') and not internal_batch and not campaign_id and not campaign_supervisor_token:
                return await self.run_internal(sid, owner, [task_id])
            await self._authorize_campaign_task(
                task=visible, **campaign_args)

        if internal_batch:
            event = await team_store.claim(sid, owner, task_id, request_id, internal_batch=True)
        else:
            event = await team_store.claim(sid, owner, task_id, request_id)
        if event['duplicate']:
            # Delivery retry returns the claim; it NEVER calls a specialist twice.
            return event
        task = event['data']
        try:
            # Revalidate at the execution boundary, after the claim and before
            # the specialist.  A failure here leaves the task blocked, never
            # running a model call outside the campaign boundary.
            await self._authorize_campaign_task(task=task, **campaign_args)
        except CampaignExecutionDenied:
            try:
                await team_store.block(
                    sid, owner, task_id, request_id,
                    'Campaign execution boundary changed before specialist '
                    'dispatch; no specialist model call was made')
            except Exception:  # noqa: BLE001 - recovery remains fail-closed.
                pass
            raise
        from llm.engagement_budget import bound_model_context
        model_token = engagement_context.set(bound_model_context(sid, owner))
        task_token = task_context.set({'id': task_id, 'run_id': request_id})
        try:
            if task.get('internal_review'):
                return await self._review_saved(sid, owner, task, request_id, await team_store.view(sid, owner))
            view = preview
            if visible is None:
                view = await team_store.view(sid, owner)
            evidence = [entry for entry in view['evidence'] if entry['id'] in task['evidence_inputs']]
            specialist = self.specialists()[task['owner_role']]
            from memory.research import hypothesis_current
            evidence_index = {entry['id']: entry for entry in view.get('evidence', [])}
            model = next(iter(view.get('research_models', [])), {})
            candidates = [item for item in view.get('research_hypotheses', [])
                if set(item['supporting_evidence']) & set(task['evidence_inputs'])]
            current = [item for item in candidates
                if hypothesis_current(item, model, evidence_index, view.get('scope', {}))]
            related = current[:3]
            research_context = {
                'omitted_stale_hypotheses': len(candidates) - len(current),
                'omitted_current_hypotheses': max(0, len(current) - len(related)),
                'hypotheses':[{key:item[key] for key in ('id','claim','alternative_explanations',
                    'positive_controls','negative_controls','uncertainty','state')} for item in related],
                'responsibility':('Challenge the discovery claims and explain missing independent controls; model agreement cannot verify a finding.'
                    if task['owner_role']=='correlation' else
                    'Propose evidence-linked hypotheses, alternative explanations and controlled tests; keep claims unverified.'),
                'verification':'untrusted research assertions; no execution authority'}
            # P0 reasoning restricted to this task's evidence (ledger IDs or worker sources).
            from orchestrator.reasoning import task_reasoning_context
            reasoning_record = next(iter(view.get('investigation_reasoning', [])), {})
            task_refs = set(task['evidence_inputs']) | {entry.get('source_id') for entry in evidence
                                                        if isinstance(entry.get('source_id'), str)}
            reasoning = task_reasoning_context(reasoning_record.get('state'), task_refs)
            if reasoning:
                research_context['investigation_reasoning'] = reasoning
            review_provenance: dict[str, set[str]] = {}
            review_token = review_evidence_context.set(
                review_provenance if task['owner_role'] in {'correlation', 'report'} else None)
            try:
                response = await specialist.process(sid, owner, {
                    'user_input': task['objective'], 'description': task['objective'],
                    'target': view.get('target', ''),
                    'team_evidence': evidence, 'expected_output': task['expected_output'],
                    'completion_criteria': task['completion_criteria'],
                    'research_context':research_context,
                    'team_task': True,
                }, skill)
            finally:
                review_evidence_context.reset(review_token)
            contract = AgentResult.model_validate(response['agent_result'])
            # Existing specialists use chat IDs; normalize only known task sources.
            mapping = {entry['source_id']: entry['id'] for entry in evidence}
            allowed = {entry['id'] for entry in evidence}
            def refs(values):
                return [mapping.get(ref, ref) for ref in values if mapping.get(ref, ref) in allowed]
            contract.evidence_references = refs(contract.evidence_references)
            for entry in contract.observations + contract.hypotheses:
                if entry.get('evidence_id'):
                    entry['evidence_references'] = refs([entry.pop('evidence_id')])
                else:
                    entry['evidence_references'] = refs(entry.get('evidence_references', []))
                entry['verified'] = False
            contract.uncertainty.append('Specialist analysis is unverified; human review and independent reproduction remain required.')
            prepared = review_provenance.get('evidence_ids')
            if prepared is None:
                return await team_store.collect(sid, owner, task_id, request_id, contract)
            return await team_store.collect(sid, owner, task_id, request_id, contract,
                                            prepared_review_evidence=sorted(prepared))
        except asyncio.CancelledError:
            try:
                await asyncio.shield(team_store.block(
                    sid, owner, task_id, request_id, 'Request cancelled; inspect task before retrying'))
            except HTTPException as error:
                if error.status_code != 409:
                    raise
            raise
        except Exception as error:
            try:
                await team_store.block(sid, owner, task_id, request_id, 'Specialist failed or storage unavailable; no automatic retry', failed=True)
            except HTTPException:
                pass  # A concurrent owner cancellation/recovery remains authoritative.
            if isinstance(error, HTTPException):
                raise
            raise HTTPException(409, 'Specialist failed; task requires inspection before retrying') from None
        finally:
            task_context.reset(task_token)
            engagement_context.reset(model_token)


team_coordinator = TeamCoordinator()
