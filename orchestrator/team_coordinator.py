"""Durable specialist delegation. This coordinator never dispatches tools."""
import asyncio
from fastapi import HTTPException
from agents.result_contract import AgentResult
from llm.engagement_budget import engagement_context, task_context
from memory.team_tasks import team_store
from orchestrator.campaign_execution import (
    CampaignExecutionDenied,
    require_campaign_execution,
)


class TeamCoordinator:
    def __init__(self, *, campaign_loader=None, context_loader=None):
        # Injectable for offline tests; production uses the durable stores.
        self.campaign_loader = campaign_loader
        self.context_loader = context_loader

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
                  worker_epoch: int | None = None) -> dict:
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
            await self._authorize_campaign_task(
                task=visible, **campaign_args)

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
        model_token = engagement_context.set({'session_id': sid, 'owner': owner})
        task_token = task_context.set({'id': task_id, 'run_id': request_id})
        try:
            view = preview
            if visible is None:
                view = await team_store.view(sid, owner)
            evidence = [entry for entry in view['evidence'] if entry['id'] in task['evidence_inputs']]
            specialist = self.specialists()[task['owner_role']]
            response = await specialist.process(sid, owner, {
                'user_input': task['objective'], 'description': task['objective'],
                'target': view.get('target', ''),
                'team_evidence': evidence, 'expected_output': task['expected_output'],
                'completion_criteria': task['completion_criteria'],
                'team_task': True,
            }, skill)
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
            return await team_store.collect(sid, owner, task_id, request_id, contract)
        except asyncio.CancelledError:
            await asyncio.shield(team_store.block(sid, owner, task_id, request_id, 'Request cancelled; inspect task before retrying'))
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
