"""Durable specialist delegation. This coordinator never dispatches tools."""
import asyncio
from fastapi import HTTPException
from agents.result_contract import AgentResult
from llm.engagement_budget import engagement_context, task_context
from memory.team_tasks import team_store


class TeamCoordinator:
    def specialists(self) -> dict:
        from agents.recon_agent import recon_agent
        from agents.scan_agent import scan_agent
        from agents.vuln_agent import vuln_agent
        from agents.web_intel_agent import web_intel_agent
        from agents.correlation_agent import correlation_agent
        from agents.report_agent import report_agent
        return {'recon': recon_agent, 'scan': scan_agent, 'vuln': vuln_agent,
                'web_intel': web_intel_agent, 'correlation': correlation_agent, 'report': report_agent}

    async def run(self, sid: str, owner: str, task_id: str, request_id: str, skill: str) -> dict:
        event = await team_store.claim(sid, owner, task_id, request_id)
        if event['duplicate']:
            # Delivery retry returns the claim; it NEVER calls a specialist twice.
            return event
        task = event['data']
        model_token = engagement_context.set({'session_id': sid, 'owner': owner})
        task_token = task_context.set({'id': task_id, 'run_id': request_id})
        try:
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
