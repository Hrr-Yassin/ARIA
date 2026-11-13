"""Agent/API bridge to the existing command-bound ledger and receipt verifier."""
from dataclasses import asdict
import json
import structlog
from fastapi import HTTPException

from security_tools.adapters import encode, decode, sha256, contract_digest
from security_tools.models import Provenance, AdapterAttestation


class ToolOperations:
    def __init__(self, authorization=None, jobs=None):
        from memory.execution_authorization import execution_authorization
        from memory.worker_jobs import worker_jobs
        self.authorization = authorization or execution_authorization
        self.jobs = jobs or worker_jobs

    async def propose(self, user_id: str, session_id: str, operation: dict) -> dict:
        command = encode(operation)
        adapter, parameters = decode(command)
        proposal = await self.authorization.propose(user_id, session_id, command, tool=adapter.name)
        return {**asdict(proposal), 'capability': adapter.capability,
                'parameters': parameters.model_dump(), 'timeout_seconds': adapter.timeout}

    async def execute(self, user_id: str, session_id: str, operation: dict, action_id: str) -> dict:
        command = encode(operation)
        adapter, parameters = decode(command)
        if not action_id:
            raise HTTPException(422, 'A command-bound proposal is required')
        result = await self.authorization.execute(user_id, session_id, command, tool=adapter.name,
            action_id=action_id, timeout=adapter.timeout)
        # Keep unknown/cancelled outcomes explicit. The existing verifier accepts
        # successful/failed receipts only; never manufacture evidence for cancellation.
        state = result.get('status', result.get('state', 'unknown'))
        if state not in {'succeeded', 'failed'}:
            return {'state': state, 'output': adapter.output_model(observations=[],
                error='cancelled' if state == 'cancelled' else 'unknown').model_dump(), 'provenance': None}
        stdout, stderr, code = result['stdout'], result['stderr'], result['exit_code']
        await self.jobs.verify_receipt(user_id, session_id, result['job_id'], stdout, stderr, code)
        stored = await self.jobs.store.get(result['job_id'])
        stamp = AdapterAttestation.model_validate(stored['adapter_attestation'])
        context = await self.authorization._context(user_id, session_id)
        adapter.validate_scope(parameters, context['scope'])
        output = adapter.normalize(stdout, parameters, context['scope'], code, state)
        provenance = Provenance(job_id=result['job_id'], session_id=session_id,
            request_sha256=sha256(command), registry_sha256=contract_digest(),
            output_sha256=sha256(stdout), stderr_sha256=sha256(stderr),
            image_id=stamp.image_id, declared_tool_version=stamp.declared_tool_version)
        structlog.get_logger(__name__).info('typed_tool_result', tool=adapter.name,
            capability=adapter.capability, job_id=result['job_id'], session_id=session_id,
            request_sha256=provenance.request_sha256, output_sha256=provenance.output_sha256,
            registry_sha256=provenance.registry_sha256, owner_id=context.get('owner_id'),
            scope_sha256=sha256(json.dumps(context['scope'],sort_keys=True)),
            error=output.error, observation_count=len(output.observations))
        return {'state': state, 'output': output.model_dump(), 'provenance': provenance.model_dump()}


tool_operations = ToolOperations()
