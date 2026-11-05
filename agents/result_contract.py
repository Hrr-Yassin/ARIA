"""Evidence-bound public agent results. Explanations exclude private reasoning."""
import re
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict
from worker.policy import validate_worker_command


class AgentResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: int = 1
    interpreted_request: str
    evidence_references: list[str] = Field(default_factory=list)
    observations: list[dict] = Field(default_factory=list)
    hypotheses: list[dict] = Field(default_factory=list)
    proposed_actions: list[dict] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    completion_criteria: list[str] = Field(default_factory=list)
    status: Literal['proposed', 'blocked', 'analysis'] = 'analysis'
    rejections: list[dict] = Field(default_factory=list)


def professional_result(agent, request, result, scope, evidence, capabilities):
    """Evidence is supplied by the server, never accepted from model output."""
    interpreted = request.get('user_input') or request.get('description') or request.get('goal_type') or 'Assess the configured target within engagement scope'
    observations = [{'evidence_id':entry['id'], 'observation':entry['summary'],
        'provenance':entry.get('provenance','saved_tool_output_unverified'), 'verified':False} for entry in evidence]
    contract = AgentResult(interpreted_request=interpreted,
        evidence_references=[entry['id'] for entry in evidence], observations=observations,
        completion_criteria=['Every observation cites saved evidence', 'Proposed actions remain within requested hosts and ports',
            'Verification requires reproducible execution evidence; missing prerequisites remain explicit'])
    if not evidence:
        contract.uncertainty.append('No durable execution evidence is available; findings remain candidates')
    hypotheses = result.get('hypotheses') or result.get('vulnerability_assessment') or result.get('correlations') or result.get('findings') or []
    if isinstance(hypotheses,list):
        for hypothesis in hypotheses[:20]:
            if not isinstance(hypothesis,dict): continue
            cited = hypothesis.get('evidence_references') or []
            valid = [ref for ref in cited if ref in contract.evidence_references]
            if len(valid)!=len(cited):
                contract.rejections.append({'code':'unknown_evidence_reference','detail':'Hypothesis cited evidence outside the owned evidence catalog'})
            contract.hypotheses.append({'description':hypothesis.get('description') or hypothesis.get('vulnerability') or hypothesis.get('finding') or hypothesis.get('title') or 'Unverified candidate',
                'verified':False,'evidence_references':valid,
                'prerequisites':hypothesis.get('conditions_unverified') or hypothesis.get('missing_validations') or []})
            if not valid: contract.uncertainty.append('A hypothesis has no attributed supporting evidence; validate applicability before reporting it as a finding')
    if agent in {'vuln','correlation','report'} and not contract.hypotheses:
        contract.uncertainty.append('Service or version matches alone do not establish a vulnerability; applicability and conflicting evidence still need validation')
    if agent == 'post':
        contract.status = 'blocked'
        contract.prerequisites = ['Verified access receipt', 'Explicit engagement authorization for the requested post-access action',
            'A capable worker; this release validates post-access behavior only with controlled fixtures']
        contract.rejections.append({'code':'post_access_unavailable', 'detail':'No post-access execution capability is enabled'})
        return contract
    commands = result.get('commands') or []
    if not isinstance(commands, list):
        commands = []
        contract.rejections.append({'code':'malformed_actions', 'detail':'Expected a command list'})
    action_scope = dict(scope)
    if request.get('target'):
        action_scope['targets'] = [request['target']]
    requested_ports = request.get('requested_ports')
    if not requested_ports and re.search(r'\bonly\s+(http|https|ssh|ftp)\b', interpreted, re.I):
        service = re.search(r'\bonly\s+(http|https|ssh|ftp)\b', interpreted, re.I).group(1).lower()
        requested_ports = [{'http':80,'https':443,'ssh':22,'ftp':21}[service]]
    if requested_ports:
        configured = set(scope.get('ports', requested_ports))
        action_scope['ports'] = sorted(configured.intersection(requested_ports))
    seen = {entry.get('command','') for entry in evidence}
    for command in commands[:8]:
        try:
            if not isinstance(command, dict): raise ValueError('Expected a command object')
            checked = validate_worker_command(command.get('command',''), scope)
            if requested_ports and not action_scope.get('ports'): raise ValueError('Requested ports conflict with engagement configuration')
            checked = validate_worker_command(checked.command, action_scope)
            if checked.tool not in capabilities: raise ValueError('Worker capability is unavailable')
            if checked.command in seen: raise ValueError('Equivalent evidence or action already exists')
            seen.add(checked.command)
            contract.proposed_actions.append({**command, 'command':checked.command, 'tool':checked.tool,
                'risk_color':checked.risk, 'expected_evidence':command.get('purpose') or 'A durable worker receipt and target response',
                'evidence_references':contract.evidence_references})
        except (ValueError, TypeError) as exc:
            contract.rejections.append({'code':'unsupported_or_out_of_scope_action', 'detail':str(exc)[:250]})
    if commands and not contract.proposed_actions:
        contract.status = 'blocked'
    elif contract.proposed_actions:
        contract.status = 'proposed'
    return contract
