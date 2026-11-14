"""Persistent multi-hypothesis research over the owner-bound immutable team ledger.

This store proposes research; it grants no scope, target execution or signoff.
Claims and graph annotations remain assertions until independently checked.
"""
from datetime import datetime, timezone
from typing import Literal
import uuid

from fastapi import HTTPException
from pydantic import Field

from memory.team_tasks import Strict, Criterion, Reference, digest, team_store

ResearchState = Literal['OBSERVED', 'HYPOTHESIZED', 'PLANNED', 'TESTED', 'CONFIRMED', 'REJECTED', 'INCONCLUSIVE']
VulnerabilityClass = Literal['idor_bola', 'access_control', 'authentication_session',
    'api_authorization', 'business_logic', 'input_validation_injection',
    'cross_service_trust', 'information_disclosure', 'multi_step', 'unclassified']
TRANSITIONS = {'OBSERVED': {'HYPOTHESIZED','REJECTED','INCONCLUSIVE'},
    'HYPOTHESIZED': {'PLANNED','REJECTED','INCONCLUSIVE'},
    'PLANNED': {'TESTED','REJECTED','INCONCLUSIVE'},
    'TESTED': {'CONFIRMED','REJECTED','INCONCLUSIVE','PLANNED'},
    'INCONCLUSIVE': {'HYPOTHESIZED'}, 'CONFIRMED': {'INCONCLUSIVE'}, 'REJECTED': set()}


class Hypothesis(Strict):
    title: Criterion
    claim: Criterion
    vulnerability_class: VulnerabilityClass = 'unclassified'
    supporting_evidence: list[Reference] = Field(min_length=1, max_length=30)
    alternative_explanations: list[Criterion] = Field(min_length=1, max_length=10)
    related_assets: list[Reference] = Field(default_factory=list, max_length=30)
    related_components: list[Reference] = Field(default_factory=list, max_length=30)
    prerequisites: list[Criterion] = Field(min_length=1, max_length=20)
    validation_strategy: Criterion
    positive_controls: list[Criterion] = Field(min_length=1, max_length=10)
    negative_controls: list[Criterion] = Field(min_length=1, max_length=10)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    uncertainty: list[Criterion] = Field(min_length=1, max_length=20)
    information_value: float = Field(default=.5, ge=0, le=1, allow_inf_nan=False)
    security_relevance: float = Field(default=.5, ge=0, le=1, allow_inf_nan=False)
    feasibility: float = Field(default=.5, ge=0, le=1, allow_inf_nan=False)
    estimated_cost_microusd: int = Field(default=1000, ge=0, le=2000000)


class CreateHypothesis(Strict):
    request_id: uuid.UUID
    hypothesis: Hypothesis


class ResearchTransition(Strict):
    request_id: uuid.UUID
    expected_revision: int = Field(ge=1)
    state: ResearchState
    reason: Criterion
    evidence_references: list[Reference] = Field(default_factory=list, max_length=30)
    finding_id: Reference | None = None


class ModelNode(Strict):
    id: Reference
    kind: Literal['asset','component','endpoint','authentication','session','identity',
        'role','permission','object','workflow','state','trust_boundary','service']
    label: Criterion
    locator: str = Field(default='', max_length=2000)
    evidence_references: list[Reference] = Field(min_length=1, max_length=20)


class ModelEdge(Strict):
    source: Reference
    target: Reference
    relation: Literal['authenticates','issues_session','assumes_role','permits','denies',
        'owns','routes_to','calls','crosses_boundary','flows_to','transitions_to',
        'precedes','requires','contains']
    condition: Criterion
    evidence_references: list[Reference] = Field(min_length=1, max_length=20)


class ApplicationModel(Strict):
    request_id: uuid.UUID
    expected_revision: int = Field(ge=0)
    nodes: list[ModelNode] = Field(max_length=300)
    edges: list[ModelEdge] = Field(max_length=1000)
    uncertainty: list[Criterion] = Field(min_length=1, max_length=20)


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_snapshot(state: dict, refs: list[str]) -> dict:
    from memory.finding_verification import evidence_snapshot as checked
    return checked(state, refs)


def priority(hypothesis: dict) -> float:
    benefit = (.4 * hypothesis['information_value'] + .4 * hypothesis['security_relevance']
               + .2 * hypothesis['feasibility'])
    return round(benefit / (1 + hypothesis['estimated_cost_microusd'] / 1000000), 8)


def model_current(model: dict, evidence: dict, scope: dict) -> bool:
    if not model:
        return True
    return (model.get('scope_digest') == digest(scope) and
        all(ref in evidence and digest(evidence[ref]) == value
            for ref, value in model.get('evidence_snapshot', {}).items()) and
        bool(model.get('evidence_snapshot')) == bool(model.get('nodes') or model.get('edges')))


def validate_model(body: ApplicationModel, state: dict, scope: dict) -> None:
    from orchestrator.execution_policy import PolicyError, allowed_target
    from urllib.parse import urlsplit
    nodes = {node.id: node for node in body.nodes}
    if len(nodes) != len(body.nodes):
        raise HTTPException(422, 'Application node identities must be unique')
    for node in body.nodes:
        evidence_snapshot(state, node.evidence_references)
        if node.locator:
            # Locators contain scoped resources only; credentials and query
            # strings belong in the existing encrypted map, never this graph.
            parsed = urlsplit(node.locator)
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise HTTPException(422, 'Graph locators cannot contain credentials, queries or fragments')
            try:
                allowed_target(node.locator, scope)
            except (PolicyError, ValueError):
                raise HTTPException(422, 'Application locator is outside engagement scope') from None
    constraints = {'owns': ({'identity'}, {'object'}),
        'assumes_role': ({'identity','session'}, {'role'}),
        'authenticates': ({'authentication'}, {'identity','session'}),
        'issues_session': ({'authentication','service'}, {'session'}),
        'transitions_to': ({'state'}, {'state'}),
        'crosses_boundary': ({'endpoint','service','component'}, {'trust_boundary'}),
        'permits': ({'role','permission'}, {'endpoint','object','workflow'}),
        'denies': ({'role','permission'}, {'endpoint','object','workflow'})}
    for edge in body.edges:
        evidence_snapshot(state, edge.evidence_references)
        if edge.source not in nodes or edge.target not in nodes or edge.source == edge.target:
            raise HTTPException(422, 'Application edge must connect two existing distinct nodes')
        if edge.relation in constraints:
            sources, targets = constraints[edge.relation]
            if nodes[edge.source].kind not in sources or nodes[edge.target].kind not in targets:
                raise HTTPException(422, 'Application relation has incompatible node types')


class ResearchStore:
    async def create(self, sid: str, owner: str, body: CreateHypothesis) -> dict:
        async def build(db, session, state):
            if len(state['research_hypotheses']) >= 500:
                raise HTTPException(409, 'Engagement hypothesis limit reached')
            item = body.hypothesis.model_dump()
            snapshot = evidence_snapshot(state, item['supporting_evidence'])
            graph = state['research_models'].get('application', {})
            if not model_current(graph, state['evidence'], session.scope or {}):
                raise HTTPException(409, 'Application model context changed; revalidate the model first')
            nodes = {n['id'] for n in graph.get('nodes', [])}
            if not set(item['related_assets'] + item['related_components']) <= nodes:
                raise HTTPException(422, 'Related assets/components must exist in this engagement model')
            hid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-research:{sid}:{body.request_id}'))
            return 'research_hypotheses', hid, {**item, 'id':hid, 'state':'OBSERVED',
                'revision':1, 'scope_digest':digest(session.scope or {}),
                'evidence_snapshot':snapshot, 'model_digest':digest(graph),
                'priority':priority(item), 'finding_id':None,
                'history':[{'state':'OBSERVED','at':timestamp(),'actor':owner,
                            'reason':'Evidence-backed research candidate registered'}]}
        return await team_store.mutate(sid, owner, str(body.request_id), body.model_dump(mode='json'), build)

    async def transition(self, sid: str, owner: str, hid: str, body: ResearchTransition) -> dict:
        async def build(db, session, state):
            item = state['research_hypotheses'].get(hid)
            if not item:
                raise HTTPException(404, 'Hypothesis not found')
            if item['revision'] != body.expected_revision or body.state not in TRANSITIONS[item['state']]:
                raise HTTPException(409, 'Stale revision or invalid research transition')
            if body.state not in {'REJECTED','INCONCLUSIVE','HYPOTHESIZED'}:
                if item['scope_digest'] != digest(session.scope or {}) or any(
                        ref not in state['evidence'] or digest(state['evidence'][ref]) != value
                        for ref, value in item['evidence_snapshot'].items()):
                    raise HTTPException(409, 'Scope or supporting evidence changed; reopen the hypothesis')
                if item['model_digest'] != digest(state['research_models'].get('application', {})):
                    raise HTTPException(409, 'Application model changed; reopen the hypothesis')
            if body.state not in {'REJECTED','INCONCLUSIVE'} and not model_current(
                    state['research_models'].get('application', {}), state['evidence'], session.scope or {}):
                raise HTTPException(409, 'Application model context changed; revalidate the model first')
            snapshot = evidence_snapshot(state, body.evidence_references)
            if body.state == 'TESTED' and not body.evidence_references:
                raise HTTPException(422, 'Tests require cataloged result evidence')
            verification = None
            if body.state == 'CONFIRMED':
                from orchestrator.research_verifier import inspect_finding
                finding = state['verification_findings'].get(body.finding_id, {})
                if not set(finding.get('evidence_references', [])) & set(item['supporting_evidence']):
                    raise HTTPException(409, 'Finding must examine this hypothesis supporting evidence')
                run_refs = {ref for key in ('test','reproduction') for ref in (finding.get(key) or {}).get('evidence_references', [])}
                if not run_refs or not run_refs <= set(item['evidence_snapshot']):
                    raise HTTPException(409, 'Both independent runs must be recorded in this hypothesis history')
                verification = await inspect_finding(db, sid, owner, body.finding_id, state, session.scope or {})
                if not verification['confirmed']:
                    raise HTTPException(409, 'Independent content verification and existing human signoff are required')
            updated = {**item, 'state':body.state, 'revision':item['revision']+1,
                'evidence_snapshot':{**item['evidence_snapshot'], **snapshot},
                'history':[*item['history'], {'state':body.state,'at':timestamp(),
                    'actor':owner,'reason':body.reason,'evidence_references':body.evidence_references}]}
            if len(updated['history']) > 100:
                raise HTTPException(409, 'Hypothesis history limit reached')
            if body.state == 'HYPOTHESIZED':
                updated.update(scope_digest=digest(session.scope or {}), model_digest=digest(state['research_models'].get('application', {})),
                    evidence_snapshot=evidence_snapshot(state, item['supporting_evidence']), independent_verification=None, finding_id=None)
            if verification:
                updated.update(finding_id=body.finding_id, independent_verification=verification)
            return 'research_hypotheses', hid, updated
        return await team_store.mutate(sid, owner, str(body.request_id), body.model_dump(mode='json'), build)

    async def save_model(self, sid: str, owner: str, body: ApplicationModel) -> dict:
        async def build(db, session, state):
            previous = state['research_models'].get('application', {})
            if previous.get('revision', 0) != body.expected_revision:
                raise HTTPException(409, 'Stale application model revision')
            validate_model(body, state, session.scope or {})
            refs = list(dict.fromkeys(ref for item in [*body.nodes, *body.edges] for ref in item.evidence_references))
            return 'research_models', 'application', {**body.model_dump(mode='json', exclude={'request_id','expected_revision'}),
                'id':'application', 'revision':body.expected_revision+1,
                'evidence_snapshot':evidence_snapshot(state, refs),
                'scope_digest':digest(session.scope or {}), 'updated_at':timestamp(),
                'verification':'evidence-linked assertions; no execution authority'}
        return await team_store.mutate(sid, owner, str(body.request_id), body.model_dump(mode='json'), build)

    async def view(self, sid: str, owner: str) -> dict:
        ledger = await team_store.view(sid, owner)
        evidence = {e['id']:e for e in ledger['evidence']}
        model = next(iter(ledger['research_models']), {})
        graph_current = model_current(model, evidence, ledger['scope'])
        hypotheses = []
        for item in ledger['research_hypotheses']:
            valid = (graph_current and item['scope_digest'] == digest(ledger['scope']) and item['model_digest'] == digest(model)
                and all(ref in evidence and digest(evidence[ref]) == value for ref, value in item['evidence_snapshot'].items()))
            hypotheses.append({**item, 'context_current':valid,
                'requires_revalidation':not valid, 'confirmed':False})
        # Never display a stale confirmation as an independently verified fact.
        if any(item['state'] == 'CONFIRMED' for item in hypotheses):
            from memory.finding_verification import verification_store
            findings = {f['id']:f for f in (await verification_store.view(sid, owner))['findings']}
            for item in hypotheses:
                item['confirmed'] = bool(item['state']=='CONFIRMED' and item['context_current'] and
                    findings.get(item['finding_id'], {}).get('ready_for_external_submission'))
        active = [h for h in hypotheses if h['state'] in {'OBSERVED','HYPOTHESIZED','PLANNED','TESTED'} and h['context_current']]
        return {'hypotheses':hypotheses, 'application_model':model,
            'application_model_current':graph_current,
            'queue':sorted(active, key=lambda h:(-h['priority'], h['id'])),
            'limitations':['Graph annotations and model confidence are assertions.',
                'Planning and test records grant no execution authority; confirmation retains existing human signoff.']}

    async def ingest_review(self, sid: str, owner: str, run_id: str, review: dict) -> list[str]:
        """Persist current-run receipt-bound proposals idempotently, never confirm."""
        from memory.team_tasks import EvidenceInput
        ids = []
        for index, item in enumerate(review['hypotheses']):
            refs = []
            for job in item['evidence_job_ids']:
                event = await team_store.catalog(sid, owner, EvidenceInput(
                    request_id=uuid.uuid5(uuid.NAMESPACE_URL, f'research-evidence:{sid}:{job}'),
                    source_kind='worker', source_id=job))
                refs.append(event['data']['id'])
            event = await self.create(sid, owner, CreateHypothesis(
                request_id=uuid.uuid5(uuid.NAMESPACE_URL, f'research-review:{sid}:{run_id}:{index}'),
                hypothesis=Hypothesis(title=item['description'], claim=item['description'],
                    supporting_evidence=refs, alternative_explanations=item.get('alternative_explanations') or ['The observation may reflect intended behavior or a generic response.'],
                    prerequisites=['Verify scope, controlled identities and required capability before testing.'],
                    validation_strategy=item['validation_criterion'], positive_controls=['Establish expected behavior using the controlled owner identity.'],
                    negative_controls=['Verify denial or absence using a separate synthetic control.'],
                    confidence=item.get('confidence', .25), uncertainty=['Model proposal; no vulnerability has been independently reproduced.'])))
            ids.append(event['entity_id'])
            await self.transition(sid, owner, event['entity_id'], ResearchTransition(
                request_id=uuid.uuid5(uuid.NAMESPACE_URL, f'research-hypothesized:{sid}:{run_id}:{index}'),
                expected_revision=1, state='HYPOTHESIZED', reason='Receipt-bound model proposal; independent testing remains pending.'))
        return ids

    async def sync_specialists(self, sid: str, owner: str, task_ids: list[str]) -> None:
        """Retry-safe projection of collected specialist results into research.

        A crash between collection and projection is repaired on the next planner
        context load; task generation never has to run twice to recover state.
        """
        ledger = await team_store.view(sid, owner)
        classes = {'authorization':'idor_bola','authentication':'authentication_session',
            'exposure':'information_disclosure','input_validation':'input_validation_injection',
            'business_logic':'business_logic'}
        for task in ledger['tasks']:
            if (task['id'] not in task_ids[:20] or not task.get('result') or
                    task.get('state') not in {'awaiting_review', 'completed'}):
                continue
            result = task['result']
            allowed = set(task['evidence_inputs']) & set(result.get('evidence_references', []))
            for index, item in enumerate(result.get('hypotheses', [])[:3]):
                refs = [ref for ref in item.get('evidence_references', []) if ref in allowed]
                claim = item.get('description')
                if not refs or not isinstance(claim, str) or not claim.strip():
                    continue
                request_id = uuid.uuid5(uuid.NAMESPACE_URL, f'research-specialist:{sid}:{task["id"]}:{task.get("run_id")}:{index}')
                await self.create(sid, owner, CreateHypothesis(request_id=request_id, hypothesis=Hypothesis(
                    title=claim[:2000], claim=claim[:2000], supporting_evidence=refs[:30],
                    vulnerability_class=classes.get(task.get('specialty'),'unclassified'),
                    alternative_explanations=['A generic response, intended workflow or incomplete ownership model may explain the observation.'],
                    prerequisites=['Current scope and controlled lab identities must be verified before any test.'],
                    validation_strategy='Independently reproduce the proposed behavior with original content and fresh controls.',
                    positive_controls=['Establish the authorized owner baseline.'], negative_controls=['Check the same operation against a denied or nonexistent resource.'],
                    confidence=.25, uncertainty=['Collected specialist interpretation; independent tests remain pending.'])))


research_store = ResearchStore()
