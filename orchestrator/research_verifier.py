"""Independent deterministic verifier: original content, controls and provenance.

Consumes no discovery prompt and invokes no tools or models. This specialist
challenges a finding against two separate recorded runs and existing signoff.
"""
from memory.finding_verification import ContentControl, current, verify_content
from memory.team_tasks import digest


async def inspect_finding(db, sid: str, owner: str, finding_id: str | None,
                          state: dict, scope: dict) -> dict:
    finding = state['verification_findings'].get(finding_id)
    result = {'specialist':'independent_content_verifier', 'finding_id':finding_id,
              'confirmed':False, 'discovery_prompt_used':False, 'checks':[], 'uncertainty':[]}
    if not finding or not current(finding, state, scope):
        result['uncertainty'].append('Finding or current provenance unavailable')
        return result
    from memory.application_map import application_map, capture_metadata
    _, _, mapped = await application_map._load(db, sid, owner)
    sources = []
    try:
        for key in ('test','reproduction'):
            run = finding[key]
            control = ContentControl.model_validate(run['content_control'])
            ids = [control.owner_capture_id, control.outsider_capture_id, control.negative_capture_id]
            for cid in ids:
                capture = mapped['captures'][cid]
                capture_metadata(capture['original'], scope)
            checked = verify_content(mapped, control, run, state)
            if checked != run.get('content_verification'):
                raise ValueError('Control changed since saved review')
            sources.append({(state['evidence'][ref]['source_kind'], state['evidence'][ref]['source_id'])
                for field in ('evidence_references','negative_control_references') for ref in run[field]})
            result['checks'].append({'run':key,'input_digest':checked['input_digest'],
                'private_match':True,'negative_match':False})
        if sources[0] & sources[1]:
            raise ValueError('Reproduction reuses discovery sources')
        result['confirmed'] = bool(finding['state']=='reportable' and finding.get('human_signoff')
            and finding.get('human_review'))
        result['evidence_digest'] = digest(finding['evidence_snapshot'])
        if not result['confirmed']:
            result['uncertainty'].append('Existing human review/signoff is still required')
    except Exception:
        result['confirmed'] = False
        result['uncertainty'].append('Original content, fresh reproduction or control verification failed')
    return result
