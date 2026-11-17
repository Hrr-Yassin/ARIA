"""Attribution and consistency checks for unverified specialist handoffs."""
from __future__ import annotations

import json

from security.redaction import redact


def review_handoff(claims: list[dict], evidence: list[dict]) -> dict:
    """Detect structured analytical errors without treating agreement as proof."""
    if not isinstance(claims,list) or len(claims)>20 or not isinstance(evidence,list) or len(evidence)>100:
        raise ValueError('Handoff exceeds review bounds')
    catalog={e['id']:e for e in evidence}
    issues=[]
    seen_sources={}
    seen_text={}
    assertions={}
    def issue(code, claim_id):
        issues.append({'code':code,'claim_id':claim_id})
    for claim in claims:
        if (not isinstance(claim,dict) or not isinstance(claim.get('id'),str)
                or not isinstance(claim.get('text'),str) or len(claim['text'])>2000
                or not isinstance(claim.get('evidence_references',[]),list)
                or any(not isinstance(ref,str) for ref in claim.get('evidence_references',[]))
                or not isinstance(claim.get('assertions',{}),dict)):
            raise ValueError('Invalid attributed handoff')
        cid=claim['id']
        refs=set(claim.get('evidence_references',[]))
        if not refs:
            issue('unattributed_claim',cid)
        elif not refs<=catalog.keys():
            issue('unknown_evidence_reference',cid)
        valid=refs & catalog.keys()
        if valid:
            signature=tuple(sorted(valid))
            if signature in seen_sources:
                issue('shared_evidence_not_independent',cid)
            seen_sources[signature]=cid
        text=(' '.join(claim['text'].lower().split()),
              json.dumps(claim.get('assertions',{}),sort_keys=True,separators=(',',':')))
        if text in seen_text:
            issue('duplicate_information',cid)
        seen_text[text]=cid
        if (claim.get('verified') is True or claim.get('claimed_verified') is True
                or claim.get('verification_status') in {'confirmed','verified','reportable'}):
            issue('unverified_confirmation',cid)
        for key,value in claim.get('assertions',{}).items():
            source_values=[catalog[ref]['facts'][key] for ref in valid
                           if isinstance(catalog[ref].get('facts'),dict) and key in catalog[ref]['facts']]
            if not source_values:
                issue('unsupported_assertion',cid)
            elif not any(type(v) is type(value) and v==value for v in source_values):
                issue('source_contradiction',cid)
            prior=assertions.get(key)
            if prior is not None and not (type(prior[1]) is type(value) and prior[1]==value):
                issue('contradictory_claims',cid)
            assertions[key]=(cid,value)
    return {'kind':'deterministic_handoff_review','issues':issues,
            'claim_count':len(claims),'distinct_cited_evidence_ids':len(set().union(*(
                set(c.get('evidence_references',[])) & catalog.keys() for c in claims))) if claims else 0,
            'confirmed_vulnerabilities':[], 'independent_collection_established':False,
            'limitations':['Structured provenance/consistency only; natural-language accuracy and peer-review intelligence remain unmeasured.',
                           'Distinct evidence IDs or specialist agreement cannot establish independent reproduction.']}


def build_handoff(entries: list[dict], evidence: list[dict], target: str) -> dict:
    """Preserve recent analyst/source identity and label every assertion unverified."""
    claims=[]
    omitted=0
    for entry in entries[-20:]:
        metadata=entry.get('metadata') or {}
        if metadata.get('target') and metadata['target']!=target:
            omitted+=1
            continue
        claims.append({'id':str(entry.get('id','unknown'))[:100],
                       'agent':str(entry.get('agent','unknown'))[:40],
                       'text':str(redact(entry.get('content','')))[:1000],
                       'evidence_references':metadata.get('evidence_references') or [],
                       'assertions':metadata.get('assertions') or {},
                       'verified':False, 'claimed_verified':metadata.get('verified') is True,
                       'provenance':'unverified_agent_assertion'})
    result={'claims':claims,'review':review_handoff(claims,evidence),
            'omitted_other_target':omitted,'omitted_older_entries':max(0,len(entries)-20),
            'authority':'Untrusted attributed analyst assertions; not execution authority or independent evidence'}
    # Retained text is deliberately bounded separately from source evidence.
    if len(json.dumps(result).encode())>40000:
        raise ValueError('Handoff context exceeds byte budget')
    return result
