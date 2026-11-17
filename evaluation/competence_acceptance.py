"""Strict answer/fixture/source-bound scoring for named software components."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from evaluation.competence import COMPONENT_SOURCES, digest


def verify_measurement(packet: dict, run: dict, *, check_sources: bool = True) -> dict:
    """Recompute every point; passing tests never certify model/human expertise."""
    if (run.get('kind')!='deterministic_software_component' or run.get('split')!=packet['split']
            or run.get('protocol_sha256')!=digest(packet)
            or run.get('independent_human_assessment') is not False
            or run.get('senior_equivalence') is not False):
        raise ValueError('Measurement kind, split, frozen protocol or assessment attribution mismatch')
    for name in ('model_calls','target_actions'):
        if type(run.get(name)) is not int or run[name]!=0:
            raise ValueError('Offline component measurements cannot claim live inference or target actions')
    cases=packet['cases']
    rows=run.get('rows')
    if not isinstance(rows,list) or len(rows)!=len(cases):
        raise ValueError('All frozen cases, including failures, must be retained')
    components={}
    for case,row in zip(cases,rows):
        if any(digest(row.get(k))!=digest(v) for k,v in case.items()):
            raise ValueError('Missing, reordered, changed or duplicated frozen case/expectation')
        if type(row.get('passed')) is not bool or type(row.get('sample_size')) is not int or row['sample_size']!=1:
            raise ValueError('Strict grades and actual sample size are required')
        passed=row.get('error') is None and digest(row.get('actual'))==digest(case['expected'])
        if passed is not row['passed']:
            raise ValueError('Claimed point does not match the retained actual answer')
        group=components.setdefault(case['component'],{'passed':0,'assessed':0})
        group['passed']+=int(passed)
        group['assessed']+=1
        if not row.get('confidence') or not row.get('method'):
            raise ValueError('Every score requires method and confidence limits')
    if run.get('components')!=components or any(g['assessed']!=10 for g in components.values()):
        raise ValueError('Each named component must retain exactly its ten frozen criteria')
    if check_sources:
        paths={p for case in cases for p in COMPONENT_SOURCES[case['component']]}
        hashes=run.get('source_sha256',{})
        if set(hashes)!=paths or any(hashlib.sha256(Path(p).read_bytes()).hexdigest()!=hashes[p] for p in paths):
            raise ValueError('Measurement source bytes changed or are unbound')
    return {'components':components,'all_cases_pass':all(row['passed'] for row in rows),
            'model_intelligence_score':None,'independent_senior_assessment':'BLOCKED',
            'scope':'Frozen deterministic component cases only'}
