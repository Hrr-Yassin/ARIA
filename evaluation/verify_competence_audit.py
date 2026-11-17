"""Standalone stdlib-only audit verification; no application/scorer imports.

Recomputes exported points, fixture/source hashes and CSV/HTML consistency.
This independent implementation is an automated checker, not a human assessor.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path

STEM='aria-cybersecurity-competence'


def strict_json(text: str):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key]=value
        return result
    def reject(value):
        raise ValueError('Nonfinite JSON value')
    return json.loads(text,object_pairs_hook=unique,parse_constant=reject)


def canonical(value) -> str:
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def file_hash(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def follow_up_values(case_id: str, evidence: dict) -> tuple[int, dict, dict]:
    if case_id in {'legacy-plan-before', 'legacy-plan-current'}:
        count = len(evidence['rows'])
        passed = sum(canonical(row['actual']) == canonical(row['expected']) for row in evidence['rows'])
        return count, {'passed': count}, {'passed': passed}
    if case_id == 'community-passive-native':
        expected = {
            'version': 'Burp Suite Community Edition 2025.2-36507',
            'conditions': 11,
            'http_dispatches': 0,
        }
        actual = {
            'version': evidence['native_version']['display'],
            'conditions': len(set(evidence['checks'])),
            'http_dispatches': evidence['native_request_counter']['burp_http_requests'],
        }
        return len(evidence['checks']), expected, actual
    component, _, phase = case_id.rpartition('-')
    if phase not in {'before', 'after'}:
        raise ValueError('Unknown follow-up case')
    check = next(c for c in evidence['checks'] if c['component'] == component)
    count = check['assessed']
    return count, {'check': check['expected'], 'passed': count}, {
        'check': check['expected'], 'passed': check[f'passed_{phase}'],
    }


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections=[];self.in_data=False;self.payload='';self.data_sha=None

    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='section':self.sections.append(attrs.get('id'))
        if tag=='script' and attrs.get('id')=='audit-data':self.in_data=True
        if tag=='meta' and attrs.get('name')=='audit-data-sha256':self.data_sha=attrs.get('content')

    def handle_data(self,data):
        if self.in_data:self.payload+=data

    def handle_endtag(self,tag):
        if tag=='script':self.in_data=False


def verify(output: Path) -> dict:
    index=strict_json((output/(STEM+'-artifacts.json')).read_text())
    expected={STEM+'-results.json',STEM+'-metrics.csv',STEM+'-audit.html'}
    if set(index)!=expected or any(file_hash(output/name)!=value for name,value in index.items()):
        raise ValueError('Audit artifact digest mismatch')
    data=strict_json((output/(STEM+'-results.json')).read_text())
    for field in ('source_sha256','evidence_sha256','protected_sources_unchanged'):
        if not data.get(field):raise ValueError('Missing source/evidence provenance')
        for name,value in data[field].items():
            path=Path(name)
            if path.is_absolute() or '..' in path.parts or file_hash(path)!=value:
                raise ValueError('Source/evidence digest mismatch: '+name)
    freeze=strict_json(Path('docs/competence/benchmark-freeze.json').read_text())
    if data['metadata']['benchmark-freeze']!=freeze:
        raise ValueError('Reported freeze manifest differs from the retained manifest')
    for name,value in freeze['files'].items():
        if file_hash(Path(name))!=value:raise ValueError('Frozen expectations changed')
    reserved_root=Path(data.get('reserved_runtime_source_root','.'))
    if reserved_root.is_absolute() or '..' in reserved_root.parts:
        raise ValueError('Invalid reserved source snapshot location')
    for name,value in freeze['runtime_sources_before_reserved_evaluation'].items():
        if file_hash(reserved_root/name)!=value:raise ValueError('Reserved evaluation source snapshot changed')
    frozen=strict_json(Path('evaluation/fixtures/competence/requirements-v1.json').read_text())['requirements']
    if [{k:r[k] for k in ('id','scope','acceptance_criterion')} for r in data['requirements']]!=frozen:
        raise ValueError('Acceptance criteria drift')
    current=[]
    for line in Path('PLANS.md').read_text().splitlines():
        if line.startswith('| C'):
            values=[v.strip() for v in line.split('|')[1:-1]]
            current.append(dict(zip(('id','scope','status','acceptance_criterion','evidence_summary'),values)))
    if current!=data['requirements']:raise ValueError('Tracking/report requirement mismatch')
    if any(r['status'] not in {'VERIFIED','BLOCKED','IN_PROGRESS','IMPLEMENTED','NOT_STARTED'} or not r['evidence_summary'] for r in current):
        raise ValueError('Unattributed requirement status')
    counts={}
    run_metric_rows=[]
    for item in data['measurements']:
        run=item['run'];packet=strict_json(Path(item['fixture']).read_text())
        if run!=strict_json(Path(item['path']).read_text()) or file_hash(Path(item['path']))!=item['sha256']:
            raise ValueError('Retained answer mismatch')
        if (run['split']!=packet['split'] or run['protocol_sha256']!=hashlib.sha256(canonical(packet).encode()).hexdigest()
                or run['kind']!='deterministic_software_component' or run['model_calls']!=0
                or run['target_actions']!=0 or run['independent_human_assessment'] is not False):
            raise ValueError('Measurement scope misrepresented')
        if len(run['rows'])!=len(packet['cases']):raise ValueError('Omitted failure or case')
        components={}
        for case,row in zip(packet['cases'],run['rows']):
            if any(canonical(row.get(k))!=canonical(v) for k,v in case.items()):raise ValueError('Expected answer edited')
            passed=row['error'] is None and canonical(row['actual'])==canonical(case['expected'])
            if type(row['passed']) is not bool or row['passed'] is not passed:raise ValueError('Fabricated point')
            if type(row['sample_size']) is not int or row['sample_size']!=1:raise ValueError('Fabricated sample size')
            group=components.setdefault(case['component'],{'passed':0,'assessed':0})
            group['passed']+=int(passed);group['assessed']+=1
            run_metric_rows.append((run['split'],row['id'],canonical(row['actual']),row['passed']))
        if components!=run['components'] or any(g['assessed']!=10 for g in components.values()):raise ValueError('Component denominator changed')
        counts[run['split']]=counts.get(run['split'],0)+len(run['rows'])
        for path,value in run['source_sha256'].items():
            if file_hash(Path(path))!=value:raise ValueError('Measured source mismatch')
    exported=[(r['cohort'].removeprefix('current_'),r['case_id'],canonical(r['actual']),r['passed'])
              for r in data['metrics'] if r['cohort'].startswith('current_')]
    if exported!=run_metric_rows:raise ValueError('Measured rows missing from CSV/data projection')
    follow_up = [r for r in data['metrics'] if r['cohort']=='follow_up']
    follow_up_ids = {'legacy-plan-before', 'legacy-plan-current', 'community-passive-native',
                     'coding_invalid_python-before', 'coding_invalid_python-after',
                     'burp_public_url_redaction-before', 'burp_public_url_redaction-after'}
    if reserved_root != Path('.') and (
            {r['case_id'] for r in follow_up} != follow_up_ids or len(follow_up) != len(follow_up_ids)):
        raise ValueError('Incomplete follow-up measurements')
    for row in follow_up:
        if data['evidence_sha256'].get(row['evidence']) != row['evidence_sha256']:
            raise ValueError('Unbound follow-up evidence')
        evidence = strict_json(Path(row['evidence']).read_text())
        count, expected, actual = follow_up_values(row['case_id'], evidence)
        if (type(row['sample_size']) is not int or row['sample_size'] != count or count < 1
                or canonical(row['expected']) != canonical(expected)
                or canonical(row['actual']) != canonical(actual)
                or row['passed'] is not (canonical(actual) == canonical(expected))):
            raise ValueError('Follow-up grade, denominator or evidence binding is invalid')
    with (output/(STEM+'-metrics.csv')).open(newline='') as handle:
        csv_rows=list(csv.DictReader(handle))
    if len(csv_rows)!=len(data['metrics']):raise ValueError('CSV omitted rows')
    for row,actual in zip(csv_rows,data['metrics']):
        for key,value in actual.items():
            parsed=strict_json(row[key]) if key in {'expected','actual','passed','limitations'} else row[key]
            expected=value if key in {'expected','actual','passed','limitations'} else '' if value is None else str(value)
            if canonical(parsed)!=canonical(expected):raise ValueError('CSV/JSON value mismatch')
    parser=ReportParser();parser.feed((output/(STEM+'-audit.html')).read_text())
    if parser.data_sha!=index[STEM+'-results.json'] or strict_json(parser.payload)!=data or len(set(parser.sections))!=13:
        raise ValueError('HTML/data/section mismatch')
    for key in ('all_competence_requirements_verified','senior_equivalence','operational_8_5_readiness'):
        if data['completion'][key] is not False:raise ValueError('Unsupported overall expertise/readiness claim')
    if data['completion']['current_model_quality_after_changes'] is not None:raise ValueError('Unmeasured fresh intelligence score')
    feasible=all(r['status']=='VERIFIED' for r in current if r['status']!='BLOCKED')
    if data['completion']['all_feasible_engineering_verified'] is not feasible:raise ValueError('False feasible-completion claim')
    if data['independent_validation']['human']!='BLOCKED: no independent senior reviewer':raise ValueError('Fabricated independent reviewer')
    return {'status':'passed','requirements':len(current),'blocked_requirements':[r['id'] for r in current if r['status']=='BLOCKED'],
            'metrics':len(data['metrics']),'case_counts_by_split':counts,'html_sections':len(parser.sections),
            'source_hashes':len(data['source_sha256']),'evidence_hashes':len(data['evidence_sha256']),
            'html_sha256':index[STEM+'-audit.html'],'independent_human_assessment':False,
            'limitations':'Independent implementation of arithmetic/integrity checks; no independent human semantic grading.'}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('reports'))
    parser.add_argument('--proof',type=Path)
    args=parser.parse_args();result=verify(args.output)
    if args.proof:args.proof.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':
    main()
