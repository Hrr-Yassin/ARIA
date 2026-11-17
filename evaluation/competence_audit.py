"""Build the competence audit from retained measured answers and source evidence."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import html
import io
import json
from pathlib import Path
import re
import subprocess

from evaluation.competence import FIXTURES, load_cases
from evaluation.competence_acceptance import verify_measurement

STEM='aria-cybersecurity-competence'
FIELDS=('cohort','requirement','component','case_id','expected','actual','passed','sample_size',
        'method','evidence','evidence_sha256','limitations','confidence','elapsed_ms')


def sha(path: Path) -> str:
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def requirements() -> list[dict]:
    rows=[]
    frozen=json.loads((FIXTURES/'requirements-v1.json').read_text())['requirements']
    for line in Path('PLANS.md').read_text().splitlines():
        if line.startswith('| C'):
            cells=[c.strip() for c in line.split('|')[1:-1]]
            rows.append(dict(zip(('id','scope','status','acceptance_criterion','evidence_summary'),cells)))
    if [{k:r[k] for k in ('id','scope','acceptance_criterion')} for r in rows]!=frozen:
        raise ValueError('Frozen competence requirement criteria changed')
    return rows


def test_result(path: Path) -> dict:
    content=path.read_text()
    match=re.search(r'Ran (\d+) tests? in ([0-9.]+)s\s+OK\s*$',content)
    if not match:
        raise ValueError('Missing successful terminal test result: '+str(path))
    return {'tests':int(match[1]),'elapsed_seconds':float(match[2]),'path':str(path),'sha256':sha(path)}


def follow_up_metrics(evidence: Path, source_evidence: dict, compatibility: dict) -> list[dict]:
    """Project retained, bounded follow-up checks without exporting plan content."""
    cycle02 = evidence.parent / 'cycle02'
    rows = []

    def record(path, requirement, component, case_id, expected, actual, n, method, limits,
               elapsed_ms=None):
        source_evidence[str(path)] = sha(path)
        rows.append({
            'cohort': 'follow_up', 'requirement': requirement, 'component': component,
            'case_id': case_id, 'expected': expected, 'actual': actual,
            'passed': expected == actual, 'sample_size': n, 'method': method,
            'evidence': str(path), 'evidence_sha256': source_evidence[str(path)],
            'limitations': limits, 'confidence': 'Scoped to the retained checks',
            'elapsed_ms': elapsed_ms,
        })

    for phase in ('before', 'current'):
        path = cycle02 / f'plan-contract-{phase}.json'
        run = json.loads(path.read_text())
        fixture = Path(run['fixture'])
        cases = json.loads(fixture.read_text())['cases']
        source_root = cycle02 / 'pre-plan-correction' if phase == 'before' else Path('.')
        passed = sum(row['actual'] == row['expected'] for row in run['rows'])
        count = len(run['rows'])
        if (sha(fixture) != run['fixture_sha256'] or run['passed'] != passed
                or run['assessed'] != count or any(run[key] != 0 for key in ('model_calls', 'target_actions'))
                or [(row['id'], row['expected']) for row in run['rows']]
                   != [(case['id'], case['expected']) for case in cases]
                or any(sha(source_root / name) != value for name, value in run['source_sha256'].items())):
            raise ValueError('Legacy planner containment evidence does not match its source')
        source_evidence[str(fixture)] = sha(fixture)
        record(path, 'C15-03', 'Legacy incomplete-plan containment', f'legacy-plan-{phase}',
               {'passed': count}, {'passed': passed}, count, 'Controlled malformed responses',
               'Recorded software containment only. No actual model response or target action.')

    native = cycle02 / 'native-community-corrected'
    path = native / 'runtime/result.json'
    run = json.loads(path.read_text())
    provenance = json.loads((native / 'provenance.json').read_text())
    version = 'Burp Suite Community Edition 2025.2-36507'
    count = len(set(run['checks']))
    dispatches = run['native_request_counter']['burp_http_requests']
    if (run['status'] != 'passed' or count != 11 or len(run['checks']) != count
            or run['native_version']['display'] != version or type(dispatches) is not int or dispatches != 0
            or run['network']['non_loopback_interfaces'] or run['new_license_terms_accepted'] is not False
            or any(run[key] != 0 for key in ('new_model_calls', 'target_requests', 'replay_jobs_submitted'))
            or any(sha(Path(name)) != value for name, value in provenance['source_sha256'].items())):
        raise ValueError('Retained native Burp evidence does not meet the passive cohort contract')
    for name, key in (('retained_jar', 'artifact_sha256'), ('compile_api', 'api_sha256')):
        artifact = compatibility[name]
        if sha(Path(artifact)) != provenance[key]:
            raise ValueError('Retained native artifact digest mismatch')
        source_evidence[artifact] = provenance[key]
    for receipt in (native / 'provenance.json', native / 'runtime/native-version.json',
                    native / 'runtime/native-request-count.json'):
        source_evidence[str(receipt)] = sha(receipt)
    record(path, 'C18-03', 'Retained native Burp artifact', 'community-passive-native',
           {'version': version, 'conditions': 11, 'http_dispatches': 0},
           {'version': run['native_version']['display'], 'conditions': count, 'http_dispatches': dispatches},
           count, 'Retained isolated Community runtime receipts',
           'Loopback-only headless passive checks. The regular desktop launcher references a missing JAR.',
           run['elapsed_seconds'] * 1000)

    path = evidence / 'defensive-verification.json'
    checks = json.loads(path.read_text())
    for hashes in (checks['evidence_sha256'], checks['source_before'], checks['source_after']):
        for name, value in hashes.items():
            if sha(Path(name)) != value:
                raise ValueError('Defensive regression evidence changed: ' + name)
            source_evidence[name] = value
    for check in checks['checks']:
        count = check['assessed']
        for phase in ('before', 'after'):
            record(path, check['requirement'], check['component'], f"{check['component']}-{phase}",
                   {'check': check['expected'], 'passed': count},
                   {'check': check['expected'], 'passed': check[f'passed_{phase}']},
                   count, 'Focused synthetic regressions against the applicable source',
                   checks['limitations'])
    return rows


def collect(evidence: Path, follow_up: Path | None = None) -> dict:
    measured=[]
    metric_rows=[]
    source_evidence={}
    packets = {path.name: path for path in evidence.glob('final-*-v1.json')}
    if follow_up is not None:
        for name in ('final-burp-development-v1.json', 'final-coding-development-v1.json'):
            packets[name] = follow_up / name
    for name, path in sorted(packets.items()):
        run=json.loads(path.read_text())
        fixture=FIXTURES/name.removeprefix('final-')
        verify_measurement(load_cases(fixture),run)
        measured.append({'path':str(path),'sha256':sha(path),'fixture':str(fixture),'run':run})
        source_evidence[str(path)]=sha(path)
    if len(measured)!=8:
        raise ValueError('All seven development packets and separate reserved packet are required')
    historical=[]
    for name in ('http-before.json','burp-before.json','parser-before.json','collaboration.json'):
        path=evidence/name
        run=json.loads(path.read_text())
        historical.append({'path':str(path),'sha256':sha(path),'run':run})
        source_evidence[str(path)]=sha(path)
    for item,cohort in [(m, 'current_'+m['run']['split']) for m in measured]+[(m,'pre_correction') for m in historical]:
        run=item['run']
        for row in run['rows']:
            metric_rows.append({'cohort':cohort,'requirement':row['requirement'],'component':row['component'],
                'case_id':row['id'],'expected':row['expected'],'actual':row['actual'],'passed':row['passed'],
                'sample_size':row['sample_size'],'method':row['method'],'evidence':item['path'],
                'evidence_sha256':item['sha256'],'limitations':run['limitations'],
                'confidence':row['confidence'],'elapsed_ms':row['elapsed_ms']})
    old_root=Path('.local-lab/operational-reliability/intelligence-v2')
    old_protocol=json.loads((old_root/'protocol.json').read_text())
    old_assessment=json.loads((old_root/'engineering-assessment.json').read_text())
    old_scores=json.loads((old_root/'engineering-scores.json').read_text())
    old_run=json.loads((old_root/'composite-run.json').read_text())
    from evaluation.agent_intelligence import score
    if score(old_protocol,old_run,old_assessment)!=old_scores:
        raise ValueError('Historical actual-model grades failed independent reconciliation')
    cases={c['case_id']:c for c in old_protocol['cases']}
    for row in old_assessment['rows']:
        checks={c['id']:c for c in cases[row['case_id']]['checks']}
        for grade in row['grades']:
            metric_rows.append({'cohort':'historical_actual_model','requirement':'C15-04',
                'component':checks[grade['criterion_id']]['dimension'],
                'case_id':row['case_id']+'/'+grade['criterion_id'],
                'expected':checks[grade['criterion_id']]['criterion'],
                'actual':{'rationale':grade['rationale'],'excerpt':grade.get('evidence_excerpt')},
                'passed':grade['passed'],'sample_size':0 if grade['passed'] is None else 1,
                'method':'retained attributable engineering rubric; wrong raw plans remain wrong even if policy rejected them',
                'evidence':str(old_root/'engineering-assessment.json'),'evidence_sha256':sha(old_root/'engineering-assessment.json'),
                'limitations':'Small historical heterogeneous role cases; no independent human calibration or post-change inference.',
                'confidence':'limited engineering assessment; missing responses unassessed','elapsed_ms':None})
    for name in ('protocol.json','engineering-assessment.json','engineering-scores.json','composite-run.json'):
        source_evidence[str(old_root/name)]=sha(old_root/name)
    metadata={}
    for name in ('agents','burp','causes','model-protocol','reviewer-packet','benchmark-freeze'):
        path=Path('docs/competence')/(name+'.json')
        metadata[name]=json.loads(path.read_text());source_evidence[str(path)]=sha(path)
    for name in ('tool-inventory','model-reconciliation'):
        path=evidence/('tool-inventory-complete.json' if name=='tool-inventory' else name+'.json')
        metadata[name]=json.loads(path.read_text());source_evidence[str(path)]=sha(path)
    code_hashes={}
    for directory in ('agents','api','memory','orchestrator','config','security','llm','worker','security_tools','evaluation','burp-community/src'):
        for path in sorted(Path(directory).rglob('*')):
            if path.is_file() and path.suffix in {'.py','.json','.java'} and '__pycache__' not in str(path):
                code_hashes[str(path)]=sha(path)
    for name in ('GOALS.md','PLANS.md','requirements.in','requirements.txt','integration/competence_report_visible.py'):
        code_hashes[name]=sha(Path(name))
    entry=json.loads((evidence/'entry-source-manifest.json').read_text())
    protected={p:h for p,h in entry['hashes'].items() if p.startswith(('worker/','security_tools/'))
               or p in {'agents/autonomous_engine.py','llm/engagement_budget.py'}}
    if any(sha(Path(p))!=h for p,h in protected.items()):
        raise ValueError('Protected reliability/worker/accounting source changed during competence program')
    current_tests=test_result(evidence/'release-full-tests.txt')
    current_tests['scope'] = 'Cycle01 full offline regression'
    test_cohorts=[current_tests,test_result(evidence/'burp-jvm-retry.txt')]
    test_cohorts[1]['scope'] = 'Cycle01 controlled-sender Java'
    reserved_source_root = Path('.')
    if follow_up is not None:
        cycle02 = follow_up.parent / 'cycle02'
        reserved_source_root = cycle02 / 'pre-plan-correction'
        metric_rows.extend(follow_up_metrics(follow_up, source_evidence, metadata['burp']['compatibility']))
        test_cohorts.extend([
            {**test_result(cycle02 / 'full-tests.txt'),
             'scope': 'Cycle02 full offline regression log. Full loaded-source manifest unavailable.'},
            {**test_result(cycle02 / 'plan-contract-focused-current.txt'),
             'scope': 'Cycle02 focused containment regression'},
            {**test_result(follow_up / 'defensive-focused.txt'),
             'scope': 'Cycle03 focused coding, passive Burp and evidence regression'},
        ])
    for result in test_cohorts:source_evidence[result['path']]=result['sha256']
    requirements_rows=requirements()
    return {'schema':'aria.competence.audit.v1','generated_at':datetime.now(timezone.utc).isoformat(),
        'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'working_tree':'Dirty entry changes preserved; current competence code is local and not deployed.',
        'requirements':requirements_rows,'measurements':measured,'pre_correction_measurements':historical,
        'metrics':metric_rows,'historical_model_scores':old_scores,'metadata':metadata,
        'test_cohorts':test_cohorts,'source_sha256':code_hashes,'evidence_sha256':source_evidence,
        'reserved_runtime_source_root': str(reserved_source_root),
        'protected_sources_unchanged':protected,
        'budget':{'approved_calls':20,'used_calls_at_entry':15,'approved_tokens':200000,
                  'reserved_tokens_at_entry':196074,'remaining_tokens_at_entry':3926,
                  'minimum_reservation':8192,'approved_cost_usd':1,'new_model_calls':0,
                  'new_paid_calls':0,'new_target_actions':0,'new_worker_operations':0,'counter_reset':False},
        'independent_validation':{'automated':'Strict separate fixture/answer/source checker; standalone report checker; no independent human assessment.',
            'human':'BLOCKED: no independent senior reviewer','senior_equivalence':False,
            'reserved_split':'Ten same-author reserved variations; not blinded independent held-out data.'},
        'completion':{'all_feasible_engineering_verified':all(r['status']=='VERIFIED' for r in requirements_rows if r['status']!='BLOCKED'),
                      'all_competence_requirements_verified':False,'current_model_quality_after_changes':None,
                      'senior_equivalence':False,'operational_8_5_readiness':False},
        'preserved_operational_gates':[{'requirement':'P08-04/P14-02','status':'DEFERRED_BY_OWNER','limitation':'Same mandatory eight-hour obligation remains deferred; four-hour result preserved.'},
            {'requirement':'P11-02','status':'BLOCKED','limitation':'Actual model quality remains incomplete under existing allocation.'},
            {'requirement':'P12-01','status':'BLOCKED','limitation':'Independent senior reviewer unavailable.'},
            {'requirement':'P13-01','status':'BLOCKED','limitation':'No fresh exact-command approval; no target action attempted.'}],
        'limitations':['10/10 means ten frozen deterministic component criteria only; no perfect real-world expertise claim.',
            'New rule aids and code fixtures have no pre-existing equivalent score; baseline unavailable is never zero.',
            'New source is not deployed; database/worker runtime acceptance and historical endurance are separate cohorts.',
            'No new inference, target access, installation, privilege, approval, financial limit or endurance change.',
            'Per-agent RSS, generalization, independent human expertise comparison and sustained8/5 operation remain unproven.']}


def csv_text(data: dict) -> str:
    output=io.StringIO(newline='')
    writer=csv.DictWriter(output,fieldnames=FIELDS);writer.writeheader()
    for row in data['metrics']:
        writer.writerow({k:json.dumps(row[k],ensure_ascii=False,allow_nan=False) if k in {'expected','actual','passed','limitations'} else '' if row[k] is None else row[k] for k in FIELDS})
    return output.getvalue()


def esc(value: object) -> str:
    return html.escape(str(value))


def table(headers: list[str], rows: list[list[object]]) -> str:
    return '<div class="table-scroll"><table><thead><tr>'+''.join('<th>'+esc(h)+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join(
        '<tr>'+''.join('<td>'+esc(cell)+'</td>' for cell in row)+'</tr>' for row in rows)+'</tbody></table></div>'


def render(data: dict, data_sha256: str) -> str:
    sections=[]
    def section(identity,title,content):
        sections.append((identity,title,'<section id="'+identity+'"><h2>'+esc(title)+'</h2>'+content+'</section>'))
    section('baseline','Previous and current competence',
        '<p class="callout">Software interpretation improved. Fresh model intelligence is unmeasured. Independent senior comparison is blocked.</p>'+
        table(['Historical actual-model dimension','Passed / assessed','Unavailable criteria','Current after changes'],[[k.replace('_',' '),f"{v['passed']} / {v['assessed']}" if v['assessed'] else 'Unavailable',v['unassessed'],'Not measured; budget blocked'] for k,v in data['historical_model_scores']['dimensions'].items()])+
        '<p>Eight actual local-model calls produced six usable answers and two timeouts. A ninth review request was denied before a provider call. A rejected wrong proposal earns no decision credit.</p>')
    before={k:v for m in data['pre_correction_measurements'] for k,v in m['run']['components'].items()}
    current={k:v for m in data['measurements'] if m['run']['split']=='development' for k,v in m['run']['components'].items()}
    chart=''
    for key,metric in current.items():
        prior=before.get(key)
        label=f"{prior['passed']}/10 → {metric['passed']}/10" if prior else f"New component · {metric['passed']}/10; prior unavailable"
        chart+='<div class="bar-row"><div><strong>'+esc(key.replace('_',' '))+'</strong><span>'+esc(label)+'</span></div><div class="track">'+(
            '<i class="before" style="width:'+str(prior['passed']*10)+'%"></i>' if prior else '')+'<i class="after" style="width:'+str(metric['passed']*10)+'%"></i></div></div>'
    section('components','Frozen software components', '<p>Each row has ten explicit deterministic criteria. Bars describe these software cases only. Amber shows the retained pre-correction result; blue shows current results. These are not agent intelligence scores.</p><div class="bars">'+chart+'</div><p>Development: 80 cases across 8 components. Reserved: 10 same-author security variations, separately measured and not independently blinded.</p>')
    section('agents','Agent-by-agent audit', table(['Agent','Actual responsibility','Previous answer quality','Current limitations / model suitability'],[[a['agent'],a['responsibility'],a['previous_answer_quality'],a['model_suitability']] for a in data['metadata']['agents']['agents']])+
        '<details><summary>Inspect prompt, context, output and resource contracts</summary><pre>'+esc(json.dumps(data['metadata']['agents'],indent=2))+'</pre></details>')
    section('tools','Tool knowledge and compatibility', '<p>'+str(len(data['metadata']['tool-inventory']['tools']))+' tools inventoried; host installation, integrated code, tests, historical verified jobs and saved advertisements are separate. Runtime versions remain unknown unless actually observed. License and resource gaps stay explicit.</p>'+
        table(['Tool','Reference version / host metadata','Integration','Historical operational result','Meaning / limitation'],[[t['tool'],str(t['reference_version'])+' / '+str(t['host_package_metadata'] or t['host_python_distribution_version'] or 'not detected'),t['integration_status'],'Verified within recorded scope' if t['historical_operationally_verified'] else 'Not verified',t['interpretation']] for t in data['metadata']['tool-inventory']['tools']])+
        '<details><summary>Inspect licenses, operating systems, dependencies, official references and resource limits</summary><pre>'+esc(json.dumps(data['metadata']['tool-inventory'],indent=2))+'</pre></details>')
    section('coding','Coding and test engineering', '<p>The new authenticated proposal route returns Python, tests and README artifacts for review. It has no execute, deployment, shell or package-install route. The fixed trusted validator parses candidate code without executing it.</p><p>Static acceptance10/10; isolated validator and authorization/budget/cancellation controls are tested. Handcrafted fixtures are not model-generated code. Passing lint does not prove semantic correctness or useful test coverage. Independent human code review and fresh generation quality remain blocked.</p>')
    burp=data['metadata']['burp']
    native_passive = next((row for row in data['metrics'] if row['case_id'] == 'community-passive-native'), None)
    native_summary = ('<p>The isolated Community artifact passed '
                      + esc(native_passive['actual']['conditions']) + ' passive checks in '
                      + esc(f"{native_passive['elapsed_ms'] / 1000:.3f}")
                      + ' seconds with zero HTTP dispatches. ' + esc(native_passive['actual']['version'])
                      + ' was reported by the native version API.</p>') if native_passive else ''
    section('burp','Burp Suite integration coverage',table(['Feature','Actual coverage','Behavior','Verification scope'],[[r['feature'],r['coverage'],r['actual_behavior'],r['verification']] for r in burp['coverage']])+
        '<p>Desktop compatibility is blocked because the launcher references an absent JAR. Pinned Montoya compilation and controlled-sender Java checks passed.</p>'+native_summary)
    section('analysis','Technical analysis and false positives','<p>Corrected evidence handling distinguishes Bearer presentation from authenticated success, HTTP protocol from product version, filtered/UDP observations from open TCP, scanner alerts from exploitability, and CORS wildcard/credentials from a proven browser leak. Public200, reflection, decoded JWTs and repeated business acknowledgements require context and controls.</p><p>Web Intel can review owned recorded Burp evidence with zero model calls. Every rule explains missing information, alternatives and defensive remediation. The rules preserve human finding verification.</p>')
    section('collaboration','Knowledge and collaboration quality','<p>Attributed handoffs preserve recent analyst IDs and source references. Deterministic checks identify duplicate information, shared evidence, unsupported assertions and contradictions. Ten synthetic checks pass after the retained9/10deduplication failure was corrected.</p><p>Actual specialist complementarity remains unavailable: the historical correlation call was denied by accounting. No model conversation or peer-review expertise is fabricated.</p>')
    model=data['metadata']['model-reconciliation']
    section('models','Model comparison, performance and costs',table(['Model','Actual attempts / usable / timeouts','Mean / maximum wall seconds','Known tokens / unknown usage calls','Artifact bytes / measured peak RSS'],[[m['model'],f"{m['actual_attempts']} / {m['usable']} / {m['timeouts']}",f"{m['wall_mean_seconds']:.3f} / {m['wall_max_seconds']:.3f}",f"{m['reported_tokens_known']} / {m['unknown_token_usage_calls']}",str(m['artifact_bytes'])+' / unavailable'] for m in model['models']])+
        '<p>Only one exact-input pair exists. No suitable model winner is established; historical samples are heterogeneous. P95, per-agent CPU/RSS and isolated causal timeout phases are unavailable. New diagnostics separately retain provider-reported load/prompt/generation phases without increasing deadlines or budgets.</p><p>Program inference/spend: 0 calls / $0 new provider spend. Accounting at entry: 15 calls, 196074 reserved tokens; 3926 remaining is below the 8192 minimum reservation. Original 20 calls / 200000 tokens / $1 limits remain unchanged. Local electricity and hardware costs are unmeasured.</p>')
    section('defects','Confirmed defects and corrections',table(['Cause category','Retained evidence','Correction / investigation','Disposition'],[[c['category'],c['evidence'],c['correction_or_investigation'],c['disposition']] for c in data['metadata']['causes']['causes']]))
    section('requirements','Requirement acceptance matrix',table(['Requirement','Scope','Status','Immutable acceptance criterion','Evidence / limitations'],[[r['id'],r['scope'],r['status'],r['acceptance_criterion'],r['evidence_summary']] for r in data['requirements']]))
    blocked=[r for r in data['requirements'] if r['status']=='BLOCKED']
    section('limitations','Missing capabilities and independent validation','<p>Independent human review: BLOCKED. Neither automated recomputation nor engineering-agent judgment establishes senior cybersecurity equivalence.</p>'+table(['Unmet requirement','External prerequisite'],[[r['id'],r['evidence_summary']] for r in blocked])+table(['Preserved operational gate','Status','Limitation'],[[r['requirement'],r['status'],r['limitation']] for r in data['preserved_operational_gates']])+'<p>Four-hour synthetic evidence remains accepted. The same eight-hour obligation is deferred by owner. Successful extended laboratory operation and8hours/day,5days/week readiness remain unproven. New code is local, not deployed.</p>')
    section('evidence','Measured answers and reproducibility','<p>Filter the retained measured rows below. JSON and CSV carry expected and actual answers, criteria, sample size, method, evidence hashes, limitations and confidence. Null model grades remain unavailable.</p><label>Find a case or component <input id="case-filter" type="search" placeholder="e.g. bearer, parser, collaboration"></label><p id="case-count"></p>'+table(['Cohort / component','Case','Expected','Actual','Passed / sample','Evidence'],[[r['cohort']+' / '+r['component'],r['case_id'],json.dumps(r['expected'],ensure_ascii=False),json.dumps(r['actual'],ensure_ascii=False),str(r['passed'])+' / '+str(r['sample_size']),r['evidence']] for r in data['metrics']])+
        '<p>Hashes identify the recorded source and evidence. The reserved cases link to their measured source snapshot.</p>'+
        table(['Test scope','Tests passed','Seconds','Retained log'], [
            [row['scope'], row['tests'], row['elapsed_seconds'], row['path']] for row in data['test_cohorts']
        ]))
    nav=''.join('<a href="#'+i+'">'+esc(t)+'</a>' for i,t,_ in sections)
    embedded=json.dumps(data,separators=(',',':'),ensure_ascii=True,allow_nan=False).replace('<','\\u003c')
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="audit-data-sha256" content="'+data_sha256+'"><title>ARIA · Cybersecurity competence audit</title><style>'+STYLE+'</style></head><body><aside><div class="brand">ARIA<span>COMPETENCE AUDIT</span></div><nav>'+nav+'</nav></aside><main><header><p class="eyebrow">Cybersecurity competence · Phases15–23</p><h1>Measured progress.<br>Explicit limits.</h1><p>Evidence interpretation, specialist quality and software engineering. Frozen cases and retained failures; no fabricated expertise.</p><div class="badges"><span>Fresh model quality: BLOCKED</span><span>Independent senior assessment: BLOCKED</span><span>8/5 readiness: UNPROVEN</span></div><p class="downloads"><a href="'+STEM+'-results.json">Structured JSON</a><a href="'+STEM+'-metrics.csv">Measured CSV</a></p><p class="provenance">'+esc(data['generated_at'])+' · HEAD '+esc(data['head'][:12])+' · Local dirty source; no deployment</p></header>'+''.join(s for _,_,s in sections)+'<footer>No global readiness percentage. Ten-point software benchmarks do not certify real-world expertise.</footer></main><script type="application/json" id="audit-data">'+embedded+'</script><script>const input=document.getElementById("case-filter");const rows=[...document.querySelectorAll("#evidence tbody tr")];function filter(){let n=0;for(const row of rows){row.hidden=!row.textContent.toLowerCase().includes(input.value.toLowerCase());if(!row.hidden)n++;}document.getElementById("case-count").textContent=n+" of "+rows.length+" measured rows";}input.addEventListener("input",filter);filter();</script></body></html>'


STYLE='''*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#eef2f5;color:#182936;font:15px/1.6 system-ui,sans-serif}aside{position:fixed;inset:0 auto 0 0;width:245px;background:#112b35;color:#e3f0f3;padding:28px 22px;overflow:auto}.brand{font-size:32px;letter-spacing:5px;font-weight:800}.brand span{display:block;font-size:10px;letter-spacing:2px;color:#88b7c4}nav{display:grid;gap:9px;margin-top:28px}nav a{font-size:12px;color:#c6dde4;text-decoration:none}nav a:hover{color:white}main{margin-left:245px;max-width:1600px;padding:40px}header{background:#fff;border-top:6px solid #167c96;padding:38px;border-radius:6px;box-shadow:0 7px 24px #162a3510}h1{font-size:clamp(32px,5vw,58px);line-height:1.07;letter-spacing:-2px;margin:16px 0 25px}h2{margin:0 0 18px;font-size:24px;line-height:1.25}.eyebrow{letter-spacing:2px;text-transform:uppercase;font-size:11px;font-weight:700;color:#167c96}.badges{display:flex;gap:9px;flex-wrap:wrap}.badges span{font-size:11px;padding:7px 10px;border-radius:4px;background:#fff0dc;color:#825310;font-weight:700}.downloads{display:flex;gap:15px}.downloads a{color:#066a82;font-weight:700}.provenance{font-size:11px;color:#607380;overflow-wrap:anywhere}section{scroll-margin-top:20px;margin-top:26px;padding:28px;background:#fff;border:1px solid #dbe4e9;border-radius:6px;min-width:0}.callout{padding:18px;border-left:4px solid #b27818;background:#fff7e9}.table-scroll{max-width:100%;overflow:auto;border:1px solid #e1e8ed;border-radius:4px}table{border-collapse:collapse;width:100%;font-size:12px}th{background:#eef4f6;text-align:left;font-size:10px;letter-spacing:.6px;text-transform:uppercase;color:#4c6773;position:sticky;top:0}th,td{padding:13px;vertical-align:top;border-bottom:1px solid #e5ebef;min-width:110px;max-width:450px;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}td:first-child{font-weight:650;color:#145c70}tbody tr:nth-child(even){background:#fafcfd}.bars{display:grid;gap:20px}.bar-row>div:first-child{display:flex;justify-content:space-between;gap:12px;font-size:13px}.bar-row span{color:#576c78}.track{height:18px;background:#edf3f5;margin-top:7px;position:relative;border-radius:3px;overflow:hidden}.track i{display:block;position:absolute;left:0;height:7px}.before{background:#bd862d;top:1px}.after{background:#1989a3;bottom:1px}details{margin-top:20px}summary{cursor:pointer;color:#166b80}pre{background:#f1f5f7;padding:18px;max-height:500px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:11px}input{margin-top:8px;display:block;width:min(100%,550px);padding:12px;border:1px solid #a7bcc6;border-radius:4px;font:inherit}#evidence table{min-width:900px}#case-count{font-size:12px;color:#58717e}footer{padding:25px;color:#536c78;font-size:12px}@media(max-width:950px){aside{position:static;width:auto;padding:18px}nav{display:flex;overflow:auto;gap:20px;margin-top:15px}nav a{white-space:nowrap}.brand{font-size:24px}main{margin-left:0;padding:18px}header{padding:25px}section{padding:18px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}'''


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--follow-up',type=Path,help='Use the reconciled cycle02 and cycle03 measurements')
    parser.add_argument('--output',type=Path,default=Path('reports'))
    args=parser.parse_args()
    data=collect(args.evidence, args.follow_up)
    args.output.mkdir(parents=True,exist_ok=True)
    content=json.dumps(data,indent=2,ensure_ascii=True,allow_nan=False)+'\n'
    json_path=args.output/(STEM+'-results.json')
    csv_path=args.output/(STEM+'-metrics.csv')
    html_path=args.output/(STEM+'-audit.html')
    existing=[p for p in (json_path,csv_path,html_path) if p.exists()]
    if existing:
        archive=args.evidence/'derived-versions'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')
        archive.mkdir(parents=True)
        for path in existing:(archive/path.name).write_bytes(path.read_bytes())
    json_path.write_text(content)
    csv_path.write_text(csv_text(data))
    html_path.write_text(render(data,sha(json_path)))
    index={str(p.name):sha(p) for p in (json_path,csv_path,html_path)}
    (args.output/(STEM+'-artifacts.json')).write_text(json.dumps(index,indent=2)+'\n')
    print(json.dumps({'requirements':len(data['requirements']),'metric_rows':len(data['metrics']),
                      'measurements':len(data['measurements']),'source_hashes':len(data['source_sha256']),
                      'html':str(html_path),'sha256':index[html_path.name]}))


if __name__=='__main__':
    main()
