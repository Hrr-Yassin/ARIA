"""Reconcile retained actual-model cohorts without making a provider request."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics


def reconcile(root: Path) -> dict:
    rows=[]
    sources={}
    artifacts={}
    for name in ('local-qwen4b-v1','local-qwen08b-v1','local-qwen08b-remaining-v1'):
        path=root/name/'run.json'
        run=json.loads(path.read_text())
        if run.get('scripted_responses') is not False or run.get('accounting_reconciled') is not True:
            raise ValueError('An actual accounted model cohort is required')
        sources[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        artifacts[run['model']]=run['model_artifact']
        for case in run['cases']:
            for record in case['provider_records']:
                rows.append({'cohort':name,'case_id':case['case_id'],
                             'model':record.get('model'), 'physical_attempt':bool(record.get('attempt_id')),
                             'attempt_id':record.get('attempt_id'),
                             'success':record['success'], 'error':record.get('error'),
                             'prompt_system_sha256':record['prompt_system_sha256'],
                             'context_utf8_bytes':len((record['prompt']+record['system']).encode()),
                             'public_structured_object':isinstance(record.get('public_json'),dict),
                             'reported_tokens':record.get('tokens_used'),
                             'cost_microusd':record.get('cost_microusd'),
                             'wall_seconds':case['wall_seconds'],'timings':record.get('timings'),
                             'response_sha256':record['provider_content_sha256'],
                             'cpu_seconds':None,'peak_rss_bytes':None,'gpu_memory_bytes':None})
    physical=[r for r in rows if r['physical_attempt']]
    if len({r['attempt_id'] for r in physical})!=len(physical):
        raise ValueError('Duplicate physical model receipt')
    models=[]
    for model in artifacts:
        cohort=[r for r in physical if r['model']==model]
        successful=[r for r in cohort if r['success']]
        models.append({'model':model,'actual_attempts':len(cohort),'usable':len(successful),
                       'timeouts':sum(r['error']=='provider_timeout' for r in cohort),
                       'structured_objects':sum(r['public_structured_object'] for r in cohort),
                       'reported_tokens_known':sum(r['reported_tokens'] or 0 for r in cohort),
                       'unknown_token_usage_calls':sum(r['reported_tokens'] is None for r in cohort),
                       'new_paid_cost_microusd':sum(r['cost_microusd'] or 0 for r in cohort),
                       'wall_mean_seconds':statistics.mean(r['wall_seconds'] for r in cohort),
                       'wall_median_seconds':statistics.median(r['wall_seconds'] for r in cohort),
                       'wall_max_seconds':max(r['wall_seconds'] for r in cohort),
                       'p95_seconds':None,'quality_score':None,
                       'artifact_bytes':artifacts[model]['size'],'artifact_digest':artifacts[model]['digest'],
                       'measured_peak_rss_bytes':None,'measured_cpu_seconds':None,
                       'suitability':'Not established by this small heterogeneous exploratory cohort'})
    matching=[]
    for key in {r['prompt_system_sha256'] for r in physical}:
        group=[r for r in physical if r['prompt_system_sha256']==key]
        if len({r['model'] for r in group})>1:
            matching.append({'prompt_system_sha256':key,'case_id':group[0]['case_id'],
                             'models':[r['model'] for r in group],
                             'outcomes':[r['error'] or 'usable but raw technical decisions need grading' for r in group]})
    return {'schema':'aria.model-competence.reconciliation.v1',
            'created_at':datetime.now(timezone.utc).isoformat(),'sources':sources,'rows':rows,
            'models':models,'identical_input_pairs':matching,
            'physical_attempts':len(physical),'usable_responses':sum(r['success'] for r in physical),
            'timeouts':sum(r['error']=='provider_timeout' for r in physical),
            'denied_before_provider':sum(not r['physical_attempt'] for r in rows),
            'new_calls_in_this_program':0, 'model_winner':None,
            'causal_findings':[
                'Both retained timeouts reached the non-schema60s client deadline; provider-discovery was about4ms, so discovery does not explain the full wait.',
                'CPU-only loading was historically reported, but retained receipts lack load/prompt/generation breakdown and per-call RSS/CPU; the exact bottleneck is not isolated.',
                'The0.8B planner timeout had5733UTF8prompt/system bytes and a1024token output ceiling. No controlled load/output/timeout ablation exists.',
                'Only the recon case has identical inputs across both models:4Btimed out;0.8Bresponded with technically wrong/out-of-profile suggestions. It establishes no suitable winner.',
                'Fresh native responses now retain separately named provider-reported phase timings. No deadline, retry, output reservation, accounting limit or model selection was changed.'],
            'limitations':['Historical exploratory configurations are not a balanced model comparison.',
                           'Structured output and policy rejection are separate from technical intelligence.',
                           'Missing timeout usage is not zero; model file size is not measured RAM.',
                           'No new inference is admissible under3926remaining tokens versus8192minimum reservation.']}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=reconcile(args.source)
    with args.output.open('x') as handle: handle.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('physical_attempts','usable_responses','timeouts','denied_before_provider','new_calls_in_this_program')}))


if __name__=='__main__':
    main()
