"""Compare retained equivalent arms without inference or target execution."""
import argparse
import json
from pathlib import Path
import re


def compare(folder: Path) -> dict:
    reports = {arm:json.loads((folder/(arm+'.json')).read_text()) for arm in ('qwen','deepseek')}
    qwen, deepseek = reports['qwen'], reports['deepseek']
    for key in ('scenario_digest','output_cap','batch_size'):
        if qwen[key] != deepseek[key]:
            raise ValueError('Non-equivalent benchmark inputs: '+key)
    schemas = [[b['schema_digest'] for b in reports[arm]['batches']] for arm in reports]
    if schemas[0] != schemas[1]:
        raise ValueError('Non-equivalent batch schemas')
    result = {'equivalent_inputs':True,'scenario_digest':qwen['scenario_digest'], 'arms':{}}
    for arm, report in reports.items():
        result['arms'][arm] = {key:report.get(key) for key in
            ('status','model','model_calls','tokens','unknown_usage_calls','cost_usd','model_seconds','metrics')}
    result['limitations'] = [
        'One small run per model; not a statistically reliable quality or speed ranking.',
        'Transparent synthetic control patterns measure triage and verification-template selection, not autonomous probing.',
        'Local cost is provider billing only; hardware, energy and operator time are excluded.',
        'A nonempty alternative field measures syntax, not a genuine alternative explanation.',
        'Provider tokenization and reasoning differ; equal output caps do not imply equal work.',
        'Local per-call deadline is 180 seconds; hosted deadline is 90 seconds. Both completed all revised batches.',
    ]
    if qwen['status'] == deepseek['status'] == 'passed':
        result['observed_wall_time_ratio'] = round(qwen['model_seconds']/deepseek['model_seconds'],3)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', default='batched-v2')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,60}', args.run_id):
        raise ValueError('Invalid run identity')
    folder = Path('.local-lab/research-benchmark')/args.run_id
    result = compare(folder)
    (folder/'comparison.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
