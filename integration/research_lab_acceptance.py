"""Exercise all lab hypotheses, including secure counterexamples; no inference.

This is verifier acceptance, distinct from model discovery effectiveness.
"""
import asyncio
import json
from pathlib import Path

from evaluation.research_lab import cases, observe, benchmark, template


async def main() -> None:
    rows = cases()
    observations = {case['id']:await observe(case) for case in rows}
    report = await benchmark([{'case_id':c['id'], 'template':template(c['class'])} for c in rows], observations)
    report.update(kind='independent_verifier_acceptance', model_calls=0, external_target_requests=0,
        rejected_secure_hypotheses=sum(not c['confirmed'] and not c['expected_vulnerable'] for c in report['cases']))
    assert report['metrics']['confirmed_vulnerabilities'] == 9
    assert report['metrics']['false_positive_findings'] == 0
    assert report['rejected_secure_hypotheses'] == 9
    output = Path('.local-lab/research-benchmark')
    output.mkdir(parents=True, exist_ok=True)
    (output/'verifier-acceptance.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({k:v for k,v in report.items() if k != 'cases'}, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
