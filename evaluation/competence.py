"""Reproducible offline component measurements; never an LLM intelligence score."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import time
from unittest.mock import patch

FIXTURES = Path(__file__).parent / 'fixtures' / 'competence'
COMPONENT_SOURCES = {
    'http_auth': ('agents/web_intel_agent.py',),
    'http_technology': ('agents/web_intel_agent.py',),
    'tool_profile': ('worker/policy.py','orchestrator/execution_policy.py'),
    'burp_evidence': ('memory/burp_community.py','security/http_messages.py','security/redaction.py'),
    'parser_interpretation': ('memory/parsers.py','memory/attack_knowledge_base.py'),
    'coding_static': ('agents/coding_agent.py','security/code_review.py'),
    'security_analysis': ('security/evidence_analysis.py',),
    'collaboration_review': ('memory/analysis_review.py',),
}


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def load_cases(path: Path) -> dict:
    """Check the frozen file bytes before evaluating any implementation."""
    lock = json.loads((FIXTURES / 'manifest.json').read_text())
    freeze_path=Path('docs/competence/benchmark-freeze.json')
    if freeze_path.exists():
        freeze=json.loads(freeze_path.read_text())
        if hashlib.sha256((FIXTURES/'manifest.json').read_bytes()).hexdigest()!=freeze['case_manifest_sha256']:
            raise ValueError('Frozen case manifest changed')
    if hashlib.sha256(path.read_bytes()).hexdigest() != lock[path.name]:
        raise ValueError('Frozen fixture digest mismatch')
    packet = json.loads(path.read_text())
    cases = packet['cases']
    if not cases or len({c['id'] for c in cases}) != len(cases):
        raise ValueError('Cases must have unique identifiers')
    if any(c['component'] not in COMPONENT_SOURCES for c in cases):
        raise ValueError('Unknown component in frozen packet')
    return packet


def evaluate_case(case: dict) -> object:
    """Invoke production helpers on controlled data without a model or network."""
    component, value = case['component'], case['input']
    if component == 'collaboration_review':
        from memory.analysis_review import review_handoff
        output = review_handoff(value['claims'],value['evidence'])
        return sorted({issue['code'] for issue in output['issues']})
    if component == 'security_analysis':
        from security.evidence_analysis import review
        output = review(value)
        return {'rules':output['rule_ids'], 'attributed':output['evidence_references']==[value['evidence_id']],
                'confirmed':bool(output['confirmed_vulnerabilities']), 'limits':bool(output['missing_information']),
                'alternatives':bool(output['alternative_explanations']), 'remediation':bool(output['remediation'])}
    if component == 'parser_interpretation':
        from memory.attack_knowledge_base import AttackKnowledgeBase
        from memory.parsers import dispatch_parser
        kb = AttackKnowledgeBase()
        with patch('memory.parsers.attack_kb', kb):
            result = dispatch_parser('competence-fixture', value['tool'], value['tool'], value['output'], '192.0.2.1')
        host = kb.get_host('competence-fixture','192.0.2.1')
        return {'tcp_ports': [r['port'] for r in result.ports_added],
                'exploitable_candidates': any(v.get('exploitable') for v in host.vulnerabilities) if host else False}
    if component == 'burp_evidence':
        import base64
        from memory.burp_community import inspect_pair
        try:
            pair = inspect_pair('http://192.0.2.1/',
                                base64.b64encode(value['request'].encode('iso-8859-1')).decode(),
                                base64.b64encode(value['response'].encode('iso-8859-1')).decode(),
                                {'targets':['192.0.2.1'],'ports':[80]})
        except ValueError:
            return False
        return not value.get('must_redact') or value['must_redact'] not in json.dumps(pair['summary'])
    if component == 'coding_static':
        from agents.coding_agent import CodingSubmission
        from security.code_review import review_files
        try:
            submission = CodingSubmission.model_validate(value)
        except ValueError:
            return False
        review = review_files([f.model_dump() for f in submission.files])
        return review['status'] == 'static_checks_passed'
    if component == 'tool_profile':
        from worker.policy import validate_worker_command
        try:
            validate_worker_command(value['command'], {'targets': ['192.0.2.1'], 'ports': [80]})
            return True
        except ValueError:
            return False
    if component in {'http_auth', 'http_technology'}:
        from agents.web_intel_agent import WebIntelAgent
        agent = WebIntelAgent()
        if component == 'http_auth':
            return agent._detect_auth(value['headers'], value['cookies'])
        return sorted(agent._detect_tech(value['headers'], value['body']))
    raise ValueError('Unknown measured component')


def measure(packet: dict) -> dict:
    rows = []
    for case in packet['cases']:
        start = time.perf_counter()
        try:
            actual = evaluate_case(case)
            error = None
        except Exception as exc:
            actual, error = None, type(exc).__name__
        rows.append({**case, 'actual': actual, 'error': error,
                     'passed': error is None and digest(actual) == digest(case['expected']),
                     'elapsed_ms': (time.perf_counter() - start) * 1000,
                     'sample_size': 1,
                     'method': 'exact deterministic component result on frozen synthetic input',
                     'confidence': 'high for reproduction; no generalization to model expertise'})
    components = {}
    for row in rows:
        group = components.setdefault(row['component'], {'passed': 0, 'assessed': 0})
        group['passed'] += int(row['passed'])
        group['assessed'] += 1
    source_paths={p for case in packet['cases'] for p in COMPONENT_SOURCES[case['component']]}
    return {'schema': 'aria.competence.measurement.v1',
            'kind': 'deterministic_software_component', 'split': packet['split'],
            'protocol_sha256': digest(packet), 'created_at': datetime.now(timezone.utc).isoformat(),
            'rows': rows, 'components': components, 'model_calls': 0, 'target_actions': 0,
            'independent_human_assessment': False, 'senior_equivalence': False,
            'source_sha256':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(source_paths)},
            'limitations': packet['limitations']}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=FIXTURES / 'http-development-v1.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # Reuse the repository's ephemeral offline configuration. No production keys.
    import tests  # noqa: F401
    with (patch.object(socket.socket, 'connect', side_effect=AssertionError('Offline benchmark')),
          patch.object(socket, 'getaddrinfo', side_effect=AssertionError('Offline benchmark'))):
        result = measure(load_cases(args.cases))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as handle:
        handle.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'components': result['components'],
                      'model_calls': 0, 'target_actions': 0}))


if __name__ == '__main__':
    main()
