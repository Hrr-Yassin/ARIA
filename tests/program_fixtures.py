"""Synthetic policy acceptance fixture; no external program or target."""
from memory.program_policy import ProgramImport, PolicyReview, make_snapshot


def policy_fixture(host='app.example.test', port=443, scheme='https'):
    text = (f'In scope:\n{host} /api\nExclusions:\nadmin.example.test and /api/private and all third parties\n'
            'Eligible issue classes:\nHTTP observations\nAccount requirements:\nUse owned test accounts only\n'
            'Automation restrictions:\nAutomation allowed: 10 requests, 1 concurrent, 1 second between requests\n'
            'Prerequisites:\nParticipation prerequisites must be met\n')
    snapshot = make_snapshot(ProgramImport(name='Synthetic fixture', source_url='https://example.test/policy', text=text), 'engagement', 'owner', 1)
    rules = []
    for category, values in snapshot['rules'].items():
        for value in values:
            rules.append({'category': category, 'quote': value['quote'], 'start': value['start'], 'interpretation': value['quote']})
    indices = {rule['category']: i for i, rule in enumerate(rules)}
    execution = {'assets': [{'host': host, 'path': '/api', 'ports': [port], 'schemes': [scheme], 'source_rule': indices['included_assets']}],
        'exclusions': [{'host': host, 'path': '/api/private', 'ports': [port], 'schemes': [scheme], 'source_rule': indices['exclusions']}],
        'third_party_exclusions': [], 'automation': 'allowed', 'accounts_confirmed': True,
        'prerequisites_confirmed': True, 'permission_confirmed': True, 'eligible_classes': ['http_observation'],
        'max_requests': 10, 'concurrency': 1, 'min_interval_seconds': 1,
        'automation_source_rule': indices['automation_restrictions'], 'budget_source_rule': indices['automation_restrictions'],
        'accounts_source_rule': indices['account_requirements'], 'prerequisites_source_rule': indices['prerequisites'],
        'classes_source_rule': indices['eligible_issue_classes'], 'exclusions_source_rule': indices['exclusions']}
    review = PolicyReview(content_sha256=snapshot['content_sha256'], rules=rules, decision='reviewed', note='Synthetic owner review', execution=execution)
    policy = {'state': 'active', 'snapshot_id': snapshot['id'], 'review_id': 'review',
              'content_sha256': snapshot['content_sha256'], 'rules': review.execution.model_dump()}
    return snapshot, review, {'targets': [host], 'exclusions': [], 'program_policy': policy}
