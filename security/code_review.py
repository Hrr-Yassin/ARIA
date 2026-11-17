"""Trusted bounded static reviewer. Candidate Python is parsed, never executed."""
from __future__ import annotations

import ast
import json
import sys

MAX_BYTES = 131072
SAFE_IMPORTS = frozenset({'ast', 'base64', 'collections', 'csv', 'dataclasses', 'datetime',
                          'decimal', 'enum', 'hashlib', 'hmac', 'io', 'ipaddress', 'itertools',
                          'json', 'math', 're', 'statistics', 'string', 'typing', 'unittest'})
UNSAFE_CALLS = frozenset({'eval', 'exec', 'compile', 'open', 'input', '__import__', 'breakpoint',
                          'globals', 'locals', 'getattr', 'setattr', 'delattr', 'vars'})


def review_files(files: list[dict]) -> dict:
    """Apply a deliberately narrow static profile, without imports or code writes."""
    issues = []
    names = {item['name'] for item in files}
    local_modules = {name[:-3] for name in names if name.endswith('.py')}
    if 'README.md' not in names or not any(n.startswith('test_') and n.endswith('.py') for n in names):
        issues.append('Source, test_*.py and README.md are required')
    if not any(n.endswith('.py') and not n.startswith('test_') for n in names):
        issues.append('A source Python artifact is required')
    for item in files:
        name, content = item['name'], item['content']
        if not name.endswith('.py'):
            continue
        try:
            tree = ast.parse(content, filename=name)
            # Check scope and other compiler constraints the AST parser accepts.
            compile(tree, name, 'exec', dont_inherit=True)
        except (SyntaxError, ValueError, RecursionError):
            issues.append(name + ': invalid Python syntax')
            continue
        if not ast.get_docstring(tree):
            issues.append(name + ': module docstring required')
        tests_have_assertions = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                           else [node.module or ''])
                if (isinstance(node, ast.ImportFrom) and node.level) or any(
                        module.split('.')[0] not in SAFE_IMPORTS | local_modules for module in modules):
                    issues.append(name + ': dependency outside reviewed standard-library/local profile')
            if isinstance(node, ast.Attribute) and node.attr.startswith('__'):
                issues.append(name + ': reflective attribute access requires manual specialist review')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in UNSAFE_CALLS:
                issues.append(name + ': dynamic execution or I/O is outside the review profile')
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith('test_'):
                    assertions = [n for n in ast.walk(node) if isinstance(n, ast.Assert) or (
                        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr.startswith('assert'))]
                    tests_have_assertions |= bool(assertions)
                    if not assertions:
                        issues.append(name + ': test method has no assertion')
                elif not node.name.startswith('_'):
                    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                    args += [a for a in (node.args.vararg, node.args.kwarg) if a is not None]
                    if node.returns is None or any(a.annotation is None and a.arg not in {'self', 'cls'} for a in args):
                        issues.append(name + ': public functions require input and return annotations')
                    if not ast.get_docstring(node):
                        issues.append(name + ': public functions require a docstring')
        if name.startswith('test_') and not tests_have_assertions:
            issues.append(name + ': no test assertion found')
    return {'status': 'static_checks_passed' if not issues else 'changes_required',
            'issues': list(dict.fromkeys(issues))[:20], 'candidate_code_executed': False,
            'tests_executed': False, 'independent_review': False,
            'limitations': ['Static profile only; does not prove correctness, secure behavior or meaningful test coverage.',
                           'Deterministic behavioral tests and independent human review remain required.']}


def main() -> None:
    # Limits apply to trusted parsing code, never to execution of the candidate.
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('Input exceeds bound')
        files = json.loads(raw)
        if (not isinstance(files, list) or not 1 <= len(files) <= 8
                or any(not isinstance(f, dict) or set(f) != {'name', 'content'}
                       or not isinstance(f['name'], str) or not isinstance(f['content'], str) for f in files)):
            raise ValueError('Invalid files')
        result = review_files(files)
    except (ValueError, TypeError, KeyError, MemoryError, RecursionError):
        result = {'status': 'unavailable', 'issues': ['Static reviewer refused input'],
                  'candidate_code_executed': False, 'tests_executed': False, 'independent_review': False}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
