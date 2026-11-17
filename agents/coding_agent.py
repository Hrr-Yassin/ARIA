"""Review-only Python/test engineering artifacts; no target or shell executor."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from agents.base_agent import BaseAgent
from llm.base_llm import response_schema


class CodeArtifact(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=80)
    content: str = Field(min_length=1, max_length=32768)

    @field_validator('name')
    @classmethod
    def simple_filename(cls, value: str) -> str:
        if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]*\.py|README\.md', value):
            raise ValueError('Only simple Python artifact names and README.md are supported')
        return value


class CodingSubmission(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    summary: str = Field(min_length=1, max_length=2000)
    files: list[CodeArtifact] = Field(min_length=1, max_length=8)
    dependencies: list[str] = Field(max_length=0)
    evidence_references: list[str] = Field(max_length=20)
    validation_plan: list[str] = Field(min_length=1, max_length=10)
    limitations: list[str] = Field(min_length=1, max_length=10)
    review_status: Literal['requires_human_review']

    @model_validator(mode='after')
    def bounded_unique_artifacts(self):
        if len({f.name for f in self.files}) != len(self.files):
            raise ValueError('Artifact names must be unique')
        raw = json.dumps([f.model_dump() for f in self.files]).encode()
        if len(raw) > 131072:
            raise ValueError('Artifact payload exceeds bound')
        if any(not s or len(s) > 2000 for s in self.validation_plan + self.limitations):
            raise ValueError('Review instructions exceed bounds')
        return self


async def static_review(submission: CodingSubmission) -> dict:
    """Run a fixed trusted parser with no inherited credentials or candidate imports."""
    validator = Path(__file__).resolve().parents[1] / 'security' / 'code_review.py'
    with TemporaryDirectory(prefix='aria-static-review-') as directory:
        process = await asyncio.create_subprocess_exec(
            sys.executable, '-I', str(validator), cwd=directory,
            env={'LC_ALL': 'C', 'PYTHONIOENCODING': 'utf-8'},
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            async with asyncio.timeout(3):
                output, _ = await process.communicate(json.dumps([f.model_dump() for f in submission.files]).encode())
            if process.returncode or len(output) > 16384:
                raise ValueError('Static review failed')
            return json.loads(output)
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        except (TimeoutError, ValueError):
            if process.returncode is None:
                process.kill()
            await process.wait()
            return {'status': 'unavailable', 'issues': ['Bounded static reviewer failed or timed out'],
                    'candidate_code_executed': False, 'tests_executed': False, 'independent_review': False}


class CodingAgent(BaseAgent):
    agent_name = 'coding'
    agent_role = 'Coding and Test Engineering — Review-only Python Artifacts'

    def get_system_prompt(self, skill_level: str = 'intermediate') -> str:
        return ('Produce reviewable Python3.11 source, deterministic unittest tests and README.md as structured data. '
                'Support defensive parsing, validation, synthetic fixtures, regression tests and reports. '
                'No shell, network, file I/O, credentials, installers, deployment or target scripts. '
                'Use only reviewed standard-library imports and local artifacts. No third-party dependencies. '
                'Include public function annotations/docstrings, actual test assertions, failure/edge cases, '
                'evidence references, reproducible validation instructions and remaining limitations. '
                'Never claim tests ran, code is independently reviewed or execution is authorized. '
                'Return the exact schema with review_status requires_human_review. '
                + self.get_skill_instruction(skill_level))

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = 'intermediate') -> dict:
        objective = input_data.get('user_input') or input_data.get('objective') or ''
        supplied = input_data.get('supplied_artifacts', [])
        prompt = json.dumps({'objective': objective, 'supplied_artifacts': supplied,
                             'execution_authority': 'none; artifacts are review-only text'})
        if len(prompt.encode()) > 65536:
            return {'commands': [], 'suggested_reply': 'Coding input exceeds the review profile bound.',
                    'rejections': [{'code': 'coding_input_too_large', 'detail': 'Supply at most64KiB of explicit text'}]}
        token = response_schema.set(CodingSubmission.model_json_schema())
        try:
            result = await self.query_llm_smart(user_id, prompt, self.get_system_prompt(skill_level),
                                                task_type='code_generation')
        finally:
            response_schema.reset(token)
        if not result.get('success'):
            return {'commands': [], 'suggested_reply': 'Code generation is blocked by model availability or accounting.'}
        try:
            submission = CodingSubmission.model_validate_json(result.get('content', ''))
        except (ValidationError, TypeError):
            self._validated_model_object(None)
            return {'commands': [], 'suggested_reply': 'Invalid coding artifact contract; no files were written or executed.'}
        # Model citations never acquire provenance outside the server-selected catalog.
        from agents.base_agent import _agent_context
        owned = {e['id'] for e in (_agent_context.get() or {}).get('evidence', [])}
        if not set(submission.evidence_references) <= owned:
            return {'commands': [], 'suggested_reply': 'Coding submission cites unavailable evidence.',
                    'rejections': [{'code': 'unknown_evidence_reference', 'detail': 'Citations must reference owned supplied evidence'}]}
        review = await static_review(submission)
        return {'type': 'code_review', 'commands': [], 'submission': submission.model_dump(),
                'static_review': review, 'execution_status': 'not_executed',
                'suggested_reply': submission.summary + ' Human review and behavioral validation remain required.',
                'needs_confirmation': False}


coding_agent = CodingAgent()
