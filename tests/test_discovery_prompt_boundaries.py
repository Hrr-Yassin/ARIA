"""Actual specialist entry points must preserve narrow discovery requests.

Provider responses are controlled fixtures, never intelligence measurements.
"""
from contextlib import ExitStack
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agents.recon_agent import ReconAgent
from agents.scan_agent import ScanAgent
from tests.support import OfflineCase
from tests.test_specialist_fixtures import grounded_context, grounded_prompt


class DiscoveryPromptBoundaryTests(OfflineCase):
    async def run_agent(self, agent_type, content, *, skill_level="intermediate"):
        agent = agent_type()
        session = {"user_id": "owner", "target": "192.0.2.1",
                   "scope": {"targets": ["192.0.2.1"], "ports": [80, 22]}}
        with ExitStack() as stack:
            stack.enter_context(patch("api.auth.current_identity", AsyncMock(
                return_value=SimpleNamespace(user_id="owner"))))
            stack.enter_context(patch("api.session_access.get_accessible_session",
                                      AsyncMock(return_value=session)))
            stack.enter_context(patch("memory.session_manager.session_manager.get_chat_logs",
                                      AsyncMock(return_value=[])))
            stack.enter_context(patch("memory.worker_jobs.worker_jobs.client.capabilities",
                                      AsyncMock(return_value={"tools": ["curl", "nmap"]})))
            stack.enter_context(patch.object(agent, "get_context", return_value=""))
            provider = stack.enter_context(patch("llm.pool_manager.pool_manager.query",
                AsyncMock(return_value={"success": True, "content": content})))
            result = await agent.process("session", "owner", {
                "target": "192.0.2.1", "requested_ports": [80],
                "original_objective": "HTTP header observation only on TCP80"}, skill_level)
            return result, provider.await_args

    async def test_incomplete_successful_response_cannot_create_a_fallback_plan(self):
        for agent_type in (ReconAgent, ScanAgent):
            for content in ("{}", '{"suggested_response":"Run the usual discovery"}'):
                with self.subTest(agent=agent_type.__name__, content=content):
                    result, _ = await self.run_agent(agent_type, content)
                    self.assertEqual(result["commands"], [])
                    self.assertEqual(result["agent_result"]["status"], "blocked")
                    self.assertIn("malformed_model_output", [r["code"] for r in result["rejections"]])
                    self.assertIn("structured response", result["suggested_reply"])

    async def test_empty_plan_remains_analysis_without_inventing_commands(self):
        for agent_type in (ReconAgent, ScanAgent):
            with self.subTest(agent=agent_type.__name__):
                result, _ = await self.run_agent(agent_type, json.dumps({
                    "commands": [], "suggested_response": "Existing evidence suffices; no action needed."}))
                self.assertEqual(result["commands"], [])
                self.assertEqual(result["agent_result"]["status"], "analysis")
                self.assertIn("no action needed", result["suggested_reply"])

    async def test_grounded_task_and_skill_guidance_do_not_require_unavailable_discovery(self):
        for agent_type in (ReconAgent, ScanAgent):
            for skill_level in ("beginner", "intermediate", "expert"):
                with self.subTest(agent=agent_type.__name__, skill_level=skill_level):
                    _, call = await self.run_agent(agent_type, '{"commands":[]}', skill_level=skill_level)
                    _, context, task = grounded_context(grounded_prompt(call))
                    self.assertEqual(context["objective"], "HTTP header observation only on TCP80")
                    self.assertEqual(context["worker_tools"], ["curl", "nmap"])
                    self.assertIn("server objective", task)
                    self.assertNotIn("Passive recon commands", task)
                    self.assertNotIn("What specific scripts", task)
                    system = call.args[2]
                    self.assertNotIn("Start passive (whois, DNS)", system)
                    self.assertNotIn("Tools you drive:", system)
                    self.assertNotIn("--script=vuln", system)
                    self.assertNotIn("Suggest attack chains", system)

    async def test_valid_header_plan_still_requires_confirmation(self):
        content = json.dumps({"commands": [{"tool": "curl",
            "command": "curl -I -s --max-time 10 http://192.0.2.1:80/"}],
            "suggested_response": "Review the bounded header observation."})
        for agent_type in (ReconAgent, ScanAgent):
            with self.subTest(agent=agent_type.__name__):
                result, _ = await self.run_agent(agent_type, content)
                self.assertEqual(len(result["commands"]), 1)
                self.assertTrue(result["needs_confirmation"])
                self.assertEqual(result["agent_result"]["status"], "proposed")
