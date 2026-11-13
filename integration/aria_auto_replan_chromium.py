"""Visible, bounded Chromium check of live ARIA AUTO replanning.

Run only against the isolated lab services and authorized lab target:
ARIA_AUTO_REPLAN_TEST=1 PLAYWRIGHT_BROWSERS_PATH=/tmp/aria-playwright-browsers \
  .local-lab/browser-venv/bin/python integration/aria_auto_replan_chromium.py
"""
import asyncio
import json
import os
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:7000"
TARGET = "192.168.77.20"
PLAN_LIMIT_SECONDS = 55
RUN_LIMIT_SECONDS = 240


async def main():
    if os.environ.get("ARIA_AUTO_REPLAN_TEST") != "1":
        raise SystemExit("Set ARIA_AUTO_REPLAN_TEST=1 for the authorized lab run")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / ".local-lab" / "aria-auto-replan" / stamp
    out.mkdir(parents=True, mode=0o700)
    credentials = dict(
        line.split(": ", 1)
        for line in (ROOT / ".local-lab/login.txt").read_text().splitlines()
    )
    report = {
        "started_utc": stamp,
        "base": BASE,
        "target": TARGET,
        "browser": "Chromium",
        "headless": False,
        "goal": "discovery",
        "max_steps": 3,
        "plan_timeout_seconds": PLAN_LIMIT_SECONDS,
        "events": [],
        "javascript_errors": [],
        "result": "running",
    }

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, slow_mo=100)
        context = await browser.new_context(viewport={"width": 1440, "height": 1000})
        page = await context.new_page()
        page.set_default_timeout(15000)
        page.on("pageerror", lambda exc: report["javascript_errors"].append(str(exc)[:400]))
        session_id = None

        async def api(path, method="GET", data=None):
            response = await context.request.fetch(
                BASE + path,
                method=method,
                headers={"Authorization": "Bearer " + await page.evaluate(
                    "localStorage.getItem('pentestai_token')"
                )},
                data=data,
                timeout=10000,
            )
            body = await response.json()
            if not response.ok:
                raise RuntimeError(f"{method} {path}: HTTP {response.status}: {body}")
            return body

        def safe_lab_command(action):
            """Approve only a tiny, command-bound observation on the test host."""
            command = action.get("command", "")
            try:
                argv = shlex.split(command)
            except ValueError:
                return False
            if action.get("tool") == "nmap" and argv and argv[0] == "nmap":
                allowed_flags = {"-sT", "--open", "-Pn", "-T3", "-p", "--max-retries", "--host-timeout"}
                i = 1
                seen_port = seen_target = False
                while i < len(argv):
                    flag = argv[i]
                    if flag == TARGET:
                        seen_target = True
                        i += 1
                        continue
                    if flag not in allowed_flags:
                        return False
                    if flag in {"-p", "--max-retries", "--host-timeout"}:
                        i += 1
                        if i >= len(argv):
                            return False
                        value = argv[i]
                        if flag == "-p":
                            if value != "80":
                                return False
                            seen_port = True
                        elif flag == "--max-retries" and value not in {"0", "1"}:
                            return False
                        elif flag == "--host-timeout" and value not in {"20s", "30s"}:
                            return False
                    elif flag.startswith("-"):
                        pass
                    else:
                        return False
                    i += 1
                return seen_port and seen_target
            if action.get("tool") == "curl" and argv and argv[0] == "curl":
                # Permit only the planner's read-only HTTP GET on the scoped host root.
                # No options that change method, headers, destination, or redirects.
                urls = [arg for arg in argv[1:] if arg.startswith("http://")]
                return (set(argv[1:]) <= {"-s", "-S", "-m", "5", "http://" + TARGET, "http://" + TARGET + ":80"}
                        and ("-m" not in argv or (argv.count("-m") == 1 and argv[argv.index("-m") + 1] == "5"))
                        and len(urls) == 1 and urls[0] in {"http://" + TARGET, "http://" + TARGET + ":80"})
            return False

        def save():
            (out / "report.json").write_text(json.dumps(report, indent=2, default=str))

        try:
            await page.goto(BASE + "/login", wait_until="domcontentloaded")
            await expect(page.locator("#username")).to_be_visible()
            await page.locator("#username").fill(credentials["Username"])
            await page.locator("#password").fill(credentials["Password"])
            async with page.expect_response(lambda r: r.url.endswith("/api/login")) as pending:
                await page.locator("#login-btn").click()
            login = await pending.value
            if not login.ok:
                raise RuntimeError(f"Login HTTP {login.status}")
            await page.wait_for_url(BASE + "/")
            await expect(page.locator("#send-button")).to_be_visible()

            scope = {"targets": [TARGET], "exclusions": [], "ports": [80]}
            session_name = "AUTO replanning lab " + stamp
            created = await api("/api/session/new", method="POST", data={
                "target": TARGET, "name": session_name, "scope": scope,
            })
            session_id = created["session_id"]
            report["session_id"] = session_id
            report["scope"] = scope
            await page.reload(wait_until="domcontentloaded")
            async with page.expect_response(lambda r: "/autonomous/status" in r.url and session_id in r.url):
                await page.locator(".session-item").filter(has_text=session_name).click()
            await expect(page.locator("#target-value")).to_have_text(TARGET)

            await page.locator("#settings-button").click()
            steps = page.locator("#max-steps")
            await steps.evaluate("el => { el.value = '3'; el.dispatchEvent(new Event('input', {bubbles: true})); el.dispatchEvent(new Event('change', {bubbles: true})); }")
            await expect(steps).to_have_value("3")
            await expect(page.locator("#max-steps-value")).to_have_text("3")
            await page.locator("#risk-threshold").select_option("green_orange")
            await page.locator("#settings-close").click()
            await page.locator("#goal-select").select_option("discovery")

            async with page.expect_response(lambda r: "/autonomous/start" in r.url) as pending:
                await page.locator("#auto-button").click()
            started_response = await pending.value
            if not started_response.ok:
                raise RuntimeError(f"AUTO start HTTP {started_response.status}")
            start_data = await started_response.json()
            report["start"] = start_data
            report["start_request"] = json.loads(started_response.request.post_data or "{}")
            if start_data.get("status") != "started":
                report["result"] = "blocked_at_start"
                report["final_status"] = start_data
                save()
                return
            if report["start_request"].get("max_steps") != 3 or start_data.get("max_steps") != 3:
                report["result"] = "incorrect_step_limit"
                await api(f"/api/pentest/{session_id}/autonomous/stop", method="POST", data={})
                save()
                raise RuntimeError("AUTO did not receive the requested two-step limit")

            start_time = time.monotonic()
            plan_started = start_time
            observed_attempts = 0
            last_successful = 0
            replans = []
            while time.monotonic() - start_time < RUN_LIMIT_SECONDS:
                status = await api(f"/api/pentest/{session_id}/autonomous/status")
                report["latest_status"] = status
                attempts = int(status.get("planning_attempts", 0))
                if attempts > observed_attempts:
                    observed_attempts = attempts
                    plan_started = time.monotonic()
                    report["events"].append({"event": "planner_attempt_started", "attempt": attempts})

                successful = int(status.get("successful_steps", 0))
                if successful > last_successful:
                    for step_number in range(last_successful + 1, successful + 1):
                        record = {
                            "event": "step_succeeded",
                            "step": step_number,
                            "evidence_job_id": (status.get("evidence_job_ids") or [None])[step_number - 1],
                            "planning_attempts_at_completion": attempts,
                        }
                        report["events"].append(record)
                    last_successful = successful

                run_state = status.get("run_state")
                if run_state in {"failed", "blocked"}:
                    report["result"] = "stopped_on_failure" if run_state == "failed" else "blocked"
                    break
                if status.get("waiting_approval"):
                    approvals = await api(f"/api/pentest/{session_id}/autonomous/approvals")
                    pending_actions = approvals.get("pending", [])
                    report["pending_approval"] = pending_actions
                    action = pending_actions[0] if pending_actions else None
                    if action and safe_lab_command(action):
                        decision = await api(
                            f"/api/pentest/{session_id}/autonomous/approve",
                            method="POST",
                            data={"action_id": action["action_id"], "decision": "approve"},
                        )
                        report["approval_decisions"] = [{"action_id": action["action_id"],
                                                           "tool": action["tool"],
                                                           "command": action["command"],
                                                           "decision": decision}]
                        await asyncio.sleep(0.5)
                        continue
                    report["result"] = "stopped_for_approval"
                    await api(f"/api/pentest/{session_id}/autonomous/stop", method="POST", data={})
                    break
                if not status.get("active"):
                    report["result"] = run_state or "ended"
                    break

                # After a successful nonterminal step, require a fresh planner attempt.
                pending_replan_step = next(
                    (item["step"] for item in reversed(report["events"])
                     if item.get("event") == "step_succeeded" and not item.get("replan_attempted")),
                    None,
                )
                if pending_replan_step is not None:
                    completed_attempts = next(
                        item["planning_attempts_at_completion"]
                        for item in reversed(report["events"])
                        if item.get("event") == "step_succeeded" and item["step"] == pending_replan_step
                    )
                    if attempts > completed_attempts:
                        record = {"step": pending_replan_step, "replan_attempted": True,
                                  "next_planning_attempt": attempts}
                        replans.append(record)
                        report["events"].append({"event": "replan_after_step", **record})
                        for item in report["events"]:
                            if item.get("event") == "step_succeeded" and item.get("step") == pending_replan_step:
                                item["replan_attempted"] = True
                    elif time.monotonic() - plan_started > PLAN_LIMIT_SECONDS:
                        report["result"] = "stopped_slow_planner"
                        report["slow_reason"] = {
                            "run_state": run_state,
                            "planning_attempts": attempts,
                            "elapsed_seconds": round(time.monotonic() - plan_started, 1),
                        }
                        await api(f"/api/pentest/{session_id}/autonomous/stop", method="POST", data={})
                        break

                if attempts and time.monotonic() - plan_started > PLAN_LIMIT_SECONDS:
                    report["result"] = "stopped_slow_planner"
                    report["slow_reason"] = {
                        "run_state": run_state,
                        "planning_attempts": attempts,
                        "elapsed_seconds": round(time.monotonic() - plan_started, 1),
                    }
                    await api(f"/api/pentest/{session_id}/autonomous/stop", method="POST", data={})
                    break
                await asyncio.sleep(0.5)
            else:
                report["result"] = "stopped_run_timeout"
                await api(f"/api/pentest/{session_id}/autonomous/stop", method="POST", data={})

            # Allow the stop/terminal transition to persist, then capture audit evidence.
            for _ in range(20):
                status = await api(f"/api/pentest/{session_id}/autonomous/status")
                if not status.get("active"):
                    break
                await asyncio.sleep(0.5)
            report["final_status"] = status
            report["replans_after_successful_steps"] = replans
            if report["result"] == "completed" and int(status.get("successful_steps", 0)) >= 2:
                expected = int(status["successful_steps"]) - 1
                if len(replans) < expected:
                    report["result"] = "completed_without_replan_evidence"
            if session_id:
                try:
                    report["decision_log"] = await api(f"/api/pentest/{session_id}/decision-log")
                except Exception as exc:
                    report["decision_log_error"] = str(exc)[:300]
            await page.screenshot(path=str(out / "final.png"), full_page=True)
            save()
            print(json.dumps({"result": report["result"], "session_id": session_id,
                              "successful_steps": status.get("successful_steps"),
                              "replans": replans, "reason_code": status.get("reason_code"),
                              "failure_detail": status.get("failure_detail"),
                              "evidence_dir": str(out)}, default=str), flush=True)
            if report["result"] != "completed":
                raise SystemExit(1)
        except Exception as exc:
            report["result"] = "harness_error"
            report["harness_error"] = type(exc).__name__ + ": " + str(exc)[:600]
            save()
            raise
        finally:
            save()
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
