"""Owner-authorized bounded discovery through the real graphical interface.

No interaction uses a direct API call. Existing scope, budget, risk threshold
and command-bound approval remain authoritative. A pending command is printed
for the owner; stdin accepts only an explicit action-ID-bound decision. Nothing
automatically approves, modifies or retries a proposed operation. Credentials,
traces, outbound WebSocket authentication and raw observations are not saved.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:7000'
TARGET = '192.168.77.20'
OBJECTIVE = ('Perform the previously authorized bounded, non-destructive discovery assessment of '
             '192.168.77.20 within the existing engagement scope and execution policy. '
             'Stop when the objective is satisfied or a genuine blocker or existing limit occurs.')


def available_budget(budget: dict) -> bool:
    """Inspect existing capacity only; the server still reserves each call."""
    if not isinstance(budget, dict) or not isinstance(budget.get('approved_at'), str):
        return False
    try:
        if datetime.fromisoformat(budget['approved_at']).tzinfo is None:
            return False
    except ValueError:
        return False
    limits, usage = budget.get('limits'), budget.get('usage')
    if not isinstance(limits, dict) or not isinstance(usage, dict) or usage.get('stopped') is not False:
        return False
    for ceiling, used in (('max_calls','calls'), ('max_tokens','reserved_tokens'),
                          ('max_cost_microusd','reserved_cost_microusd')):
        if (type(limits.get(ceiling)) is not int or type(usage.get(used)) is not int
                or not 0 <= usage[used] < limits[ceiling]):
            return False
    return all(type(usage.get(key)) is int and usage[key] == 0
        for key in ('unknown_usage_calls','unknown_cost_calls'))


async def wait_for_owner_decision(action_id: str, terminal: asyncio.Event, timeout: float,
                                   input_fd: int | None = None) -> dict | None:
    """Bounded input without executor threads that survive timeout/shutdown."""
    if terminal.is_set() or timeout <= 0:
        return None
    loop = asyncio.get_running_loop()
    fd = sys.stdin.fileno() if input_fd is None else input_fd
    decision = loop.create_future()
    buffer = bytearray()
    def received():
        try:
            chunk = os.read(fd, 4097-len(buffer))
            buffer.extend(chunk)
            if len(buffer) > 4096:
                raise ValueError('Decision input exceeds bound')
            if not chunk or b'\n' in buffer:
                line, _, extra = bytes(buffer).partition(b'\n')
                if extra.strip():
                    raise ValueError('Only one exact owner decision is accepted')
                if not line.strip():
                    decision.set_result(None)
                else:
                    value = json.loads(line)
                    if (not isinstance(value, dict) or set(value) != {'action_id','decision'}
                            or value['action_id'] != action_id or value['decision'] not in {'approve','reject'}):
                        raise ValueError('Exact action-bound owner decision required')
                    decision.set_result(value)
        except Exception:
            if not decision.done():
                decision.set_exception(ValueError('Valid bounded action-bound decision required'))
        if decision.done():
            loop.remove_reader(fd)
    ended = asyncio.create_task(terminal.wait())
    started = loop.time()
    try:
        loop.add_reader(fd, received)
        done, _ = await asyncio.wait({decision, ended}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if ended in done:  # A terminal event wins a simultaneous input race.
            return None
        if decision in done:
            value = decision.result()
            if value is not None:
                return value
            # EOF means no human input, never an implicit decision. Continue
            # watching the controller's bounded terminal/expiry outcome.
            remaining = max(0, timeout-(loop.time()-started))
            done, _ = await asyncio.wait({ended}, timeout=remaining)
        return None
    finally:
        loop.remove_reader(fd)
        for task in (decision, ended):
            if not task.done():
                task.cancel()
        await asyncio.gather(decision, ended, return_exceptions=True)


def accepted_decision(status: int, body: dict, decision: str) -> bool:
    return (type(status) is int and 200 <= status < 300 and isinstance(body, dict)
            and body.get('status') == 'recorded' and body.get('decision') == decision)


async def run(session_id: str) -> int:
    from playwright.async_api import async_playwright, expect
    directory = ROOT / '.local-lab/operational-reliability' / ('lab-visible-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    started = time.monotonic_ns()
    result = {'status': 'IN_PROGRESS', 'headless': False, 'chromium_sandbox': True,
        'target': TARGET, 'session_id': session_id, 'objective': OBJECTIVE,
        'head': subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'directory': str(directory.relative_to(ROOT)), 'api_interaction_substitutions': False,
        'started_at': datetime.now(timezone.utc).isoformat(), 'screenshots': [],
        'run_id': None, 'events': [], 'human_decisions': [], 'page_error_types': []}
    captures = set()
    terminal = asyncio.Event()
    start_observed = asyncio.Event()
    session_name = None
    def checkpoint():
        result['observation_elapsed_ms'] = (time.monotonic_ns()-started)/1e6
        (directory/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    credentials = dict(line.split(': ',1) for line in (ROOT/'.local-lab/login.txt').read_text().splitlines())
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False,chromium_sandbox=True)
        context = await browser.new_context(viewport={'width':1600,'height':1100})
        page = await context.new_page()
        page.set_default_timeout(20000)
        page.on('pageerror',lambda exc:result['page_error_types'].append(type(exc).__name__))
        async def capture(response):
            nonlocal session_name
            path = response.url.split('?',1)[0]
            if not response.ok:
                return
            if path.endswith('/api/session/list'):
                body=await response.json()
                sessions=body.get('sessions',[]) if isinstance(body,dict) else body
                session_name=next((s.get('name') or s.get('target') for s in sessions
                    if s.get('session_id')==session_id),None)
            elif path.endswith('/'+session_id+'/model-budget'):
                body=await response.json()
                budget={k:body.get(k) for k in ('approved_at','limits','usage')}
                # Usage diagnostics are closed counts, never provider content.
                budget['usage']={k:(body.get('usage') or {}).get(k) for k in (
                    'calls','reserved_tokens','reported_tokens','reserved_cost_microusd',
                    'reported_cost_microusd','unknown_usage_calls','unknown_cost_calls','stopped','stop_reason')}
                result['budget_after' if result['run_id'] else 'budget_before']=budget
            elif path.endswith('/'+session_id+'/autonomous/start'):
                body=await response.json()
                result['run_id']=body.get('run_id')
                result['start_response']={k:body.get(k) for k in ('status','run_state','reason_code','max_steps')}
                if result['run_id'] and body.get('run_state') in {'completed','blocked','failed'}:
                    result['terminal_observation']={'source':'graphical_start_response',
                        'run_id':result['run_id'],**result['start_response']}
                    terminal.set()
                checkpoint()
                start_observed.set()
            elif path.endswith('/'+session_id+'/autonomous/status'):
                body=await response.json()
                if result['run_id'] and body.get('run_id')==result['run_id']:
                    result['run_status']={k:body.get(k) for k in ('run_id','run_state','reason_code','active',
                        'steps_taken','model_calls','successful_steps','completed_observations',
                        'evidence_job_ids','original_objective','completion','mission','timings')}
                    checkpoint()
        def response_seen(response):
            task=asyncio.create_task(capture(response));captures.add(task)
            task.add_done_callback(captures.discard)
        page.on('response',response_seen)
        def received(payload):
            try:
                event=json.loads(payload)
            except (ValueError,TypeError):
                return
            if event.get('run_id') != result['run_id'] or not result['run_id']:
                return
            safe={k:event.get(k) for k in ('type','run_id','session_id','event_sequence','step','status',
                'run_state','reason_code','action_id','timings','structured_validation_ms') if k in event}
            safe.update(received_elapsed_ms=(time.monotonic_ns()-started)/1e6,
                        received_payload_bytes=len(payload.encode() if isinstance(payload,str) else payload))
            result['events'].append(safe)
            checkpoint()
            if event.get('type')=='auto_complete' and event.get('run_state') in {'completed','blocked','failed'}:
                result['terminal_event']=safe;terminal.set()
        page.on('websocket',lambda socket:socket.on('framereceived',received))
        async def screenshot(name):
            await page.screenshot(path=directory/name,full_page=True,animations='disabled',
                mask=[page.locator('#account-name'),page.locator('#account-initial')])
            result['screenshots'].append(name)
        try:
            response=await page.goto(BASE+'/login')
            result['server_build']=response.headers.get('x-aria-build')
            await page.locator('#username').fill(credentials['Username'])
            await page.locator('#password').fill(credentials['Password'])
            await page.locator('#login-btn').click()
            await page.wait_for_url(BASE+'/')
            await page.locator('a[href="/dashboard"]').click()
            await page.locator('#engagement-select').select_option(session_id)
            await expect(page.locator('#hero-target')).to_have_text(TARGET)
            await expect(page.locator('#budget-body')).to_contain_text('Engagement ceiling')
            if captures:await asyncio.gather(*list(captures))
            budget=result.get('budget_before') or {}
            limits,usage=budget.get('limits') or {},budget.get('usage') or {}
            if not available_budget(budget):
                raise RuntimeError('Existing budget approval or capacity is unavailable')
            await screenshot('lab-budget-before.png')
            await page.locator('.hero a[href="/"]').click()
            await page.wait_for_url(BASE+'/')
            await expect(page.locator('#target-value')).to_have_text(TARGET)
            await expect(page.locator('#auto-button')).to_have_attribute('data-state','off')
            await page.locator('#goal-select').select_option('discovery')
            result['risk_threshold']=await page.locator('#risk-threshold').input_value()
            await page.locator('#user-input').fill(OBJECTIVE)
            await page.locator('#auto-button').click()
            await asyncio.wait_for(start_observed.wait(),timeout=30)
            if not result['run_id']:
                raise RuntimeError('No run identity was returned; start is never automatically retried')
            print(json.dumps({'stage':'STARTED','directory':result['directory']}),flush=True)
            seen=set()
            deadline=time.monotonic()+1800
            while not terminal.is_set() and time.monotonic()<deadline:
                if await page.locator('#approval-banner').is_visible():
                    action=await page.locator('#approval-approve').get_attribute('data-action-id')
                    command=await page.locator('#approval-approve').get_attribute('data-command')
                    if action and action not in seen:
                        seen.add(action)
                        from orchestrator.execution_policy import validate_command
                        # This is only a presentation safety check; no authority
                        # or expected finding is added and the UI stays pending.
                        validate_command(command,{'targets':[TARGET]})
                        result['pending_approval']={'action_id':action,'command':command}
                        await screenshot('lab-approval-'+str(len(seen))+'.png')
                        checkpoint()
                        print(json.dumps({'stage':'OWNER_DECISION_REQUIRED','action_id':action,
                            'command':command,'directory':result['directory']}),flush=True)
                        decision=await wait_for_owner_decision(action, terminal,
                            max(0,deadline-time.monotonic()))
                        if decision is None:
                            continue
                        if (decision.get('action_id')!=action or decision.get('decision') not in {'approve','reject'}
                                or await page.locator('#approval-approve').get_attribute('data-action-id')!=action
                                or await page.locator('#approval-approve').get_attribute('data-command')!=command):
                            raise RuntimeError('Explicit unchanged action-bound owner decision required')
                        async with page.expect_response(lambda response:
                                response.url.split('?',1)[0].endswith('/'+session_id+'/autonomous/approve')
                                and response.request.method=='POST') as receipt:
                            await page.locator('#approval-'+decision['decision']).click()
                        response=await receipt.value
                        body=await response.json()
                        accepted=accepted_decision(response.status,body,decision['decision'])
                        result.setdefault('decision_attempts',[]).append({'action_id':action,
                            'decision':decision['decision'],'accepted':accepted,'http_status':response.status})
                        if accepted:
                            result['human_decisions'].append({'action_id':action,'decision':decision['decision']})
                            result.pop('pending_approval',None)
                        checkpoint()
                await asyncio.sleep(.25)
            if not terminal.is_set():
                result.update(status='BLOCKED',reason_code='visible_observation_timeout')
            else:
                await screenshot('lab-workspace-terminal.png')
                await page.reload()
                await expect(page.locator('#auto-button')).to_have_attribute('data-state','off')
                await page.locator('a[href="/dashboard"]').click()
                await page.wait_for_function("document.body.dataset.dashboardReady === 'true'")
                await expect(page.locator('#hero-note')).to_contain_text(OBJECTIVE)
                await screenshot('lab-dashboard-terminal.png')
                await page.locator('#evidence-tab-catalog').click()
                await screenshot('lab-evidence.png')
                if captures:await asyncio.gather(*list(captures))
                result['browser_measurements']=await page.evaluate("""() => performance.getEntriesByType('measure')
                  .filter(e=>e.name.startsWith('aria.')).map(e=>({name:e.name,duration_ms:e.duration,detail:e.detail}))""")
                result['status']='VERIFIED' if not result['page_error_types'] else 'FAILED'
                result['acceptance_scope']='Visible bounded objective/limit/blocker stop; not a twelve-operation benchmark or endurance proof.'
        except asyncio.CancelledError:
            result.update(status='BLOCKED',reason_code='observation_cancelled')
            raise
        except Exception as exc:
            result.update(status='BLOCKED',error_type=type(exc).__name__)
        finally:
            if captures:await asyncio.gather(*list(captures),return_exceptions=True)
            checkpoint()
            await context.close();await browser.close()
    print(json.dumps({'status':result['status'],'directory':result['directory'],
        'run_id':result['run_id'],'terminal_event':result.get('terminal_event'),
        'error_type':result.get('error_type')}),flush=True)
    return 0 if result['status']=='VERIFIED' else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-session',required=True)
    args=parser.parse_args()
    raise SystemExit(asyncio.run(run(args.owner_session)))
