"""Real Firefox/HTTP/WS/cache with synthetic provider/worker fixtures.
No owner DB, credentials, target requests or global browser settings are used.
"""
import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/browser-matrix'
BASE='http://127.0.0.1:17002'


async def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    results,errors,requests={},[],[]
    with tempfile.TemporaryDirectory(prefix='aria-browser-matrix-') as work:
        work=Path(work); web=work/'web'; shutil.copytree(ROOT/'web',web)
        script=web/'static/scripts/app.js'; script.write_text(script.read_text()+'\nglobalThis.ariaFixtureBuild=1;\n')
        env={**os.environ,'ARIA_BROWSER_STATE':str(work/'state.json'),'ARIA_BROWSER_WEB':str(web)}
        log=(OUTPUT/'server.log').open('w')
        server=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B','-m','uvicorn','integration.browser_fixture_server:app','--host','127.0.0.1','--port','17002','--log-level','warning'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            async with async_playwright() as pw:
                context=await pw.firefox.launch_persistent_context(str(work/'profile'),headless=True,viewport={'width':1440,'height':1000})
                page=await context.new_page()
                page.on('pageerror',lambda exc:errors.append(str(exc)))
                page.on('request',lambda req:requests.append({'method':req.method,'path':req.url.split(BASE)[-1]}))
                for _ in range(100):
                    try:
                        response=await context.request.get(BASE+'/__control',timeout=1000)
                        if response.ok: break
                    except Exception: await asyncio.sleep(.1)
                else: raise RuntimeError('Fixture server unavailable')
                async def inspect(): return await (await context.request.get(BASE+'/__control')).json()
                async def control(**values): await context.request.post(BASE+'/__control',data=values)
                async def accepted(dialog): await dialog.accept()
                async def rejected(dialog): await dialog.dismiss()
                async def login():
                    await page.goto(BASE+'/login')
                    await page.locator('#username').fill('fixture-owner'); await page.locator('#password').fill('fixture-only')
                    await page.locator('#login-btn').click(); await page.wait_for_url(BASE+'/')
                    await page.evaluate("localStorage.setItem('current_session','a')"); await page.reload()
                    await expect(page.locator('#messages')).to_contain_text('Saved Alpha')
                await page.goto(BASE+'/login')
                await page.locator('#username').fill('fixture-owner'); await page.locator('#password').fill('wrong')
                await page.locator('#login-btn').click(); await expect(page.locator('#error-msg')).to_contain_text('Invalid credentials')
                results['invalid_login_visible']='passed'
                await login(); results['login_and_restore']='passed'
                await expect(page.locator('#goal-select')).to_have_value('discovery')
                await expect(page.locator('#mode-select')).to_be_disabled(); results['supported_defaults']='passed'
                await page.locator('#settings-button').click(); await page.get_by_text('Add new key',exact=True).click(); await page.locator('#new-key-provider').select_option('groq')
                await page.locator('#new-key-value').fill('fixture-key-only'); await page.locator('#new-key-label').fill('Matrix fixture')
                await page.locator('#new-key-add').click(); await expect(page.locator('#llm-keys-list')).to_contain_text('Matrix fixture')
                page.once('dialog',accepted); await page.locator('#llm-keys-list').get_by_role('button',name='Delete').click()
                await expect(page.locator('#llm-keys-list')).not_to_contain_text('Matrix fixture')
                await page.locator('input[name="skill"][value="expert"]').check()
                await page.wait_for_timeout(150)
                assert (await inspect())['profile']=='expert'
                await page.locator('#risk-threshold').select_option('green_only')
                await page.locator('#settings-close').click(); results['settings_keys_skill_risk']='passed'
                await page.locator('#user-input').fill('Observe HTTP only')
                await page.evaluate("document.getElementById('send-button').click(); document.getElementById('send-button').click()")
                await expect(page.locator('#messages')).to_contain_text('Bounded HTTP observation proposed')
                assert (await inspect())['counts']['prompts']==1; results['rapid_prompt_submission']='passed'
                run=page.locator('.cmd-card').last.get_by_role('button',name='Run')
                page.once('dialog',rejected); await run.click()
                await page.wait_for_timeout(150); assert (await inspect())['counts'].get('executions',0)==0
                results['manual_rejection_no_dispatch']='passed'
                page.once('dialog',accepted); await run.click()
                await expect(page.locator('#messages')).to_contain_text('controlled-fixture')
                assert (await inspect())['counts']['executions']==1
                results['manual_approved_execution_analysis']='passed'
                await page.reload(); await expect(page.locator('#messages')).to_contain_text('controlled-fixture')
                results['execution_history_reload']='passed'
                await page.locator('#user-input').fill('report'); await page.locator('#send-button').click()
                await page.get_by_role('button',name='Markdown',exact=True).click()
                await expect(page.get_by_role('link',name='Download report')).to_be_visible()
                async with page.expect_download() as downloaded: await page.get_by_role('link',name='Download report').click()
                artifact=await downloaded.value
                await artifact.save_as(str(OUTPUT/'fixture-report.md'))
                await page.reload(); await expect(page.get_by_role('link',name='Download report')).to_be_visible()
                results['report_format_download_and_restore']='passed'
                headers={'Authorization':'Bearer fixture-token'}
                denied=await context.request.get(BASE+'/api/session/private/restore',headers=headers); assert denied.status==403
                denied=await context.request.post(BASE+'/api/execution/proposals',headers=headers,data={'session_id':'a','command':'curl -I http://198.51.100.1','tool':'curl'}); assert denied.status==403
                results['ownership_and_scope_denial']='passed (browser API; real scope parser)'
                await control(errors={'/api/session/a/restore':503}); await page.reload()
                await expect(page.locator('#messages')).to_contain_text('History could not be loaded')
                await control(errors={}); await page.get_by_role('button',name='History could not be loaded. Click to retry.').click()
                await expect(page.locator('#messages')).to_contain_text('controlled-fixture')
                results['api_outage_history_recovery']='passed'
                await control(delays={'/api/v8/input':.5})
                await page.locator('#user-input').fill('Delayed Alpha plan'); await page.locator('#send-button').click()
                await page.locator('.session-item',has_text='Fixture Beta').click()
                await expect(page.locator('#messages')).to_contain_text('Saved Beta response')
                await page.locator('#user-input').fill('New Beta plan while Alpha is pending'); await page.locator('#send-button').click()
                await expect(page.locator('#messages')).to_contain_text('New Beta plan while Alpha is pending')
                await page.wait_for_timeout(700)
                await expect(page.locator('#messages')).to_contain_text('Saved Beta response')
                await expect(page.locator('#messages')).not_to_contain_text('Delayed Alpha')
                results['stale_planning_response']='passed'
                await control(delays={}); await page.locator('.session-item',has_text='Fixture Alpha').click()
                for phase in ['planning','awaiting_approval','executing','cancelling']:
                    await control(runs={},phase=phase); await page.reload()
                    await expect(page.locator('#auto-label')).to_have_text('Auto mode')
                    await page.locator('#auto-button').click()
                    await expect(page.locator('#auto-label')).to_contain_text('RUNNING')
                    before=(await inspect())['counts']['auto_starts']
                    await page.reload(); await expect(page.locator('#auto-label')).to_contain_text('RUNNING')
                    assert (await inspect())['counts']['auto_starts']==before
                    if phase=='awaiting_approval': await expect(page.locator('#approval-banner')).to_be_visible()
                    results['refresh_during_'+phase]='passed'
                await page.locator('#auto-button').click(); await expect(page.locator('#auto-label')).to_have_text('Auto mode')
                results['stop_pending_then_terminal']='passed'
                await control(runs={},phase='planning',disconnects=1); await page.reload()
                await expect(page.locator('#auto-button')).to_be_enabled()
                await page.evaluate("document.getElementById('auto-button').click(); document.getElementById('auto-button').click()")
                await expect(page.locator('#auto-label')).to_contain_text('RUNNING')
                await page.wait_for_timeout(2300)
                assert (await inspect())['disconnects']==0
                results['socket_disconnect_reconnect']='passed'
                other=await context.new_page(); await other.goto(BASE)
                await expect(other.locator('#auto-label')).to_contain_text('RUNNING')
                await other.locator('#auto-button').click(); await expect(page.locator('#auto-label')).to_have_text('Auto mode')
                await other.close(); results['multiple_tabs_stop_observation']='passed'
                await control(runs={}); await page.reload(); await page.locator('#goal-select').select_option('initial_access')
                await page.locator('#auto-button').click(); await expect(page.locator('#toast-container')).to_contain_text('Verified access capability unavailable')
                results['unsupported_goal_visible']='passed'
                await control(burp_enabled=True); await page.locator('[data-tab="burp"]').click()
                await expect(page.locator('#tab-burp')).to_contain_text('evidence: e1')
                await page.get_by_role('button',name='Stage in Repeater').click(); await expect(page.locator('#toast-container')).to_contain_text('Request staged')
                results['burp_repeater_staging_ui']='passed (synthetic connector)'
                before=(await inspect())['counts'].get('replays',0)
                page.once('dialog',rejected); await page.get_by_role('button',name='Review exact replay').click(); await page.wait_for_timeout(150)
                assert (await inspect())['counts'].get('replays',0)==before; results['burp_replay_rejection_ui']='passed'
                page.once('dialog',accepted); await page.get_by_role('button',name='Review exact replay').click()
                await expect(page.locator('#tab-burp')).to_contain_text('HTTP/1.1 200 OK')
                results['burp_approved_replay_comparison_ui']='passed (synthetic connector)'
                await page.reload(); await page.locator('[data-tab="burp"]').click()
                await expect(page.locator('#tab-burp')).to_contain_text('HTTP/1.1 200 OK')
                results['burp_replay_history_reload']='passed'
                await control(errors={'/api/burp/a/e1/repeater':503}); await page.get_by_role('button',name='Stage in Repeater').click()
                await expect(page.locator('#toast-container')).to_contain_text('Repeater unavailable'); await control(errors={})
                results['burp_disconnection_visible']='passed'
                before=await page.locator('script[src*="app.js"]').get_attribute('src')
                script.write_text(script.read_text()+'\nglobalThis.ariaFixtureBuild=2;\n')
                await page.reload(); after=await page.locator('script[src*="app.js"]').get_attribute('src')
                assert before!=after and await page.evaluate('globalThis.ariaFixtureBuild')==2
                results['two_ui_builds_warm_cache_upgrade']='passed (real HTTP cache; no request interception)'
                await page.screenshot(path=str(OUTPUT/'upgraded-ui.png'),full_page=True)
                await control(expired=True); await page.locator('#settings-button').click(); await expect(page).to_have_url(BASE+'/login.html')
                assert await page.evaluate("localStorage.getItem('pentestai_token')")==None
                results['token_expiry_redirect']='passed'
                await login(); await page.locator('#settings-button').click(); await page.locator('#logout-button').click()
                await page.wait_for_url(BASE+'/login'); results['logout']='passed'
                await context.close()
                assert not errors,errors
                results['javascript_errors']='passed'
        except Exception as exc:
            results['harness']='failed: '+str(exc)
            if 'page' in locals():
                try: await page.screenshot(path=str(OUTPUT/'failure.png'),full_page=True)
                except Exception: pass
            raise
        finally:
            if 'context' in locals():
                try: await context.close()
                except Exception: pass
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=5)
            log.close()
            (OUTPUT/'report.json').write_text(json.dumps({'environment':'real Firefox, HTTP/cache and WS; synthetic providers/workers/connector',
                'results':results,'page_errors':errors,'live_model_calls':0,'live_model_tokens':0},indent=2))
            (OUTPUT/'requests.json').write_text(json.dumps(requests,indent=2))
    print(json.dumps(results,indent=2))


if __name__=='__main__': asyncio.run(main())
