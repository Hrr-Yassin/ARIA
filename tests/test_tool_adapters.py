"""Deterministic adapter contracts; no installed tools, DNS, sockets or providers."""
import asyncio
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from pydantic import ValidationError

from security_tools.adapters import ADAPTERS, AdapterError, encode, decode, validate, catalog
from security_tools.models import Observation
from security_tools.worker_profiles import Profile, load_profiles, prepare_tool
from security_tools.runner import tree_digest, supervise
from tests.support import OfflineCase

FIXTURES = Path(__file__).with_name('fixtures') / 'security_tools'


def fixture(name):
    return json.loads((FIXTURES / (name + '.json')).read_text())


def profile(name):
    assets = {'http-observation.yaml':'b'*64} if name == 'nuclei' else {'aria-python.yaml':'b'*64} if name == 'semgrep' else {}
    return Profile(image_id='sha256:'+'c'*64, tool_version='1.0.0', binary_sha256='b'*64,
        assets=assets, artifacts=['a'*64] if name == 'semgrep' else [],
        passive_sources=['crtsh'] if name == 'subfinder' else [])


class AdapterUnitTests(unittest.TestCase):
    def test_discovery_distinguishes_names_from_executable_adapters(self):
        self.assertEqual(len(catalog()), 10)
        self.assertTrue(all(not a['worker_available'] for a in catalog({'tools':list(ADAPTERS)})))
        for adapter in ADAPTERS.values():
            view = catalog({'typed_adapters':{adapter.capability:1}})
            self.assertEqual(sum(a['worker_available'] for a in view),1)
            self.assertTrue(all(not a['runtime_validated'] for a in view))

    def test_canonical_envelope_rejects_tampering_and_noncanonical_json(self):
        command = encode(fixture('httpx')['request'])
        for bad in (command+'=', command+';', command+'\n', command.replace('aria-tool','sh'), 'aria-tool e30', 'aria-tool '+('a'*5000)):
            with self.subTest(command=bad[:40]), self.assertRaises(AdapterError):
                decode(bad)

    def test_profile_pins_and_source_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'source';source.mkdir()
            (source/'fixture.py').write_text('eval(user_input)\n')
            self.assertEqual(tree_digest(source), tree_digest(source))
            (source/'escape').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): tree_digest(source)
            path=root/'profiles.json'
            path.write_text(json.dumps({'httpx':profile('httpx').model_dump()}))
            self.assertEqual(set(load_profiles(str(path))),{'httpx'})
            for raw in ('{"httpx":{},"httpx":{}}', '{"unknown":{}}', '[]', '{}'*20000):
                path.write_text(raw)
                with self.assertRaises(ValueError): load_profiles(str(path))
            self.assertEqual(load_profiles(None),{})
        with self.assertRaises(ValidationError): Profile(image_id='mutable:latest',tool_version='1.0.0',binary_sha256='a'*64)

    def test_observations_cannot_assert_verification(self):
        with self.assertRaises(ValidationError):
            Observation(kind='finding',locator='fixture',summary='fixture',verification='verified')


def make_unit(tool, check):
    def test(self):
        data=fixture(tool);adapter=ADAPTERS[tool]
        command=encode(data['request']);_,params=decode(command)
        if check=='roundtrip':
            self.assertEqual(validate(command,data['scope']).tool,tool)
            self.assertEqual(params.model_dump(),adapter.parameters(params.model_dump()).model_dump())
            argv=adapter.argv(params)
            self.assertIsInstance(argv,list)
            self.assertTrue(all(isinstance(a,str) for a in argv))
            self.assertNotIn('/bin/sh',argv)
        elif check=='invalid_parameters':
            for mutation in ({**data['request']['parameters'],'extra':'--dump'},
                             {key:True for key in data['request']['parameters']}, {}):
                with self.subTest(mutation=mutation), self.assertRaises(AdapterError):
                    encode({**data['request'],'parameters':mutation})
        elif check=='unauthorized':
            for scope in ({}, {'targets':[]}, {'targets':['198.51.100.1']},
                          {**data['scope'],'program_policy':{}}, {**data['scope'],'mode':'bug_bounty'}):
                with self.subTest(scope=scope), self.assertRaises(ValueError):
                    validate(command,scope)
        elif check=='normalize':
            result=adapter.normalize(data['stdout'],params,data['scope'])
            self.assertEqual(result.error,'none',result)
            self.assertEqual(len(result.observations),1)
            self.assertEqual(result.observations[0].verification,'unverified')
            adapter.output_model.model_validate(result.model_dump())
        elif check=='malformed_output':
            for raw in ('{broken', 'null', '[]', '\x00', 'x'*100000):
                with self.subTest(raw=raw[:12]):
                    self.assertEqual(adapter.normalize(raw,params,data['scope']).error,'invalid_output')
            self.assertTrue(adapter.normalize('x'*100000,params,data['scope']).truncated)
        elif check=='errors':
            for code,state,expected in ((1,'failed','tool_failed'),(124,'failed','timeout'),(137,'failed','resource_exhausted'),(-1,'cancelled','cancelled')):
                result=adapter.normalize(data['stdout'],params,data['scope'],code,state)
                self.assertEqual(result.error,expected)
                self.assertEqual(result.observations,[])
    return test

for name in ADAPTERS:
    for check in ('roundtrip','invalid_parameters','unauthorized','normalize','malformed_output','errors'):
        setattr(AdapterUnitTests,f'test_{name}_{check}',make_unit(name,check))


class AdapterPolicyTests(OfflineCase):
    async def test_ceiling_exclusions_port_and_dns_pins(self):
        data=fixture('httpx');data['request']['parameters']['url']='http://lab.example:8080/'
        data['scope']['targets']=['lab.example']
        command=encode(data['request'])
        resolver=AsyncMock(return_value=['192.0.2.1'])
        plan=await prepare_tool(command,data['scope'],['192.0.2.0/24'],[8080],{'httpx':profile('httpx')},resolver)
        self.assertEqual(plan['hosts'],{'lab.example':['192.0.2.1']})
        self.assertEqual(plan['networks'],['192.0.2.1/32'])
        for addresses in (['198.51.100.1'],['192.0.2.1','198.51.100.1']):
            resolver.return_value=addresses
            with self.assertRaises(ValueError): await prepare_tool(command,data['scope'],['192.0.2.0/24'],[8080],{'httpx':profile('httpx')},resolver)
        resolver.return_value=['192.0.2.1']
        with self.assertRaises(ValueError): await prepare_tool(command,{**data['scope'],'exclusions':['192.0.2.1']},['192.0.2.0/24'],[8080],{'httpx':profile('httpx')},resolver)
        with self.assertRaises(ValueError): await prepare_tool(command,data['scope'],['192.0.2.0/24'],[443],{'httpx':profile('httpx')},resolver)

    async def test_active_tools_have_no_data_extraction_or_shell_options(self):
        for name in ('sqlmap','nuclei','ffuf'):
            adapter=ADAPTERS[name];params=adapter.parameters(fixture(name)['request']['parameters'])
            argv=adapter.argv(params)
            for forbidden in ('--dump','--dbs','--tables','--os-shell','--os-cmd','--sql-shell','-headless','-code','-interactsh-url','-r'):
                self.assertNotIn(forbidden,argv)
            self.assertEqual(adapter.risk,'red')

    async def test_output_scope_rejects_foreign_urls_names_and_ports(self):
        for name in ('httpx','katana','nuclei','zap','ffuf','playwright'):
            data=fixture(name);adapter=ADAPTERS[name];params=adapter.parameters(data['request']['parameters'])
            for raw in (data['stdout'].replace('192.0.2.1','198.51.100.1'),data['stdout'].replace(':8080',':22')):
                self.assertEqual(adapter.normalize(raw,params,data['scope']).error,'invalid_output',name)
        data=fixture('subfinder');adapter=ADAPTERS['subfinder'];params=adapter.parameters(data['request']['parameters'])
        self.assertEqual(adapter.normalize('{"host":"unrelated.test"}',params,data['scope']).error,'invalid_output')

    async def test_browser_context_is_fresh_sandboxed_and_network_closed(self):
        from security_tools.browser_runner import observe
        browser=AsyncMock();context=AsyncMock();page=AsyncMock()
        page.set_default_timeout=lambda value: None
        browser.new_context.return_value=context;context.new_page.return_value=page
        page.title.return_value='Fixture title'
        playwright=AsyncMock();playwright.chromium.launch.return_value=browser
        async def navigation(*args,**kwargs):
            handler=context.route.call_args.args[1]
            route=AsyncMock();route.request.url='http://192.0.2.1:8080/';route.request.method='GET'
            route.request.is_navigation_request=lambda:True
            await handler(route);route.fulfill.assert_awaited_once()
            await handler(route);route.abort.assert_awaited_once()
            foreign=AsyncMock();foreign.request.url='http://198.51.100.1/'
            await handler(foreign);foreign.abort.assert_awaited_once()
        page.goto.side_effect=navigation
        result=await observe(playwright,'http://192.0.2.1:8080/',200,[],b'<title>Fixture title</title>')
        self.assertEqual(result['title'],'Fixture title')
        self.assertTrue(playwright.chromium.launch.call_args.kwargs['chromium_sandbox'])
        self.assertFalse(browser.new_context.call_args.kwargs['java_script_enabled'])
        context.close.assert_awaited_once();browser.close.assert_awaited_once()

    async def test_browser_cleanup_after_navigation_error(self):
        from security_tools.browser_runner import observe
        playwright=AsyncMock();browser=playwright.chromium.launch.return_value
        context=browser.new_context.return_value;page=context.new_page.return_value
        page.set_default_timeout=lambda value:None;page.goto.side_effect=ValueError('fixture')
        with self.assertRaises(ValueError): await observe(playwright,'http://192.0.2.1:8080/',200,[],b'fixture')
        context.close.assert_awaited_once();browser.close.assert_awaited_once()

    async def test_supervisor_bounds_pipes_timeout_and_cancellation(self):
        import signal
        class Stream:
            def __init__(self, chunk=b'fixture', hang=False):self.chunk=chunk;self.hang=hang
            async def read(self, size):
                if self.hang:await asyncio.Future()
                chunk,self.chunk=self.chunk,b''
                return chunk
        for mode in ('success','overflow','timeout','cancel'):
            child=AsyncMock();child.pid=999999
            child.stdout=Stream(b'x'*100000 if mode=='overflow' else b'fixture',mode in {'timeout','cancel'})
            child.stderr=Stream(b'');child.wait.return_value=0
            with patch('security_tools.runner.asyncio.create_subprocess_exec',AsyncMock(return_value=child)) as spawn, \
                 patch('security_tools.runner.os.killpg') as kill:
                if mode=='success':
                    self.assertEqual(await supervise(['/opt/tools/fixture'],1,{}),(0,'fixture',''))
                elif mode=='overflow':
                    with self.assertRaises(OverflowError):await supervise(['/opt/tools/fixture'],1,{})
                elif mode=='timeout':
                    with self.assertRaises(asyncio.TimeoutError):await supervise(['/opt/tools/fixture'],0.01,{})
                else:
                    task=asyncio.create_task(supervise(['/opt/tools/fixture'],1,{}))
                    await asyncio.sleep(0);await asyncio.sleep(0);task.cancel()
                    with self.assertRaises(asyncio.CancelledError):await task
                kill.assert_called_with(child.pid,signal.SIGKILL)
                self.assertTrue(spawn.call_args.kwargs['start_new_session'])

    async def test_zap_imports_one_message_without_spider_or_replay(self):
        from security_tools.runner import prepare_zap
        files={}
        with patch('security_tools.snapshot.fetch',return_value=(200,[],b'fixture')), \
             patch('security_tools.runner.Path.write_text',lambda path,value:files.update({str(path):value})):
            prepare_zap('http://192.0.2.1:8080/')
        config=json.loads(files['/tmp/aria-zap.yaml'])
        self.assertEqual([job['type'] for job in config['jobs']],['import','passiveScan-wait','report'])
        self.assertFalse(config['jobs'][0]['parameters']['sendRequests'])
        self.assertEqual(config['jobs'][0]['parameters']['maxMessages'],1)
        self.assertEqual(len(json.loads(files['/tmp/aria-message.har'])['log']['entries']),1)

    async def test_runner_verifies_binary_assets_and_source_before_execution(self):
        from security_tools.runner import setup
        for name in ADAPTERS:
            data=fixture(name)
            plan=await prepare_tool(encode(data['request']),data['scope'],['192.0.2.0/24'],[8080,443],{name:profile(name)},AsyncMock(return_value=['192.0.2.1']))
            with patch('security_tools.runner.file_digest',return_value='bad'):
                with self.assertRaises(ValueError):setup(plan)
            with patch('security_tools.runner.file_digest',return_value='b'*64), \
                 patch('security_tools.runner.tree_digest',return_value='a'*64), \
                 patch('security_tools.runner.Path.write_text'),patch('security_tools.runner.prepare_zap'):
                argv=setup(plan)
                self.assertEqual(argv[0],ADAPTERS[name].argv(ADAPTERS[name].parameters(data['request']['parameters']))[0])

    async def test_nmap_accepts_native_inert_doctype_and_denies_external_entities(self):
        data=fixture('nmap');adapter=ADAPTERS['nmap'];params=adapter.parameters(data['request']['parameters'])
        self.assertEqual(adapter.normalize('<!DOCTYPE nmaprun>'+data['stdout'],params,data['scope']).error,'none')
        for declaration in ('<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">',
                            '<!DOCTYPE nmaprun [<!ENTITY x "fixture">]>'):
            self.assertEqual(adapter.normalize(declaration+data['stdout'],params,data['scope']).error,'invalid_output')

    async def test_runtime_adapter_image_and_large_resource_envelope_are_fixed(self):
        import time
        import uuid
        from worker.runtime import DockerRuntime
        from worker.policy import firewall
        runtime=DockerRuntime('sha256:'+'b'*64)
        runtime.cli=AsyncMock(return_value=(0,b'',b''))
        for name in ('playwright','zap','semgrep'):
            data=fixture(name)
            plan=await prepare_tool(encode(data['request']),data['scope'],['192.0.2.0/24'],[8080,443],{name:profile(name)},AsyncMock(return_value=['192.0.2.1']))
            await runtime.create({'job_id':str(uuid.uuid4()),'deadline':time.time()+60,'plan':plan})
            args=runtime.cli.call_args.args
            self.assertIn(profile(name).image_id,args)
            self.assertIn('--read-only',args)
            self.assertNotIn('--privileged',args)
            self.assertNotIn('--volume',args)
            if name=='semgrep':
                self.assertEqual(plan['networks'],[])
                self.assertNotIn('daddr',firewall(plan))
            else:
                self.assertIn('--memory=1024m',args)
                self.assertIn('--pids-limit=128',args)
