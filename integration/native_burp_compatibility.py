"""Native Community version and passive staging in a loopback-only namespace.

No application imports, provider calls, database access, installations, replay job
submissions or target requests. Only explicitly mounted JARs, trusted probe code,
the existing same-artifact Community consent preference and disposable files exist
inside the namespace. New terms are never accepted or synthesized.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def namespace_probe() -> dict:
    interfaces=json.loads(subprocess.check_output(['/usr/bin/ip','-j','address'],text=True))
    routes=json.loads(subprocess.check_output(['/usr/bin/ip','-j','route','show','table','all'],text=True))
    if {entry['ifname'] for entry in interfaces}!={'lo'} or any(route.get('dev') not in {None,'lo'} for route in routes):
        raise RuntimeError('Refusing a namespace with a non-loopback interface or route')
    return {'interfaces':interfaces,'routes':routes,'non_loopback_interfaces':[]}


def inside() -> int:
    output=Path('/work')
    result={'status':'failed','scope':'Native Community runtime, synthetic passive staging only',
            'new_model_calls':0,'target_requests':0,'replay_jobs_submitted':0,
            'new_license_terms_accepted':False,'network':namespace_probe()}
    token=secrets.token_hex(32)
    environment={'PATH':'/opt/java/bin:/usr/bin','LANG':'C.UTF-8','HOME':'/work/home',
        'ARIA_BURP_CONNECTOR_TOKEN':token,'ARIA_BURP_TARGETS':'192.0.2.1',
        'ARIA_BURP_STATE_FILE':'/work/replay.properties','ARIA_NATIVE_PROBE_OUTPUT':'/work'}
    config=output/'project.json'
    config.write_text(json.dumps({'proxy':{'request_listeners':[]}}))
    command=['/opt/java/bin/java','-Xmx768m','-Djava.awt.headless=true','-Duser.home=/work/home',
        '-Djava.util.prefs.userRoot=/work/prefs','-cp','/probe/burp.jar:/probe/classes',
        'burp.StartBurp','--use-defaults','--disable-auto-update','--data-dir=/work/data',
        '--config-file=/work/project.json','--developer-extension-class-name=aria.NativeCommunityProbe']
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    calls=[]
    def request(path,form=None,*,authorized=True,origin=None):
        headers={'Authorization':'Bearer '+(token if authorized else 'invalid-fixture')}
        if origin:headers['Origin']=origin
        req=urllib.request.Request('http://127.0.0.1:17777'+path,
            data=urllib.parse.urlencode(form).encode() if form is not None else None,headers=headers)
        try:
            with client.open(req,timeout=4) as response:
                data=response.read(131073)
                if len(data)>131072:raise RuntimeError('Connector response exceeds probe bound')
                status=response.status
        except urllib.error.HTTPError as error:
            status=error.code;data=error.read(131073)
        calls.append({'path':path,'method':'POST' if form is not None else 'GET','status':status})
        return status,json.loads(data) if data else None
    process=None
    started=time.monotonic()
    try:
        with (output/'native-runtime.log').open('w') as log:
            process=subprocess.Popen(command,env=environment,stdin=subprocess.DEVNULL,stdout=log,
                                     stderr=subprocess.STDOUT,start_new_session=True)
            deadline=time.monotonic()+50
            while time.monotonic()<deadline:
                if process.poll() is not None:raise RuntimeError('Native runtime exited before readiness; inspect private log')
                try:
                    status,capabilities=request('/capabilities')
                    if status==200:break
                except (OSError,urllib.error.URLError,ValueError):pass
                time.sleep(.25)
            else:raise RuntimeError('Native readiness unavailable; no EULA prompt was accepted')
            assert capabilities['edition']=='COMMUNITY' and capabilities['repeater_staging'] is True
            assert request('/capabilities',authorized=False)[0]==403
            assert request('/capabilities',origin='http://untrusted.invalid')[0]==403
            assert request('/history')==(200,{'captures':[]})
            assert request('/history/selected',{'ids':'a'*64})[0]==422
            raw=b'GET /synthetic-review HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n'
            form={'url':'http://192.0.2.1/synthetic-review','request_b64':base64.b64encode(raw).decode(),
                  'evidence_id':str(uuid.uuid4())}
            expected=(200,{'status':'staged','network_request_sent':False})
            assert request('/repeater',form)==expected
            assert request('/repeater',form)==expected
            assert request('/repeater',{**form,'url':'http://198.51.100.1/'})[0]==422
            version=json.loads((output/'native-version.json').read_text())
            count=json.loads((output/'native-request-count.json').read_text())
            assert version['edition']=='COMMUNITY_EDITION'
            # buildNumber() is an opaque version-comparison value, not the
            # manifest's legacy build string. Do not parse its numeric format.
            assert version['build']=='36507',version
            assert count['burp_http_requests']==0,count
            result.update({'status':'passed','native_version':version,'native_request_counter':count,
                'checks':['native_version_api','actual_extension_initialization','authenticated_capabilities',
                    'invalid_auth_denied','origin_denied','native_empty_history',
                    'missing_history_selection_denied','passive_repeater_staging',
                    'duplicate_staging_receipt','other_target_staging_denied','zero_native_http_dispatch'],
                'limitations':['No live Proxy capture, replay, Scanner, Decoder, Comparer or site-map coverage is inferred.',
                    'Headless native Montoya compatibility, not graphical desktop-launcher repair.',
                    'HTTP handler count covers Burp HTTP dispatch; namespace isolation independently prevents external network access.']})
    except Exception as error:
        result['error_type']=type(error).__name__
        result['error']=str(error)[:300]
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)
        result.update({'elapsed_seconds':time.monotonic()-started,'connector_requests':calls,
                       'observed_at':datetime.now(timezone.utc).isoformat()})
        (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result.get(k) for k in ('status','native_version','checks','error','elapsed_seconds')}),flush=True)
    return 0 if result['status']=='passed' else 1


def run(output: Path) -> int:
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    work=output/'runtime';work.mkdir(mode=0o700)
    classes=output/'classes';classes.mkdir()
    artifact=ROOT/'.local-lab/burpsuite-community-2025.2.jar'
    api=ROOT/'.local-lab/montoya-api-2025.2.jar'
    known=json.loads((ROOT/'docs/competence/burp.json').read_text())['compatibility']
    if digest(artifact)!=known['retained_jar_sha256'] or digest(api)!=known['compile_api_sha256']:
        raise RuntimeError('Refusing unknown native/API artifacts')
    java_home=Path(shutil.which('java')).resolve().parent.parent
    sources=[ROOT/'burp-community/src/aria/CommunityExtension.java',
             ROOT/'burp-community/src/aria/ReplayBoundary.java',ROOT/'integration/java/NativeCommunityProbe.java']
    subprocess.run([str(java_home/'bin/javac'),'--release','17','-cp',str(api),'-d',str(classes),
                    *map(str,sources)],check=True)
    # Preserve only an existing consent preference verbatim; never synthesize or
    # update acceptance, and never copy the rest of the private Burp preferences.
    original=ROOT/'.local-lab/burp-runtime/prefs/.java/.userPrefs/burp/prefs.xml'
    prefs=ET.parse(original).getroot()
    consent=[entry for entry in prefs.findall('entry') if entry.get('key')=='eulacommunity']
    if len(consent)!=1:raise RuntimeError('Existing Community consent preference unavailable')
    minimal=ET.Element('map',prefs.attrib);minimal.append(consent[0])
    destination=work/'prefs/.java/.userPrefs/burp/prefs.xml'
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE map SYSTEM "http://java.sun.com/dtd/preferences.dtd">\n'+ET.tostring(minimal,encoding='utf-8'))
    (work/'home').mkdir()
    provenance={'artifact_sha256':digest(artifact),'api_sha256':digest(api),
                'source_sha256':{str(p.relative_to(ROOT)):digest(p) for p in [*sources,Path(__file__)]},
                'existing_consent_source_sha256':digest(original),'existing_consent_reused_verbatim':True,
                'new_terms_accepted':False,'source_deployed':False}
    (output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    command=['bwrap','--die-with-parent','--unshare-net','--unshare-pid',
        '--ro-bind','/usr','/usr','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev',
        '--tmpfs','/tmp','--ro-bind',str(java_home),'/opt/java','--ro-bind',str(artifact),'/probe/burp.jar',
        '--ro-bind',str(classes),'/probe/classes','--ro-bind',str(Path(__file__).resolve()),'/probe/run.py',
        '--bind',str(work),'/work','--chdir','/work','--clearenv','--setenv','PATH','/usr/bin:/opt/java/bin',
        '/usr/bin/python3.11','/probe/run.py','--inside']
    completed=subprocess.run(command,cwd=ROOT,timeout=80)
    return completed.returncode


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.inside:raise SystemExit(inside())
    if not args.output:parser.error('--output is required')
    raise SystemExit(run(args.output))


if __name__=='__main__':
    main()
