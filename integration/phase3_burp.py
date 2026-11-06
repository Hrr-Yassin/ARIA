"""Opt-in real Community gate using disposable SQL and the documented lab VM.

Starts the isolated target only when off and restores that state afterward.
ARIA_PHASE3_BURP=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=sha256:... \
  .venv/bin/python -m integration.phase3_burp
"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/phase3'
VM = 'aria-metasploitable2'


def virsh(*args):
    return subprocess.check_output(['virsh','-c','qemu:///system',*args],text=True,timeout=20).strip()


def main():
    if os.environ.get('ARIA_PHASE3_BURP') != '1':
        raise SystemExit('Set ARIA_PHASE3_BURP=1 for the isolated Community acceptance gate')
    from integration.test_worker import WorkerLab
    from sqlalchemy.engine import make_url
    from cryptography.fernet import Fernet
    interfaces=ET.fromstring(virsh('dumpxml',VM)).findall('./devices/interface')
    network=ET.fromstring(virsh('net-dumpxml','aria-lab'))
    if len(interfaces)!=1 or interfaces[0].find('source').get('network')!='aria-lab' or network.find('forward') is not None:
        raise SystemExit('Refusing a target outside its documented isolated network')
    state=virsh('domstate',VM)
    if state not in {'running','shut off'}:
        raise SystemExit('Target must be running or shut off')
    started_here=state=='shut off' or os.environ.get('ARIA_PHASE3_TARGET_STARTED')=='1'
    OUTPUT.mkdir(mode=0o700,parents=True,exist_ok=True)
    (OUTPUT/'burp.json').write_text(json.dumps({'status':'running'}))
    try:
        if state=='shut off':
            virsh('start',VM)
        WorkerLab.setUpClass()
        WorkerLab.cli('exec',WorkerLab.containers[0],'createdb','-U','postgres','aria_test')
        deadline=time.monotonic()+45
        while True:
            try:
                with socket.create_connection(('192.168.77.20',80),timeout=1):
                    break
            except OSError:
                if time.monotonic()>=deadline:
                    raise RuntimeError('Isolated target TCP80 did not become ready')
                time.sleep(1)
        env={**os.environ,'ARIA_BURP_RUNTIME':'1','DEBUG':'false',
             'DATABASE_URL':make_url(WorkerLab.url).set(database='aria_test').render_as_string(hide_password=False),
             'SECRET_KEY':secrets.token_hex(32),'FERNET_KEY':Fernet.generate_key().decode(),
             'KALI_AGENT_TOKEN':secrets.token_hex(32),'HTTP_REPLAY_KEY':'','BROWSER_MAPPING_ENABLED':'false',
             'ARIA_EMBEDDING_MODEL_PATH':'','REDIS_URL':'redis://127.0.0.1:1/15'}
        # The child uses the same migration head as the application, in fresh SQL.
        with (OUTPUT/'burp-migrations.log').open('w') as log:
            subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,env=env,
                           stdout=log,stderr=log,check=True)
        with (OUTPUT/'burp.log').open('w') as log:
            subprocess.run([sys.executable,'-m','integration.run_burp_runtime'],cwd=ROOT,env=env,
                           stdout=log,stderr=log,check=True)
        report=json.loads((ROOT/'.local-lab/burp-runtime/report.json').read_text())
        required={'official_community_extension_load','real_proxy_capture','selected_import_and_duplicates','real_repeater_staging'}
        if any(report['results'].get(key)!='passed' for key in required):
            raise RuntimeError('Real Community capture/Repeater acceptance did not pass')
        result={'status':'passed','checks':report['results'],'target':'192.168.77.20','port':80,
                'target_request_upper_bound':report['target_request_upper_bound'],'live_model_calls':0,
                'owner_database_accessed':False,'disposable_sql':True,'limitations':report['limitations']}
        (OUTPUT/'burp.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(result))
    except BaseException as exc:
        (OUTPUT/'burp.json').write_text(json.dumps({'status':'failed','error_type':type(exc).__name__},indent=2))
        raise
    finally:
        if hasattr(WorkerLab,'containers') and hasattr(WorkerLab,'network'):
            WorkerLab.cleanup()
        if started_here and virsh('domstate',VM)!='shut off':
            virsh('shutdown',VM)
            deadline=time.monotonic()+45
            while virsh('domstate',VM)!='shut off':
                if time.monotonic()>=deadline:
                    raise RuntimeError('Graceful target shutdown is pending; no forced power-off was performed')
                time.sleep(1)


if __name__=='__main__':main()
