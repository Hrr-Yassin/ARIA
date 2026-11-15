"""Owner-approved metadata-only Kali maintenance through the existing guest agent.

Never imported by the application. Only worker/app.py may change. Existing
service identity, policy/credential environment, tools, images and networking
must remain unchanged. No image build, tool execution or VM configuration occurs.
The owner explicitly approved this exact source update and worker restart.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import time
import uuid

from deploy.lab.kali_guest import KaliGuest, WORKER_ROOT

BASE_SHA = '1590a9fc1fa6c32b359fc20b0a6987570bc2453ac70ec532a15e6ed69368007a'
APPROVED_SHA = 'c82ab818403e400152dd7cd1d190c18425938d08d8a20b35742455969f99f11e'
REMOTE = r'''
import hashlib,json,os,re,shutil,subprocess,time
from pathlib import Path
unit='aria-kali-worker.service'
p=Path('/home/kali/.local/share/aria-worker/app/worker/app.py')
staged=Path(__STAGE__)
backup=Path(__BACKUP__)
result={'status':'IN_PROGRESS','scope':'metadata-only capabilities','tool_operations':0}
changed=False
def properties():
 return dict(line.split('=',1) for line in subprocess.check_output(['systemctl','show',unit,'-p','MainPID','-p','ActiveState','-p','User','-p','Group','-p','WorkingDirectory'],text=True).splitlines())
def environ(pid):
 raw=Path(f'/proc/{pid}/environ').read_bytes()
 return dict(item.decode().split('=',1) for item in raw.split(b'\0') if b'=' in item)
def security(pid):
 return {k:v.strip() for line in Path(f'/proc/{pid}/status').read_text().splitlines()
  for k,_,v in [line.partition(':')] if k in ('Uid','Gid','Groups','CapEff','NoNewPrivs','Seccomp')}
def selected(env):
 return {k:v for k,v in env.items() if k.startswith(('WORKER_','HTTP_','SPECIALIST_'))}
def fingerprint(env):
 safe={k:v for k,v in selected(env).items() if not re.search('TOKEN|PASSWORD|SECRET|KEY|DATABASE',k)}
 return hashlib.sha256(json.dumps(safe,sort_keys=True).encode()).hexdigest()
def restart():
 subprocess.run(['systemctl','restart',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=20)
 deadline=time.monotonic()+20
 while time.monotonic()<deadline:
  props=properties()
  if props['ActiveState']=='active' and int(props['MainPID'])>0:return props
  time.sleep(.2)
 raise TimeoutError('Worker startup deadline')
try:
 if p.is_symlink() or not p.resolve().is_relative_to(Path('/home/kali/.local/share/aria-worker').resolve()):raise ValueError('Unexpected worker source path')
 old=properties();pid=int(old['MainPID'])
 if old['User']!='kali' or old['WorkingDirectory']!=str(p.parents[1]):raise ValueError('Unexpected service identity')
 old_env=environ(pid);old_security=security(pid);stat=p.stat()
 if hashlib.sha256(p.read_bytes()).hexdigest()!=__BASE_SHA__:raise ValueError('Worker source differs from reviewed baseline')
 if hashlib.sha256(staged.read_bytes()).hexdigest()!=__NEW_SHA__:raise ValueError('Staged source differs from approved metadata patch')
 compile(staged.read_bytes(),str(p),'exec')
 query="""import asyncio,json,os
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
async def main():
 e=create_async_engine(os.environ['WORKER_DATABASE_URL'],connect_args={'timeout':5})
 try:
  async with e.connect() as c:
   n=await c.scalar(text("SELECT count(*) FROM aria_worker_jobs WHERE record->>'state' NOT IN ('succeeded','failed','cancelled')"))
   print(json.dumps({'active':n}))
 finally:await e.dispose()
try:asyncio.run(main())
except Exception as exc:print(json.dumps({'error_type':type(exc).__name__}));raise SystemExit(1)
"""
 q=subprocess.run(['/usr/sbin/runuser','-u','kali','--','/usr/bin/python3','-c',query],
  env={'PATH':'/usr/bin:/bin','WORKER_DATABASE_URL':old_env['WORKER_DATABASE_URL']},
  stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=15)
 if q.returncode or json.loads(q.stdout).get('active')!=0:raise RuntimeError('Worker has active or unverified jobs')
 shutil.copy2(p,backup);os.chown(backup,stat.st_uid,stat.st_gid)
 os.chown(staged,stat.st_uid,stat.st_gid);os.chmod(staged,stat.st_mode&0o777)
 os.replace(staged,p);changed=True
 new=restart();new_pid=int(new['MainPID']);new_env=environ(new_pid)
 same_identity=all(old[k]==new[k] for k in ('User','Group','WorkingDirectory'))
 same_environment=selected(old_env)==selected(new_env)
 same_security=old_security==security(new_pid)
 if not(same_identity and same_environment and same_security):raise RuntimeError('Worker configuration or security identity changed')
 result.update(status='APPLIED',source_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
  old_pid=pid,new_pid=new_pid,service_identity_unchanged=same_identity,
  policy_and_credentials_unchanged=same_environment,process_security_unchanged=same_security,
  policy_fingerprint_before=fingerprint(old_env),policy_fingerprint_after=fingerprint(new_env),
  source_backup=str(backup),source_uid=p.stat().st_uid,source_gid=p.stat().st_gid,source_mode=p.stat().st_mode&0o777)
except Exception as exc:
 result.update(status='FAILED',error_type=type(exc).__name__)
 if changed:
  try:
   rollback=p.with_name(p.name+'.metadata-rollback')
   shutil.copy2(backup,rollback);os.chown(rollback,stat.st_uid,stat.st_gid)
   os.replace(rollback,p);restart();result['source_rolled_back']=True
  except Exception as rollback_error:result['rollback_error_type']=type(rollback_error).__name__
print(json.dumps(result))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply-owner-approved', action='store_true')
    args = parser.parse_args()
    if not args.apply_owner_approved:
        parser.error('Explicit owner approval and --apply-owner-approved are required')
    source = Path('worker/app.py')
    if hashlib.sha256(source.read_bytes()).hexdigest() != APPROVED_SHA:
        raise RuntimeError('Local worker file differs from the reviewed metadata-only patch')
    run = uuid.uuid4().hex[:12]
    directory = Path('.local-lab/operational-reliability') / ('kali-metadata-deploy-' + run)
    directory.mkdir(mode=0o700)
    staged = WORKER_ROOT + 'app/worker/.app.py.metadata-' + run
    backup = WORKER_ROOT + 'app/worker/.app.py.before-metadata-' + run
    code = REMOTE.replace('__STAGE__', repr(staged)).replace('__BACKUP__', repr(backup)).replace(
        '__BASE_SHA__', repr(BASE_SHA)).replace('__NEW_SHA__', repr(APPROVED_SHA))
    guest = KaliGuest()
    try:
        count = guest.upload(source, staged)
        print(json.dumps({'status': 'STAGED', 'bytes': count, 'directory': str(directory)}), flush=True)
        result = guest.execute(code, timeout=30)
        (directory / 'remote-result.json').write_text(json.dumps(result, indent=2) + '\n')
        if result.get('running'):
            print(json.dumps({'status': 'PENDING', 'guest_pid': result['pid'], 'directory': str(directory)}), flush=True)
            # Observe the same maintenance process; never re-upload/restart on a timeout.
            while not result.get('exited'):
                time.sleep(.5)
                result = guest.agent({'execute': 'guest-exec-status', 'arguments': {'pid': result['pid']}})
                if not result.get('exited'):
                    result['pid'] = json.loads((directory / 'remote-result.json').read_text())['pid']
            for src, dst in [('out-data', 'stdout'), ('err-data', 'stderr')]:
                result[dst] = base64.b64decode(result.pop(src, '')).decode(errors='replace')
        (directory / 'remote-result.json').write_text(json.dumps(result, indent=2) + '\n')
        body = json.loads(result.get('stdout', '{}'))
        print(json.dumps({'directory': str(directory), **body}), flush=True)
        return 0 if body.get('status') == 'APPLIED' else 1
    finally:
        guest.close()


if __name__ == '__main__':
    raise SystemExit(main())
