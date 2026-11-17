"""Bounded PostgreSQL/Redis failure tests on newly owned rootless containers.

Uses cached images only. Never modifies an owner container or database. Retains
private logs and stopped disposable containers; no worker/model/target request.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {'postgres':'eee71f45c6dfebd5d85644a85eb955b1f27d84ea4edccf9e21f51761cbed3818',
          'redis':'2724e40d4303391e1a46884134da358e20a6d0b03f32ee6c412079ddb4ac6783'}


def command(args: list[str], timeout: int = 30) -> str:
    result = subprocess.run(args,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                            text=True,timeout=timeout)
    if result.returncode:
        raise RuntimeError('Disposable infrastructure command failed')
    return result.stdout.strip()


def owner_state() -> dict:
    rows=json.loads(command(['podman','inspect','aria-postgres','aria-redis']))
    return {r['Name']:{'id':r['Id'],'pid':r['State']['Pid'],
                     'started_at':r['State']['StartedAt']} for r in rows}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',choices=('postgres','redis','both'),default='both')
    args=parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    run_id=uuid.uuid4().hex[:12]
    output=ROOT/'.local-lab/operational-reliability'/('infrastructure-'+run_id)
    output.mkdir(mode=0o700,parents=True)
    report={'run_id':run_id,'started_at':datetime.now(timezone.utc).isoformat(),
        'status':'IN_PROGRESS','synthetic':True,'case':args.case,
        'provider_worker_target_operations':0,'containers':{},'owner_objects_modified':False}
    before=owner_state()
    pg_password,redis_password=secrets.token_hex(24),secrets.token_hex(24)
    pg_env=output/'postgres.env';pg_env.write_text('POSTGRES_USER=aria_infra\nPOSTGRES_DB=aria_infra_test\nPOSTGRES_PASSWORD='+pg_password+'\n');pg_env.chmod(0o600)
    redis_config=output/'redis.conf'
    redis_config.write_text('bind 0.0.0.0\nprotected-mode yes\nsave ""\nappendonly no\nrequirepass '+redis_password+'\n')
    # Parent directory is private; the mounted file is readable by the image's
    # unprivileged Redis user without putting its password in process arguments.
    redis_config.chmod(0o444)
    ids={}
    code=1
    try:
        for kind,image in IMAGES.items():
            assert command(['podman','image','inspect',image,'--format','{{.ID}}'])==image
            name='aria-infra-'+kind+'-'+run_id
            create=['podman','run','--detach','--pull=never','--name',name,
                '--label','aria.infrastructure.run='+run_id,'--memory','256m' if kind=='postgres' else '128m',
                '--cpus','1','--pids-limit','256','--security-opt','no-new-privileges',
                '--publish','127.0.0.1::'+('5432' if kind=='postgres' else '6379')]
            if kind=='postgres':create+=['--env-file',str(pg_env),image]
            else:create+=['--volume',str(redis_config)+':/usr/local/etc/redis/aria.conf:ro,Z',image,
                          'redis-server','/usr/local/etc/redis/aria.conf']
            identifier=command(create);ids[kind]=identifier
            row=json.loads(command(['podman','inspect',identifier]))[0]
            binding=row['HostConfig']['PortBindings'][('5432' if kind=='postgres' else '6379')+'/tcp'][0]
            assert binding['HostIp']=='127.0.0.1' and row['Config']['Labels']['aria.infrastructure.run']==run_id
            report['containers'][kind]={'id':identifier,'name':name,'image':image,'port':int(binding['HostPort'])}
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            ready=subprocess.run(['podman','exec',ids['postgres'],'pg_isready','-U','aria_infra','-d','aria_infra_test'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
            if ready.returncode==0:break
            time.sleep(.2)
        else:raise RuntimeError('Disposable PostgreSQL readiness deadline')
        pg_port=report['containers']['postgres']['port'];redis_port=report['containers']['redis']['port']
        from cryptography.fernet import Fernet
        env={**os.environ,'SECRET_KEY':secrets.token_hex(32),'KALI_AGENT_TOKEN':secrets.token_hex(32),
            'FERNET_KEY':Fernet.generate_key().decode(),'FERNET_PREVIOUS_KEYS':'[]',
            'DATABASE_URL':f'postgresql+asyncpg://aria_infra:{pg_password}@127.0.0.1:{pg_port}/aria_infra_test',
            'REDIS_URL':f'redis://:{redis_password}@127.0.0.1:{redis_port}/15',
            'ARIA_INFRA_RECOVERY':'1','ARIA_INFRA_RUN_ID':run_id,
            'ARIA_INFRA_ARTIFACT_DIR':str(output),'ARIA_INFRA_POSTGRES_ID':ids['postgres'],
            'ARIA_INFRA_REDIS_ID':ids['redis'],'KALI_AGENT_URL':'','LLM_ROUTING':'local',
            'REPORT_OUTPUT_DIR':str(output/'reports'),'DEBUG':'false'}
        selected='integration.test_infrastructure_recovery.InfrastructureRecovery'
        suffix={'postgres':'.test_postgres_restart_validates_idle_pool_before_first_statement',
                'redis':'.test_redis_loss_preserves_sql_commits_and_recovers_without_api_restart','both':''}[args.case]
        with (output/'tests.log').open('w') as log:
            migration=subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,env=env,
                stdout=log,stderr=subprocess.STDOUT,timeout=30)
            if migration.returncode:raise RuntimeError('Disposable migration failed')
            result=subprocess.run([sys.executable,'-m','unittest',selected+suffix,'-v'],cwd=ROOT,env=env,
                stdout=log,stderr=subprocess.STDOUT,timeout=90)
        code=result.returncode
        report.update(status='VERIFIED' if code==0 else 'FAILED',exit_code=code,
                      log_sha256=hashlib.sha256((output/'tests.log').read_bytes()).hexdigest())
    except Exception as error:
        report.update(status='FAILED',error_type=type(error).__name__)
    except KeyboardInterrupt:
        report.update(status='CANCELLED',reason='process_signal_or_interrupt');code=130
    finally:
        for identifier in ids.values():
            row=json.loads(command(['podman','inspect',identifier]))[0]
            if row['Config']['Labels'].get('aria.infrastructure.run')!=run_id:
                raise RuntimeError('Refusing cleanup of unowned container')
            command(['podman','stop','--time','2',identifier])
        after=owner_state();report['owner_container_pids_and_start_times_unchanged']=after==before
        if after!=before:report['status']='FAILED';code=1
        report.update(finished_at=datetime.now(timezone.utc).isoformat(),directory=str(output.relative_to(ROOT)),
            source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (
                'memory/database_models.py','memory/session_manager.py','api/main.py',
                'integration/infrastructure_recovery.py','integration/test_infrastructure_recovery.py')})
        if (output/'tests.log').exists():
            (output/'tests.log').chmod(0o600)
        (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    return code if report['status']=='VERIFIED' else 1


if __name__=='__main__':
    raise SystemExit(main())
