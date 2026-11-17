"""Read-only local infrastructure observation; never restart, submit or replay work."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import httpx


def assess(sample: dict, previous: dict | None = None) -> dict:
    """Classify point evidence without inferring uptime across observations."""
    reasons=[]
    units=sample.get('units',{})
    containers=sample.get('containers',{})
    api=units.get('aria.service',{})
    database=containers.get('aria-postgres',{})
    cache=containers.get('aria-redis',{})
    readiness=sample.get('readiness',{})
    unavailable=False
    if sample.get('observation_errors'):
        reasons.append('observation_incomplete');unavailable=True
    if api.get('ActiveState')!='active':
        reasons.append('controller_not_active');unavailable=True
    if database.get('running') is not True:
        reasons.append('postgres_not_running');unavailable=True
    if readiness.get('http_status')!=200 or readiness.get('database') is not True:
        reasons.append('required_readiness_unavailable');unavailable=True
    if cache.get('running') is not True or readiness.get('cache') is not True:
        reasons.append('optional_cache_unavailable')
    if units.get('aria-lab-dependencies.service',{}).get('ActiveState')!='active':
        reasons.append('dependency_unit_not_active')
    suspended=None
    same_boot=bool(previous and previous.get('boot_id')==sample.get('boot_id'))
    if same_boot:
        suspended=max(0,(sample['boottime_seconds']-previous['boottime_seconds'])
            -(sample['monotonic_seconds']-previous['monotonic_seconds']))
        old_count=int(previous.get('units',{}).get('aria.service',{}).get('NRestarts','0'))
        if int(api.get('NRestarts','0'))>old_count:reasons.append('controller_restart_observed')
    elif int(api.get('NRestarts','0'))>0:
        reasons.append('controller_restart_counter_nonzero')
    return {**sample,'status':'UNAVAILABLE' if unavailable else 'DEGRADED' if reasons else 'READY',
        'reason_codes':reasons,'same_boot_as_previous':same_boot,
        'measured_suspended_since_previous_seconds':suspended,
        'continuous_availability_verified':False,
        'scope':'Local point readiness/process observations only;gaps and host sleep do not prove availability.',
        'automatic_restart_dispatch_replay_operations':0}


def collect() -> dict:
    start=time.monotonic()
    sample={'observed_at':datetime.now(timezone.utc).isoformat(),
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'monotonic_seconds':time.monotonic(),'boottime_seconds':time.clock_gettime(time.CLOCK_BOOTTIME),
        'units':{},'containers':{},'readiness':{},'observation_errors':[]}
    try:
        result=subprocess.run(['systemctl','--user','show','aria.service','aria-lab-dependencies.service',
            '-p','Id','-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts'],
            capture_output=True,text=True,timeout=3,check=True)
        for block in result.stdout.strip().split('\n\n'):
            fields=dict(line.split('=',1) for line in block.splitlines())
            sample['units'][fields['Id']]=fields
    except Exception as error:sample['observation_errors'].append({'stage':'systemd','error_type':type(error).__name__})
    try:
        template='{"name":"{{.Name}}","id":"{{.Id}}","running":{{.State.Running}},"exit_code":{{.State.ExitCode}},"oom_killed":{{.State.OOMKilled}},"restart_count":{{.RestartCount}}}'
        result=subprocess.run(['podman','inspect','--format',template,'aria-postgres','aria-redis'],
            capture_output=True,text=True,timeout=3,check=True)
        sample['containers']={r['name'].lstrip('/'):r for line in result.stdout.splitlines() for r in [json.loads(line)]}
    except Exception as error:sample['observation_errors'].append({'stage':'containers','error_type':type(error).__name__})
    try:
        with httpx.Client(timeout=3,trust_env=False,follow_redirects=False) as client:
            response=client.get('http://127.0.0.1:7000/api/ready')
        data=response.json()
        sample['readiness']={'http_status':response.status_code,'database':data.get('database'),
            'cache':data.get('cache'),'degraded':data.get('degraded'),
            'build':response.headers.get('X-ARIA-Build')}
    except Exception as error:sample['observation_errors'].append({'stage':'readiness','error_type':type(error).__name__})
    sample['collection_seconds']=time.monotonic()-start
    return sample


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    args=parser.parse_args()
    args.state.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if args.state.is_symlink():raise ValueError('Linked observation state refused')
    old=json.loads(args.state.read_text()) if args.state.exists() else None
    if old is not None and (old.get('schema')!='aria.infrastructure.observation.v1'
            or type(old.get('samples')) is not int or not isinstance(old.get('latest'),dict)):
        raise ValueError('Invalid prior observation state;retain for inspection')
    current=assess(collect(),old['latest'] if old else None)
    events=list(old.get('recent_events',[])) if old else []
    if current['reason_codes'] or (current['measured_suspended_since_previous_seconds'] or 0)>1:
        events.append({k:current[k] for k in ('observed_at','boot_id','status','reason_codes',
            'measured_suspended_since_previous_seconds')})
    state={'schema':'aria.infrastructure.observation.v1','samples':old['samples']+1 if old else 1,
        'latest':current,'recent_events':events[-50:],'maximum_retained_events':50}
    temporary=args.state.with_name(args.state.name+'.'+uuid.uuid4().hex+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as file:file.write(json.dumps(state,indent=2)+'\n')
    os.replace(temporary,args.state)
    print(json.dumps({'status':current['status'],'reason_codes':current['reason_codes'],
        'collection_seconds':current['collection_seconds'],'samples':state['samples'],
        'automatic_restart_dispatch_replay_operations':0}))
    return 0


if __name__=='__main__':raise SystemExit(main())
