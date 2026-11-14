"""Authenticated API harness for the specifically authorized isolated ARIA lab.

No model responses or tool actions are supplied by this harness. The server plans
and executes; required human approvals must be submitted through the ordinary UI.
Use a private JSON token file containing {"token": "..."}; never commit it.
"""
import argparse
import asyncio
import json
from pathlib import Path
import time
import httpx


async def run(args):
    token=json.loads(args.token_file.read_text())['token']
    args.output.mkdir(parents=True,exist_ok=True)
    async with httpx.AsyncClient(base_url=args.api_url,timeout=30,trust_env=False,follow_redirects=False,
            headers={'Authorization':'Bearer '+token}) as client:
        session_id=args.session_id
        if not session_id:
            response=await client.post('/api/session/new',json={
                'target':'192.168.77.20','name':'Autonomous intelligence acceptance',
                'scope':{'targets':['192.168.77.20'],'ports':[21,22,80,139,445],'exclusions':[]}})
            response.raise_for_status();session_id=response.json()['session_id']
            response=await client.post(f'/api/pentest/{session_id}/autonomous/start',json={
                'goal':'discovery','max_steps':3,'auto_risk_threshold':'green_orange',
                'objective':'Perform bounded TCP and HTTP discovery. Interpret receipt-backed evidence, keep vulnerability hypotheses unverified, and propose safe follow-up investigations.'})
            response.raise_for_status()
        deadline=time.monotonic()+900
        try:
            while time.monotonic()<deadline:
                response=await client.get(f'/api/pentest/{session_id}/autonomous/status')
                response.raise_for_status();status=response.json()
                (args.output/f'{session_id}.json').write_text(json.dumps(status,indent=2))
                print(session_id,status.get('run_state'),status.get('successful_steps'),flush=True)
                if not status.get('active'):
                    usage=await client.get(f'/api/team/{session_id}/model-budget');usage.raise_for_status()
                    (args.output/f'{session_id}-usage.json').write_text(json.dumps(usage.json(),indent=2))
                    if status.get('run_state')!='completed':raise RuntimeError('Investigation did not complete')
                    if not any(event.get('type')=='investigation_review' for event in status.get('activity_tail',[])):
                        raise RuntimeError('Completed run lacks evidence review')
                    return
                await asyncio.sleep(5)
            raise TimeoutError('Bounded laboratory run deadline exceeded')
        finally:
            if time.monotonic()>=deadline:
                response=await client.post(f'/api/pentest/{session_id}/autonomous/stop')
                response.raise_for_status()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--api-url',choices=['http://127.0.0.1:7000','http://127.0.0.1:7002'],default='http://127.0.0.1:7002')
    parser.add_argument('--token-file',type=Path,required=True)
    parser.add_argument('--session-id',default='')
    parser.add_argument('--output',type=Path,default=Path('.local-lab/intelligence'))
    asyncio.run(run(parser.parse_args()))


if __name__=='__main__':main()
