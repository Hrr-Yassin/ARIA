"""Back up the owner DB and migrate a uniquely named staging restore only.
Never runs owner DDL, deletes records, resets credentials or prints a connection URL.
"""
import asyncio
import hashlib
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from config.settings import settings

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/upgrade-stage'


async def fingerprint(url):
    engine=create_async_engine(url,echo=False)
    try:
        async with engine.connect() as connection:
            counts={table:await connection.scalar(text('SELECT count(*) FROM '+table)) for table in
                ['users','user_api_keys','pentest_sessions','chat_logs','findings','audit_logs','decision_logs']}
            keys=(await connection.execute(text('SELECT id,provider,encrypted_key,requests_used FROM user_api_keys ORDER BY id'))).all()
            accounts=(await connection.execute(text('SELECT id,password_hash FROM users ORDER BY id'))).all()
            credentials=hashlib.sha256(json.dumps({'keys':[list(row) for row in keys],'accounts':[list(row) for row in accounts]},default=str).encode()).hexdigest()
            owner=await connection.scalar(text("SELECT id FROM users WHERE username='labadmin'"))
            revision=await connection.scalar(text('SELECT version_num FROM alembic_version'))
            return {'records':counts,'credential_fingerprint':credentials,'connector_user_id':owner,'revision':revision}
    finally: await engine.dispose()


async def main():
    if os.environ.get('ARIA_STAGE_UPGRADE')!='1': raise SystemExit('Set ARIA_STAGE_UPGRADE=1 to back up and restore into a fresh staging DB')
    os.umask(0o077); OUTPUT.mkdir(mode=0o700,exist_ok=True)
    url=make_url(settings.DATABASE_URL)
    if url.database!='aria': raise RuntimeError('Expected the documented owner database aria')
    before=await fingerprint(settings.DATABASE_URL)
    stamp=datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    name='aria_upgrade_'+stamp+'_test'
    backup=OUTPUT/('aria_before_0003_'+stamp+'.dump')
    with backup.open('xb') as file:
        subprocess.run(['podman','exec','aria-postgres','pg_dump','-U',url.username,'-d','aria','-Fc'],stdout=file,check=True)
    with backup.open('rb') as file:
        subprocess.run(['podman','exec','-i','aria-postgres','pg_restore','--list'],stdin=file,stdout=subprocess.DEVNULL,check=True)
    subprocess.run(['podman','exec','aria-postgres','createdb','-U',url.username,name],check=True)
    with backup.open('rb') as file:
        subprocess.run(['podman','exec','-i','aria-postgres','pg_restore','--exit-on-error','--no-owner','-U',url.username,'-d',name],stdin=file,check=True)
    staging=url.set(database=name).render_as_string(hide_password=False)
    restored=await fingerprint(staging)
    assert before['records']==restored['records'] and before['credential_fingerprint']==restored['credential_fingerprint']
    env={**os.environ,'DATABASE_URL':staging,'REDIS_URL':make_url(settings.REDIS_URL).set(database='15').render_as_string(hide_password=False)}
    for args in [('upgrade','head'),('check',)]: subprocess.run([str(ROOT/'.venv/bin/python'),'-B','-m','alembic',*args],cwd=ROOT,env=env,check=True)
    upgraded=await fingerprint(staging); owner_after=await fingerprint(settings.DATABASE_URL)
    assert upgraded['revision']=='0003'
    assert upgraded['records']==before['records'] and upgraded['credential_fingerprint']==before['credential_fingerprint']
    assert owner_after['revision']==before['revision'] and owner_after['credential_fingerprint']==before['credential_fingerprint']
    report={'database':name,'backup':str(backup),'owner_before':before,'staging_after':upgraded,
        'owner_unchanged':owner_after==before,'restored_records_preserved':True,'encrypted_credentials_preserved':True}
    (OUTPUT/'metadata.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({'staging_database':name,'revision':upgraded['revision'],'records_preserved':True,'credentials_preserved':True,'owner_revision':owner_after['revision']},indent=2))


if __name__=='__main__': asyncio.run(main())
