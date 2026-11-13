"""Prepare minimal, secret-free build contexts and complete Python wheel locks."""
import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]
FILES=['worker/__init__.py','worker/policy.py','worker/container_entry.py','worker/http_profile.py',
       'worker/http_runner.py','config/__init__.py','config/security_tool_registry.py',
       'config/security_tools.json','orchestrator/__init__.py','orchestrator/execution_policy.py',
       'orchestrator/program_scope.py']
TOOLS=('nmap','httpx','katana','playwright','nuclei','zap','ffuf','sqlmap','semgrep','subfinder')
PYTHON_COMPATIBILITY_PINS={'setuptools':'80.9.0'}


def wheel_lock(directory: Path, destination: Path) -> None:
    rows=[]
    for path in sorted(directory.glob('*.whl')):
        with zipfile.ZipFile(path) as archive:
            metadata=BytesParser().parsebytes(archive.read(next(name for name in archive.namelist() if name.endswith('.dist-info/METADATA'))))
        if metadata['Name'].lower() in PYTHON_COMPATIBILITY_PINS and metadata['Version'] != PYTHON_COMPATIBILITY_PINS[metadata['Name'].lower()]:
            continue
        rows.append(f'{metadata["Name"]}=={metadata["Version"]} --hash=sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}')
    if not rows:raise ValueError('Wheelhouse is empty')
    destination.write_text('\n'.join(sorted(rows))+'\n')


def prepare(tool: str, downloads: Path, build: Path) -> Path:
    context=build/tool;context.mkdir(parents=True,exist_ok=True)
    source=context/'source';source.mkdir(exist_ok=True)
    for name in FILES:
        destination=source/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/name,destination)
    shutil.copytree(ROOT/'security_tools',source/'security_tools',dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(ROOT/'worker/assets',source/'assets',dirs_exist_ok=True)
    overlay=context/'overlay';overlay.mkdir(exist_ok=True)
    if tool in {'httpx','katana','nuclei','ffuf','subfinder'}:
        target=overlay/'opt/tools'/tool;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(downloads/'tools'/tool,target)
    if tool=='sqlmap':
        destination=overlay/'opt/sqlmap';destination.mkdir(parents=True,exist_ok=True)
        with tarfile.open(downloads/'sqlmap-1.9.11.tar.gz') as archive:
            prefix=archive.getmembers()[0].name.split('/')[0]+'/'
            for member in archive.getmembers():
                if not member.name.startswith(prefix):continue
                relative=member.name[len(prefix):]
                if not relative:continue
                if not member.isfile() and not member.isdir():raise ValueError('Unexpected SQLmap archive entry')
                target=destination/relative
                if '..' in Path(relative).parts or Path(relative).is_absolute():raise ValueError('Archive traversal')
                if member.isdir():target.mkdir(parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.extractfile(member).read())
        launcher=overlay/'opt/tools/sqlmap';launcher.parent.mkdir(parents=True,exist_ok=True)
        launcher.write_text('#!/usr/local/bin/python3.11\nimport runpy,sys\nsys.path.insert(0,"/opt/sqlmap")\nsys.argv[0]="/opt/sqlmap/sqlmap.py"\nrunpy.run_path(sys.argv[0],run_name="__main__")\n');launcher.chmod(0o755)
    dockerfile=(ROOT/'worker/adapters/Dockerfile.tool').read_text()
    if tool=='semgrep':
        shutil.copytree(downloads/'semgrep-wheels',context/'wheels',dirs_exist_ok=True)
        wheel_lock(context/'wheels',context/'wheels.lock')
        dockerfile=dockerfile.replace('COPY overlay/ /','COPY wheels/ /tmp/wheels/\nCOPY wheels.lock /tmp/wheels.lock\nRUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-index --require-hashes --find-links=/tmp/wheels -r /tmp/wheels.lock && rm -rf /tmp/wheels\nCOPY overlay/ /')
        fixture=context/'fixture';fixture.mkdir(exist_ok=True)
        (fixture/'fixture.py').write_text('def synthetic_handler(user_input):\n    return eval(user_input)  # disposable static-analysis fixture; never executed\n')
        from security_tools.runner import tree_digest
        digest=tree_digest(fixture)
        shutil.copytree(fixture,source/'source'/digest,dirs_exist_ok=True)
        (context/'artifact.json').write_text(json.dumps({'artifact_sha256':digest})+'\n')
    if tool=='playwright':
        shutil.copytree(downloads/'playwright-wheels',context/'wheels',dirs_exist_ok=True)
        wheel_lock(context/'wheels',context/'wheels.lock')
        libraries='libglib2.0-0 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxcb1 libdrm2 libxkbcommon0 libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 fonts-liberation'
        extra=f'RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends {libraries} && dpkg-query -W > /usr/local/share/aria-dpkg.lock && rm -rf /var/lib/apt/lists/*\nCOPY wheels/ /tmp/wheels/\nCOPY wheels.lock /tmp/wheels.lock\nRUN pip install --no-index --require-hashes --find-links=/tmp/wheels -r /tmp/wheels.lock && rm -rf /tmp/wheels\nRUN PLAYWRIGHT_BROWSERS_PATH=/opt/chromium python -m playwright install chromium\n'
        dockerfile=dockerfile.replace('COPY overlay/ /',extra+'COPY overlay/ /')
    if tool=='zap':
        (overlay/'opt/zap').exists() and shutil.rmtree(overlay/'opt/zap')
        for stale in (overlay/'opt').glob('ZAP_*'):
            shutil.rmtree(stale)
        with tarfile.open(downloads/'ZAP_2.16.1_Linux.tar.gz') as archive:
            destination=overlay/'opt';destination.mkdir(parents=True,exist_ok=True)
            archive.extractall(destination,filter='data')
        unpacked=next((overlay/'opt').glob('ZAP_*'));unpacked.rename(overlay/'opt/zap')
        extra='RUN apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends openjdk-17-jre-headless && dpkg-query -W > /usr/local/share/aria-dpkg.lock && rm -rf /var/lib/apt/lists/*\n'
        dockerfile=dockerfile.replace('COPY overlay/ /',extra+'COPY overlay/ /')
    (context/'Containerfile').write_text(dockerfile)
    return context


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,default=ROOT/'.local-lab/phase2-adapters')
    parser.add_argument('--tool',choices=TOOLS,action='append');args=parser.parse_args()
    for tool in args.tool or TOOLS:print(prepare(tool,args.root/'downloads',args.root/'build'))


if __name__=='__main__':main()
