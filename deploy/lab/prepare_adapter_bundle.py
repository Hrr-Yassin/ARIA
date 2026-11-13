"""Fetch official release artifacts for offline image builds; execute none on host.

Artifacts are verified against GitHub's release-asset digest and/or the release's
checksum file and retained with a SHA-256 provenance lock. This is build-input
retrieval, not a security probe. No target/domain information is sent upstream.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import urllib.request
import zipfile
import tarfile
import concurrent.futures

RELEASES = {
    'httpx': ('projectdiscovery/httpx', 'v1.7.1', 'httpx_1.7.1_linux_amd64.zip'),
    'katana': ('projectdiscovery/katana', 'v1.1.2', 'katana_1.1.2_linux_amd64.zip'),
    'nuclei': ('projectdiscovery/nuclei', 'v3.4.10', 'nuclei_3.4.10_linux_amd64.zip'),
    'ffuf': ('ffuf/ffuf', 'v2.1.0', 'ffuf_2.1.0_linux_amd64.tar.gz'),
    'subfinder': ('projectdiscovery/subfinder', 'v2.9.0', 'subfinder_2.9.0_linux_amd64.zip'),
    'zap': ('zaproxy/zaproxy', 'v2.16.1', 'ZAP_2.16.1_Linux.tar.gz'),
}
PINNED_RELEASE_LOCK = Path(__file__).resolve().parents[2] / 'worker/adapters/locks/security-tools.json'


def get(url: str) -> bytes:
    request=urllib.request.Request(url,headers={'User-Agent':'ARIA-offline-worker-build/1'})
    with urllib.request.urlopen(request,timeout=120) as response:
        return response.read()


def release(name: str, root: Path) -> dict:
    repo,version,filename=RELEASES[name]
    metadata=json.loads(get(f'https://api.github.com/repos/{repo}/releases/tags/{version}'))
    asset=next(item for item in metadata['assets'] if item['name']==filename)
    path=root/filename
    if not path.exists():
        path.write_bytes(get(asset['browser_download_url']))
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    expected=asset.get('digest')
    if expected:
        if expected!='sha256:'+digest:raise ValueError('Release digest mismatch: '+name)
    else:
        checksum=next((item for item in metadata['assets'] if 'checksum' in item['name'].lower()),None)
        if checksum:
            lines=get(checksum['browser_download_url']).decode().splitlines()
            expected=next(line.split()[0] for line in lines if line.split()[-1].lstrip('*')==filename)
            if expected!=digest:raise ValueError('Release checksum mismatch: '+name)
        else:
            # ZAP additionally publishes .sha256 assets, depending on release age.
            checksum=next((item for item in metadata['assets'] if item['name']==filename+'.sha256'),None)
            if checksum:
                expected=get(checksum['browser_download_url']).decode().split()[0]
            else:
                line=next((line for line in metadata.get('body','').splitlines() if '['+filename+']' in line), '')
                match=re.search(r'`([0-9a-f]{64})`',line)
                if not match:raise ValueError('No upstream integrity digest: '+name)
                expected=match.group(1)
            if expected!=digest:raise ValueError('Release checksum mismatch: '+name)
    if name!='zap':
        destination=root/'tools'/name;destination.parent.mkdir(exist_ok=True)
        if filename.endswith('.zip'):
            with zipfile.ZipFile(path) as archive:destination.write_bytes(archive.read(name))
        else:
            with tarfile.open(path) as archive:
                member=next(item for item in archive.getmembers() if item.name==name and item.isfile())
                destination.write_bytes(archive.extractfile(member).read())
        destination.chmod(0o755)
    return {'tool':name,'version':version.lstrip('v'),'url':asset['browser_download_url'],
            'archive_sha256':digest,'github_asset_id':asset['id'],'upstream_verified':True}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('destination',type=Path)
    args=parser.parse_args();root=args.destination;root.mkdir(parents=True,exist_ok=True)
    records=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures={pool.submit(release,name,root):name for name in RELEASES}
        for future in concurrent.futures.as_completed(futures):
            try:
                item=future.result();records.append(item);print(item['tool'],item['version'],'verified',flush=True)
            except Exception as error:
                records.append({'tool':futures[future],'error':str(error)})
                print(futures[future],type(error).__name__,str(error),flush=True)
    records=sorted(records,key=lambda row:row['tool'])
    pinned=json.loads(PINNED_RELEASE_LOCK.read_text())
    if records != pinned:
        raise SystemExit('Fetched release artifacts differ from the committed security-tools lock')
    (root/'release-lock.json').write_text(json.dumps(records,indent=2)+'\n')
    if any('error' in row for row in records):raise SystemExit(1)


if __name__=='__main__':main()
