"""Import the verified VMware Metasploitable 2 image into isolated QEMU/KVM.

Run on the Fedora host as the libvirt-authorized user. Never overwrites a VM,
volume, or converted image. The original downloaded ZIP is retained.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ROOT / '.local-lab/images'
ARCHIVE = IMAGES / 'metasploitable-linux-2.0.0.zip'
# SourceForge project file metadata, fetched 2026-11-01.
SHA256 = '2ae8788e95273eee87bd379a250d86ec52f286fa7fe84773a3a8f6524085a1ff'
NAME = 'aria-metasploitable2'
VOLUME = NAME + '.qcow2'
VIRSH = ['virsh', '-c', 'qemu:///system']


def run(args):
    return subprocess.run(args, check=True)


def main():
    for args in ([*VIRSH, 'dominfo', NAME], [*VIRSH, 'vol-info', VOLUME, '--pool', 'default']):
        if subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise SystemExit('A target VM/volume already exists; refusing to overwrite it')
    digest = hashlib.sha256()
    with ARCHIVE.open('rb') as file:
        while block := file.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != SHA256:
        raise SystemExit('SourceForge SHA-256 mismatch; image not imported')
    print('SourceForge SHA-256 verified.', flush=True)
    vmdk, qcow = IMAGES / 'metasploitable2.vmdk', IMAGES / VOLUME
    if vmdk.exists() or qcow.exists():
        raise SystemExit('Intermediate images already exist; refusing to overwrite them')
    with zipfile.ZipFile(ARCHIVE) as archive:
        disks = [item for item in archive.infolist() if item.filename.lower().endswith('.vmdk')]
        if len(disks) != 1 or disks[0].file_size > 12 * 1024**3:
            raise SystemExit('Unexpected VMware image layout')
        # Extract only disk bytes to a chosen file; do not trust archive paths.
        with archive.open(disks[0]) as source, vmdk.open('xb') as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
    run(['qemu-img', 'convert', '-f', 'vmdk', '-O', 'qcow2', '-c', str(vmdk), str(qcow)])
    run(['qemu-img', 'check', '-f', 'qcow2', str(qcow)])
    info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(qcow)]))
    run([*VIRSH, 'vol-create-as', 'default', VOLUME, str(info['virtual-size']), '--format', 'qcow2', '--allocation', '0'])
    run([*VIRSH, 'vol-upload', VOLUME, str(qcow), '--pool', 'default', '--sparse'])
    run(['virt-install', '--connect', 'qemu:///system', '--name', NAME,
         '--memory', '1024', '--vcpus', '1', '--import', '--osinfo', 'generic',
         '--machine', 'pc', '--disk', f'vol=default/{VOLUME},bus=ide',
         '--network', 'network=aria-lab,model=e1000,mac=52:54:00:77:00:20',
         '--graphics', 'spice,listen=none', '--video', 'vga', '--noautoconsole'])
    # Remove only the intermediate copies this script created, after successful import.
    vmdk.unlink()
    qcow.unlink()
    print('Target imported and started on aria-lab. Archive retained; intermediate copies removed.')


if __name__ == '__main__':
    main()
