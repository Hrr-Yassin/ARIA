"""Operator-only Kali worker maintenance over its existing QEMU guest agent.

No API/agent imports this module. Security-tool execution and laboratory traffic
must still use ARIA authorization and jobs-v1. No SSH/network configuration is
changed. The upload boundary is the existing ARIA worker directory on Kali.
"""
import base64
import ctypes
import json
from pathlib import Path
import time

WORKER_ROOT = '/home/kali/.local/share/aria-worker/'


class KaliGuest:
    def __init__(self):
        self.lib = ctypes.CDLL('libvirt.so.0')
        self.qemu = ctypes.CDLL('libvirt-qemu.so.0')
        self.libc = ctypes.CDLL(None)
        self.lib.virConnectOpen.argtypes=[ctypes.c_char_p];self.lib.virConnectOpen.restype=ctypes.c_void_p
        self.lib.virDomainLookupByName.argtypes=[ctypes.c_void_p,ctypes.c_char_p];self.lib.virDomainLookupByName.restype=ctypes.c_void_p
        self.qemu.virDomainQemuAgentCommand.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint]
        self.qemu.virDomainQemuAgentCommand.restype=ctypes.c_void_p
        self.libc.free.argtypes=[ctypes.c_void_p]
        self.lib.virDomainFree.argtypes=[ctypes.c_void_p];self.lib.virConnectClose.argtypes=[ctypes.c_void_p]
        self.connection=self.lib.virConnectOpen(b'qemu:///system')
        if not self.connection:raise RuntimeError('Cannot open existing libvirt management connection')
        self.domain=self.lib.virDomainLookupByName(self.connection,b'kali')
        if not self.domain:raise RuntimeError('The designated Kali VM is unavailable')

    def close(self):
        self.lib.virDomainFree(self.domain);self.lib.virConnectClose(self.connection)

    def agent(self, command: dict) -> dict:
        raw=self.qemu.virDomainQemuAgentCommand(self.domain,json.dumps(command).encode(),30,0)
        if not raw:raise RuntimeError('Kali guest agent command failed')
        try:data=json.loads(ctypes.string_at(raw))
        finally:self.libc.free(raw)
        if 'error' in data:raise RuntimeError(data['error'].get('desc','Guest operation denied'))
        return data['return']

    def execute(self, code: str, timeout: float = 30) -> dict:
        pid=self.agent({'execute':'guest-exec','arguments':{'path':'/usr/bin/python3','arg':['-'],
            'input-data':base64.b64encode(code.encode()).decode(),'capture-output':True}})['pid']
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            result=self.agent({'execute':'guest-exec-status','arguments':{'pid':pid}})
            if result.get('exited'):
                for src,dst in [('out-data','stdout'),('err-data','stderr')]:
                    result[dst]=base64.b64decode(result.pop(src,'')).decode(errors='replace')
                return result
            time.sleep(.25)
        return {'pid':pid,'running':True}

    def upload(self, source: Path, destination: str) -> int:
        if not destination.startswith(WORKER_ROOT) or '..' in Path(destination).parts:
            raise ValueError('Uploads must stay in the existing ARIA worker tree')
        handle=self.agent({'execute':'guest-file-open','arguments':{'path':destination,'mode':'wb'}})
        count=0
        try:
            with source.open('rb') as stream:
                # QEMU's agent chardev has a small message bound on this lab;
                # larger writes can time out before the guest consumes the JSON.
                while chunk:=stream.read(24*1024):
                    result=self.agent({'execute':'guest-file-write','arguments':{'handle':handle,
                        'buf-b64':base64.b64encode(chunk).decode()}})
                    if result['count']!=len(chunk):raise RuntimeError('Incomplete guest file write')
                    count+=len(chunk)
            self.agent({'execute':'guest-file-flush','arguments':{'handle':handle}})
        finally:self.agent({'execute':'guest-file-close','arguments':{'handle':handle}})
        return count
