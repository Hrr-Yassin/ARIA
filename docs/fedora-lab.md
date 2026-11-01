# Fedora manual-test lab

This laptop now runs ARIA in its existing Python 3.11 venv as the Fedora user
`hryassin`. PostgreSQL 16.6 and Redis 7.4.1 run in rootless Podman containers with
localhost-only ports. No global Python packages or root application service were
installed. Existing application changes were retained. Local secrets, VM archives and runtime data remain excluded from Git.

## Open ARIA

Open **http://127.0.0.1:7000/login** on Fedora. Login credentials are stored privately
in the project directory:

```bash
cat .local-lab/login.txt
```

The administrator is `labadmin`; its password was randomly generated, not a demo
default. Keep `.env` and `.local-lab/` private and out of Git. The persistent Fernet
key in `.env` is required to decrypt saved provider credentials after restart.

The service uses the current checkout. Start/stop/status/log commands, from Fedora:

```bash
systemctl --user start aria
systemctl --user status aria
journalctl --user -u aria -n 50 --no-pager
systemctl --user stop aria
```

It is enabled for your user session; user-service operation before login depends
on Fedora's user-manager/lingering configuration, which was not changed. Starting
ARIA starts its named database/cache containers. Stopping ARIA leaves those
containers running. To stop them after stopping the application:

```bash
podman stop aria-postgres aria-redis
```

Persistent database/cache data is in the rootless Podman volumes `aria-postgres`
and `aria-redis`; do not remove them to stop the lab. Redis DB 15 and the separate
PostgreSQL database `aria_test` are disposable integration-test resources. The
application uses database `aria` and Redis DB 0.

## Lab network and machines

| Component | Address / access |
| --- | --- |
| Fedora bridge | `192.168.77.1` |
| ARIA UI on Fedora | `http://127.0.0.1:7000/login` |
| Existing Kali VM (`kali`) | DHCP reservation `192.168.77.10` |
| Metasploitable 2 (`aria-metasploitable2`) | DHCP reservation `192.168.77.20` |
| PostgreSQL on Fedora | `127.0.0.1:15432` |
| Redis on Fedora | `127.0.0.1:16379` |

`aria-lab` has no libvirt `forward` element, no NAT and no DNS service. Both VMs use
one NIC connected only to this network. Fedora remains reachable by design, and
Fedora retains its normal Internet connection for the browser/model APIs. This is
an isolated lab subnet, not a security boundary protecting Fedora from its guests.
Do not attach the vulnerable target to the existing NAT network named `network`.
See [libvirt's isolated-network definition](https://libvirt.org/formatnetwork.html).

Kali was already installed; its original VM XML was backed up to
`.local-lab/kali-before-aria.xml` before moving its NIC from NAT to `aria-lab`.
Its disks and login credentials were preserved. The guest agent is already present,
and nmap/curl were found. Kali's observed route table contains the lab subnet and
no default Internet route; IPv4 forwarding is disabled.

Metasploitable 2 comes from the
[Rapid7-linked SourceForge project](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/).
Its VMware VMDK is converted to QCOW2 and imported into libvirt's default managed
storage pool with 1 GiB RAM, one vCPU, BIOS boot and an IDE disk. The published
SourceForge archive SHA-256 is:

```text
2ae8788e95273eee87bd379a250d86ec52f286fa7fe84773a3a8f6524085a1ff
```

The importer checks that hash and the converted QCOW2 structure. It refuses to
overwrite an existing VM or volume. The ZIP is retained in `.local-lab/images/`;
intermediate VMDK/QCOW2 copies are removed after successful import. The managed
volume contains the running target. Disk space on this laptop is limited; avoid
creating duplicate image copies or large snapshots.

Open either console in **Virtual Machine Manager**, using the **QEMU/KVM system**
connection. Start/stop machines with:

```bash
virsh -c qemu:///system start kali
virsh -c qemu:///system start aria-metasploitable2
virsh -c qemu:///system shutdown aria-metasploitable2
virsh -c qemu:///system shutdown kali
```

Use your existing Kali login. Metasploitable's intentionally public lab credentials
are `msfadmin` / `msfadmin`, documented by
[Rapid7](https://docs.rapid7.com/metasploit/metasploitable-2/).
Neither VM is configured to autostart. The isolated libvirt network is persistent
and autostarts. If Kali ever needs Internet updates, shut down the vulnerable VM
first and deliberately review any temporary network change; do not dual-home it
while running this isolated exercise.

## First manual test

1. Sign in to ARIA on Fedora. Add your own Groq, Gemini or OpenRouter API key in
   the key-management UI if you want AI planning/analysis. No provider key was
   supplied or external model call made during setup.
2. Create a session with target **192.168.77.20**, keeping its scope limited to
   that address. Ask ARIA for a scan plan. Treat suggestions as untrusted; this
   prototype does not establish vulnerability applicability or exploitation success.
3. Run a small scan in the Kali terminal:

   ```bash
   nmap -sT --open --max-retries 1 --host-timeout 30s -p 21,22,80,139,445 192.168.77.20
   ```

4. To collect that same fixed scan into a Fedora file without transferring it
   manually, use the existing Kali guest agent from the project directory on Fedora:

   ```bash
   .venv/bin/python -m deploy.lab.collect_demo
   ```

   It saves `.local-lab/nmap-demo.txt`. It performs only the displayed scan against
   the fixed lab target and does not send evidence to a model.
5. After configuring a provider, submit the collected output for analysis:

   ```bash
   .venv/bin/python -m deploy.lab.submit_output \
     --file .local-lab/nmap-demo.txt \
     --command 'nmap -sT --open --max-retries 1 --host-timeout 30s -p 21,22,80,139,445 192.168.77.20'
   ```

   The helper signs in locally, finds/creates a matching lab session and posts
   the evidence. Use `--session-id <id>` to choose a specific existing session.
   Refresh that session in the UI. The private response is saved in
   `.local-lab/last-analysis.json`; manual evidence remains labelled unverified.

The separate Kali execution-worker server is **absent from this repository**.
`KALI_AGENT_URL` is deliberately empty. The UI's Run button and autonomous
execution therefore do not constitute a working worker integration. Run tools
manually as above; automatic execution requires a worker implementing
[worker-contract.md](worker-contract.md), plus deployment and isolation validation.
AI analysis also remains unverified until you supply a provider key and run it.

## Checks and recovery

```bash
.venv/bin/python deploy/lab/check_local.py
virsh -c qemu:///system net-dhcp-leases aria-lab
virsh -c qemu:///system domiflist kali
virsh -c qemu:///system domiflist aria-metasploitable2
```

HTTP liveness/readiness, administrator login and session listing pass. The target
received `192.168.77.20` via DHCP, its HTTP page returned 200, and the fixed scan
from Kali confirmed reachable open TCP ports 21, 22, 80, 139 and 445. This verifies
lab connectivity, not exploitation or model analysis. Both real
PostgreSQL/Redis integration scenarios pass; their logs are in
`.local-lab/integration.log`. All 78 offline Python regressions and the Node frontend scenarios pass. Offline
regression results and demo-scan evidence are retained privately under `.local-lab/`.

To restore Kali's original network configuration, shut it down normally, then
run `virsh -c qemu:///system define .local-lab/kali-before-aria.xml`. This restores
its original NAT attachment and is incompatible with the isolated test until you
move it back. It does not undo disk contents. No original VM disks were replaced.
