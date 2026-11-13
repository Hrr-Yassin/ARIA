# Kali worker deployment — 7 November 2026

ARIA uses the jobs-v1 worker at `http://192.168.77.10:7001` on the isolated
`192.168.77.0/24` lab network. The Kali worker is managed by systemd as
`aria-kali-worker.service` and runs as the `kali` user. It starts jobs in
rootless Podman containers using the existing worker image. The image contains
curl and Nmap; installing additional tools on Kali does not add worker support.

A dedicated PostgreSQL database `aria_kali_worker` stores the worker job ledger.
The worker configuration is private at
`/home/kali/.local/share/aria-worker/worker.env`; do not publish its token. The
independent firewall unit `aria-kali-worker-firewall.service` permits TCP port
7001 from the ARIA host `192.168.77.1` and drops other IPv4 sources. This is an
isolated lab HTTP connection, not a TLS deployment. The worker's independent
ceiling permits only `192.168.77.20/32` and TCP ports 21, 22, 80, 139 and 445;
each engagement can restrict these further.

```bash
# On Kali
systemctl status aria-kali-worker.service aria-kali-worker-firewall.service
journalctl -u aria-kali-worker.service --no-pager -n 50
podman image ls
```

A successful authenticated capability check and rejection without a token were
verified. An out-of-scope worker job was rejected. Through ARIA's normal
proposal and execution endpoints, a curl header request and a separate Nmap
TCP port-80 scan of the authorized lab target both completed with exit code 0.
Their two test engagements and worker receipts are retained for inspection.
No model-provider calls were needed for these checks.

Kali currently provides Python 3.14 and its distribution packages for the
worker service. This differs from the project's supported Python 3.11 locked
runtime; the real jobs above establish this lab flow, not full compatibility
with Python 3.14. The isolated job image itself uses Python 3.11. Existing
PostgreSQL installation reports a collation-version mismatch on its older
system databases; the new worker database was created from template0 without
changing those databases. PostgreSQL should be maintained separately.

The previous local worker has not been removed. ARIA's previous environment is
backed up privately under `.local-lab/aria-env-before-kali-worker`; treat it as
secret. Existing jobs from the old worker remain in its separate ledger. Do not
switch workers while jobs are active or assume historical receipts exist in the
other worker's ledger.
