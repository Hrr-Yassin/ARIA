# P13 supervised laboratory run card

Disposition:BLOCKED. Proposal6f80803d-f053-48c2-8953-749644eff87c expired at15:39:36UTC without an owner decision;native denial403 was verified. No target action
has been executed by this card and no automatic renewal occurs. The independent senior comparison is BLOCKED by
owner instruction;the owner permits continuing without waiting for it.

The controlled local-model evaluation has produced real proposals but poor
decision quality. It does not justify unsupervised execution. The valid HTTP GET
candidate from the measured Recon response can be reviewed by the owner and
changed into the following single header observation:

```sh
curl -I -s --max-time 10 http://192.168.77.20:80/
```

This exact bounded HEAD command is an operator correction,not a claim that the
model emitted correct flags. Shared policy validates it,and the existing worker
advertises compatibility with192.168.77.20/32,TCP80. Neither compatible metadata
nor the model's proposal authorizes execution.

| Item | Bound |
| --- | --- |
| Target/action | One unauthenticated HTTP HEAD to192.168.77.20:80/ |
| Worker | Existing jobs-v1 isolated worker;existing independent policy |
| Maximum submissions | One;no automatic retry or alternative target/action |
| Tool/worker deadline | Ten seconds;existing cancellation/reconciliation applies |
| New model calls/spend | Zero;retain already-accounted real-model proposal and failures |
| Model budget | Existing20calls/200000reserved tokens/$1;no reset,refund or increase |
| Authorization | Fresh durable proposal,exact owner approval,one-use claim |
| Supervision | Owner approves this specific run;Codex observes submission/terminal/receipt and stops on uncertainty |
| Evidence | Canonical command,scope/approval binding,worker job/receipt,output hash,terminal state,timing and zero new model-usage delta |
| Disclosure | Private bounded header output;publish only sanitized status/hash metadata |

Stop before dispatch if approval is missing/expired,scope or ownership changes,
worker compatibility is unavailable,budget/accounting is inconsistent,or other
active/uncertain work makes the session unsafe. Stop after the one terminal or
unknown outcome;never replay a consumed authorization. Original expired approvals
remain untouched. Do not change VMs,networking,Kali,worker privileges or policy.

Acceptance for this narrow pilot requires the approved command to traverse the
real shared authorization and worker path,with bound receipt/terminal evidence
and explicit model/operator limitations. Missing post-result model review remains
unavailable because the current inference token ceiling is effectively exhausted.
This single supervised integration observation does not establish successful
autonomous discovery,general agent expertise,continuous availability or8/5 readiness.
