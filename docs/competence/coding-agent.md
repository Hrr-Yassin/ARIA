# Coding and test engineering contract

The coding agent produces Python source, tests and documentation as data for review.
It supports programming, regression/test design, synthetic fixtures, static analysis,
log/evidence parsing, validation, report generation and defensive automation. It has
no shell tool, file-reader, target client, package installer or deployment API.
Neither source text, a model confidence value nor a passing static check grants
execution privileges. Existing session ownership and durable pre-inference accounting
apply; a denied budget makes no provider call. Code generation is currently blocked
by the unchanged allocation, while controlled provider fixtures verify the software.

The API accepts bounded explicitly supplied text, not filesystem paths or target
access. Provider redaction still applies. Output uses a closed schema containing
source/test/README artifacts, an empty dependency list, limitations and proposed
validation instructions. Artifacts remain in the response and are never written,
imported, executed, installed or deployed by the agent.

Static validation runs only trusted validator code in a fresh Python process using
isolated import mode, a temporary directory, a minimal environment, CPU/address-space/
file-size limits and a wall deadline. It checks AST syntax and compiler constraints,
imports, dynamic execution, unsafe I/O, docstrings, annotations and test assertions.
Candidate code never executes. This is bounded static review, not a sandbox capable
of safely running arbitrary Python. No claim of semantic correctness follows.
Third-party dependencies are rejected in this initial profile. The repository hash
lock and installed dependency consistency are checked separately; external advisory
coverage is unavailable without an approved cached database or online check.

Independent human review, deterministic behavior tests in an independently managed
credential-free/network-isolated environment, and explicit operator action remain
required before using an artifact. There is no approve-and-execute route. The model
may describe test commands for a reviewer, but the service never runs them. The
offline suite exercises trusted synthetic examples, rejection/cancellation/ownership
and failure paths. It must never relabel handcrafted examples as generated-model
performance. Independent code review and fresh model-code quality remain BLOCKED.
