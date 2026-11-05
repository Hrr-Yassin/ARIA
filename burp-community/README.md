# ARIA Burp Community connector (release gate disabled)

This extension uses Montoya selected-request context menus and Repeater staging.
It does not call Burp Scanner, the Professional request engine, interception
certificate installation, or automatic HTTP replay in Burp.

Compile with Java 17+ and an official Montoya API JAR:

```bash
bash burp-community/build.sh /absolute/path/to/montoya-api-2025.2.jar
```

Load `burp-community/build/aria-community.jar` as a Java extension in Burp Community.
Runtime desktop validation is pending; compilation passed. Do not enable the API
feature until the [release register](../docs/aria-upgrade-validation.md) gaps close.

When staging validation is ready, configure `BURP_COMMUNITY_ENABLED=true` and a
private `BURP_CONNECTOR_TOKEN` of at least 32 characters in the ARIA test deployment.
Launch Burp with the same secret in `ARIA_BURP_CONNECTOR_TOKEN`, an owned ARIA user
access token in `ARIA_BURP_USER_TOKEN`, and explicit literal target IPs in
`ARIA_BURP_TARGETS` (default `192.168.77.20`). Never print tokens or commit them.
The connector binds only `127.0.0.1:17777`; ARIA is expected at `127.0.0.1:7000`.
Only TCP80 HTTP requests are accepted by this release. Add the target to Burp scope
and configure the owning ARIA engagement before importing.

Select at most 20 in-scope Proxy request/response pairs, choose **Import selected
pairs into ARIA engagement**, and enter the owning session UUID. ARIA checks ownership
and scope, deduplicates per engagement, encrypts original bytes, and retains redacted
endpoint/authentication maps. Different credential contexts receive keyed fingerprints.
The Burp Community Intel tab lists imported observations and their evidence IDs.

**Stage in Repeater** creates a tab without sending network traffic. Review and Send
manually in Burp. **Review availability check** creates a command-bound proposal;
accept or reject its exact displayed command. Approved checks use the existing worker
with ten-second timeout, durable jobs, a 20-job engagement ceiling and normal session
Stop/cancellation. They use bodyless unauthenticated GET/HEAD and explicitly omit
captured custom headers. Their comparisons are observations, not vulnerability proof.
Authenticated replay and mutation are disabled instead of silently dropping credentials
or changing an original request. No globally trusted interception certificates are installed.

All `/api/burp/*` routes require user authentication; operations also require a direct
loopback connection and the feature gate. Scope is revalidated before staging/checks.
Use the existing execution decision endpoint for approval/rejection; approval does not
bypass scope policy. Imported source bytes never enter model prompts or report manifests.

Official API references:

- [Context-menu selection](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/ui/contextmenu/ContextMenuEvent.html)
- [Repeater staging semantics](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/repeater/Repeater.html)
- [HTTP APIs and Professional-only request engine](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/Http.html)
