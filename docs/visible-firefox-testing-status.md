# Visible Firefox testing status

The user subsequently authorized Playwright with visible Chromium. That method
was executed successfully; see the [Chromium acceptance report](chromium-acceptance-2026-11-07.md).
The Firefox-only access limitation below is historical and does not describe
the later Chromium run.

7 November 2026. The user clarified that acceptance must use their normal visible
Firefox, with direct UI interaction, rather than Python browser automation.

A normal Firefox window was requested with `firefox --new-window
http://localhost:7000`. The command returned successfully and Firefox processes
were present. No installed browser/computer-control tool is exposed in this
session. Plugin discovery found no integration for controlling this local Firefox.
The GNOME accessibility desktop listed other applications but did not expose
Firefox, including after temporarily enabling accessibility. Both accessibility
settings were restored to their original false values.

No visible-browser target creation, single-probe execution or autonomous run was
performed. The previous automated acceptance report must not be presented as
completion of this clarified request. A working local desktop/browser-control
connection is needed to continue this form of acceptance testing.

The user requires that any Kali or Metasploitable problem be explained with a
proposed fix and approved before changes to those systems. No Kali or target
changes were made during this attempt, and no new diagnosis of either system was
established.
