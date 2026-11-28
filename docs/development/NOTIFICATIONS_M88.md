<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.8 — Configurable notifications and alert presentation

Issue #76. Candidate pending target-host and manual qualification. This is a
presentation-only foundation for explicitly requested stored alerts, not a
live alert notification service or evidence of monitoring coverage.

## Controls and privacy contract

- Settings provides independently configurable, session-only notification
  history and desktop window-attention controls. Both default to off.
- A completed asynchronous stored alert **list** request can generate one
  fixed, generic in-app notice, whether the result was successful or denied.
  The notice says only that the request ended; it does not establish success,
  authorization, detection, urgency or the existence of any alert.
- No notification is produced for evidence inspection, acknowledgement,
  preset selection, page navigation, cancelled requests or a request that
  cannot enter the asynchronous exchange. Existing result text remains the
  authoritative source of request feedback.
- History contains at most eight newest-first generic notices in memory;
  it contains no evidence, result, source, severity, alert identity, time,
  credentials, manager session or raw event data. Disable history or use
  Clear notification history to empty it immediately. Restart clears it.
- A generic footer indicator appears only if history is enabled and nonempty.
  It is not an alert count. Settings contains the history, not evidence.
- Optional desktop behavior uses a three-second Qt window-attention hint
  only when a list exchange ends while the window is inactive. It sends no
  event or notification payload, does not raise the window or request focus,
  and is subject to window-manager policy. No notification daemon, tray,
  external notification history, toast API or background query is introduced.
  A window manager may render its own attention effect or ignore the hint.
  The opt-in can reveal application activity timing to nearby observers; leave
  it off for privacy or reduced-distraction use. No external evidence detail
  is ever sent. Desktop popup integration and live notification delivery are
  outstanding under #76.
- The Alerts page displays the number of open or acknowledged records only
  in its currently returned authorized page. Empty success is zero; pending,
  unavailable, rejected, expired or cleared snapshot is unavailable. It is
  neither a deployment-wide total nor a measure of live monitoring. A count
  is not copied to history or the desktop. Acknowledgement retains its existing
  separately authorized operation and revision binding.

## Theme correction

M8.7 manual review identified unreadable unselected investigation rows under
light appearance. Events, Alerts and Investigations now explicitly pair the
same control palette's window/windowText and highlight/highlightedText roles,
including the actual opaque delegate background. The preferred palette text
is retained at 4.5:1 contrast or better; a black/white fallback is used only
for an insufficient or translucent foreground. No forced theme is used. Cursor movement, row activation, plain text, accessible names and
focus outlines are preserved. The local visual-review runner retains its
isolated writable XDG configuration and includes the normal user configuration
in the fallback lookup path for theme discovery. This is not guaranteed for
all platform plugins; inspect both actual light and dark appearance.

## Qualification

The existing three rendered evidence integrations check actual foreground and
background pairing and 4.5:1 contrast with and without keyboard focus. Existing alert integration
also checks notification isolation from acknowledgement and evidence inspection,
plus empty and unavailable indicator behavior. Separate processes against a
read-only and default-denied manager test opt-in, defaults, eight-entry cap,
clear, disable, navigation, generic contents and current-page indicator. The
read-only process must make exactly eleven explicit authorized reads and no
acknowledgement; ledger and evidence bytes remain unchanged. The prior M8.6
query-count assertions remain. All 584 configured CTests remain registered.
The maintained full local runner expects 79 structural verifiers and 178
successful gates with GUI review (177 without). Actual Qt build, strict QML,
rendered integration, all previous security gates, manual contrast and desktop
attention qualification and hosted CI remain required. No production-scale
notification throughput or cross-theme accessibility conformance is claimed.
