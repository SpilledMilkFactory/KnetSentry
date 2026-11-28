<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# M8.7 — Keyboard navigation and accessibility

Issue #75, implementation candidate pending Ubuntu 26.04 target qualification.
The desktop is a bounded read-only inspection and explicitly authorized alert
interface, not an operational SIEM. Accessibility must not change authority.

## Keyboard and focus contract

- Ctrl+1 through Ctrl+7 retain the existing top-level navigation destinations.
  F6 focuses the active page content; Shift+F6 focuses the navigation button.
  Tab and Shift+Tab traverse native enabled controls. Page Up and Page Down
  scroll focused page content. A page replacement focuses its content rather
  than preserving a stale focused control from a retired page.
- Focus inside a page scrolls the outer content viewport to reveal the focused
  item. Popups, toolbar controls and items outside that content are excluded.
- Events, Alerts and Investigations expose named list controls and named record
  delegates. Each list is one tab stop when available, with a bounded keyboard
  cursor. Up/Down moves the cursor without a query; Enter/Space explicitly
  inspects the cursor row through the existing selection method. Mouse clicks
  still inspect the clicked row. The keyboard highlight indicates the cursor,
  not an independent evidence identity or verified relationship.
- Empty or busy result lists cannot inspect a record. Existing model refusal,
  expiry, evidence authorization, revision binding and page clearing remain.
  Related evidence inspection and acknowledgement still require their own
  existing explicit controls. No shortcut acknowledges alerts or retrieves
  evidence automatically.

## Text, contrast and motion

The startup Qt platform font supplies the logical-pixel baseline (14 px fallback
if its size is unavailable). Settings offers session-only 100%, 125% and 150%
text size, applied to native control typography and first-party headings/cards/
status badges. The setting resets on restart. Compact control grids reflow to
one column, and enlarged Dashboard content uses a higher split threshold.
Record labels wrap rather than elide their content. Footer status labels wrap.

Native palettes supply text, surfaces and highlighted text; list focus has a
text-colored outline, and the cursor uses native delegate highlighting. Chart
count names include their category. Severity retains the existing five checked
contrast pairs and textual labels, distinct from health or monitoring status.
The M8.5 default reduced-motion and platform duration policy is unchanged.

No new persistent settings, data sources, IPC commands, privileges, network
operations or dependencies. Magnification is not a screen magnifier or a
universal cross-desktop accessibility API. Platform font changes while running,
non-English layouts, high-contrast themes and assistive-technology support
require target validation; no full accessibility conformance is claimed.

## Qualification

The existing visual-system test checks 100/150% scaling, restoration and
compact layout plus actual focus targets. Existing rendered event, alert and
timeline fixtures deliver Qt key events to focused lists and verify selected
metadata, including off-page evidence verification. The existing exact audit
query counts and evidence invariance must still pass. CTest registration counts
are unchanged (584 total across seven presets). The new source verifier does not
replace actual Qt compilation, QML lint, runtime or manual review.

The maintained local-only acceptance runner consolidates full configured
inventories, focused tests, repeated Release/sanitized/rendered checks,
compiler diagnostics, native library resolution, installed-manager equality,
strict QML analysis, structural and privileged fixtures. Optional manual GUI
fixture creation, manager launch and cleanup are automated; only the actual
visual and human keyboard/assistive-technology verdict stays manual. Never
publish local scripts, logs, private evidence or operator preferences.

Manual review: use keyboard-only navigation and structured searches in Events,
Alerts and Investigations; inspect records with Up/Down and Enter; check Tab and
reverse Tab, related record/evidence controls, focus visibility and scrolling;
exercise 100/125/150% text at full and compact sizes in light/dark or available
high-contrast themes. Check readable labels, contrast, reduced motion, and no
stale evidence after navigation or expiry. If a screen reader is available,
verify practical announcement of control names, rows and status text. Record
any observed limitations and keep broader #75 scope open until qualified.

## M8.7 qualification follow-up

The first target run passed all 584 configured tests and all supplementary
keyboard/search regressions, but strict QML analysis rejected the untyped
`Component.createObject()` result at the call to `focusPrimary()`. The created
page is now explicitly cast to `SectionPage` before the existing null check,
page replacement and focus request. No warning suppression is added. The
source verifier checks the typed creation path. The local runner moves strict
QML analysis directly after the Release build and stops on lint failure before
remaining qualification or privileged fixture activation. Full qualification
of the corrected revision, including the previously skipped installed systemd
and visual-review fixture gates, remains required.
