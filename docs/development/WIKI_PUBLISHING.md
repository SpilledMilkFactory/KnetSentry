<!--
SPDX-FileCopyrightText: 2026 Chris Sutton
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Wiki publishing

The [documentation index](../README.md) and source Markdown in the main repository
are authoritative. The GitHub Wiki is a separately versioned, generated presentation.
Never add private logs, development acceptance runners, credentials or private network
evidence to either repository.

## First publication

1. In GitHub Settings, confirm Wikis are enabled and restrict editing to collaborators.
2. Open the Wiki tab and create/save the first page named `Home` (temporary text is fine).
3. Merge the documentation PR, pull `main`, and run the following as your ordinary user.
   The Wiki checkout must be a separate sibling directory. Do not run this with sudo.

```bash
gh auth status
gh auth setup-git
cd ~/Documents/CPP_Projects/KnetSentry
git switch main
git pull --ff-only
git clone https://github.com/SpilledMilkFactory/KnetSentry.wiki.git ../KnetSentry-wiki
```

## Publish or refresh after an accepted documentation change

From the main repository, confirm `git status --short` is clean. The exporter reads
only the explicit root policy documents and Markdown linked from the reviewed
`docs/README.md` index; it does not
copy acceptance logs, local scripts, build directories or arbitrary repository files.
It converts internal Markdown links into Wiki URLs and other repository-relative
links into source URLs. It does not write to GitHub or the source checkout.

```bash
cd ~/Documents/CPP_Projects/KnetSentry
git switch main
git pull --ff-only
python3 -B scripts/verify_m_docs_wiki.py
export_dir=$(mktemp -d)
python3 -B scripts/export_wiki.py "$export_dir/pages"
```

In the Wiki checkout, inspect `git status --short` and stop if there are existing
uncommitted edits. The following copies generated pages without deleting other
pages; review any obsolete generated pages manually. The exporter uses stable page
names derived from unique Markdown filenames and checks collisions.

```bash
cd ../KnetSentry-wiki
git pull --ff-only
cp -- "$export_dir/pages/"*.md .
git add -- '*.md'
git diff --cached --check
git diff --cached --stat
git diff --cached
```

If the staged content is correct and nonempty, commit and push the current Wiki
branch (do not assume it is named `main`):

```bash
git commit -m "docs: publish current KnetSentry documentation"
git push
```

If nothing changed, skip the commit and push. Remove the temporary export directory
when no longer needed. Check the Wiki Home, custom sidebar, index, a technical page,
a cross-page link and a link back to a source document in the browser. Use the Wiki
history to review or revert publication errors; never force-push. The generated
source links point to `main`, so older Wiki revisions may reference newer source.
No CI publishing credentials, workflow permission changes or automatic pushes are required.

## Repository About metadata

Use the landing page About gear or GitHub CLI. The description should explicitly
say the platform is in development; the website may point to the published Wiki.
Use relevant project topics, not claims of production readiness or KDE affiliation.

Recommended description:

> Security-first, local-first SIEM platform for authorized LAN monitoring, network telemetry, threat detection, and incident investigation. Built with C++23, Qt 6, and Kirigami. In active development.

Recommended website: https://github.com/SpilledMilkFactory/KnetSentry/wiki

Recommended topics: `cybersecurity`, `siem`, `network-security`, `network-monitoring`,
`security-monitoring`, `threat-detection`, `incident-response`, `network-traffic-analysis`,
`security-analytics`, `local-first`, `privacy`, `cpp`, `cpp23`, `qt6`, `qml`,
`kirigami`, `kde`, `linux`, `ubuntu`, `open-source`.

For each future issue, update the authoritative documents and their index in the
main repository PR. Update the project status with confirmed evidence after
acceptance, then regenerate and publish the Wiki. The Wiki is not the source of
truth for live GitHub issue or branch-protection settings.
