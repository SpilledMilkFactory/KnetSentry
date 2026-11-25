#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Export reviewed project Markdown to a separate, new directory; no network writes."""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
REPO = 'https://github.com/SpilledMilkFactory/KnetSentry'
WIKI = REPO + '/wiki/'
HEADER = ('<!--\nSPDX-FileCopyrightText: 2026 Chris Sutton\n'
          'SPDX\x2dLicense-Identifier: CC-BY-SA-4.0\n-->\n\n')
ROOT_DOCS = ('PRODUCT_VISION.md', 'CONTRIBUTING.md', 'DEVELOPMENT_CONTRACT.md',
             'GOVERNANCE.md', 'CODE_OF_CONDUCT.md', 'SECURITY.md')
LINK = re.compile(r'(!?\[[^\]\n]+\]\()([^\s)]+)(\))')


def sources(root: Path) -> dict[Path, str]:
    index = root / 'docs/README.md'
    paths = [root / name for name in ROOT_DOCS] + [index]
    # The reviewed index is the publication allowlist, not a recursive copy
    # of a developer's working directory.
    for match in LINK.finditer(index.read_text(encoding='utf-8')):
        parsed = urlsplit(match.group(2))
        if parsed.scheme or parsed.netloc or not parsed.path.endswith('.md'):
            continue
        target = index.parent / unquote(parsed.path)
        resolved = target.resolve()
        if resolved.is_relative_to(root / 'docs'):
            paths.append(target)
        elif resolved not in [root / name for name in ROOT_DOCS]:
            raise ValueError(f'Unexpected Markdown outside documentation: {target}')
    result: dict[Path, str] = {}
    names = set()
    for path in paths:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError(f'Unsafe or missing documentation: {path}')
        if path.resolve() in result:
            continue
        relative = path.resolve().relative_to(root)
        name = 'Documentation-Index' if relative == Path('docs/README.md') else path.stem.replace('_', '-').title()
        if name.casefold() in names or name in {'Home', '_Sidebar', '_Footer'}:
            raise ValueError(f'Wiki page name collision: {name}')
        names.add(name.casefold())
        result[path.resolve()] = name
    return result


def page_url(name: str) -> str:
    return WIKI + quote(name, safe='-')


def convert(text: str, source: Path, pages: dict[Path, str], root: Path) -> str:
    def replace(match: re.Match[str]) -> str:
        prefix, target, suffix = match.groups()
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)
        if parsed.path.startswith('/'):
            raise ValueError(f'Unsupported absolute link in {source}: {target}')
        resolved = (source.parent / unquote(parsed.path)).resolve()
        if not resolved.is_relative_to(root) or not resolved.exists():
            raise ValueError(f'Broken or escaping link in {source}: {target}')
        if resolved in pages and not prefix.startswith('!'):
            url = page_url(pages[resolved])
        else:
            kind = 'tree' if resolved.is_dir() else ('raw' if prefix.startswith('!') else 'blob')
            url = f'{REPO}/{kind}/main/' + quote(resolved.relative_to(root).as_posix(), safe='/')
        if parsed.query:
            url += '?' + parsed.query
        if parsed.fragment:
            url += '#' + parsed.fragment
        return prefix + url + suffix

    # Preserve fenced examples verbatim. The source corpus uses inline links.
    out = []
    fence = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r'^\s*(`{3,}|~{3,})', line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            out.append(line)
        else:
            out.append(line if fence else LINK.sub(replace, line))
    return ''.join(out)


def render(root: Path = ROOT) -> dict[str, str]:
    root = root.resolve()
    pages = sources(root)
    output = {}
    for path, name in pages.items():
        text = path.read_text(encoding='utf-8')
        body = convert(text, path, pages, root)
        # Keep SPDX header first, and explicitly identify the authoritative source.
        pos = body.index('-->') + 3 if body.startswith('<!--') else 0
        source_link = REPO + '/blob/main/' + quote(path.relative_to(root).as_posix(), safe='/')
        note = ('\n\n> Published documentation mirror. [Edit the source through a repository PR]('
                + source_link + '). See [Project status](' + page_url('Project-Status') + ').\n')
        output[name + '.md'] = body[:pos] + note + body[pos:]
    index = page_url('Documentation-Index')
    status = page_url('Project-Status')
    quick = page_url('Contributor-Quickstart')
    roadmap = page_url('Release-Objectives')
    output['Home.md'] = HEADER + f'''# KnetSentry documentation

**Local Network Security Intelligence**

Welcome to the documentation for KnetSentry, a security-first, local-first SIEM
in development for explicitly authorized local networks.

The current application is a pre-release foundation, not operational monitoring
software. Read the current project status before interpreting older milestone guides.

## Start here

- [Project status and acceptance evidence]({status})
- [Build and contributor quickstart]({quick})
- [Roadmap and release objectives]({roadmap})
- [Complete documentation index]({index})

## Technical reference

- [Product vision]({page_url('Product-Vision')})
- [System architecture]({page_url('System-Architecture')})
- [Network scope requirements]({page_url('Network-Scope-Requirements')})
- [Threat model]({page_url('Threat-Model')})
- [Toolchain and test matrix]({page_url('Toolchain-Test-Matrix')})

[Source repository]({REPO}) · [Issues]({REPO}/issues) · [Milestones]({REPO}/milestones)

The main repository is authoritative. Update documentation through its ordinary
review process, then regenerate this Wiki. Documentation is CC-BY-SA-4.0;
see the [licensing policy]({page_url('Licensing-Policy')}).
'''
    output['_Sidebar.md'] = HEADER + f'''**KnetSentry**

- [Home]({WIKI}Home)
- [Project status]({status})
- [Getting started]({quick})
- [Roadmap]({roadmap})
- [All documentation]({index})

**Reference**

- [Architecture]({page_url('System-Architecture')})
- [Security requirements]({page_url('Network-Scope-Requirements')})
- [Threat model]({page_url('Threat-Model')})
- [Testing]({page_url('Toolchain-Test-Matrix')})
- [Contributing]({page_url('Contributing')})
- [Wiki publishing]({page_url('Wiki-Publishing')})
'''
    output['_Footer.md'] = HEADER + f'''[Source repository]({REPO}) · [Documentation index]({index}) · [License policy]({page_url('Licensing-Policy')})

Documentation mirror — CC-BY-SA-4.0. KnetSentry is not an official KDE project.
'''
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='new directory outside the source checkout')
    args = parser.parse_args()
    dest = args.output.resolve()
    if dest.is_relative_to(ROOT) or dest.exists():
        parser.error('output must be a new directory outside the source checkout')
    content = render()
    dest.mkdir(parents=False, exist_ok=False)
    for name, body in sorted(content.items()):
        (dest / name).write_text(body, encoding='utf-8', newline='\n')
    print(f'Exported {len(content)} Wiki Markdown files to {dest}; no network operation performed.')


if __name__ == '__main__':
    main()
