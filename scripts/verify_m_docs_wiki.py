#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: MIT
"""Offline documentation index and deterministic Wiki export contract."""
from pathlib import Path
from urllib.parse import unquote, urlsplit

from export_wiki import LINK, ROOT, ROOT_DOCS, WIKI, convert, render, sources


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    pages = sources(ROOT)
    expected = {p.resolve() for p in (ROOT / 'docs').rglob('*.md')}
    expected.update(ROOT / name for name in ROOT_DOCS)
    require(set(pages) == expected, 'Documentation missing from reviewed index')
    result = render()
    require(result == render(), 'Nondeterministic export')
    require(len(result) == len(pages) + 3, 'Unexpected page inventory')
    require({'Home.md', '_Sidebar.md', '_Footer.md'} <= result.keys(), 'Missing Wiki navigation')
    for name, body in result.items():
        require(body.startswith('<!--\nSPDX-FileCopyrightText:'), f'{name}: missing copyright')
        require('SPDX\x2dLicense-Identifier: CC-BY-SA-4.0' in body[:160], f'{name}: missing license')
        for match in LINK.finditer(body):
            target = match.group(2)
            if target.startswith(WIKI):
                page = unquote(urlsplit(target).path.split('/wiki/', 1)[1])
                require(page + '.md' in result, f'{name}: nonexistent Wiki page {page}')
    index = result['Documentation-Index.md']
    for name in pages.values():
        if name != 'Documentation-Index':
            require(WIKI + name in index, f'Missing indexed page {name}')
    source = ROOT / 'docs/README.md'
    require(convert('[status](PROJECT_STATUS.md#available-today)', source, pages, ROOT)
            == f'[status]({WIKI}Project-Status#available-today)', 'Anchor lost')
    require(convert('```md\n[x](missing.md)\n```\n', source, pages, ROOT)
            == '```md\n[x](missing.md)\n```\n', 'Fenced example modified')
    for bad in ('[x](missing.md)', '[x](../../../etc/passwd)'):
        try:
            convert(bad, source, pages, ROOT)
        except ValueError:
            pass
        else:
            raise ValueError('Broken or escaping link accepted')
    require('local_acceptance_results' not in result.keys(), 'Local evidence exported')
    readme = (ROOT / 'README.md').read_text()
    for link in ('/wiki)', 'docs/README.md', 'docs/PROJECT_STATUS.md'):
        require(link in readme, f'Landing page missing {link}')
    print(f'Documentation index and Wiki export: PASS ({len(pages)} source documents, '
          f'{len(result)} generated Markdown files; offline only)')


if __name__ == '__main__':
    main()
