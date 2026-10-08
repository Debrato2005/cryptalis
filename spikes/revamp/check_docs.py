"""Verify current owners and this revamp's preservation boundary, not runtime safety."""
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
DRAFT = Path('/tmp/cryptalis-revamp-drafts') if '--draft' in sys.argv else ROOT
BASELINE = Path('/tmp/cryptalis-revamp-baseline')
CORE = ['README.md', 'docs/architecture/README.md', 'docs/security.md', 'docs/lifecycle.md',
        'docs/compatibility.md', 'docs/status.md', 'docs/build-guide.md']
OWNERS = CORE + ['AGENTS.md', 'ENGINEERING_PLAYBOOK.md', 'docs/decisions.md', 'docs/prior-art.md',
                'docs/research/README.md', 'docs/research/revamp-evidence.md', 'spikes/revamp/README.md']


def source(name):
    candidate = DRAFT / name
    return candidate if candidate.exists() else ROOT / name


def anchors(value):
    result = set()
    used = {}
    for heading in re.findall(r'^#{1,6}\s+(.+)$', value, re.M):
        heading = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', heading)
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        count = used.get(slug, 0)
        used[slug] = count + 1
        result.add(slug if count == 0 else slug + '-' + str(count))
    result.update(re.findall(r'<a\s+(?:id|name)="([^"]+)"', value))
    return result


def main():
    errors = []
    links = 0
    for name in OWNERS:
        path = source(name)
        if not path.exists():
            errors.append('Missing owner: ' + name)
            continue
        body = re.sub(r'```.*?```', '', path.read_text(), flags=re.S)
        for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', body):
            if re.match(r'[a-z]+://|mailto:', target):
                continue
            target = unquote(target.strip().strip('<>'))
            relative, _, anchor = target.partition('#')
            relative = re.sub(r':\d+$', '', relative)
            logical = (ROOT / name).parent / relative if relative else ROOT / name
            logical = logical.resolve()
            try:
                resolved = source(str(logical.relative_to(ROOT)))
            except ValueError:
                resolved = logical
            links += 1
            if not resolved.exists():
                errors.append(name + ' -> missing ' + target)
            elif anchor and resolved.suffix == '.md' and anchor not in anchors(resolved.read_text()):
                errors.append(name + ' -> missing anchor ' + target)
    report = source('docs/research/revamp-evidence.md').read_text()
    old = (BASELINE / 'docs/decisions.md').read_text()
    old_ids = {re.match(r'\| (D\d+) ', line)[1] for line in old.splitlines()
               if re.match(r'\| D\d+ ', line) and 'DECIDED-BLOCKED-ON-TEST' in line}
    mapped_ids = re.findall(r'^\| (D\d+) \|', report, re.M)
    if set(mapped_ids) != old_ids or len(mapped_ids) != len(old_ids):
        errors.append('Historical blocked-decision dispositions are incomplete or duplicated')
    kills = re.findall(r'^\| (\d+) \|', report.split('## Fifteen kill criteria')[1].split('## Old dependency graph')[0], re.M)
    if kills != [str(n) for n in range(1, 16)]:
        errors.append('Kill criterion disposition inventory incomplete')
    gates = set(re.findall(r'\bG-[A-Z]+\b', '\n'.join(source(name).read_text() for name in OWNERS)))
    build_gates = set(re.findall(r'\bG-[A-Z]+\b', source('docs/build-guide.md').read_text()))
    if gates != build_gates:
        errors.append('Gate ownership differs from build guide')
    original = json.loads((BASELINE / 'hashes.json').read_text())
    unchanged_non_markdown = []
    changed_markdown = []
    for name, expected in original.items():
        path = ROOT / name
        if not path.exists():
            errors.append('Starting existing file removed: ' + name)
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            if name.endswith('.md'):
                changed_markdown.append(name)
            else:
                errors.append('Starting executable/evidence changed: ' + name)
        elif not name.endswith('.md'):
            unchanged_non_markdown.append(name)
    if hashlib.sha256((ROOT / 'AGENTS.md').read_bytes()).hexdigest() != original['AGENTS.md']:
        errors.append('Starting user AGENTS work changed')
    old_playbook = (BASELINE / 'ENGINEERING_PLAYBOOK.md').read_text()
    expected_playbook = old_playbook.replace('crypto wheel/native backend, AWS SDK, database build and service/IAM identities.',
                                            'crypto wheel/native backend, selected provider SDK, database build and service/workload identities.')
    if DRAFT == ROOT and (ROOT / 'ENGINEERING_PLAYBOOK.md').read_text() != expected_playbook:
        errors.append('Playbook change exceeded the exact provider-wording scope')
    deletions = [line[3:] for line in (BASELINE / 'git-status.txt').read_text().splitlines() if line.startswith(' D ')]
    for name in deletions:
        if (ROOT / name).exists():
            errors.append('Starting deletion restored: ' + name)
    for path in (ROOT / 'docs/research').glob('*.md'):
        if path.name.startswith('revamp-') or path.name == 'README.md':
            continue
        current = source(str(path.relative_to(ROOT))).read_text()
        if 'Historical research archive.' not in current[:650]:
            errors.append('Historical research lacks archive notice: ' + str(path.relative_to(ROOT)))
    core_metrics = {name: {'before_words': len((BASELINE/name).read_text().split()),
                           'after_words': len(source(name).read_text().split())} for name in CORE}
    result = {'status': 'PASS_DOCUMENT_BOUNDARIES' if not errors else 'FAIL', 'draft_preflight': DRAFT != ROOT,
              'errors': errors, 'current_owner_links_checked': links,
              'historical_blocked_decisions_mapped': len(mapped_ids), 'kill_results': len(kills),
              'essential_gates': sorted(build_gates), 'starting_non_markdown_unchanged': len(unchanged_non_markdown),
              'starting_deletions_preserved': len(deletions), 'starting_markdown_changed': changed_markdown,
              'core_metrics': core_metrics, 'before_core_words': sum(x['before_words'] for x in core_metrics.values()),
              'after_core_words': sum(x['after_words'] for x in core_metrics.values()),
              'limits': ['Historical body links/hashes retain original context; current owner links checked',
                         'External URLs were researched separately, not crawled by this checker',
                         'Link/hash/inventory checks do not prove semantic completeness or runtime safety']}
    if DRAFT == ROOT:
        (ROOT/'spikes/revamp/results/documents.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
