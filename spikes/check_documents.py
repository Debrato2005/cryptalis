"""Required local documentation/source integrity checks, not a runtime gate."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ["README.md", "AGENTS.md", "ENGINEERING_PLAYBOOK.md", "docs/architecture/README.md",
             "docs/security.md", "docs/lifecycle.md", "docs/compatibility.md", "docs/build-guide.md",
             "docs/status.md", "docs/decisions.md", "docs/prior-art.md"]


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def anchors(text):
    used = {}; result = set()
    for heading in re.findall(r"^#{1,6}\s+(.+)$", text, re.M):
        heading = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        count = used.get(slug, 0); used[slug] = count + 1
        result.add(slug if not count else slug + "-" + str(count))
    result.update(re.findall(r'<a\s+(?:id|name)="([^"]+)"', text))
    return result


def main():
    docs = [ROOT/n for n in CANONICAL] + sorted((ROOT/"docs/research").rglob("*.md")) + [ROOT/"spikes/README.md"]
    errors = []; links = 0; external = 0
    for path in docs:
        text = re.sub(r"```.*?```", "", path.read_text(), flags=re.S)
        for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", text):
            target = match[1].strip().strip("<>")
            if re.match(r"[a-z]+://|mailto:", target): external += 1; continue
            target = unquote(target); file, _, anchor = target.partition("#")
            file = re.sub(r":\d+$", "", file)
            resolved = (path.parent/file).resolve() if file else path
            links += 1
            if not resolved.exists(): errors.append(f"{path.relative_to(ROOT)} -> missing {target}")
            elif anchor and resolved.suffix == ".md" and anchor not in anchors(resolved.read_text()):
                errors.append(f"{path.relative_to(ROOT)} -> missing anchor {target}")
    trace = (ROOT/"docs/research/reset-traceability.md").read_text(); source_cache = {}; section_count = 0
    for line in trace.splitlines():
        match = re.match(r"\| `([^`]+):(\d+)-(\d+)` \|.*\| `([0-9a-f]{12})` \|$", line)
        if not match: continue
        file, first, last, expected = match.groups()
        if file not in source_cache:
            source_cache[file] = subprocess.check_output(["git", "show", "49d34f2:"+file], cwd=ROOT).decode().splitlines()
        section = "\n".join(source_cache[file][int(first)-1:int(last)]).encode()
        if hashlib.sha256(section).hexdigest()[:12] != expected: errors.append("Trace hash mismatch: " + file + ":" + first)
        section_count += 1
    property_ids = re.findall(r"^\| (K\d+) \|", trace, re.M)
    if property_ids != [f"K{i:02}" for i in range(1,131)]: errors.append("Trace property inventory changed")
    decisions = (ROOT/"docs/decisions.md").read_text()
    rows = [line for line in decisions.splitlines() if re.match(r"\| D\d\d(?: |\d)", line)]
    blocked = sum("DECIDED-BLOCKED-ON-TEST" in x for x in rows)
    decided = sum(bool(re.search(r"\bDECIDED(?: /| \||$)", x)) for x in rows)
    if (len(rows), decided, blocked) != (42,9,33): errors.append(f"Wrong decision counts: {len(rows),decided,blocked}")
    canonical_text = "\n".join((ROOT/n).read_text() for n in CANONICAL)
    obsolete = re.findall(r"(?:shred --(?:subject|domain)|G-SHRED|UnsupportedEncryptedQuery|no greenlet helper dependency)", canonical_text)
    if obsolete: errors.append("Obsolete canonical tokens: " + str(obsolete))
    gates = set(re.findall(r"\bG-[A-Z]+\b",canonical_text))
    build_gates = set(re.findall(r"\bG-[A-Z]+\b",(ROOT/"docs/build-guide.md").read_text()))
    if gates - build_gates: errors.append("Gates absent from build guide: " + str(sorted(gates-build_gates)))
    metrics = {n:{"lines":len((ROOT/n).read_text().splitlines()),"words":len((ROOT/n).read_text().split())} for n in CANONICAL}
    total_lines = sum(x["lines"] for x in metrics.values()); total_words=sum(x["words"] for x in metrics.values())
    if total_lines>2500 or total_words>30000: errors.append(f"Local canonical budget exceeded: {total_lines} lines / {total_words} words")
    source = json.loads((ROOT/"spikes/results/package-baseline.json").read_text())
    for name, sha in source.items():
        if digest(ROOT/name) != sha: errors.append("Production source changed: "+name)
    actual = {str(p.relative_to(ROOT)) for p in (ROOT/"src").rglob("*.py")}
    if actual != set(source): errors.append("Production source file inventory changed")
    baseline_path=Path('/tmp/cryptalis-hardening-baseline/files.json'); original_count=0
    if baseline_path.exists():
        for name,sha in json.loads(baseline_path.read_text()).items():
            if name.endswith('.md') or name.startswith('docs/research/council-review-1/'): continue
            original_count+=1
            if digest(ROOT/name)!=sha: errors.append('Original non-Markdown file changed: '+name)
    result = {"status":"PASS_DOCUMENT_CHECKS" if not errors else "FAIL", "errors":errors,
              "local_file_anchor_links":links,"external_links_not_network_checked":external,
              "trace_source_sections_checked":section_count,"trace_properties":len(property_ids),
              "decisions":{"total":len(rows),"decided":decided,"blocked":blocked},
              "production_source_files_unchanged":len(source),"starting_non_markdown_files_unchanged":original_count,
              "canonical_metrics":metrics,"canonical_total_lines":total_lines,"canonical_total_words":total_words,
              "limits":["machine checks cannot establish normative semantic completeness", "historical review text is immutable evidence", "duplicate ownership requires human/council review"]}
    (ROOT/"spikes/results/document-checks.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    if errors: raise SystemExit(1)


if __name__ == "__main__": main()
