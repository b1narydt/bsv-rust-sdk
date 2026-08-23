#!/usr/bin/env python3
"""Ratchet against `pub fn`s that only tests reference.

`dead_code` never fires on a `pub` item — it is public, so the compiler assumes
a consumer calls it. That blind spot let a fully implemented, fully tested
`validate_certificates` sit unreferenced by production code while the inbound
certificate path skipped validation entirely (bsv-rust-sdk#45).

The signal is "referenced from #[cfg(test)] and nowhere else": someone wrote it,
proved it worked, and never connected it. A pub fn with no references anywhere
is ordinary consumer API and is NOT reported — every such case reviewed so far
has been benign.

This is deliberately a RATCHET, not a clean gate. The signal cannot separate a
disconnected helper from a genuine consumer entry point on its own: both
`validate_certificates` (a real defect) and `aes_gcm_encrypt` (perfectly good
public API) are free functions exercised only by unit tests. So BASELINE records
the set as reviewed on a date, and CI fails only when something NEW appears.
That is the moment worth catching — when a function is added, tested, and never
wired up.

Reviewing an entry means answering one question: does a production path in this
crate have to call it? If yes, wire it in. If no, move it to BASELINE with the
reason.

Usage:  scripts/unwired-pub-fns.py [src_dir]
        scripts/unwired-pub-fns.py --update   # re-baseline after review
"""
import re, sys, glob, os, json
from collections import defaultdict

BASELINE_PATH = os.path.join(os.path.dirname(__file__), "unwired-pub-fns.baseline.json")

DEF   = re.compile(r'\s*pub(?:\((?:crate|super)\))?\s+(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)')
IDENT = re.compile(r'\b([a-z_][a-z0-9_]*)\b')

def test_ranges(lines):
    out = []
    for i, l in enumerate(lines):
        if re.match(r'\s*#\[cfg\(test\)\]', l):
            j = i
            while j < len(lines) and '{' not in lines[j]:
                j += 1
            if j >= len(lines):
                continue
            depth, k = 0, j
            while k < len(lines):
                depth += lines[k].count('{') - lines[k].count('}')
                if depth <= 0 and k > j:
                    break
                k += 1
            out.append((i, k))
    return out

def scan(root):
    files = {p: open(p, errors='ignore').read().split('\n')
             for p in glob.glob(os.path.join(root, '**', '*.rs'), recursive=True)}
    defs, ranges = {}, {}
    for p, lines in files.items():
        ranges[p] = test_ranges(lines)
        for i, l in enumerate(lines):
            m = DEF.match(l)
            if m and not any(a <= i <= b for a, b in ranges[p]):
                defs.setdefault(m.group(1), f"{p}:{i+1}")

    prod, tst = defaultdict(int), defaultdict(int)
    for p, lines in files.items():
        for i, l in enumerate(lines):
            d = DEF.match(l)
            declared = d.group(1) if d else None
            it = any(a <= i <= b for a, b in ranges[p])
            # A fn passed by reference (not invoked) still counts as wired, so
            # match bare identifiers rather than call syntax.
            for name in set(IDENT.findall(l)):
                if name == declared or name not in defs:
                    continue
                (tst if it else prod)[name] += 1

    return {n: defs[n] for n in defs if prod[n] == 0 and tst[n] > 0}

def main():
    update = "--update" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = args[0] if args else "src"

    current = scan(root)
    baseline = {}
    if os.path.exists(BASELINE_PATH):
        baseline = json.load(open(BASELINE_PATH)).get("reviewed", {})

    if update:
        json.dump({
            "_comment": "pub fns referenced only by #[cfg(test)], reviewed and accepted as "
                        "consumer API. A NEW entry fails CI until reviewed. See scripts/unwired-pub-fns.py.",
            "reviewed": {n: baseline.get(n, "pre-existing; reviewed 2026-08-22") for n in sorted(current)},
        }, open(BASELINE_PATH, "w"), indent=2)
        print(f"unwired-pub-fns: baseline updated — {len(current)} entries")
        return 0

    new = sorted(set(current) - set(baseline))
    if not new:
        print(f"unwired-pub-fns: OK — {len(current)} test-only pub fns, all baselined")
        return 0

    print("unwired-pub-fns: FAIL — implemented and tested, never called by production code:\n")
    for n in new:
        print(f"  {n}\n      {current[n]}")
    print("\nDoes a production path in this crate have to call it?")
    print("  yes -> wire it in (this is the bsv-rust-sdk#45 shape)")
    print("  no  -> scripts/unwired-pub-fns.py --update, and record why in the baseline")
    return 1

if __name__ == "__main__":
    sys.exit(main())
