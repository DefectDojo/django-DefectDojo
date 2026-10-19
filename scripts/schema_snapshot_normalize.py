#!/usr/bin/env python3
"""
Compare two `pg_dump --schema-only` files, ignoring what a dump and restore changes on its own.

Used by scripts/build_schema_snapshot.sh to check that a loaded schema snapshot is the schema the
migrations build. Two differences are expected and carry no meaning:

1. PostgreSQL 18 stores NOT NULL as a named constraint, and the name is fixed when the table is
   created. A database migrated from zero keeps names derived from old table and column names
   (dojo_finding_is_Mitigated_not_null); a restored dump gets names from the current ones.
2. A restore re-parses CHECK constraints and partial-index predicates, which moves a cast:
   = ANY ((ARRAY['a'::character varying])::text[])  becomes
   = ANY (ARRAY[('a'::character varying)::text]).

Usage: schema_snapshot_normalize.py <expected.sql> <actual.sql>
Exits 0 when they match after normalizing, 1 with a unified diff when they do not.
"""

from __future__ import annotations

import difflib
import re
import sys
from pathlib import Path

_NOISE_PREFIXES = ("--", "SET ", "SELECT pg_catalog.set_config", "\\")
_NAMED_NOT_NULL = re.compile(r' CONSTRAINT "?[A-Za-z0-9_]+"? NOT NULL')
_CAST_ELEMENT = re.compile(r"\('((?:[^']|'')*)'::character varying\)::text")
_CAST_ARRAY = re.compile(r"ANY \(\(ARRAY\[(.*?)\]\)::text\[\]\)")


def normalize(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.startswith(_NOISE_PREFIXES):
            continue
        line = _NAMED_NOT_NULL.sub(" NOT NULL", raw)
        line = _CAST_ELEMENT.sub(r"'\1'::character varying", line)
        line = _CAST_ARRAY.sub(r"ANY (ARRAY[\1])", line)
        lines.append(line)
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write(__doc__.strip().splitlines()[-2] + "\n")
        return 2
    expected, actual = (normalize(Path(p).read_text(encoding="utf-8")) for p in argv[1:])
    if expected == actual:
        sys.stdout.write(f"Schemas match after normalizing ({len(expected)} lines)\n")
        return 0
    diff = list(difflib.unified_diff(expected, actual, argv[1], argv[2], lineterm="", n=1))
    changed = sum(1 for d in diff if d[:1] in "+-" and d[:3] not in {"+++", "---"})
    sys.stdout.write("\n".join(diff[:200]) + f"\nSchemas differ: {changed} lines\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
