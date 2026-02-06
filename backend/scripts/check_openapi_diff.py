"""Compare two OpenAPI JSON files and report compatibility-relevant diffs.

Usage:
  uv run python scripts/check_openapi_diff.py --old ../docs/reports/openapi-baseline-2026-02-06.json --new ./openapi.new.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def path_method_set(doc: dict) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for p, methods in doc.get("paths", {}).items():
        for m in methods:
            out.add((p, m.lower()))
    return out


def schema_set(doc: dict) -> set[str]:
    schemas = doc.get("components", {}).get("schemas", {})
    return set(schemas.keys())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", type=Path, required=True, help="baseline openapi json")
    parser.add_argument("--new", type=Path, required=True, help="new openapi json")
    args = parser.parse_args()

    old = load_json(args.old)
    new = load_json(args.new)

    old_ops = path_method_set(old)
    new_ops = path_method_set(new)
    removed_ops = sorted(old_ops - new_ops)
    added_ops = sorted(new_ops - old_ops)

    old_schemas = schema_set(old)
    new_schemas = schema_set(new)
    removed_schemas = sorted(old_schemas - new_schemas)
    added_schemas = sorted(new_schemas - old_schemas)

    print("OpenAPI Diff Summary")
    print(f"- removed operations: {len(removed_ops)}")
    print(f"- added operations: {len(added_ops)}")
    print(f"- removed schemas: {len(removed_schemas)}")
    print(f"- added schemas: {len(added_schemas)}")

    if removed_ops:
        print("\nRemoved operations:")
        for p, m in removed_ops:
            print(f"- {m.upper()} {p}")

    if removed_schemas:
        print("\nRemoved schemas:")
        for name in removed_schemas:
            print(f"- {name}")

    # Non-zero when compatibility-risking removals are detected.
    return 1 if (removed_ops or removed_schemas) else 0


if __name__ == "__main__":
    raise SystemExit(main())
