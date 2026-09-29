#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from rule_files import discover_addition_files
from rule_sort import RULE_TYPE_ORDER, sort_and_dedupe_rules

ROOT = Path(__file__).resolve().parents[1]
COMMENT_PREFIXES = ("#", ";", "//")
def normalize_rule(raw: str, path: Path, line_number: int) -> str:
    parts = [part.strip() for part in raw.strip().split(",")]
    kind = parts[0].upper()

    if kind not in RULE_TYPE_ORDER:
        supported = ", ".join(RULE_TYPE_ORDER)
        raise ValueError(
            f"{path.relative_to(ROOT)}:{line_number}: unsupported rule type "
            f"{parts[0]!r}; expected one of: {supported}"
        )
    if len(parts) < 2 or not parts[1]:
        raise ValueError(
            f"{path.relative_to(ROOT)}:{line_number}: rule must contain a non-empty value"
        )

    return ",".join((kind, *parts[1:]))


def sort_add_file(path: Path) -> bool:
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    header: list[str] = []
    trailing_comments: list[str] = []
    rules: list[str] = []
    seen_rule = False

    for line_number, raw in enumerate(original.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            if not seen_rule:
                header.append("")
            continue
        if stripped.startswith(COMMENT_PREFIXES):
            if seen_rule:
                trailing_comments.append(raw.rstrip())
            else:
                header.append(raw.rstrip())
            continue

        seen_rule = True
        rules.append(normalize_rule(raw, path, line_number))

    while header and not header[-1]:
        header.pop()

    output = list(header)
    if output and rules:
        output.append("")
    ordered_rules = sort_and_dedupe_rules(rules)
    output.extend(ordered_rules)
    if trailing_comments:
        if output:
            output.append("")
        output.extend(trailing_comments)

    rendered = "\n".join(output) + "\n"
    if rendered == original:
        print(f"[unchanged] {path.relative_to(ROOT)}")
        return False

    path.write_text(rendered, encoding="utf-8")
    print(f"[sorted] {path.relative_to(ROOT)} ({len(ordered_rules)} unique rules)")
    return True


def main() -> int:
    for path in discover_addition_files(ROOT):
        sort_add_file(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
