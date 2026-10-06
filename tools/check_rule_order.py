#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from build_rules import read_local_rules, to_oxidns_domain_set, to_surge_dns_rules
from rule_files import discover_addition_files, discover_rule_names
from rule_sort import sort_and_dedupe_rules

ROOT = Path(__file__).resolve().parents[1]
COMMENT_PREFIXES = ("#", ";", "//")


def data_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(COMMENT_PREFIXES)
    ]


def check_canonical(name: str) -> None:
    path = ROOT / f"{name}.list"
    rules = read_local_rules(path)
    if rules != sort_and_dedupe_rules(rules):
        raise ValueError(f"{path.name} is not sorted and deduplicated")

    surge_dns_path = ROOT / "dns" / f"{name}.list"
    if data_lines(surge_dns_path) != to_surge_dns_rules(rules):
        raise ValueError(
            f"{surge_dns_path.relative_to(ROOT)} must contain exactly the canonical domain rules"
        )

    expected_dns: list[str] = []
    seen_dns: set[str] = set()
    for rule in rules:
        entry = to_oxidns_domain_set(rule)
        if entry and entry not in seen_dns:
            seen_dns.add(entry)
            expected_dns.append(entry)

    dns_path = ROOT / "oxidns" / f"{name}.txt"
    if data_lines(dns_path) != expected_dns:
        raise ValueError(f"{dns_path.relative_to(ROOT)} does not match canonical ordering")
    print(f"[ok] {path.name}: {len(rules)} unique sorted rules")


def main() -> int:
    for name in discover_rule_names(ROOT):
        check_canonical(name)

    for path in discover_addition_files(ROOT):
        rules = data_lines(path)
        if rules != sort_and_dedupe_rules(rules):
            raise ValueError(f"{path.name} is not sorted and deduplicated")
        print(f"[ok] {path.name}: {len(rules)} unique sorted rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
