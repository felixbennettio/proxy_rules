#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

RULE_TYPE_ORDER = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "IP-CIDR": 3,
    "IP-CIDR6": 4,
    "IP-ASN": 5,
}


def value_sort_key(kind: str, value: str) -> tuple[Any, ...]:
    if kind in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return (1, value.casefold())
        return (0, network.version, int(network.network_address), network.prefixlen)

    if kind == "IP-ASN":
        asn = value.upper().removeprefix("AS")
        try:
            return (0, int(asn))
        except ValueError:
            return (1, value.casefold())

    return (0, value.casefold())


def rule_sort_key(rule: str) -> tuple[Any, ...]:
    kind, value, *extra = rule.split(",")
    return (
        RULE_TYPE_ORDER.get(kind, len(RULE_TYPE_ORDER)),
        value_sort_key(kind, value),
        tuple(part.casefold() for part in extra),
        rule.casefold(),
    )


def sort_and_dedupe_rules(rules: Iterable[str]) -> list[str]:
    return sorted(dict.fromkeys(rules), key=rule_sort_key)
