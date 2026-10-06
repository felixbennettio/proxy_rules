#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_rules
import check_rule_order
from build_dist_manifest import discover_published_files


class DNSPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        (self.root / "RULE_PRIORITIES.json").write_text(
            json.dumps({"priorities": {"direct": 100, "rule42": 200}}), encoding="utf-8"
        )
        (self.root / "rule42_add.list").write_text(
            "DOMAIN-SUFFIX,priority.example\nDOMAIN-KEYWORD,cloud\n", encoding="utf-8"
        )
        self.ip_rules = [
            "IP-CIDR,203.0.113.0/24",
            "IP-CIDR6,2001:db8::/32",
            "IP-ASN,13335",
        ]
        self.stack.enter_context(patch.multiple(
            build_rules,
            ROOT=self.root,
            DNS_DIR=self.root / "dns",
            OXIDNS_DIR=self.root / "oxidns",
            PRIORITIES_PATH=self.root / "RULE_PRIORITIES.json",
            SOURCES={"direct": []},
        ))
        self.stack.enter_context(patch.object(
            build_rules, "collect_group", return_value=[
                "DOMAIN,host.example",
                "DOMAIN-SUFFIX,tencent.com",
                "DOMAIN-SUFFIX,priority.example",
                "DOMAIN-KEYWORD,cdn",
                *self.ip_rules,
            ],
        ))
        self.stack.enter_context(patch.object(check_rule_order, "ROOT", self.root))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.assertEqual(build_rules.main(), 0)

    def test_full_build_keeps_ip_routing_and_projects_after_priorities(self) -> None:
        canonical = check_rule_order.data_lines(self.root / "direct.list")
        for rule in self.ip_rules:
            self.assertIn(rule, canonical)
        self.assertNotIn("DOMAIN-SUFFIX,priority.example", canonical)
        self.assertEqual(check_rule_order.data_lines(self.root / "dns/direct.list"), [
            "DOMAIN,host.example", "DOMAIN-SUFFIX,tencent.com", "DOMAIN-KEYWORD,cdn",
        ])
        self.assertEqual(check_rule_order.data_lines(self.root / "dns/rule42.list"), [
            "DOMAIN-SUFFIX,priority.example", "DOMAIN-KEYWORD,cloud",
        ])
        self.assertEqual(check_rule_order.main(), 0)
        published = discover_published_files(self.root)
        for name in ("direct", "rule42"):
            for path in (f"{name}.list", f"dns/{name}.list", f"oxidns/{name}.txt"):
                self.assertIn(path, published)

    def test_validation_rejects_ip_leaks_and_missing_keywords(self) -> None:
        path = self.root / "dns/direct.list"
        original = path.read_text(encoding="utf-8")
        for content in (
            original + "IP-CIDR,203.0.113.0/24\n",
            original.replace("DOMAIN-KEYWORD,cdn\n", ""),
        ):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "canonical domain rules"):
                    check_rule_order.check_canonical("direct")

    def test_ip_only_custom_list_keeps_routes_and_publishes_empty_dns_list(self) -> None:
        (self.root / "only_ip.list").write_text(self.ip_rules[0] + "\n", encoding="utf-8")
        self.assertEqual(build_rules.main(), 0)
        self.assertEqual(check_rule_order.data_lines(self.root / "only_ip.list"), [self.ip_rules[0]])
        self.assertEqual(check_rule_order.data_lines(self.root / "dns/only_ip.list"), [])
        self.assertIn("dns/only_ip.list", discover_published_files(self.root))
        self.assertEqual(check_rule_order.main(), 0)


if __name__ == "__main__":
    unittest.main()
