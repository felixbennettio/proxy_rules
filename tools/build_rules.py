#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterable

from rule_files import addition_files, discover_addition_files, discover_rule_names
from rule_sort import sort_and_dedupe_rules

ROOT = Path(__file__).resolve().parents[1]
OXIDNS_DIR = ROOT / "oxidns"
PRIORITIES_PATH = ROOT / "RULE_PRIORITIES.json"

COMMENT_PREFIXES = ("#", ";", "//")
PORTABLE_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN"}
IGNORED_SOURCE_MARKERS = {
    # SukkaW embeds this leetspeak ownership marker in generated domain sets;
    # it is metadata, not an AI service endpoint.
    "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe",
}

# Built-in lists are rebuilt from current external upstream sources declared
# here. Any matching *_add.list is merged into the canonical
# output. Rule-set names not listed here are discovered from repository files.
SOURCES = {
    # Explicit allow exceptions are rebuilt only from allow_add.list.
    "allow": [],
    "ai": [
        # Merge focused AI rules from several independently maintained projects.
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Claude/Claude.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Gemini/Gemini.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Copilot/Copilot.list",
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list",
        "https://raw.githubusercontent.com/Repcz/Tool/X/Surge/Rules/AI.list",
        "https://ruleset.skk.moe/List/non_ip/ai.conf",
    ],
    "push": [
        # Mobile-vendor service sets are kept separate so push endpoints can be
        # routed directly and protected from advertising-list false positives.
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/XiaoMi/XiaoMi.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Huawei/Huawei.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OPPO/OPPO.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Vivo/Vivo.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/MeiZu/MeiZu.list",
    ],
    "proxy": [
        # Proxy / global
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OneDrive/OneDrive.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Proxy/Proxy.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Proxy/Proxy_Domain.list",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/proxy.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
        "https://ruleset.skk.moe/List/non_ip/global.conf",
        "https://ruleset.skk.moe/List/non_ip/global_plus.conf",
        # Stream / media
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GlobalMedia/GlobalMedia.list",
        "https://ruleset.skk.moe/List/non_ip/stream.conf",
        "https://ruleset.skk.moe/List/ip/stream.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_us.conf",
        "https://ruleset.skk.moe/List/ip/stream_us.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_eu.conf",
        "https://ruleset.skk.moe/List/ip/stream_eu.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_jp.conf",
        "https://ruleset.skk.moe/List/ip/stream_jp.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_kr.conf",
        "https://ruleset.skk.moe/List/ip/stream_kr.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_hk.conf",
        "https://ruleset.skk.moe/List/ip/stream_hk.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_tw.conf",
        "https://ruleset.skk.moe/List/ip/stream_tw.conf",
    ],
    "stream": [
        # Streaming-media subset, sourced from the same upstreams merged into
        # proxy. Not listed in RULE_PRIORITIES.json, so proxy.list is unchanged;
        # clients can route this set to a dedicated streaming group.
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GlobalMedia/GlobalMedia.list",
        "https://ruleset.skk.moe/List/non_ip/stream.conf",
        "https://ruleset.skk.moe/List/ip/stream.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_us.conf",
        "https://ruleset.skk.moe/List/ip/stream_us.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_eu.conf",
        "https://ruleset.skk.moe/List/ip/stream_eu.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_jp.conf",
        "https://ruleset.skk.moe/List/ip/stream_jp.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_kr.conf",
        "https://ruleset.skk.moe/List/ip/stream_kr.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_hk.conf",
        "https://ruleset.skk.moe/List/ip/stream_hk.conf",
        "https://ruleset.skk.moe/List/non_ip/stream_tw.conf",
        "https://ruleset.skk.moe/List/ip/stream_tw.conf",
    ],
    "direct": [
        # Apple / China / direct / LAN
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Apple/Apple.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Apple/Apple_Domain.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China_Domain.list",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/apple.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/direct.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/google.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/google-cn.txt",
        "https://ruleset.skk.moe/List/non_ip/apple_cn.conf",
        "https://ruleset.skk.moe/List/non_ip/apple_services.conf",
        "https://ruleset.skk.moe/List/ip/apple_services.conf",
        "https://ruleset.skk.moe/List/non_ip/lan.conf",
        "https://ruleset.skk.moe/List/ip/lan.conf",
        "https://ruleset.skk.moe/List/non_ip/direct.conf",
        "https://ruleset.skk.moe/List/non_ip/domestic.conf",
        "https://ruleset.skk.moe/List/ip/domestic.conf",
        "https://ruleset.skk.moe/List/ip/china_ip.conf",
    ],
    "reject": [
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising_Domain.list",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksurge.list",
        "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockmihomo.yaml",
        "https://raw.githubusercontent.com/afwfv/DD-AD/refs/heads/release/clash.yaml",
        "https://raw.githubusercontent.com/felixbennettio/DD-AD/release/surge-domainset.txt",
        "https://anti-ad.net/surge.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt",
        "https://ruleset.skk.moe/List/non_ip/reject-drop.conf",
        "https://ruleset.skk.moe/List/domainset/reject.conf",
        "https://ruleset.skk.moe/List/domainset/reject_extra.conf",
        "https://ruleset.skk.moe/List/non_ip/reject.conf",
        "https://ruleset.skk.moe/List/non_ip/reject-no-drop.conf",
        "https://ruleset.skk.moe/List/ip/reject.conf",
    ],
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9_-]{2,63}\.?$", re.I)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
IPV6_LIKE_RE = re.compile(r"^[0-9a-f:]+(?:/\d{1,3})?$", re.I)


def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def strip_inline_comment(line: str) -> str:
    line = line.rstrip()
    if not line:
        return ""
    if line.lstrip().upper().startswith(("URL-REGEX", "DOMAIN-REGEX")):
        return line.strip()
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double:
            if line.startswith("//", i):
                break
            if ch in ("#", ";"):
                break
        out.append(ch)
        i += 1
    return "".join(out).strip()


def clean_yaml_item(line: str) -> str:
    line = line.strip()
    if line.startswith("- "):
        line = line[2:].strip()
    elif line.startswith("-"):
        line = line[1:].strip()
    if (line.startswith("'") and line.endswith("'")) or (line.startswith('"') and line.endswith('"')):
        line = line[1:-1].strip()
    return line.strip().rstrip(",")


def normalize_domain(value: str) -> str:
    value = value.strip().strip("'\"").strip().split(",", 1)[0].strip().lower().lstrip("+")
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("."):
        value = value[1:]
    return value.rstrip(".")


def looks_like_domain(value: str) -> bool:
    if not value or "/" in value or " " in value or "@" in value or value.startswith(("http://", "https://")):
        return False
    if IPV4_RE.match(value) or IPV6_LIKE_RE.match(value):
        return False
    return bool(DOMAIN_RE.match(value))


def build(kind: str, payload: str, extra: str = "") -> str | None:
    kind = kind.upper().strip()
    payload = payload.strip().strip("'\"")
    extra = extra.strip().strip("'\"")
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        domain = normalize_domain(payload)
        if domain in IGNORED_SOURCE_MARKERS:
            return None
        return f"{kind},{domain}" if looks_like_domain(domain) else None
    if kind == "DOMAIN-KEYWORD":
        return f"DOMAIN-KEYWORD,{payload}" if payload else None
    if kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
        return f"{kind},{payload}{',' + extra if extra else ''}"
    return None


def convert_line(raw: str) -> str | None:
    line = strip_inline_comment(raw)
    if not line or line.lstrip().startswith(COMMENT_PREFIXES):
        return None
    line = clean_yaml_item(line)
    if not line:
        return None
    lower = line.lower().strip()
    if lower in {"payload:", "payload", "rules:", "rules"}:
        return None
    if re.match(r"^[a-zA-Z0-9_-]+\s*:\s*$", line) or re.match(r"^(type|behavior|format|url|path|interval|proxy|name|description|payload)\s*:", lower):
        return None
    for prefix, kind in (("domain:", "DOMAIN-SUFFIX"), ("full:", "DOMAIN"), ("keyword:", "DOMAIN-KEYWORD")):
        if lower.startswith(prefix):
            return build(kind, line[len(prefix):])
    if lower.startswith(("regexp:", "regex:", "include:")):
        return None
    parts = [p.strip() for p in line.split(",")]
    if len(parts) >= 2:
        kind = {"HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "DOMAIN-WILDCARD": "DOMAIN-SUFFIX"}.get(parts[0].upper(), parts[0].upper())
        if kind in PORTABLE_KINDS:
            return build(kind, parts[1], ",".join(parts[2:]).strip())
        return None
    domain = normalize_domain(line)
    return build("DOMAIN-SUFFIX", domain) if looks_like_domain(domain) else None


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def domain_rule(rule: str) -> tuple[str, str] | None:
    parts = [part.strip() for part in rule.split(",")]
    if len(parts) < 2:
        return None
    kind = parts[0].upper()
    if kind not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        return None
    return kind, parts[1].lower().strip(".\"")


def domain_parents(domain: str) -> list[str]:
    labels = domain.split(".")
    return [".".join(labels[index:]) for index in range(len(labels))]


class RuleIndex:
    """Fast lookup index for precedence checks across very large rule lists."""

    def __init__(self, rules: Iterable[str]) -> None:
        self.rules = set(rules)
        self.exact_domains: set[str] = set()
        self.suffix_domains: set[str] = set()
        self.keywords: set[str] = set()
        for rule in self.rules:
            parsed = domain_rule(rule)
            if not parsed:
                continue
            kind, value = parsed
            if kind == "DOMAIN":
                self.exact_domains.add(value)
            elif kind == "DOMAIN-SUFFIX":
                self.suffix_domains.add(value)
            else:
                self.keywords.add(value)

    def matches_domain(self, domain: str) -> bool:
        return (
            domain in self.exact_domains
            or any(parent in self.suffix_domains for parent in domain_parents(domain))
            or any(keyword in domain for keyword in self.keywords)
        )

    def covers(self, rule: str) -> bool:
        if rule in self.rules:
            return True
        parsed = domain_rule(rule)
        if not parsed:
            return False
        kind, value = parsed
        if kind == "DOMAIN":
            return self.matches_domain(value)
        if kind == "DOMAIN-SUFFIX":
            return (
                any(parent in self.suffix_domains for parent in domain_parents(value))
                or any(keyword in value for keyword in self.keywords)
            )
        return any(keyword in value for keyword in self.keywords)

def remove_covered(items: list[str], higher_priority: list[str], label: str) -> list[str]:
    """Remove only lower-priority rules wholly covered by a higher-priority set."""
    higher_priority_index = RuleIndex(higher_priority)
    out = [item for item in items if not higher_priority_index.covers(item)]
    eprint(f"[precedence] removed {len(items) - len(out)} covered {label} rules")
    return out


def fetch_remote(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "proxy-rules-builder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = resp.read()
        text = data.decode("utf-8", errors="ignore")
        eprint(f"[remote:ok] {url} ({len(text)} bytes)")
        return text.splitlines()
    except Exception as exc:
        eprint(f"[remote:failed] {url}: {exc}")
        return []


def collect_group(name: str) -> list[str]:
    rules: list[str] = []
    for url in SOURCES[name]:
        for line in fetch_remote(url):
            converted = convert_line(line)
            if converted:
                rules.append(converted)
        time.sleep(0.15)
    return dedupe_keep_order(rules)


def read_local_rules(path: Path) -> list[str]:
    if not path.exists():
        return []
    rules: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        converted = convert_line(line)
        if converted:
            rules.append(converted)
    return dedupe_keep_order(rules)


def read_addition_rules(root: Path, name: str) -> list[str]:
    rules: list[str] = []
    for path in addition_files(root, name):
        rules.extend(read_local_rules(path))
    return dedupe_keep_order(rules)


def load_priorities(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    raw_priorities = document.get("priorities")
    if not isinstance(raw_priorities, dict):
        raise ValueError(f"{path.name}: 'priorities' must be an object")

    priorities: dict[str, int] = {}
    for name, value in raw_priorities.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"{path.name}: every rule-set name must be a non-empty string")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path.name}: priority for {name!r} must be an integer")
        priorities[name] = value
    return priorities


def apply_priorities(
    rule_sets: dict[str, list[str]], priorities: dict[str, int]
) -> dict[str, list[str]]:
    """Remove lower-priority rules covered by a higher-priority rule set.

    Larger integers mean higher priority. Sets sharing a priority do not remove
    entries from one another. Unconfigured sets are generated unchanged.
    """
    output: dict[str, list[str]] = {}
    higher_priority_rules: list[str] = []
    configured_names = {name for name in rule_sets if name in priorities}

    for priority in sorted({priorities[name] for name in configured_names}, reverse=True):
        level_names = sorted(
            (name for name in configured_names if priorities[name] == priority),
            key=str.casefold,
        )
        level_rules: list[str] = []
        for name in level_names:
            output[name] = remove_covered(
                rule_sets[name], higher_priority_rules, f"{name} (priority {priority})"
            )
            level_rules.extend(output[name])
        higher_priority_rules.extend(level_rules)

    for name, rules in rule_sets.items():
        if name not in output:
            output[name] = rules
            if name not in priorities:
                eprint(f"[precedence] {name}: no priority configured; kept unchanged")
    return output


def write_rules(path: Path, title: str, rules: list[str]) -> None:
    name = path.stem
    ordered_rules = sort_and_dedupe_rules(rules)
    body = [
        f"# {title}",
        "# Auto-generated by tools/build_rules.py.",
        f"# Extra rules from {name}_add.list are merged automatically.",
    ]
    if ordered_rules:
        body.append("")
        body.extend(ordered_rules)
    body.append("")
    path.write_text("\n".join(body), encoding="utf-8")
    eprint(f"[write] {path.relative_to(ROOT)} ({len(ordered_rules)} sorted rules)")


def to_oxidns_domain_set(rule: str) -> str | None:
    parts = [p.strip() for p in rule.split(",")]
    if len(parts) < 2:
        return None
    kind = parts[0].upper()
    value = parts[1]
    if kind == "DOMAIN":
        domain = normalize_domain(value)
        return f"full:{domain}" if looks_like_domain(domain) else None
    if kind == "DOMAIN-SUFFIX":
        domain = normalize_domain(value)
        return f"domain:{domain}" if looks_like_domain(domain) else None
    if kind == "DOMAIN-KEYWORD":
        keyword = value.strip().strip("'\"")
        return f"keyword:{keyword}" if keyword else None
    # OxiDNS domain_set cannot use IP-CIDR / IP-CIDR6 / IP-ASN entries.
    return None


def write_oxidns_rules(path: Path, title: str, rules: list[str]) -> None:
    entries = dedupe_keep_order(
        entry
        for rule in sort_and_dedupe_rules(rules)
        if (entry := to_oxidns_domain_set(rule))
    )
    body = [
        f"# {title}",
        "# Auto-generated by tools/build_rules.py for OxiDNS domain_set.",
        "# Do not edit this generated file directly.",
        "# DOMAIN -> full:, DOMAIN-SUFFIX -> domain:, DOMAIN-KEYWORD -> keyword:.",
        "# IP rules are intentionally omitted because OxiDNS domain_set matches qname only.",
    ]
    if entries:
        body.append("")
        body.extend(entries)
    body.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body), encoding="utf-8")
    eprint(f"[write] {path.relative_to(ROOT)} ({len(entries)} OxiDNS domain rules)")


def ensure_add_files() -> None:
    templates = {
        "allow_add.list": "# Manual allow exceptions. One portable classical rule per line.\n",
        "ai_add.list": "# Manual AI rules. One portable classical rule per line.\n",
        "push_add.list": "# Manual vendor-push rules. One portable classical rule per line.\n",
        "proxy_add.list": "# Manual proxy rules. One portable classical rule per line.\n",
        "direct_add.list": "# Manual direct rules. One portable classical rule per line.\n",
        "reject_add.list": "# Manual reject rules. One portable classical rule per line.\n",
    }
    for filename, content in templates.items():
        path = ROOT / filename
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def main() -> int:
    ensure_add_files()

    # Discover before writing so any newly added <name>.list or <name>_add.list
    # automatically creates the complete output set for that arbitrary name.
    rule_names = discover_rule_names(ROOT, SOURCES)

    raw_rules = {
        name: dedupe_keep_order(collect_group(name) + read_addition_rules(ROOT, name))
        for name in SOURCES
    }
    titles = {
        "allow": "Explicit allow exceptions",
        "ai": "Consolidated AI rules",
        "push": "Consolidated mobile-vendor push/service rules",
        "reject": "Consolidated reject rules",
        "proxy": "Consolidated proxy/global rules",
        "direct": "Consolidated direct/domestic rules",
        "stream": "Consolidated streaming-media rules",
    }

    # A custom canonical file is its own persistent base. Its matching additions
    # are merged on every run, for any name, without editing this script or the workflow.
    for name in rule_names:
        if name in raw_rules:
            continue
        raw_rules[name] = dedupe_keep_order(
            read_local_rules(ROOT / f"{name}.list") + read_addition_rules(ROOT, name)
        )
        titles[name] = f"Consolidated {name} rules"

    canonical_rules = apply_priorities(raw_rules, load_priorities(PRIORITIES_PATH))

    for name in rule_names:
        rules = canonical_rules[name]
        title = titles[name]
        write_rules(ROOT / f"{name}.list", title, rules)
        write_oxidns_rules(OXIDNS_DIR / f"{name}.txt", title, rules)

    # Keep standalone OxiDNS outputs for manual files for backward compatibility.
    # New client configs should reference only the canonical <name>.txt file.
    for path in discover_addition_files(ROOT):
        write_oxidns_rules(
            OXIDNS_DIR / f"{path.stem}.txt",
            f"Manual additions from {path.name}",
            read_local_rules(path),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
