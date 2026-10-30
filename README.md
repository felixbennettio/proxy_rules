# proxy_rules

`proxy_rules` is a consolidated proxy-rule repository for Surge, mihomo, Egern, Loon, OxiDNS, and other clients that consume remote rule lists.

The repository provides portable rule lists, Surge DNS mapping lists, OxiDNS domain sets, and mirrored GeoX assets. Client configurations should reference this repository instead of depending on many upstream sources directly.

## Canonical client files

Generated rule files:

```text
allow.list
ai.list
push.list
proxy.list
direct.list
reject.list
stream.list
```

`stream.list` is the streaming-media subset built from the same upstreams that
feed `proxy.list`. It has no entry in `RULE_PRIORITIES.json`, so it does not
remove anything from `proxy.list`; clients place it before `proxy.list` to send
streaming traffic to a dedicated group.

Custom file-based sets: `zju.list` (campus routing) and `download.list`
(bulk-download hosts that clients load-balance across nodes). Every
`download.list` entry is also covered by `proxy.list`.

`ai.list` merges and deduplicates focused AI rules from blackmatrix7,
ACL4SSR, Repcz, and SukkaW. `push.list` keeps the Xiaomi, Huawei, OPPO,
vivo, and Meizu service families separate so mobile push traffic can be
routed directly and adjusted without weakening the general reject list.

Cross-set deduplication is controlled by `RULE_PRIORITIES.json`. Larger numbers
have higher priority. The default order is:

```text
allow exceptions (600) > AI (500) > mobile push (400) > reject (300) > generic proxy (200) > generic direct (100)
```

Duplicate rules, and lower-priority rules fully covered by a higher-priority
domain rule, are kept only in the higher-priority set. For example, a rejected
`api.xmpush.xiaomi.com` entry is removed when the higher-priority push set
contains `xiaomi.com`. Sets with the same priority do not remove rules from one
another. A dynamically added set without a configured priority is generated
unchanged; add its name to `RULE_PRIORITIES.json` to include it in cross-set
deduplication.

Every generated canonical list and every `_add.list` file is deduplicated and
sorted deterministically. Rules are grouped in this order:

```text
DOMAIN → DOMAIN-SUFFIX → DOMAIN-KEYWORD → IP-CIDR → IP-CIDR6 → IP-ASN
```

Within each type, domain and keyword values are sorted alphabetically without
case sensitivity. IP networks and ASNs are sorted numerically.

Manual override files:

```text
allow_add.list
ai_add.list
push_add.list
proxy_add.list
direct_add.list
reject_add.list
```

Every manual addition is merged into its same-name canonical file. For example,
rules in `ai_add.list` become part of `ai.list`; clients only need to reference
`ai.list`.

`allow_add.list` contains explicit exceptions for services incorrectly blocked
by upstream lists. These exceptions take priority over the other configured
sets, so covered reject entries are removed from both `reject.list` and
`oxidns/reject.txt` on every rebuild. `allow.list` is rebuilt from
`allow_add.list` only; removing an exception there removes its protection on
the next rebuild.

The initial exceptions allow the NetEase Yidun CAPTCHA loader and anti-cheat
hosts required by the copyright registration login page. Their parent domains
are already covered by `direct.list` and `oxidns/direct.txt`, so existing
clients can use the fix by refreshing their current rule subscriptions.
Clients can also load `allow.list` with a direct policy, or `oxidns/allow.txt`
with their normal DNS upstream, before reject rules.

Rule-set names are discovered automatically; `rule10` is only an example, not a
fixed name. Adding any `<name>.list` creates its Surge DNS and OxiDNS outputs and distribution
entry. Adding any `<name>_add.list` also creates or updates `<name>.list` and
merges those additions. No workflow allow-list needs to be edited. For
upstream-backed built-in sets, put custom rules in the `_add.list` file instead
of editing the generated canonical file directly.

## Surge DNS mapping files

Use root-level lists such as `direct.list` and `proxy.list` in Surge's `[Rule]`
section. They retain all domain and IP rules for traffic routing.

Use `dns/<name>.list` in `[Host]` to choose a DNS server by domain. These lists
contain only `DOMAIN`, `DOMAIN-SUFFIX`, and `DOMAIN-KEYWORD` rules, so DNS mapping
does not depend on resolving an IP address first. Reference them as `RULE-SET`,
not `DOMAIN-SET`, to preserve keyword matching.

```ini
[Rule]
RULE-SET,https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/proxy.list,Proxy
RULE-SET,https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/direct.list,DIRECT
FINAL,Proxy

[Host]
RULE-SET:https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/dns/direct.list = server:https://dns.alidns.com/dns-query
RULE-SET:https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/dns/proxy.list = server:https://dns.google/dns-query
```

The example assumes a policy named `Proxy`; use your own policies and DNS
servers. `[Host]` controls Surge's local DNS lookups; proxied connections may
still resolve names on the proxy server.

Every canonical list automatically gets a matching DNS list after the same
priority and deduplication rules are applied. Continue editing `<name>_add.list`;
there is no second list to maintain. Daily builds verify that DNS lists contain
exactly the canonical domain rules, then publish both versions together.

## OxiDNS files

Generated OxiDNS files are stored under:

```text
oxidns/
```

The conversion is:

```text
DOMAIN,example.com         -> full:example.com
DOMAIN-SUFFIX,example.com  -> domain:example.com
DOMAIN-KEYWORD,example     -> keyword:example
```

IP rules are omitted from OxiDNS domain sets because they only match DNS names.

## GeoX assets

The workflow mirrors Loyalsoldier v2ray-rules-dat GeoX databases for machines that cannot directly access external networks.

| File | Source |
| --- | --- |
| `geox/geoip.dat` | `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat` |
| `geox/geosite.dat` | `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` |

Use these URLs in mihomo `geox-url` configuration:

```yaml
geox-url:
  geoip: https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/geox/geoip.dat
  geosite: https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/geox/geosite.dat
```

## Distribution

Recommended jsDelivr endpoint:

```text
https://cdn.jsdelivr.net/gh/felixbennettio/proxy_rules@main/<file>
```

Raw GitHub URLs can be used as fallback.

## Update process

GitHub Actions rebuilds rules and refreshes GeoX assets daily:

```text
tools/build_rules.py
tools/fetch_geox.py
tools/build_dist_manifest.py
.github/workflows/build-rules.yml
```

The workflow can also be triggered manually from GitHub Actions.
