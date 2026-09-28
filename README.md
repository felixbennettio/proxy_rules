# proxy_rules

`proxy_rules` is a consolidated proxy-rule repository for Surge, mihomo, Egern, Loon, OxiDNS, and other clients that consume remote rule lists.

The repository provides portable rule lists, generated OxiDNS domain sets, and mirrored GeoX assets. Client configurations should reference this repository instead of depending on many upstream sources directly.

## Canonical client files

Generated rule files:

```text
ai.list
push.list
proxy.list
direct.list
reject.list
```

`ai.list` merges and deduplicates focused AI rules from blackmatrix7,
ACL4SSR, Repcz, and SukkaW. `push.list` keeps the Xiaomi, Huawei, OPPO,
vivo, and Meizu service families separate so mobile push traffic can be
routed directly and adjusted without weakening the general reject list.

The generator applies this precedence when resolving semantic domain
overlaps:

```text
AI / mobile push > reject > generic proxy > generic direct
```

This includes parent/child domain relationships, not only identical lines.
For example, a rejected `api.xmpush.xiaomi.com` entry is removed when the
protected push set contains `xiaomi.com`.

Manual override files:

```text
proxy_added.list
direct_added.list
reject_added.list
```

Do not edit generated files directly.

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
