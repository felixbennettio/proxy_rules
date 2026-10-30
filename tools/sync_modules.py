#!/usr/bin/env python3
"""Mirror installed Surge modules and their declared script dependencies."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_RE = re.compile(r"(?P<prefix>script-path\s*=\s*)(?P<url>https?://[^,\s]+)")
USER_AGENT = "proxy-rules-module-mirror/1.0"


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def public_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Sources must be public HTTPS URLs without credentials or query parameters")
    return url


def asset_path(url: str) -> str:
    name = Path(urlsplit(public_url(url)).path).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.js", name):
        raise ValueError("Unsupported script filename")
    return "modules/scripts/" + hashlib.sha256(url.encode()).hexdigest()[:16] + "-" + name


def module_filename(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.sgmodule", value):
        raise ValueError("Unsafe module filename")
    return value


def validate(data: bytes, kind: str, name: str = "") -> str:
    text = data.decode("utf-8-sig")
    if not text.strip() or text.lstrip().lower().startswith(("<!doctype", "<html")):
        raise ValueError("Empty or HTML response")
    if kind == "module":
        match = re.search(r"(?m)^#!name=(.+)$", text)
        if not match or match[1].strip() != name or not re.search(r"(?m)^\[[^\]]+\]", text):
            raise ValueError("Unexpected module identity or format")
    return text


def download(url: str) -> bytes:
    public_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(8 * 1024 * 1024 + 1)
        length = response.headers.get("Content-Length")
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Module asset exceeds the 8 MiB limit")
    if length and length.isdigit() and len(data) != int(length):
        raise ValueError("Incomplete download")
    return data


def resolve(root: Path, url: str, path: str, kind: str, name: str, fetch, previous: dict) -> tuple[bytes, dict]:
    public_url(url)
    try:
        data = fetch(url)
        validate(data, kind, name)
        return data, {"url": url, "path": path, "status": "fresh",
                      "last_success": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                      "sha256": hashlib.sha256(data).hexdigest()}
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError) as exc:
        local = root / path
        if not local.is_file():
            raise RuntimeError(f"No verified local copy for unavailable source: {url}") from None
        data = local.read_bytes()
        validate(data, kind, name)
        checksum = hashlib.sha256(data).hexdigest()
        if previous.get("sha256") and previous["sha256"] != checksum:
            raise ValueError(f"Cached source checksum mismatch: {path}")
        error = (f"HTTP {exc.code}" if isinstance(exc, urllib.error.HTTPError) else type(exc).__name__)
        return data, {"url": url, "path": path, "status": "cached", "error": error,
                      "last_success": previous.get("last_success", previous.get("seed_last_success")),
                      "sha256": checksum}


def render_module(text: str, paths: dict[str, str], base: str, project_id: int) -> str:
    if not SCRIPT_RE.search(text):
        return text
    arguments = re.search(r"(?m)^#!arguments=(.*)$", text)
    if arguments and re.search(r"(?:^|,)\s*GitLabToken(?:[:,]|$)", arguments[1]):
        raise ValueError("Upstream already declares the reserved GitLabToken argument")
    addition = 'GitLabToken:""'
    if re.search(r"(?m)^#!arguments=", text):
        text = re.sub(r"(?m)^(#!arguments=.*)$", lambda m: m[1] + "," + addition, text, count=1)
    else:
        text = re.sub(r"(?m)^(#!name=.*)$", lambda m: m[1] + "\n#!arguments=" + addition, text, count=1)
    def replace(match):
        path = paths[match["url"]]
        target = f"{base}/api/v4/projects/{project_id}/repository/files/{quote(path, safe='')}/raw?ref=main&private_token={{{{{{GitLabToken}}}}}}"
        return match["prefix"] + target
    return SCRIPT_RE.sub(replace, text)


def build(root: Path = ROOT, fetch=download) -> dict:
    config = json.loads((root / "modules/SOURCES.json").read_text(encoding="utf-8"))
    base = config["gitlab_base"].rstrip("/")
    if base != "https://git.routeforge.zone" or config["gitlab_project_id"] != 13:
        raise ValueError("Unexpected private distribution destination")
    status_path = root / "modules/STATUS.json"
    previous = json.loads(status_path.read_text()) if status_path.exists() else {}
    history = {item["url"]: item for item in previous.get("sources", [])}
    seeds = {item["url"]: item for item in config["assets"]}
    for module in config["modules"]:
        seeds[module["url"]] = module
    pending: dict[str, bytes] = {}
    statuses = []
    modules = config["modules"]
    def get_module(module):
        filename = module_filename(module["filename"])
        path = "modules/upstream/" + filename
        old = history.get(module["url"], seeds.get(module["url"], {}))
        return module, resolve(root, module["url"], path, "module", module["name"], fetch, old)
    with ThreadPoolExecutor(max_workers=6) as pool:
        resolved = list(pool.map(get_module, modules))
    urls = set()
    for module, (data, status) in resolved:
        pending[status["path"]] = data
        statuses.append(status)
        urls.update(match["url"] for match in SCRIPT_RE.finditer(data.decode("utf-8-sig")))
    paths = {url: asset_path(url) for url in urls}
    def get_asset(url):
        old = history.get(url, seeds.get(url, {}))
        return resolve(root, url, paths[url], "script", "", fetch, old)
    with ThreadPoolExecutor(max_workers=6) as pool:
        assets = list(pool.map(get_asset, sorted(urls)))
    for data, status in assets:
        pending[status["path"]] = data
        statuses.append(status)
    for module, (data, _) in resolved:
        text = render_module(data.decode("utf-8-sig"), paths, base, config["gitlab_project_id"])
        pending["modules/" + module["filename"]] = text.encode("utf-8")
    # Nothing is written until every module and declared dependency is available.
    for path, data in pending.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for folder, suffix in [("modules", ".sgmodule"), ("modules/upstream", ".sgmodule"), ("modules/scripts", ".js")]:
        for path in (root / folder).glob("*" + suffix):
            if path.relative_to(root).as_posix() not in pending:
                path.unlink()
    fresh = sum(status["status"] == "fresh" for status in statuses)
    report = {"schema_version": 1, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "status": "fresh" if fresh == len(statuses) else "using_cached_sources",
              "modules": len(modules), "scripts": len(urls), "fresh_sources": fresh,
              "cached_sources": len(statuses) - fresh, "sources": sorted(statuses, key=lambda s: s["path"])}
    write_json(status_path, report)
    print(f"Mirrored {len(modules)} modules and {len(urls)} scripts: {fresh} fresh sources, {len(statuses)-fresh} retained cached sources.")
    return report


if __name__ == "__main__":
    build()
