#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "DIST_MANIFEST.json"

# Single source of truth for files published through jsDelivr.
# Root-level portable rule lists, generated DNS rule files, and GeoX assets are published.
PUBLISHED_FILES = tuple(
    sorted(
        [path.name for path in ROOT.glob("*.list")]
        + [str(path.relative_to(ROOT)) for path in (ROOT / "oxidns").glob("*.txt")]
        + [str(path.relative_to(ROOT)) for path in (ROOT / "geox").glob("*.dat")]
    )
)


def main() -> int:
    missing = [path for path in PUBLISHED_FILES if not (ROOT / path).is_file()]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise SystemExit(f"Cannot build distribution manifest; missing files:\n{formatted}")

    manifest = {
        "schema_version": 1,
        "repository": "felixbennettio/proxy_rules",
        "files": list(PUBLISHED_FILES),
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {MANIFEST_PATH.relative_to(ROOT)} with {len(PUBLISHED_FILES)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
