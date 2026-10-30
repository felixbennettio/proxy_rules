#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "DIST_MANIFEST.json"

# Single source of truth for files published through jsDelivr.
# Root-level portable rule lists, generated DNS rule files, and GeoX assets are published.
def discover_published_files(root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            [path.name for path in root.glob("*.list")]
            + [str(path.relative_to(root)) for path in (root / "dns").glob("*.list")]
            + [str(path.relative_to(root)) for path in (root / "oxidns").glob("*.txt")]
            + [str(path.relative_to(root)) for path in (root / "geox").glob("*.dat")]
        )
    )


def main() -> int:
    published_files = discover_published_files(ROOT)
    missing = [path for path in published_files if not (ROOT / path).is_file()]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise SystemExit(f"Cannot build distribution manifest; missing files:\n{formatted}")

    manifest = {
        "schema_version": 1,
        "repository": "felixbennettio/proxy_rules",
        "files": list(published_files),
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {MANIFEST_PATH.relative_to(ROOT)} with {len(published_files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
