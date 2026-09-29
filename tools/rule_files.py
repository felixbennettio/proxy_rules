#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Iterable

ADDITION_SUFFIXES = ("_add",)


def addition_base(path: Path) -> str | None:
    """Return the canonical rule-set name for an addition file."""
    if path.suffix != ".list":
        return None
    for suffix in ADDITION_SUFFIXES:
        if path.stem.endswith(suffix):
            base = path.stem[: -len(suffix)]
            return base or None
    return None


def is_addition_file(path: Path) -> bool:
    return addition_base(path) is not None


def addition_files(root: Path, name: str) -> list[Path]:
    """Return all supported manual-addition files for one canonical set."""
    return [
        path
        for suffix in ADDITION_SUFFIXES
        if (path := root / f"{name}{suffix}.list").is_file()
    ]


def discover_addition_files(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.glob("*.list") if is_addition_file(path)),
        key=lambda path: path.name.casefold(),
    )


def discover_rule_names(root: Path, built_in_names: Iterable[str] = ()) -> list[str]:
    """Discover canonical rule-set names without a hard-coded allow-list."""
    names = set(built_in_names)
    for path in root.glob("*.list"):
        names.add(addition_base(path) or path.stem)
    return sorted((name for name in names if name), key=str.casefold)
