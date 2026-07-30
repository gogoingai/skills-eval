"""Local documentation reference extraction."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlsplit


_MARKDOWN_LINK = re.compile(
    r"(?<!!)\[[^\]]*\]\(\s*(?P<target><[^>]+>|[^)\s]+)(?:\s+['\"][^)]*['\"])?\s*\)"
)
_QUOTED_PATH = re.compile(r"(?P<quote>['\"])(?P<target>[^'\"\r\n]+)(?P=quote)")


def extract_local_references(text: str, source: Path, root: Path) -> list[Path]:
    """Return normalized local targets found in Markdown and quoted path literals.

    The caller decides whether a target is allowed or exists.  Keeping that
    policy outside this extractor lets it report attempted root escapes too.
    """
    source = source.resolve()
    root = root.resolve()
    targets: list[Path] = []
    seen: set[Path] = set()

    for match in _MARKDOWN_LINK.finditer(text):
        _append_target(match.group("target"), source, root, targets, seen)
    for match in _QUOTED_PATH.finditer(text):
        _append_target(match.group("target"), source, root, targets, seen)
    return targets


def _append_target(
    raw_target: str,
    source: Path,
    root: Path,
    targets: list[Path],
    seen: set[Path],
) -> None:
    target = _clean_target(raw_target)
    if target is None:
        return
    candidate = (source.parent / target).resolve()
    if candidate not in seen:
        seen.add(candidate)
        targets.append(candidate)


def _clean_target(raw_target: str) -> str | None:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if not target or target.startswith("#") or "$" in target:
        return None

    parsed = urlsplit(target)
    if parsed.scheme or target.startswith("//"):
        return None
    target = parsed.path
    if not target or not _looks_like_path(target):
        return None
    return target


def _looks_like_path(target: str) -> bool:
    """Avoid treating quoted prose as a path while retaining ordinary files."""
    path = Path(target)
    return "/" in target or path.suffix != ""
