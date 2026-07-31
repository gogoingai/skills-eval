"""Local documentation reference extraction."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlsplit


_MARKDOWN_LINK = re.compile(
    r"(?<!!)\[[^\]]*\]\(\s*(?P<target><[^>]+>|[^)\s]+)"
    r"(?:\s+(?P<title>\"[^\"]*\"|'[^']*'))?\s*\)"
)
_QUOTED_PATH = re.compile(r"(?P<quote>['\"])(?P<target>[^'\"\s\r\n]+)(?P=quote)")


def extract_local_references(text: str, source: Path, root: Path) -> list[Path]:
    """Return normalized local targets found in Markdown and quoted path literals.

    The caller decides whether a target is allowed or exists.  Keeping that
    policy outside this extractor lets it report attempted root escapes too.
    """
    source = source.resolve()
    root = root.resolve()
    targets: list[Path] = []
    seen: set[Path] = set()

    markdown_links = list(_MARKDOWN_LINK.finditer(text))
    for match in markdown_links:
        _append_target(match.group("target"), source, root, targets, seen, quoted=False)
    title_spans = [match.span("title") for match in markdown_links if match.group("title")]
    for match in _QUOTED_PATH.finditer(text):
        if any(start <= match.start() and match.end() <= end for start, end in title_spans):
            continue
        _append_target(match.group("target"), source, root, targets, seen, quoted=True)
    return targets


def _append_target(
    raw_target: str,
    source: Path,
    root: Path,
    targets: list[Path],
    seen: set[Path],
    *,
    quoted: bool,
) -> None:
    target = _clean_target(raw_target, quoted=quoted)
    if target is None:
        return
    candidate = (source.parent / target).resolve()
    if candidate not in seen:
        seen.add(candidate)
        targets.append(candidate)


def _clean_target(raw_target: str, *, quoted: bool) -> str | None:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if not target or target.startswith("#") or "$" in target:
        return None

    parsed = urlsplit(target)
    if parsed.scheme or target.startswith("//"):
        return None
    target = parsed.path
    if not target or not _looks_like_path(target, quoted=quoted):
        return None
    return target


def _looks_like_path(target: str, *, quoted: bool) -> bool:
    """Keep quoted-path extraction conservative to avoid prose false positives."""
    if quoted:
        return target.startswith(("./", "../")) or Path(target).suffix != ""
    path = Path(target)
    return "/" in target or path.suffix != ""
