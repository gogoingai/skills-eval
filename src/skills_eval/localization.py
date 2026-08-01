"""Resolve the human-report language from configuration and system settings."""

from __future__ import annotations

import locale
import os
import platform
import re
import subprocess


def resolve_report_language(configured_language: str) -> str:
    """Return ``zh`` for Chinese preferences and ``en`` for every other case."""
    if configured_language in {"zh", "en"}:
        return configured_language
    return "zh" if _preferred_language().lower().startswith("zh") else "en"


def _preferred_language() -> str:
    if platform.system() == "Darwin":
        macos_language = _macos_preferred_language()
        if macos_language:
            return macos_language
    for key in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        value = os.environ.get(key)
        if value:
            return value.split(":", maxsplit=1)[0].split(".", maxsplit=1)[0]
    return locale.getlocale()[0] or "en"


def _macos_preferred_language() -> str | None:
    try:
        completed = subprocess.run(
            ["defaults", "read", "-g", "AppleLanguages"],
            capture_output=True,
            check=False,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    languages = re.findall(r'"([^"\\]+)"', completed.stdout)
    return languages[0] if languages else None
