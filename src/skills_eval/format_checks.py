"""Portable plugin format checks with optional Wenqu release rules."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
from typing import Iterator
from urllib.parse import urlsplit

import pathspec
import yaml

from skills_eval.config import EvalConfig
from skills_eval.models import Diagnostic, Plugin, Severity, Skill, parse_frontmatter
from skills_eval.references import extract_local_references


_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"})
_WENQU_IMAGE_REFERENCE = re.compile(
    r"wenqu-image-assets/styles/([A-Za-z0-9._/-]+\.(?:png|jpe?g|webp|gif|svg))",
    re.IGNORECASE,
)


def check_format(root: Path, plugin: Plugin, skills: list[Skill], config: EvalConfig) -> list[Diagnostic]:
    """Validate selected Skills and configured repository-format expectations."""
    root = root.resolve()
    diagnostics: list[Diagnostic] = []
    _check_root_files(root, config, diagnostics)
    _check_forbidden_paths(root, config, diagnostics)
    _check_skill_frontmatter(skills, config, diagnostics)
    _check_local_references(root, config, diagnostics)

    if config.require_marketplace_metadata:
        _check_wenqu_release_metadata(root, diagnostics)
    if config.require_openclaw_metadata:
        _check_openclaw_homepages(skills, diagnostics)
    if config.require_image_references:
        _check_wenqu_image_assets(root, diagnostics)
    return diagnostics


def _check_root_files(root: Path, config: EvalConfig, diagnostics: list[Diagnostic]) -> None:
    for relative_path in config.required_root_files:
        path = root / relative_path
        if not path.is_file():
            _fail(diagnostics, "ROOT_FILE_MISSING", f"Missing required root file: {relative_path}", path)


def _check_forbidden_paths(root: Path, config: EvalConfig, diagnostics: list[Diagnostic]) -> None:
    if not config.forbidden_paths:
        return
    spec = pathspec.GitIgnoreSpec.from_lines(config.forbidden_paths)
    for path in _walk_files(root):
        relative_path = path.relative_to(root).as_posix()
        if spec.match_file(relative_path):
            _fail(diagnostics, "FORBIDDEN_PATH", f"Forbidden path matches configuration: {relative_path}", path)


def _check_skill_frontmatter(skills: list[Skill], config: EvalConfig, diagnostics: list[Diagnostic]) -> None:
    for skill in skills:
        skill_file = skill.path / "SKILL.md"
        try:
            frontmatter = parse_frontmatter(skill_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as error:
            _fail(diagnostics, "FRONTMATTER_INVALID", f"Invalid frontmatter: {error}", skill_file)
            continue
        if frontmatter is None:
            _fail(diagnostics, "FRONTMATTER_INVALID", "SKILL.md must begin with mapping YAML frontmatter.", skill_file)
            continue
        required_keys = dict.fromkeys(("name", "description", *config.required_skill_frontmatter))
        for key in required_keys:
            if key not in frontmatter:
                _fail(diagnostics, "FRONTMATTER_REQUIRED", f"SKILL.md frontmatter is missing {key!r}.", skill_file)
            elif not _is_nonempty_scalar(frontmatter[key]):
                _fail(
                    diagnostics,
                    "FRONTMATTER_VALUE_INVALID",
                    f"SKILL.md frontmatter {key!r} must be a non-empty scalar.",
                    skill_file,
                )


def _is_nonempty_scalar(value: object) -> bool:
    if value is None or isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return False
    return not isinstance(value, str) or bool(value.strip())


def _check_local_references(root: Path, config: EvalConfig, diagnostics: list[Diagnostic]) -> None:
    extensions = {extension.lower() for extension in config.reference_extensions}
    for source in _walk_files(root):
        if source.suffix.lower() not in extensions:
            continue
        try:
            text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for target in extract_local_references(text, source, root):
            if not _is_within(root, target):
                _fail(
                    diagnostics,
                    "REFERENCE_OUTSIDE_ROOT",
                    f"Local reference resolves outside plugin root: {target}",
                    source,
                )
            elif not target.exists():
                _fail(diagnostics, "REFERENCE_MISSING", f"Local reference does not exist: {target}", source)


def _check_wenqu_release_metadata(root: Path, diagnostics: list[Diagnostic]) -> None:
    version_path = root / "VERSION"
    version = _read_text(version_path, diagnostics, "VERSION_MISSING")
    if version is None:
        return
    version = version.strip()
    if not _SEMVER.fullmatch(version):
        _fail(diagnostics, "VERSION_INVALID", f"VERSION must contain a semantic version, got {version or 'none'}", version_path)

    changelog_path = root / "CHANGELOG.md"
    changelog = _read_text(changelog_path, diagnostics, "CHANGELOG_MISSING")
    if changelog is not None and version and f"## {version}" not in changelog:
        _fail(diagnostics, "CHANGELOG_VERSION_MISSING", f"CHANGELOG.md has no entry for {version}", changelog_path)

    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = _read_json(manifest_path, diagnostics)
    if not isinstance(manifest, dict) or not version:
        return
    plugin_name = manifest.get("name")
    if not isinstance(plugin_name, str) or not plugin_name:
        _fail(diagnostics, "PLUGIN_NAME_MISSING", "plugin.json must declare name", manifest_path)
        return
    if manifest.get("version") != version:
        _fail(diagnostics, "PLUGIN_VERSION_MISMATCH", f"plugin.json must declare version {version}", manifest_path)

    marketplace_path = root / ".claude-plugin" / "marketplace.json"
    marketplace = _read_json(marketplace_path, diagnostics)
    if not isinstance(marketplace, dict):
        return
    if marketplace.get("name") != plugin_name:
        _fail(diagnostics, "MARKET_NAME_MISMATCH", f"marketplace.json must use name {plugin_name}", marketplace_path)
    plugins = marketplace.get("plugins")
    entry = next(
        (
            item
            for item in plugins
            if isinstance(item, dict) and item.get("name") == plugin_name
        ),
        None,
    ) if isinstance(plugins, list) else None
    if not isinstance(entry, dict):
        _fail(diagnostics, "MARKET_PLUGIN_MISSING", f"marketplace.json must declare plugin {plugin_name}", marketplace_path)
        return
    if entry.get("source") != "./":
        _fail(diagnostics, "MARKET_SOURCE_INVALID", "Marketplace plugin source must be './'.", marketplace_path)
    if entry.get("version") != version:
        _fail(diagnostics, "MARKET_VERSION_MISMATCH", f"Marketplace version must be {version}.", marketplace_path)
    if not _is_nonempty_scalar(entry.get("description")):
        _fail(diagnostics, "MARKET_DESCRIPTION_MISSING", "Marketplace plugin must have a description.", marketplace_path)


def _check_openclaw_homepages(skills: list[Skill], diagnostics: list[Diagnostic]) -> None:
    for skill in skills:
        skill_file = skill.path / "SKILL.md"
        try:
            frontmatter = parse_frontmatter(skill_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError):
            continue
        if not isinstance(frontmatter, dict):
            continue
        metadata = frontmatter.get("metadata")
        openclaw = metadata.get("openclaw") if isinstance(metadata, dict) else None
        homepage = openclaw.get("homepage") if isinstance(openclaw, dict) else None
        if not isinstance(homepage, str) or not homepage.strip():
            _fail(diagnostics, "OPENCLAW_HOMEPAGE_MISSING", "SKILL.md is missing metadata.openclaw.homepage", skill_file)
        elif not _is_valid_https_url(homepage):
            _fail(diagnostics, "OPENCLAW_HOMEPAGE_INVALID", f"Invalid OpenClaw homepage: {homepage}", skill_file)


def _is_valid_https_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(hostname)
        and not any(character.isspace() for character in hostname)
    )


def _check_wenqu_image_assets(root: Path, diagnostics: list[Diagnostic]) -> None:
    asset_root = root / "wenqu-image-assets" / "styles"
    documentation_root = root / "wenqu-image"
    documentation = "\n".join(
        _read_optional_text(path) for path in _walk_files(documentation_root) if path.suffix.lower() in {".md", ".sh"}
    )
    if not asset_root.exists() and not documentation:
        return
    assets = list(_walk_files(asset_root, _IMAGE_EXTENSIONS))
    referenced_assets: set[Path] = set()
    for match in _WENQU_IMAGE_REFERENCE.finditer(documentation):
        relative_asset = Path(match.group(1))
        resolved_asset = (asset_root / relative_asset).resolve()
        if not _is_within(asset_root.resolve(), resolved_asset) or not resolved_asset.is_file():
            _fail(
                diagnostics,
                "IMAGE_REFERENCE_MISSING",
                f"Image reference has no matching asset: wenqu-image-assets/styles/{relative_asset.as_posix()}",
                asset_root,
            )
        else:
            referenced_assets.add(resolved_asset)
    basename_counts: dict[str, int] = {}
    for asset in assets:
        basename_counts[asset.name] = basename_counts.get(asset.name, 0) + 1
    for asset in assets:
        relative_asset = asset.relative_to(asset_root).as_posix()
        path_mentioned = relative_asset in documentation
        uniquely_named = basename_counts[asset.name] == 1 and asset.name in documentation
        if asset not in referenced_assets and not path_mentioned and not uniquely_named:
            _fail(
                diagnostics,
                "IMAGE_ASSET_UNREFERENCED",
                f"Image asset is not referenced by Wenqu image documentation: {relative_asset}",
                asset,
            )


def _walk_files(root: Path, extensions: frozenset[str] | None = None) -> Iterator[Path]:
    if not root.is_dir():
        return
    for directory, child_dirs, filenames in os.walk(root):
        child_dirs[:] = [name for name in child_dirs if name != ".git"]
        for filename in filenames:
            path = Path(directory) / filename
            if extensions is None or path.suffix.lower() in extensions:
                yield path


def _read_optional_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _read_text(path: Path, diagnostics: list[Diagnostic], missing_code: str) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        _fail(diagnostics, missing_code, f"Missing required file: {path}", path)
        return None


def _read_json(path: Path, diagnostics: list[Diagnostic]) -> object | None:
    text = _read_text(path, diagnostics, "JSON_FILE_MISSING")
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        _fail(diagnostics, "JSON_INVALID", f"Invalid JSON: {path}", path)
        return None


def _is_within(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def _fail(diagnostics: list[Diagnostic], code: str, message: str, path: Path) -> None:
    diagnostics.append(Diagnostic(Severity.FAIL, code, message, path))
