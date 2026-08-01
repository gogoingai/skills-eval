"""Portable plugin format checks with optional, project-configured release rules."""

from __future__ import annotations

from collections.abc import Mapping
import ipaddress
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
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_SKILLHUB_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])$")


def check_format(root: Path, plugin: Plugin, skills: list[Skill], config: EvalConfig) -> list[Diagnostic]:
    """Validate selected Skills and configured repository-format expectations."""
    root = root.resolve()
    diagnostics: list[Diagnostic] = []
    _check_root_files(root, config, diagnostics)
    _check_forbidden_paths(root, config, diagnostics)
    _check_skill_frontmatter(skills, config, diagnostics)
    _check_local_references(root, skills, config, diagnostics)

    _check_release_baseline(root, config, diagnostics)
    _check_asset_references(root, config, diagnostics)
    for target in _enabled_publishing_targets(config):
        name = str(target["name"])
        _PUBLISHING_TARGET_CHECKS[name](root, plugin, skills, config, target, diagnostics)
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


def _check_local_references(
    root: Path, skills: list[Skill], config: EvalConfig, diagnostics: list[Diagnostic]
) -> None:
    extensions = {extension.lower() for extension in config.reference_extensions}
    sources = (source for skill in skills for source in _walk_files(skill.path))
    for source in sources:
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


def _enabled_publishing_targets(config: EvalConfig) -> tuple[Mapping[str, object], ...]:
    return tuple(
        target
        for target in getattr(config, "publishing_targets", ())
        if target.get("enabled") is True
    )


def _release_version(root: Path, config: EvalConfig, diagnostics: list[Diagnostic]) -> str | None:
    release = _release_settings(config)
    version_file = release.get("versionFile")
    if not isinstance(version_file, str):
        return None
    version_path = root / version_file
    version = _read_text(version_path, diagnostics, "VERSION_MISSING")
    if version is None:
        return None
    version = version.strip()
    if release.get("requireVersionSemver") is True and not _SEMVER.fullmatch(version):
        _fail(diagnostics, "VERSION_INVALID", f"{version_file} must contain a semantic version, got {version or 'none'}", version_path)
    return version


def _check_release_baseline(root: Path, config: EvalConfig, diagnostics: list[Diagnostic]) -> None:
    version = _release_version(root, config, diagnostics)
    release = _release_settings(config)
    changelog_file = release.get("changelogFile")
    if version is None or not isinstance(changelog_file, str):
        return
    changelog_path = root / changelog_file
    changelog = _read_text(changelog_path, diagnostics, "CHANGELOG_MISSING")
    heading = release.get("changelogVersionHeading", "## {version}")
    assert isinstance(heading, str)
    if changelog is not None and version and heading.replace("{version}", version) not in changelog:
        _fail(
            diagnostics,
            "CHANGELOG_VERSION_MISSING",
            f"{changelog_file} has no entry for {version}",
            changelog_path,
        )


def _check_claude_plugin(
    root: Path,
    plugin: Plugin,
    skills: list[Skill],
    config: EvalConfig,
    target: Mapping[str, object],
    diagnostics: list[Diagnostic],
) -> None:
    del skills
    version = _release_version(root, config, diagnostics)

    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = _read_json(manifest_path, diagnostics)
    if not isinstance(manifest, dict):
        return
    plugin_name = manifest.get("name")
    if not isinstance(plugin_name, str) or not plugin_name:
        _fail(diagnostics, "PLUGIN_NAME_MISSING", "plugin.json must declare name", manifest_path)
        return
    if version is not None and manifest.get("version") != version:
        _fail(diagnostics, "PLUGIN_VERSION_MISMATCH", f"plugin.json must declare version {version}", manifest_path)

    options = _target_options(target)
    skill_directory_prefix = options.get("skillDirectoryPrefix")
    if isinstance(skill_directory_prefix, str):
        _check_undeclared_skills(root, plugin, skill_directory_prefix, diagnostics)

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
    if version is not None and entry.get("version") != version:
        _fail(diagnostics, "MARKET_VERSION_MISMATCH", f"Marketplace version must be {version}.", marketplace_path)
    if not _is_nonempty_scalar(entry.get("description")):
        _fail(diagnostics, "MARKET_DESCRIPTION_MISSING", "Marketplace plugin must have a description.", marketplace_path)


def _check_undeclared_skills(
    root: Path, plugin: Plugin, directory_prefix: str, diagnostics: list[Diagnostic]
) -> None:
    declared_paths = {skill.path.resolve() for skill in plugin.skills}
    for path in root.iterdir():
        if not path.is_dir() or not path.name.startswith(directory_prefix):
            continue
        skill_file = path / "SKILL.md"
        if skill_file.is_file() and path.resolve() not in declared_paths:
            _fail(
                diagnostics,
                "PLUGIN_SKILL_UNDECLARED",
                f"{path.name}/SKILL.md exists but is absent from plugin.json skills.",
                path,
            )


def _check_workbuddy(
    root: Path,
    plugin: Plugin,
    skills: list[Skill],
    config: EvalConfig,
    target: Mapping[str, object],
    diagnostics: list[Diagnostic],
) -> None:
    del root, plugin, config, target
    for skill in skills:
        frontmatter = skill.frontmatter or {}
        skill_file = skill.path / "SKILL.md"
        for field in ("displayName", "version", "summary", "license"):
            if field not in frontmatter:
                _fail(
                    diagnostics,
                    "WORKBUDDY_METADATA_MISSING",
                    f"SKILL.md is missing {field}.",
                    skill_file,
                )
            elif not _is_nonempty_scalar(frontmatter[field]):
                _fail(
                    diagnostics,
                    "WORKBUDDY_METADATA_EMPTY",
                    f"SKILL.md has an empty {field}.",
                    skill_file,
                )
        version = frontmatter.get("version")
        if _is_nonempty_scalar(version) and not _SEMVER.fullmatch(str(version).strip()):
            _fail(
                diagnostics,
                "WORKBUDDY_VERSION_INVALID",
                f"SKILL.md has invalid version {version}.",
                skill_file,
            )


def _check_skillhub(
    root: Path,
    plugin: Plugin,
    skills: list[Skill],
    config: EvalConfig,
    target: Mapping[str, object],
    diagnostics: list[Diagnostic],
) -> None:
    del root, plugin, config, target
    slugs: dict[str, Path] = {}
    for skill in skills:
        frontmatter = skill.frontmatter or {}
        skill_file = skill.path / "SKILL.md"
        slug = frontmatter.get("slug")
        if not _is_nonempty_scalar(slug):
            _fail(diagnostics, "SKILLHUB_SLUG_MISSING", "SKILL.md is missing slug.", skill_file)
        else:
            normalized_slug = str(slug).strip()
            if not _SKILLHUB_SLUG.fullmatch(normalized_slug):
                _fail(
                    diagnostics,
                    "SKILLHUB_SLUG_INVALID",
                    f"SKILL.md has invalid SkillHub slug {normalized_slug}.",
                    skill_file,
                )
            elif normalized_slug in slugs:
                _fail(
                    diagnostics,
                    "SKILLHUB_SLUG_DUPLICATE",
                    f"SKILL.md reuses slug {normalized_slug} already declared by {slugs[normalized_slug]}.",
                    skill_file,
                )
            else:
                slugs[normalized_slug] = skill_file
        for image in _walk_files(skill.path, _IMAGE_EXTENSIONS):
            _fail(
                diagnostics,
                "SKILLHUB_UNSUPPORTED_FILE",
                f"SkillHub does not accept image files inside a Skill package: {image}",
                image,
            )


def _check_openclaw(
    root: Path,
    plugin: Plugin,
    skills: list[Skill],
    config: EvalConfig,
    target: Mapping[str, object],
    diagnostics: list[Diagnostic],
) -> None:
    del plugin, target
    version = _release_version(root, config, diagnostics)
    manifest_path = root / "openclaw.plugin.json"
    manifest = _read_json(manifest_path, diagnostics)
    if isinstance(manifest, dict) and version is not None and manifest.get("version") != version:
        _fail(
            diagnostics,
            "OPENCLAW_VERSION_MISMATCH",
            f"openclaw.plugin.json must declare version {version}.",
            manifest_path,
        )
    _check_openclaw_homepages(skills, diagnostics)


def _check_clawhub(
    root: Path,
    plugin: Plugin,
    skills: list[Skill],
    config: EvalConfig,
    target: Mapping[str, object],
    diagnostics: list[Diagnostic],
) -> None:
    del plugin, skills
    version = _release_version(root, config, diagnostics)
    package_path = root / "package.json"
    package = _read_json(package_path, diagnostics)
    if not isinstance(package, dict):
        return
    package_name = _target_options(target).get("packageName")
    if isinstance(package_name, str) and package.get("name") != package_name:
        _fail(
            diagnostics,
            "PACKAGE_NAME_MISMATCH",
            f"package.json must use package name {package_name}.",
            package_path,
        )
    if version is not None and package.get("version") != version:
        _fail(
            diagnostics,
            "PACKAGE_VERSION_MISMATCH",
            f"package.json must declare version {version}.",
            package_path,
        )


_PUBLISHING_TARGET_CHECKS = {
    "claude-plugin": _check_claude_plugin,
    "workbuddy": _check_workbuddy,
    "skillhub": _check_skillhub,
    "openclaw": _check_openclaw,
    "clawhub": _check_clawhub,
}


def _target_options(target: Mapping[str, object]) -> Mapping[str, object]:
    options = target.get("options")
    return options if isinstance(options, Mapping) else {}


def _release_settings(config: EvalConfig) -> Mapping[str, object]:
    release = getattr(config, "release", {})
    return release if isinstance(release, Mapping) else {}


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
    if not value or value != value.strip() or any(character.isspace() for character in value):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return False
    return parsed.scheme == "https" and bool(hostname) and _is_valid_hostname(hostname)


def _is_valid_hostname(hostname: str) -> bool:
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if hostname.endswith("."):
        return False
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return len(ascii_hostname) <= 253 and all(
        _HOST_LABEL.fullmatch(label) for label in ascii_hostname.split(".")
    )


def _check_asset_references(root: Path, config: EvalConfig, diagnostics: list[Diagnostic]) -> None:
    settings = _release_settings(config).get("assetReferences")
    if not isinstance(settings, Mapping):
        return
    asset_directory = settings.get("assetDirectory")
    documentation_directory = settings.get("documentationDirectory")
    reference_prefix = settings.get("referencePrefix")
    if not all(isinstance(value, str) for value in (asset_directory, documentation_directory, reference_prefix)):
        return
    asset_root = root / asset_directory
    documentation_root = root / documentation_directory
    documentation = "\n".join(
        _read_optional_text(path) for path in _walk_files(documentation_root) if path.suffix.lower() in {".md", ".sh"}
    )
    if not asset_root.exists() and not documentation:
        return
    assets = list(_walk_files(asset_root, _IMAGE_EXTENSIONS))
    referenced_assets: set[Path] = set()
    reference_pattern = re.compile(
        rf"{re.escape(reference_prefix.rstrip('/'))}/([A-Za-z0-9._/-]+\.(?:png|jpe?g|webp|gif|svg))",
        re.IGNORECASE,
    )
    for match in reference_pattern.finditer(documentation):
        relative_asset = Path(match.group(1))
        resolved_asset = (asset_root / relative_asset).resolve()
        if not _is_within(asset_root.resolve(), resolved_asset) or not resolved_asset.is_file():
            _fail(
                diagnostics,
                "IMAGE_REFERENCE_MISSING",
                f"Image reference has no matching asset: {reference_prefix.rstrip('/')}/{relative_asset.as_posix()}",
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
                f"Image asset is not referenced by configured documentation: {relative_asset}",
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
