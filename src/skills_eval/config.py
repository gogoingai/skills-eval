"""Strict, versioned configuration for Skills evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator

from skills_eval.models import Diagnostic, Severity


_CONFIG_NAME = ".skills-eval.json"
_SCHEMA_RESOURCE = "schemas/skills-eval.schema.json"
_PROFILE_RESOURCE = "profiles/wenqu.json"
_KNOWN_SOURCES = frozenset({"cisco"})
_FORMAT_KEYS = {
    "requiredRootFiles": "required_root_files",
    "requiredSkillFrontmatter": "required_skill_frontmatter",
    "forbiddenPaths": "forbidden_paths",
    "referenceExtensions": "reference_extensions",
    "requireMarketplaceMetadata": "require_marketplace_metadata",
    "requireOpenClawMetadata": "require_openclaw_metadata",
    "requireImageReferences": "require_image_references",
}
_PORTABLE_FORMAT: dict[str, object] = {
    "requiredRootFiles": [],
    "requiredSkillFrontmatter": ["name", "description"],
    "forbiddenPaths": [],
    "referenceExtensions": [".md"],
    "requireMarketplaceMetadata": False,
    "requireOpenClawMetadata": False,
    "requireImageReferences": False,
}
_DEFAULT_SOURCES = [{"name": "cisco", "enabled": True}]
_DEFAULT_REPORT_LANGUAGE = "auto"


@dataclass(frozen=True)
class EvalConfig:
    """Resolved evaluator settings, independent of their JSON representation."""

    required_root_files: tuple[str, ...]
    required_skill_frontmatter: tuple[str, ...]
    forbidden_paths: tuple[str, ...]
    reference_extensions: tuple[str, ...]
    security_sources: tuple[Mapping[str, object], ...]
    report_language: str = _DEFAULT_REPORT_LANGUAGE
    require_marketplace_metadata: bool = False
    require_openclaw_metadata: bool = False
    require_image_references: bool = False


def load_config(root: Path) -> tuple[EvalConfig, list[Diagnostic]]:
    """Load ``.skills-eval.json`` below *root*, returning safe defaults on errors."""
    root = root.resolve()
    config_path = root / _CONFIG_NAME
    raw_config: dict[str, object]
    try:
        contents = config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _resolved_config(_PORTABLE_FORMAT, _DEFAULT_SOURCES), []
    except (OSError, UnicodeDecodeError) as error:
        return _portable_with_error(config_path, f"Cannot read configuration: {error}")

    try:
        decoded = json.loads(contents)
    except json.JSONDecodeError as error:
        return _portable_with_error(config_path, f"Invalid JSON: {error.msg}.")
    if not isinstance(decoded, dict):
        return _portable_with_error(config_path, "Configuration must be a JSON object.")
    raw_config = decoded

    schema_errors = sorted(_validator().iter_errors(raw_config), key=lambda error: list(error.absolute_path))
    if schema_errors:
        return _portable_with_error(config_path, f"Invalid configuration: {schema_errors[0].message}")

    requested_profiles = raw_config.get("extends", [])
    assert isinstance(requested_profiles, list)
    format_config = dict(_PORTABLE_FORMAT)
    for name in requested_profiles:
        if not isinstance(name, str) or name != "wenqu":
            return _portable_with_error(config_path, f"Unknown configuration profile: {name!r}.")
        profile = _load_profile(name)
        profile_format = profile.get("format")
        if not isinstance(profile_format, dict):
            return _portable_with_error(config_path, f"Profile {name!r} has no valid format section.")
        format_config.update(profile_format)

    user_format = raw_config.get("format", {})
    assert isinstance(user_format, dict)
    format_config.update(user_format)

    security = raw_config.get("security", {})
    assert isinstance(security, dict)
    sources = security.get("sources", _DEFAULT_SOURCES)
    assert isinstance(sources, list)
    unknown_sources = [source.get("name") for source in sources if source.get("name") not in _KNOWN_SOURCES]
    if unknown_sources:
        return _portable_with_error(config_path, f"Unknown security source: {unknown_sources[0]!r}.")

    report = raw_config.get("report", {})
    assert isinstance(report, dict)
    report_language = report.get("language", _DEFAULT_REPORT_LANGUAGE)
    assert isinstance(report_language, str)

    return _resolved_config(format_config, sources, report_language), []


def _validator() -> Draft202012Validator:
    schema = json.loads(resources.files("skills_eval").joinpath(_SCHEMA_RESOURCE).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _load_profile(name: str) -> dict[str, object]:
    if name != "wenqu":
        raise ValueError(f"Unknown profile: {name}")
    return json.loads(resources.files("skills_eval").joinpath(_PROFILE_RESOURCE).read_text(encoding="utf-8"))


def _resolved_config(
    format_config: Mapping[str, object],
    sources: list[object],
    report_language: str = _DEFAULT_REPORT_LANGUAGE,
) -> EvalConfig:
    frozen_sources = tuple(_freeze_mapping(source) for source in sources)
    return EvalConfig(
        required_root_files=tuple(format_config["requiredRootFiles"]),
        required_skill_frontmatter=tuple(format_config["requiredSkillFrontmatter"]),
        forbidden_paths=tuple(format_config["forbiddenPaths"]),
        reference_extensions=tuple(format_config["referenceExtensions"]),
        security_sources=frozen_sources,
        report_language=report_language,
        require_marketplace_metadata=bool(format_config["requireMarketplaceMetadata"]),
        require_openclaw_metadata=bool(format_config["requireOpenClawMetadata"]),
        require_image_references=bool(format_config["requireImageReferences"]),
    )


def _freeze_mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: Any) -> object:
    if isinstance(value, dict):
        return _freeze_mapping(value)
    if isinstance(value, list):
        return tuple(_freeze_value(item) for item in value)
    return value


def _portable_with_error(path: Path, message: str) -> tuple[EvalConfig, list[Diagnostic]]:
    return _resolved_config(_PORTABLE_FORMAT, _DEFAULT_SOURCES), [
        Diagnostic(Severity.FAIL, "CONFIG_INVALID", message, path)
    ]
