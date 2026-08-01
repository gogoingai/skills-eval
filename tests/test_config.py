import json

from skills_eval.config import load_config


def write_config(tmp_path, contents: dict) -> None:
    (tmp_path / ".skills-eval.json").write_text(json.dumps(contents), encoding="utf-8")


def test_missing_config_returns_portable_defaults_and_enabled_cisco(tmp_path) -> None:
    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.required_root_files == ()
    assert config.required_skill_frontmatter == ("name", "description")
    assert config.security_sources == ({"name": "cisco", "enabled": True},)


def test_wenqu_profile_adds_distribution_requirements(tmp_path) -> None:
    write_config(tmp_path, {"schemaVersion": 1, "extends": ["wenqu"]})

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert "VERSION" in config.required_root_files
    assert "slug" in config.required_skill_frontmatter


def test_wenqu_profile_enables_its_default_publishing_targets(tmp_path) -> None:
    write_config(tmp_path, {"schemaVersion": 1, "extends": ["wenqu"]})

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.publishing_targets == (
        {"name": "claude-plugin", "enabled": True},
        {"name": "workbuddy", "enabled": True},
        {"name": "skillhub", "enabled": True},
        {"name": "openclaw", "enabled": True},
        {"name": "clawhub", "enabled": True},
    )


def test_publishing_target_overrides_profile_by_name(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "extends": ["wenqu"],
            "publishing": {
                "targets": [
                    {"name": "skillhub", "enabled": False},
                    {"name": "clawhub", "enabled": False, "options": {"dryRun": True}},
                ]
            },
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.publishing_targets == (
        {"name": "claude-plugin", "enabled": True},
        {"name": "workbuddy", "enabled": True},
        {"name": "skillhub", "enabled": False},
        {"name": "openclaw", "enabled": True},
        {"name": "clawhub", "enabled": False, "options": {"dryRun": True}},
    )


def test_unknown_or_duplicate_publishing_target_is_a_config_error(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "publishing": {"targets": [{"name": "unknown", "enabled": True}]},
        },
    )

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)

    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "publishing": {
                "targets": [
                    {"name": "skillhub", "enabled": True},
                    {"name": "skillhub", "enabled": False},
                ]
            },
        },
    )

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_standard_schema_url_is_allowed(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "$schema": "https://raw.githubusercontent.com/gogoingai/skills-eval/main/src/skills_eval/schemas/skills-eval.schema.json",
            "schemaVersion": 1,
        },
    )

    _, diagnostics = load_config(tmp_path)

    assert diagnostics == []


def test_unknown_security_source_is_a_config_error(tmp_path) -> None:
    write_config(
        tmp_path,
        {"schemaVersion": 1, "security": {"sources": [{"name": "unknown", "enabled": True}]}},
    )

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_unknown_config_field_is_a_config_error(tmp_path) -> None:
    write_config(tmp_path, {"schemaVersion": 1, "typo": True})

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_invalid_config_types_are_a_config_error(tmp_path) -> None:
    write_config(tmp_path, {"schemaVersion": 1, "format": {"requiredRootFiles": "VERSION"}})

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_format_overrides_merge_after_profile(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "extends": ["wenqu"],
            "format": {"requiredRootFiles": ["CUSTOM"]},
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.required_root_files == ("CUSTOM",)


def test_supported_cisco_options_are_preserved(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "security": {
                "sources": [
                    {
                        "name": "cisco",
                        "enabled": False,
                        "options": {"policy": "strict", "useBehavioral": True},
                    }
                ]
            },
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.security_sources == (
        {"name": "cisco", "enabled": False, "options": {"policy": "strict", "useBehavioral": True}},
    )


def test_report_language_can_be_configured(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "report": {"language": "en"},
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.report_language == "en"


def test_unknown_cisco_option_is_a_config_error(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "security": {
                "sources": [
                    {"name": "cisco", "enabled": True, "options": {"unrecognized": True}}
                ]
            },
        },
    )

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)
