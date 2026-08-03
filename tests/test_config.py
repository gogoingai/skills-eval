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


def test_explicit_project_config_adds_distribution_requirements(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "format": {
                "requiredRootFiles": ["VERSION"],
                "requiredSkillFrontmatter": ["slug"],
            },
            "release": {"versionFile": "VERSION", "requireVersionSemver": True},
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert "VERSION" in config.required_root_files
    assert "slug" in config.required_skill_frontmatter


def test_explicit_project_config_enables_publishing_targets(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "publishing": {
                "targets": [
                    {"name": "claude-plugin", "enabled": True},
                    {"name": "clawhub", "enabled": True},
                ]
            },
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.publishing_targets == (
        {"name": "claude-plugin", "enabled": True},
        {"name": "clawhub", "enabled": True},
    )


def test_publishing_target_options_are_preserved(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "publishing": {
                "targets": [
                    {
                        "name": "claude-plugin",
                        "enabled": True,
                        "options": {"skillDirectoryPrefix": "skills-"},
                    },
                    {"name": "clawhub", "enabled": False, "options": {"packageName": "@example/skills"}},
                ]
            },
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.publishing_targets == (
        {
            "name": "claude-plugin",
            "enabled": True,
            "options": {"skillDirectoryPrefix": "skills-"},
        },
        {"name": "clawhub", "enabled": False, "options": {"packageName": "@example/skills"}},
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


def test_project_specific_profiles_are_not_part_of_the_cli(tmp_path) -> None:
    write_config(tmp_path, {"schemaVersion": 1, "extends": ["some-project"]})

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_invalid_config_types_are_a_config_error(tmp_path) -> None:
    write_config(tmp_path, {"schemaVersion": 1, "format": {"requiredRootFiles": "VERSION"}})

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_explicit_format_configuration_is_used(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
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


def test_missing_config_defaults_fail_on_to_high(tmp_path) -> None:
    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.security_fail_on == "high"


def test_fail_on_can_be_configured(tmp_path) -> None:
    write_config(
        tmp_path,
        {"schemaVersion": 1, "security": {"failOn": "medium", "sources": []}},
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert config.security_fail_on == "medium"


def test_invalid_fail_on_is_a_config_error(tmp_path) -> None:
    write_config(
        tmp_path,
        {"schemaVersion": 1, "security": {"failOn": "block-everything"}},
    )

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)


def test_required_flag_is_preserved_on_sources(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "security": {
                "sources": [
                    {"name": "cisco", "enabled": True, "required": False},
                    {"name": "snyk", "enabled": True, "required": True, "options": {"tokenEnv": "SNYK_TOKEN"}},
                ]
            },
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    by_name = {s["name"]: s for s in config.security_sources}
    assert by_name["cisco"]["required"] is False
    assert by_name["snyk"]["required"] is True


def test_new_provider_sources_and_options_are_accepted(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "security": {
                "sources": [
                    {"name": "skillspector", "enabled": True, "options": {"useLlm": False}},
                    {"name": "tencent-aig", "enabled": False, "options": {"apiKeyEnv": "LLM_API_KEY", "baseUrlEnv": "LLM_BASE_URL", "modelEnv": "LLM_MODEL"}},
                    {"name": "snyk", "enabled": False, "options": {"tokenEnv": "SNYK_TOKEN"}},
                ]
            },
        },
    )

    config, diagnostics = load_config(tmp_path)

    assert diagnostics == []
    assert {s["name"] for s in config.security_sources} == {
        "skillspector",
        "tencent-aig",
        "snyk",
    }


def test_unknown_provider_option_is_a_config_error(tmp_path) -> None:
    write_config(
        tmp_path,
        {
            "schemaVersion": 1,
            "security": {
                "sources": [
                    {"name": "snyk", "enabled": True, "options": {"bogus": True}}
                ]
            },
        },
    )

    _, diagnostics = load_config(tmp_path)

    assert any(item.code == "CONFIG_INVALID" for item in diagnostics)
