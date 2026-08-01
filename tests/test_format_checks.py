import json
import re
from dataclasses import replace

import pytest

from skills_eval.discovery import discover_plugin
from skills_eval.format_checks import check_format
from skills_eval.references import extract_local_references


def _codes(diagnostics) -> set[str]:
    return {item.code for item in diagnostics}


def _skill_file(root):
    return root / "write" / "SKILL.md"


def _write_wenqu_release_files(root, *, version: str = "1.2.3") -> None:
    (root / "README.md").write_text("# Read me\n", encoding="utf-8")
    (root / "README.en.md").write_text("# Read me\n", encoding="utf-8")
    (root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    (root / "CHANGELOG.md").write_text(f"# Changelog\n\n## {version}\n", encoding="utf-8")
    metadata = root / ".claude-plugin"
    (metadata / "plugin.json").write_text(
        json.dumps({"name": "example-plugin", "version": version, "skills": ["./write"]}),
        encoding="utf-8",
    )
    (metadata / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "example-plugin",
                "plugins": [
                    {
                        "name": "example-plugin",
                        "source": "./",
                        "version": version,
                        "description": "Example plugin.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"version": version}),
        encoding="utf-8",
    )
    (root / "package.json").write_text(
        json.dumps({"name": "@gogoingai/wenqu-skills", "version": version}),
        encoding="utf-8",
    )
    _skill_file(root).write_text(
        "---\n"
        "name: write\n"
        "description: Test skill\n"
        "slug: write\n"
        "displayName: Write\n"
        "version: 1.2.3\n"
        "summary: Write content\n"
        "license: MIT\n"
        "metadata:\n"
        "  openclaw:\n"
        "    homepage: https://example.test/write\n"
        "---\n"
        "Useful instructions.\n",
        encoding="utf-8",
    )


def test_format_reports_missing_local_markdown_reference(plugin_factory, portable_config) -> None:
    root = plugin_factory(skill_body="See [guide](references/missing.md).")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), portable_config)

    assert "REFERENCE_MISSING" in _codes(diagnostics)


def test_format_reports_reference_resolving_outside_plugin_root(plugin_factory, portable_config) -> None:
    root = plugin_factory(skill_body="See [private note](../../outside.md).")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), portable_config)

    assert "REFERENCE_OUTSIDE_ROOT" in _codes(diagnostics)


def test_format_ignores_urls_anchors_and_interpolated_shell_paths(plugin_factory, portable_config) -> None:
    root = plugin_factory(
        skill_body=(
            "[website](https://example.test/guide) [section](#usage) "
            '"$ROOT/references/missing.md"'
        )
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), portable_config)

    assert not {"REFERENCE_MISSING", "REFERENCE_OUTSIDE_ROOT"} & _codes(diagnostics)


def test_extract_local_references_normalizes_markdown_and_quoted_paths(tmp_path) -> None:
    root = tmp_path / "plugin"
    source = root / "write" / "SKILL.md"
    source.parent.mkdir(parents=True)

    references = extract_local_references(
        '[guide](references/../guide.md#intro) and "references/quoted.md"', source, root
    )

    assert references == [
        (source.parent / "guide.md").resolve(),
        (source.parent / "references" / "quoted.md").resolve(),
    ]


def test_extract_local_references_ignores_quoted_prose_and_markdown_link_titles(tmp_path) -> None:
    root = tmp_path / "plugin"
    source = root / "write" / "SKILL.md"
    referenced = source.parent / "references" / "guide.md"
    referenced.parent.mkdir(parents=True)
    referenced.write_text("# Guide\n", encoding="utf-8")

    references = extract_local_references(
        'Call it "the guide.md" in prose. '
        '[guide](references/guide.md "guide.md")',
        source,
        root,
    )

    assert references == [referenced.resolve()]


def test_extract_local_references_keeps_quoted_filenames_but_ignores_slash_prose(tmp_path) -> None:
    root = tmp_path / "plugin"
    source = root / "write" / "SKILL.md"
    source.parent.mkdir(parents=True)

    references = extract_local_references(
        '"guide.md" "references/guide.md" "read/write" "input/output"', source, root
    )

    assert references == [
        (source.parent / "guide.md").resolve(),
        (source.parent / "references" / "guide.md").resolve(),
    ]


def test_format_reports_invalid_missing_and_non_scalar_frontmatter(plugin_factory, portable_config) -> None:
    root = plugin_factory()
    plugin, _ = discover_plugin(root)
    assert plugin is not None
    _skill_file(root).write_text("---\n- not-a-mapping\n---\n", encoding="utf-8")

    diagnostics = check_format(root, plugin, list(plugin.skills), portable_config)

    assert "FRONTMATTER_INVALID" in _codes(diagnostics)


def test_format_reports_missing_and_invalid_required_frontmatter_values(plugin_factory, portable_config) -> None:
    root = plugin_factory()
    plugin, _ = discover_plugin(root)
    assert plugin is not None
    _skill_file(root).write_text("---\nname: []\n---\n", encoding="utf-8")

    diagnostics = check_format(root, plugin, list(plugin.skills), portable_config)

    assert {"FRONTMATTER_REQUIRED", "FRONTMATTER_VALUE_INVALID"} <= _codes(diagnostics)


def test_format_always_requires_portable_name_and_description(plugin_factory, portable_config) -> None:
    root = plugin_factory()
    plugin, _ = discover_plugin(root)
    assert plugin is not None
    _skill_file(root).write_text("---\nname: '   '\n---\n", encoding="utf-8")
    no_extra_requirements = portable_config.__class__(
        **{**portable_config.__dict__, "required_skill_frontmatter": ()}
    )

    diagnostics = check_format(root, plugin, list(plugin.skills), no_extra_requirements)

    assert {"FRONTMATTER_REQUIRED", "FRONTMATTER_VALUE_INVALID"} <= _codes(diagnostics)


def test_format_reports_forbidden_paths(plugin_factory, portable_config) -> None:
    root = plugin_factory()
    (root / ".DS_Store").write_text("metadata", encoding="utf-8")
    restricted = portable_config.__class__(
        **{**portable_config.__dict__, "forbidden_paths": (".DS_Store", "**/*.secret")}
    )
    (root / "write" / "token.secret").write_text("secret", encoding="utf-8")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), restricted)

    assert sum(item.code == "FORBIDDEN_PATH" for item in diagnostics) == 2


def test_wenqu_profile_requires_version_file(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert any(item.code == "ROOT_FILE_MISSING" and item.path and item.path.name == "VERSION" for item in diagnostics)


def test_wenqu_checks_release_metadata_and_openclaw_homepage(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        _skill_file(root).read_text(encoding="utf-8").replace(
            "https://example.test/write", "http://example.test/write"
        ),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None
    (root / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
    marketplace = root / ".claude-plugin" / "marketplace.json"
    marketplace.write_text(
        json.dumps({"name": "wrong", "plugins": [{"name": "example-plugin", "version": "0.0.1"}]}),
        encoding="utf-8",
    )

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert {"CHANGELOG_VERSION_MISSING", "MARKET_NAME_MISMATCH", "MARKET_VERSION_MISMATCH", "OPENCLAW_HOMEPAGE_INVALID"} <= _codes(diagnostics)


def test_wenqu_rejects_https_homepage_without_a_hostname(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        _skill_file(root).read_text(encoding="utf-8").replace(
            "https://example.test/write", "https:///write"
        ),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert "OPENCLAW_HOMEPAGE_INVALID" in _codes(diagnostics)


@pytest.mark.parametrize(
    "homepage",
    [
        " https://example.test/write",
        "https://example_test.test/write",
        "https://-example.test/write",
        "https://example..test/write",
        "https://example.test../write",
        "https://example.test.../write",
        "https://example.test/a path",
        "https://example.test:invalid/write",
    ],
)
def test_wenqu_rejects_malformed_https_homepages(plugin_factory, wenqu_config, homepage) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        re.sub(
            r"(?m)^    homepage: .+$",
            f"    homepage: {json.dumps(homepage)}",
            _skill_file(root).read_text(encoding="utf-8"),
        ),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert "OPENCLAW_HOMEPAGE_INVALID" in _codes(diagnostics)


def test_wenqu_accepts_single_trailing_dot_fqdn(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        _skill_file(root).read_text(encoding="utf-8").replace(
            "https://example.test/write", "https://example.test./write"
        ),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert diagnostics == []


def test_wenqu_profile_accepts_a_clean_release(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert diagnostics == []


def test_wenqu_only_checks_are_gated_for_portable_plugins(plugin_factory, portable_config) -> None:
    root = plugin_factory()
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), portable_config)

    assert diagnostics == []


def test_wenqu_checks_missing_and_unreferenced_image_assets(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    assets = root / "wenqu-image-assets" / "styles"
    assets.mkdir(parents=True)
    (assets / "unused.png").write_bytes(b"png")
    docs = root / "wenqu-image"
    docs.mkdir()
    (docs / "guide.md").write_text(
        "![Missing](wenqu-image-assets/styles/missing.png)", encoding="utf-8"
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(root, plugin, list(plugin.skills), wenqu_config)

    assert {"IMAGE_REFERENCE_MISSING", "IMAGE_ASSET_UNREFERENCED"} <= _codes(diagnostics)


def _publishing_target_config(wenqu_config, target: str):
    selected = next(item for item in wenqu_config.publishing_targets if item["name"] == target)
    return replace(
        wenqu_config,
        publishing_targets=(selected,),
    )


def test_claude_plugin_target_reports_undeclared_wenqu_skill(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    orphan = root / "wenqu-extra"
    orphan.mkdir()
    (orphan / "SKILL.md").write_text("---\nname: extra\ndescription: Extra\n---\n", encoding="utf-8")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "claude-plugin")
    )

    assert "PLUGIN_SKILL_UNDECLARED" in _codes(diagnostics)


def test_workbuddy_target_requires_distribution_metadata(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        _skill_file(root).read_text(encoding="utf-8").replace("displayName: Write\n", ""),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "workbuddy")
    )

    assert "WORKBUDDY_METADATA_MISSING" in _codes(diagnostics)


def test_workbuddy_target_requires_a_semantic_skill_version(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        _skill_file(root).read_text(encoding="utf-8").replace("version: 1.2.3", "version: current"),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "workbuddy")
    )

    assert "WORKBUDDY_VERSION_INVALID" in _codes(diagnostics)


def test_skillhub_target_rejects_invalid_slug(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    _skill_file(root).write_text(
        _skill_file(root).read_text(encoding="utf-8").replace("slug: write", "slug: Invalid_Slug"),
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "skillhub")
    )

    assert "SKILLHUB_SLUG_INVALID" in _codes(diagnostics)


def test_skillhub_target_rejects_duplicate_slugs_and_images(plugin_factory, wenqu_config) -> None:
    root = plugin_factory(skills=["./write", "./review"])
    _write_wenqu_release_files(root)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "example-plugin", "version": "1.2.3", "skills": ["./write", "./review"]}),
        encoding="utf-8",
    )
    (root / "review" / "SKILL.md").write_text(
        _skill_file(root).read_text(encoding="utf-8").replace("name: write", "name: review"),
        encoding="utf-8",
    )
    (root / "write" / "cover.png").write_bytes(b"image")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "skillhub")
    )

    assert {"SKILLHUB_SLUG_DUPLICATE", "SKILLHUB_UNSUPPORTED_FILE"} <= _codes(diagnostics)


def test_openclaw_target_requires_manifest_version_match(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    (root / "openclaw.plugin.json").write_text('{"version": "0.0.1"}', encoding="utf-8")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "openclaw")
    )

    assert "OPENCLAW_VERSION_MISMATCH" in _codes(diagnostics)


def test_clawhub_target_checks_package_identity(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    (root / "package.json").write_text('{"name": "wrong", "version": "1.2.3"}', encoding="utf-8")
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "clawhub")
    )

    assert "PACKAGE_NAME_MISMATCH" in _codes(diagnostics)


def test_disabled_target_does_not_contribute_diagnostics(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    (root / "package.json").write_text('{"name": "wrong", "version": "0.0.1"}', encoding="utf-8")
    plugin, _ = discover_plugin(root)
    assert plugin is not None
    disabled_clawhub = replace(
        wenqu_config,
        publishing_targets=({"name": "clawhub", "enabled": False},),
    )

    diagnostics = check_format(root, plugin, list(plugin.skills), disabled_clawhub)

    assert not {"PACKAGE_NAME_MISMATCH", "PACKAGE_VERSION_MISMATCH"} & _codes(diagnostics)


def test_clawhub_target_accepts_matching_package_identity(plugin_factory, wenqu_config) -> None:
    root = plugin_factory()
    _write_wenqu_release_files(root)
    (root / "package.json").write_text(
        '{"name": "@gogoingai/wenqu-skills", "version": "1.2.3"}',
        encoding="utf-8",
    )
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    diagnostics = check_format(
        root, plugin, list(plugin.skills), _publishing_target_config(wenqu_config, "clawhub")
    )

    assert diagnostics == []
