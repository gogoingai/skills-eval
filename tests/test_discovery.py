from skills_eval.discovery import discover_plugin, select_skill


def test_discovery_rejects_duplicate_resolved_skill_paths(plugin_factory) -> None:
    root = plugin_factory(skills=["./write", "./write/../write"])

    plugin, diagnostics = discover_plugin(root)

    assert plugin is not None
    assert len(plugin.skills) == 1
    assert any(item.code == "SKILL_PATH_DUPLICATE" for item in diagnostics)


def test_discovery_retains_valid_skills_when_sibling_is_missing(plugin_factory) -> None:
    root = plugin_factory(skills=["./write", "./missing"])
    (root / "missing" / "SKILL.md").unlink()

    plugin, diagnostics = discover_plugin(root)

    assert plugin is not None
    assert [skill.name for skill in plugin.skills] == ["write"]
    assert any(item.code == "SKILL_FILE_MISSING" for item in diagnostics)


def test_discovery_rejects_path_outside_plugin_root(plugin_factory) -> None:
    root = plugin_factory(skills=["./write", "../outside"])

    plugin, diagnostics = discover_plugin(root)

    assert plugin is not None
    assert [skill.name for skill in plugin.skills] == ["write"]
    assert any(item.code == "SKILL_PATH_OUTSIDE_ROOT" for item in diagnostics)


def test_discovery_rejects_duplicate_frontmatter_names(plugin_factory) -> None:
    root = plugin_factory(skills=["./one", "./two"], names=["writer", "writer"])

    plugin, diagnostics = discover_plugin(root)

    assert plugin is not None
    assert [skill.name for skill in plugin.skills] == ["one", "two"]
    assert any(item.code == "SKILL_NAME_DUPLICATE" for item in diagnostics)


def test_discovery_reports_malformed_plugin_json(plugin_factory) -> None:
    root = plugin_factory()
    (root / ".claude-plugin" / "plugin.json").write_text("{not json", encoding="utf-8")

    plugin, diagnostics = discover_plugin(root)

    assert plugin is None
    assert any(item.code == "PLUGIN_JSON_INVALID" for item in diagnostics)


def test_selection_rejects_selector_matching_two_names(plugin_factory) -> None:
    root = plugin_factory(skills=["./one", "./two"], names=["writer", "writer"])
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    selected, selection_diagnostics = select_skill(plugin, "writer")

    assert selected == []
    assert any(item.code == "SKILL_SELECTOR_AMBIGUOUS" for item in selection_diagnostics)


def test_selection_selects_all_skills_without_a_selector(plugin_factory) -> None:
    root = plugin_factory(skills=["./one", "./two"])
    plugin, diagnostics = discover_plugin(root)

    assert diagnostics == []
    assert plugin is not None
    selected, selection_diagnostics = select_skill(plugin, None)

    assert selected == list(plugin.skills)
    assert selection_diagnostics == []


def test_selection_reports_a_selector_miss(plugin_factory) -> None:
    root = plugin_factory()
    plugin, _ = discover_plugin(root)
    assert plugin is not None

    selected, diagnostics = select_skill(plugin, "missing")

    assert selected == []
    assert any(item.code == "SKILL_SELECTOR_NOT_FOUND" for item in diagnostics)
