from skills_eval.localization import resolve_report_language


def test_auto_language_uses_chinese_only_for_chinese_preferences(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.localization._preferred_language", lambda: "zh-Hans-CN")

    assert resolve_report_language("auto") == "zh"


def test_auto_language_uses_english_for_every_non_chinese_preference(monkeypatch) -> None:
    monkeypatch.setattr("skills_eval.localization._preferred_language", lambda: "ja-JP")

    assert resolve_report_language("auto") == "en"
