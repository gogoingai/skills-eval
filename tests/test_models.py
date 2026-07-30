from pathlib import Path

from skills_eval.models import CheckResult, CheckStatus, Diagnostic, Severity


def test_result_is_ready_with_warning_when_review_exists() -> None:
    result = CheckResult(
        plugin_name="Example",
        skills=[],
        diagnostics=[Diagnostic(Severity.REVIEW, "TEST", "Review this", Path("a.md"))],
    )

    assert result.status is CheckStatus.READY_WITH_WARNINGS
    assert result.exit_code == 0
