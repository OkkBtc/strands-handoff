from strands_handoff.redaction import HOME, REDACTED, RedactionReport, redact_text, redact_value


def test_redacts_sensitive_keys_and_nested_strings() -> None:
    report = RedactionReport()
    result = redact_value(
        {
            "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz",
            "nested": {"note": "Bearer abcdefghijklmnop and bob@example.com"},
        },
        report,
    )

    assert result["api_key"] == REDACTED
    assert result["nested"]["note"] == f"Bearer {REDACTED} and {REDACTED}"
    assert report.total == 3


def test_redacts_cross_platform_home_directories() -> None:
    report = RedactionReport()
    result = redact_text("/Users/alice/a /home/bob/b C:\\Users\\Carol\\c", report)

    assert result == f"{HOME}/a {HOME}/b {HOME}\\c"
    assert report.total == 3
