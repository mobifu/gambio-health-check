import pytest
import os
import json
from core.logger import HealthCheckLogger


@pytest.fixture
def logger(tmp_path):
    # Wir patchen den Pfad so, dass er im tmp_path arbeitet
    # HealthCheckLogger nutzt "profiles/..." relativ
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    yield HealthCheckLogger("TestProfile")
    os.chdir(old_cwd)


def test_logger_directory_creation(logger):
    assert os.path.exists(logger.get_log_dir())
    assert "TestProfile" in logger.get_log_dir()


def test_logger_sanitization(logger):
    # Teste Anonymisierung von Passwörtern
    msg = 'User logged in with password=secret123 and token: "abc-123"'
    sanitized = logger._sanitize(msg)
    assert "secret123" not in sanitized
    assert "abc-123" not in sanitized
    assert "********" in sanitized


def test_logger_session(logger):
    logger.start_session()
    log_file = logger.current_file
    assert os.path.exists(log_file)

    logger.log("WARN", "Test Warning")
    logger.end_session()

    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) >= 3  # Start, Warning, End

        first_entry = json.loads(lines[0])
        second_entry = json.loads(lines[1])
        assert first_entry["level"] == "INFO"
        assert second_entry["level"] == "WARN"
        assert second_entry["msg"] == "Test Warning"


def test_logging_config_sensitive_filter():
    import logging
    from logging_config import SensitiveFilter, setup_logging

    # Teste SensitiveFilter direkt
    filter_obj = SensitiveFilter()

    # Mock log record
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg='API Key is key=mysecrettoken and password: "my_pwd"',
        args=(),
        exc_info=None,
    )

    assert filter_obj.filter(record) is True
    assert "mysecrettoken" not in record.msg
    assert "my_pwd" not in record.msg
    assert "key=********" in record.msg
    assert 'password: "********"' in record.msg

    # Teste weitere komplexe JSON- und URL-Szenarien
    test_cases = [
        ("pass=secret123", "pass=********"),
        ("pwd=secret123", "pwd=********"),
        ("password=secret123", "password=********"),
        ("key=secret123", "key=********"),
        ("token=secret123", "token=********"),
        ("auth=secret123", "auth=********"),
        ('{"password": "my_secret"}', '{"password": "********"}'),
        ('{"pwd": "my_secret"}', '{"pwd": "********"}'),
        ('{"pass" : "my_secret"}', '{"pass" : "********"}'),
        ("{\"token\" :'my_secret'}", "{\"token\" :'********'}"),
        ('password : "my_secret"', 'password : "********"'),
        ("auth=my_secret_token_123&other=param", "auth=********&other=param"),
    ]

    for raw, expected in test_cases:
        rec = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg=raw,
            args=(),
            exc_info=None,
        )
        filter_obj.filter(rec)
        assert rec.msg == expected, f"Failed for raw: {raw}, got: {rec.msg}"

    # Test setup_logging
    setup_logging()
    # Sicherstellen, dass der SensitiveFilter zu den Handlern hinzugefügt wurde
    assert len(logging.root.handlers) > 0
    for handler in logging.root.handlers:
        assert any(isinstance(f, SensitiveFilter) for f in handler.filters)


def test_sanitize_sensitive_data_direct():
    from logging_config import sanitize_sensitive_data

    # Direktaufruf der Sanitization-Funktion
    assert sanitize_sensitive_data("pass=topsecret") == "pass=********"
    assert sanitize_sensitive_data('{"token": "xyz123"}') == '{"token": "********"}'
    # Nicht-String Eingaben
    assert sanitize_sensitive_data(12345) == "12345"
    assert sanitize_sensitive_data(None) == "None"


def test_sensitive_filter_with_args():
    import logging
    from logging_config import SensitiveFilter

    filter_obj = SensitiveFilter()
    rec = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Login fehlgeschlagen für %s mit Token %s",
        args=("user_admin", "token=secret456"),
        exc_info=None,
    )
    assert filter_obj.filter(rec) is True
    assert "secret456" not in rec.msg
    assert "token=********" in rec.msg
    assert rec.args == ()


def test_setup_logging_idempotent():
    import logging
    from logging_config import setup_logging, SensitiveFilter

    setup_logging(level=logging.DEBUG)
    count_before = sum(1 for h in logging.root.handlers for f in h.filters if isinstance(f, SensitiveFilter))

    # Zweiter Aufruf sollte keine doppelten Filter registrieren
    setup_logging(level=logging.DEBUG)
    count_after = sum(1 for h in logging.root.handlers for f in h.filters if isinstance(f, SensitiveFilter))
    assert count_before == count_after
