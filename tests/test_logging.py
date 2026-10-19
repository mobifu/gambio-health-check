import json
import os
from pathlib import Path

import pytest

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


def test_logger_context_manager(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        with HealthCheckLogger("ContextProfile") as log:
            log.info("Info Msg")
            log.warning("Warn Msg")
            log.error("Error Msg")
            log_file = log.current_file
            assert os.path.exists(log_file)

        # Nach Context Manager muss die Datei geschlossen sein
        assert log.file_handle is None

        with open(log_file, "r", encoding="utf-8") as f:
            entries = [json.loads(line) for line in f]
            levels = [e["level"] for e in entries]
            assert "INFO" in levels
            assert "WARN" in levels
            assert "ERROR" in levels
    finally:
        os.chdir(old_cwd)


def test_logger_path_sanitization_and_traversal(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Profil mit ungültigen Zeichen
        l1 = HealthCheckLogger("Shop:1/Test?*")
        assert "Shop_1_Test__" in l1.get_log_dir()

        # Profil mit Leerzeichen / leer
        l2 = HealthCheckLogger("   ")
        assert "default" in l2.get_log_dir()

        # Path Traversal Versuch
        l3 = HealthCheckLogger("../../../evil")
        base_dir = (tmp_path / "profiles").resolve()
        assert Path(l3.get_log_dir()).resolve().is_relative_to(base_dir)
    finally:
        os.chdir(old_cwd)


def test_logger_relative_to_fallback(tmp_path, monkeypatch):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Simuliere, dass is_relative_to False zurückgibt
        monkeypatch.setattr(Path, "is_relative_to", lambda self, other: False)
        logger = HealthCheckLogger("OutsideProfile")
        assert "default" in logger.get_log_dir()
    finally:
        os.chdir(old_cwd)


def test_logger_close_oserror(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("CloseErrProfile")
        logger.start_session()

        class FaultyHandle:
            closed = False

            def close(self):
                raise OSError("Close error")

            def write(self, s):
                pass

            def flush(self):
                pass

        logger.file_handle = FaultyHandle()
        # Teste Schließen in start_session()
        logger.start_session()
        assert logger.file_handle is not None

        # Teste Schließen in end_session()
        logger.file_handle = FaultyHandle()
        logger.end_session()
        assert logger.file_handle is None
    finally:
        os.chdir(old_cwd)


def test_logger_mkdir_error(tmp_path, monkeypatch):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:

        def mock_mkdir(*args, **kwargs):
            raise OSError("Access denied")

        monkeypatch.setattr(Path, "mkdir", mock_mkdir)
        # Sollte nicht abstürzen, sondern Fehler loggen
        logger = HealthCheckLogger("ErrProfile")
        assert logger is not None
    finally:
        os.chdir(old_cwd)


def test_logger_start_session_when_already_open(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("ReopenProfile")
        logger.start_session()
        file1 = logger.current_file
        handle1 = logger.file_handle
        assert handle1 is not None and not handle1.closed

        # Erneuter Start schließt das alte Handle
        logger.start_session()
        assert handle1.closed
        assert logger.current_file is not None
        logger.end_session()
    finally:
        os.chdir(old_cwd)


def test_logger_start_session_oserror(tmp_path, monkeypatch):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("OpenErrProfile")

        def mock_open(*args, **kwargs):
            raise OSError("Disk full")

        monkeypatch.setattr("builtins.open", mock_open)
        logger.start_session()
        assert logger.file_handle is None
        # Log-Aufrufe ohne geöffnetes Handle stürzen nicht ab
        logger.info("Test without handle")
    finally:
        os.chdir(old_cwd)


def test_logger_write_oserror(tmp_path, monkeypatch):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("WriteErrProfile")
        logger.start_session()

        def mock_write(*args, **kwargs):
            raise OSError("Write failed")

        monkeypatch.setattr(logger.file_handle, "write", mock_write)
        # Darf nicht abstürzen
        logger.info("Write error test")
        logger.end_session()
    finally:
        os.chdir(old_cwd)


def test_logger_get_last_log_file(tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("LatestProfile")
        # Noch keine Logs vorhanden
        assert logger.get_last_log_file() is None

        # Session 1
        logger.start_session()
        file1 = logger.current_file
        logger.end_session()

        assert logger.get_last_log_file() == file1

        # Wenn Verzeichnis nicht existiert
        logger.log_dir = str(tmp_path / "non_existing_dir")
        assert logger.get_last_log_file() is None
    finally:
        os.chdir(old_cwd)


def test_logger_get_last_log_file_oserror(tmp_path, monkeypatch):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("LatestErrProfile")

        def mock_glob(*args, **kwargs):
            raise OSError("Disk read error")

        monkeypatch.setattr(Path, "glob", mock_glob)
        assert logger.get_last_log_file() is None
    finally:
        os.chdir(old_cwd)


def test_logger_multithreading(tmp_path):
    import threading

    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        logger = HealthCheckLogger("ThreadedProfile")
        logger.start_session()

        def worker(num):
            for i in range(20):
                logger.info(f"Thread-{num} Message-{i}")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        logger.end_session()

        with open(logger.current_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            # 1 Start + 100 Messages + 1 End = 102
            assert len(lines) == 102
    finally:
        os.chdir(old_cwd)


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

    from logging_config import SensitiveFilter, setup_logging

    setup_logging(level=logging.DEBUG)
    count_before = sum(1 for h in logging.root.handlers for f in h.filters if isinstance(f, SensitiveFilter))

    # Zweiter Aufruf sollte keine doppelten Filter registrieren
    setup_logging(level=logging.DEBUG)
    count_after = sum(1 for h in logging.root.handlers for f in h.filters if isinstance(f, SensitiveFilter))
    assert count_before == count_after
