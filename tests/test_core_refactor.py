import html
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.hash_engine import HashCheckEngine
from core.logger import HealthCheckLogger
from core.reporting import _get_latest_log_file, generate_html_report


def test_logger_context_manager(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with HealthCheckLogger("ContextTest") as h_logger:
        assert h_logger.file_handle is not None
        assert not h_logger.file_handle.closed
        h_logger.info("Meldung im Context Manager")

    # Nach Verlassen muss der File Handle geschlossen sein
    assert h_logger.file_handle is None


def test_logger_path_traversal_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    base_dir = (tmp_path / "profiles").resolve()

    # Versuch von Path Traversal über Profilnamen
    traversal_logger = HealthCheckLogger("../../../malicious_profile")
    log_dir_path = Path(traversal_logger.get_log_dir()).resolve()

    # Muss zwingend innerhalb von base_dir liegen
    assert log_dir_path.is_relative_to(base_dir)


def test_logger_double_start_session(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    h_logger = HealthCheckLogger("DoubleSession")
    h_logger.start_session()
    first_file = h_logger.current_file
    first_handle = h_logger.file_handle

    # Zweiter Start ohne explizites end_session schließt das vorherige Handle
    h_logger.start_session()
    assert first_handle.closed
    assert h_logger.file_handle is not None
    assert not h_logger.file_handle.closed

    h_logger.end_session()
    assert h_logger.file_handle is None


def test_reporting_xss_protection(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "2026-10-17_test.log"

    xss_payload = '<script>alert("XSS")</script>'
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"time": "2026-10-17 12:00:00", "level": "WARN", "msg": xss_payload}) + "\n")

    out_html = tmp_path / "report.html"
    success = generate_html_report(xss_payload, str(log_dir), str(out_html))

    assert success is True
    with open(out_html, "r", encoding="utf-8") as f:
        content = f.read()

    # Payload darf nicht unescaped vorkommen
    assert '<script>alert("XSS")</script>' not in content
    assert html.escape(xss_payload) in content


def test_reporting_corrupt_json_lines(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "2026-10-17_test.log"

    with open(log_file, "w", encoding="utf-8") as f:
        f.write("INVALID JSON LINE\n")
        f.write(json.dumps({"time": "2026-10-17 12:00:00", "level": "INFO", "msg": "Valide Zeile"}) + "\n")

    out_html = tmp_path / "report.html"
    success = generate_html_report("SafeProfile", str(log_dir), str(out_html))

    assert success is True
    with open(out_html, "r", encoding="utf-8") as f:
        content = f.read()

    assert "Valide Zeile" in content


def test_hash_engine_path_traversal_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    base_dir = (tmp_path / "profiles").resolve()

    engine = HashCheckEngine("../../../attack_profile", conn=MagicMock())
    hash_dir_path = Path(engine.hash_dir).resolve()

    assert hash_dir_path.is_relative_to(base_dir)


def test_hash_engine_malware_indicators_robustness():
    engine = HashCheckEngine("RobustTest", conn=MagicMock(), logger=MagicMock())

    # None oder nicht-bytes darf nicht zu Exceptions führen
    engine._check_malware_indicators(None, "test.php")
    engine._check_malware_indicators("keine bytes", "test.php")

    mock_logger = MagicMock()
    engine.logger = mock_logger
    engine._check_malware_indicators(b"<?php eval(base64_decode('abc')); ?>", "danger.php")
    mock_logger.error.assert_called()


def test_hash_engine_utf8_baseline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    mock_conn = MagicMock()
    engine = HashCheckEngine("Utf8Shop", conn=mock_conn, logger=MagicMock())

    # Speichern mit Umlauten
    baseline_data = {"dateien/äöü_test.php": "abcdef123456"}
    with open(engine.baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f)

    # compare_with_baseline aufrufen
    mock_conn.mlsd.return_value = []
    mock_conn.retrlines = MagicMock()
    mock_conn.nlst.return_value = []

    engine.compare_with_baseline()
    # Sicherstellen, dass kein UnicodeDecodeError aufgetreten ist
