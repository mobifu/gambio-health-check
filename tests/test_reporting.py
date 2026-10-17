import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.reporting import (
    _build_html,
    _determine_css_class,
    _get_latest_log_file,
    generate_html_report,
    generate_pdf_report,
    load_log_entries,
)


def test_generate_html_report():
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_dir = os.path.join(tmp_dir, "logs")
        os.makedirs(log_dir)

        log_file = os.path.join(log_dir, "test.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "time": "2026-07-03 10:00:00",
                        "level": "INFO",
                        "msg": "Test start",
                    }
                )
                + "\n"
            )
            f.write(
                json.dumps(
                    {
                        "time": "2026-07-03 10:00:01",
                        "level": "WARN",
                        "msg": "Test warning",
                    }
                )
                + "\n"
            )

        output_html = os.path.join(tmp_dir, "report.html")

        result = generate_html_report("TestProfile", log_dir, output_html)

        assert result is True
        assert os.path.exists(output_html)

        with open(output_html, "r", encoding="utf-8") as f:
            content = f.read()

        assert "TestProfile" in content
        assert "Test start" in content
        assert "Test warning" in content
        assert "level-warn" in content
        assert "Content-Security-Policy" in content


def test_load_log_entries_direct_file_and_limits(tmp_path):
    log_file = tmp_path / "custom.log"
    lines = [json.dumps({"time": f"2026-10-17 10:00:0{i}", "level": "INFO", "msg": f"Zeile {i}"}) for i in range(10)]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Begrenzung auf max_entries = 3 (die neuesten 3 Zeilen)
    resolved_path, entries = load_log_entries(log_file, max_entries=3)
    assert resolved_path == log_file.resolve()
    assert len(entries) == 3
    assert entries[0]["msg"] == "Zeile 7"
    assert entries[2]["msg"] == "Zeile 9"


def test_load_log_entries_corrupt_and_non_dict(tmp_path):
    log_file = tmp_path / "mixed.log"
    content = (
        "NOT JSON\n"
        + json.dumps(["ein", "array"])
        + "\n"
        + "12345\n"
        + json.dumps({"time": "2026-10-17 11:00:00", "level": "ERROR", "msg": "Kritischer Fehler"})
        + "\n"
    )
    log_file.write_text(content, encoding="utf-8")

    resolved_path, entries = load_log_entries(log_file)
    assert len(entries) == 1
    assert entries[0]["level"] == "ERROR"
    assert entries[0]["msg"] == "Kritischer Fehler"


def test_load_log_entries_invalid_utf8_bytes(tmp_path):
    log_file = tmp_path / "invalid_bytes.log"
    # Schreibe ungültige Bytes gefolgt von einer validen JSON-Zeile
    valid_json = json.dumps({"time": "2026-10-17", "level": "OK", "msg": "Erfolg"}).encode("utf-8")
    with open(log_file, "wb") as f:
        f.write(b"\xff\xfe\xfa\n" + valid_json + b"\n")

    resolved_path, entries = load_log_entries(log_file)
    assert len(entries) == 1
    assert entries[0]["msg"] == "Erfolg"


def test_load_log_entries_invalid_sources(tmp_path):
    # Nicht existierendes Verzeichnis/Datei
    non_existent = tmp_path / "does_not_exist"
    path, entries = load_log_entries(non_existent)
    assert path is None
    assert entries == []

    # Leeres Verzeichnis ohne Logs
    empty_dir = tmp_path / "empty_logs"
    empty_dir.mkdir()
    path, entries = load_log_entries(empty_dir)
    assert path is None
    assert entries == []


def test_get_latest_log_file(tmp_path):
    log1 = tmp_path / "2026-10-10.log"
    log2 = tmp_path / "2026-10-17.log"
    log1.write_text("log 1", encoding="utf-8")
    log2.write_text("log 2", encoding="utf-8")

    # Zeitstempel manuell manipulieren
    os.utime(log1, (1000, 1000))
    os.utime(log2, (2000, 2000))

    latest = _get_latest_log_file(tmp_path)
    assert Path(latest).resolve() == log2.resolve()

    # Nicht existierender Pfad
    assert _get_latest_log_file(tmp_path / "non_existing") == ""


def test_determine_css_class():
    assert _determine_css_class("ERROR", "Fehler") == "level-error"
    assert _determine_css_class("FATAL", "Absturz") == "level-error"
    assert _determine_css_class("CRITICAL", "Problem") == "level-error"
    assert _determine_css_class("WARN", "Achtung") == "level-warn"
    assert _determine_css_class("OK", "Alles gut") == "level-ok"
    assert _determine_css_class("INFO", "Erfolg beim Speichern") == "level-ok"
    assert _determine_css_class("INFO", "System ist bereit") == "level-ok"
    assert _determine_css_class("INFO", "Normale Info") == "level-info"


def test_build_html_csp_and_escaping():
    entries = [
        {"time": "2026-10-17", "level": "ERROR", "msg": '<img src=x onerror=alert("XSS")>'},
        {"time": "2026-10-17", "level": "INFO", "msg": "Mehrzeiliger\nText\nmit Stacktrace"},
    ]
    html_out = _build_html("<script>evil()</script>", entries)

    # CSP muss vorhanden sein
    assert "Content-Security-Policy" in html_out
    assert "default-src 'none'" in html_out
    # Profilname & HTML-Tags müssen maskiert sein
    assert "<script>evil()</script>" not in html_out
    assert "&lt;script&gt;evil()&lt;/script&gt;" in html_out
    assert "<img src=x" not in html_out
    assert "&lt;img src=x onerror=alert(&quot;XSS&quot;)&gt;" in html_out


def test_generate_pdf_report_mocked(tmp_path):
    log_dir = tmp_path / "pdf_logs"
    log_dir.mkdir()
    log_file = log_dir / "audit.log"
    log_file.write_text(
        json.dumps({"time": "2026-10-17", "level": "INFO", "msg": "PDF Test"}) + "\n",
        encoding="utf-8",
    )
    out_pdf = tmp_path / "audit.pdf"

    with patch("core.reporting.PYSIDE_AVAILABLE", False):
        assert generate_pdf_report("Profile", log_dir, out_pdf) is False

    with (
        patch("core.reporting.PYSIDE_AVAILABLE", True),
        patch("core.reporting.QTextDocument") as mock_doc,
        patch("core.reporting.QPrinter") as mock_printer,
    ):
        assert generate_pdf_report("Profile", log_dir, out_pdf) is True
        mock_doc.return_value.setHtml.assert_called_once()
        mock_doc.return_value.print_.assert_called_once()
