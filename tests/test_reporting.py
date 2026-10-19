import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from core.reporting import (
    _build_html,
    _determine_css_class,
    _get_latest_log_file,
    generate_html_report,
    generate_pdf_report,
    load_log_entries,
)


def test_generate_html_report() -> None:
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


def test_load_log_entries_direct_file_and_limits(tmp_path: Path) -> None:
    log_file = tmp_path / "custom.log"
    lines = [json.dumps({"time": f"2026-10-17 10:00:0{i}", "level": "INFO", "msg": f"Zeile {i}"}) for i in range(10)]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Begrenzung auf max_entries = 3 (die neuesten 3 Zeilen)
    resolved_path, entries = load_log_entries(log_file, max_entries=3)
    assert resolved_path == log_file.resolve()
    assert len(entries) == 3
    assert entries[0]["msg"] == "Zeile 7"
    assert entries[2]["msg"] == "Zeile 9"


def test_load_log_entries_corrupt_and_non_dict(tmp_path: Path) -> None:
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

    _resolved_path, entries = load_log_entries(log_file)
    assert len(entries) == 1
    assert entries[0]["level"] == "ERROR"
    assert entries[0]["msg"] == "Kritischer Fehler"


def test_load_log_entries_invalid_utf8_bytes(tmp_path: Path) -> None:
    log_file = tmp_path / "invalid_bytes.log"
    # Schreibe ungültige Bytes gefolgt von einer validen JSON-Zeile
    valid_json = json.dumps({"time": "2026-10-17", "level": "OK", "msg": "Erfolg"}).encode("utf-8")
    with open(log_file, "wb") as f:
        f.write(b"\xff\xfe\xfa\n" + valid_json + b"\n")

    _resolved_path, entries = load_log_entries(log_file)
    assert len(entries) == 1
    assert entries[0]["msg"] == "Erfolg"


def test_load_log_entries_invalid_sources(tmp_path: Path) -> None:
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


def test_get_latest_log_file(tmp_path: Path) -> None:
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


def test_determine_css_class() -> None:
    assert _determine_css_class("ERROR", "Fehler") == "level-error"
    assert _determine_css_class("FATAL", "Absturz") == "level-error"
    assert _determine_css_class("CRITICAL", "Problem") == "level-error"
    assert _determine_css_class("WARN", "Achtung") == "level-warn"
    assert _determine_css_class("OK", "Alles gut") == "level-ok"
    assert _determine_css_class("INFO", "Erfolg beim Speichern") == "level-ok"
    assert _determine_css_class("INFO", "System ist bereit") == "level-ok"
    assert _determine_css_class("INFO", "Normale Info") == "level-info"


def test_build_html_csp_and_escaping() -> None:
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


def test_generate_pdf_report_mocked(tmp_path: Path) -> None:
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
        patch("core.reporting.QPrinter") as _mock_printer,
    ):
        assert generate_pdf_report("Profile", log_dir, out_pdf) is True
        mock_doc.return_value.setHtml.assert_called_once()
        mock_doc.return_value.print_.assert_called_once()


def test_load_log_entries_empty_lines(tmp_path: Path) -> None:
    """Testet das Überspringen von Leerzeilen beim Laden von Logs."""
    log_file = tmp_path / "whitespace.log"
    valid_entry = json.dumps({"time": "2026-10-17 12:00:00", "level": "INFO", "msg": "Eintrag nach Leerzeilen"})
    log_file.write_text(f"\n   \n\t\n{valid_entry}\n\n", encoding="utf-8")

    path, entries = load_log_entries(log_file)
    assert path == log_file.resolve()
    assert len(entries) == 1
    assert entries[0]["msg"] == "Eintrag nach Leerzeilen"


def test_load_log_entries_os_error(tmp_path: Path) -> None:
    """Testet das Abfangen von OSError beim Lesen der Log-Datei."""
    log_file = tmp_path / "locked.log"
    log_file.write_text("Dummy", encoding="utf-8")

    with patch("builtins.open", side_effect=OSError("Zugriff verweigert")):
        path, entries = load_log_entries(log_file)
        assert path == log_file.resolve()
        assert entries == []


def test_generate_html_report_empty_or_missing_source(tmp_path: Path) -> None:
    """Testet das Verhalten von generate_html_report bei fehlenden/leeren Logs."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    out_html = tmp_path / "report.html"

    result = generate_html_report("ProfilOhneLogs", empty_dir, out_html)
    assert result is False
    assert not out_html.exists()


def test_generate_html_report_write_error(tmp_path: Path) -> None:
    """Testet das Abfangen von OSError beim Schreiben der HTML-Datei."""
    log_file = tmp_path / "app.log"
    log_file.write_text(json.dumps({"time": "2026-10-17", "level": "INFO", "msg": "Test"}) + "\n", encoding="utf-8")
    out_html = tmp_path / "error_report.html"

    with patch("builtins.open", side_effect=[open(log_file, "r", encoding="utf-8"), OSError("Festplatte voll")]):
        result = generate_html_report("Profil", log_file, out_html)
        assert result is False


def test_generate_pdf_report_empty_or_missing_source(tmp_path: Path) -> None:
    """Testet das Verhalten von generate_pdf_report bei fehlenden/leeren Logs."""
    empty_dir = tmp_path / "empty_pdf_dir"
    empty_dir.mkdir()
    out_pdf = tmp_path / "report.pdf"

    result = generate_pdf_report("ProfilOhneLogs", empty_dir, out_pdf)
    assert result is False
    assert not out_pdf.exists()


def test_generate_pdf_report_print_exceptions(tmp_path: Path) -> None:
    """Testet die Ausnahmebehandlung bei RuntimeError und generischen Fehlern im PDF-Export."""
    log_file = tmp_path / "pdf_data.log"
    log_file.write_text(json.dumps({"time": "2026-10-17", "level": "INFO", "msg": "PDF Test"}) + "\n", encoding="utf-8")
    out_pdf = tmp_path / "output.pdf"

    with (
        patch("core.reporting.PYSIDE_AVAILABLE", True),
        patch("core.reporting.QTextDocument") as mock_doc,
        patch("core.reporting.QPrinter"),
    ):
        # 1. RuntimeError beim Drucken
        mock_doc.return_value.print_.side_effect = RuntimeError("Qt Print Error")
        assert generate_pdf_report("Profile", log_file, out_pdf) is False

        # 2. Unerwartete Exception beim Drucken
        mock_doc.return_value.print_.side_effect = Exception("Unerwarteter Fehler")
        assert generate_pdf_report("Profile", log_file, out_pdf) is False


def test_get_latest_log_file_os_error(tmp_path: Path) -> None:
    """Testet die Fehlerbehandlung bei OSError in _get_latest_log_file."""
    log_dir = tmp_path / "dir_with_logs"
    log_dir.mkdir()
    log_file = log_dir / "test.log"
    log_file.write_text("Inhalt", encoding="utf-8")

    with patch("pathlib.Path.glob", side_effect=OSError("I/O Fehler")):
        assert _get_latest_log_file(log_dir) == ""
