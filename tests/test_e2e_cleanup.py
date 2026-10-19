import ftplib
import sys
from unittest.mock import MagicMock, call

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qapp():
    """Erstellt die notwendige QApplication Instanz für GUI-Tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


from ui.main_window import HealthCheckPage, LegacyDeleteWorker


@pytest.fixture
def cleanup_page(qapp):
    """Erstellt eine Instanz von HealthCheckPage für Cleanup E2E Tests."""
    auth = MagicMock()
    config = MagicMock()
    # Konfiguriere die Whitelist
    config.get_excluded_files.return_value = "paypal3.php, custom_theme/style.css, includes/configure.php"

    test_page = HealthCheckPage(auth, config)
    test_page.status_label = MagicMock()
    test_page.spinner_bar = MagicMock()
    test_page.worker = MagicMock()
    test_page.worker._is_cancelled = False
    return test_page


def test_e2e_whitelist_protection_during_cleanup(cleanup_page):
    """
    E2E Test: Simuliert den kompletten Ablauf von der Erkennung der Altlasten
    bis hin zum tatsächlichen (gemockten) Löschen. Stellt sicher, dass
    Whitelist-Dateien niemals gelöscht werden, selbst wenn sie in alten
    Update-Paketen als 'zu löschen' markiert sind.
    """
    # 1. Mock FTP Verbindung für die Analyse
    conn = MagicMock(spec=ftplib.FTP)

    # Simuliere Ordnerstruktur mit einem Update
    conn.nlst.return_value = ["gambio_updater/updates/v4.0.0.0"]

    # In diesem alten Update sollen 3 Dateien gelöscht werden:
    # 1 normale, 1 Whitelist-Datei, 1 weitere Whitelist-Datei
    def mock_retr(cmd, callback):
        if "to_delete.php" in cmd:
            callback(b"<?php $files = ['old_module.php', 'paypal3.php', 'includes/configure.php'];")
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr

    # Simuliere, dass alle 3 Dateien auf dem Server noch existieren
    conn.size.side_effect = (
        lambda p: 100 if p in ["old_module.php", "paypal3.php", "includes/configure.php"] else Exception("550")
    )

    signal = MagicMock()

    # --- PHASE 1: Analyse der Altlasten ---
    legacy_files = cleanup_page._run_legacy_delete_analysis_logic(conn, signal)

    # Verifizierung Phase 1: Die Whitelist-Dateien dürfen NICHT in der Liste der Altlasten auftauchen
    assert "old_module.php" in legacy_files, "Normale Altlast wurde nicht gefunden"
    assert "paypal3.php" not in legacy_files, "Whitelist-Datei (paypal3.php) fälschlicherweise als Altlast markiert!"
    assert "includes/configure.php" not in legacy_files, (
        "Whitelist-Datei (configure.php) fälschlicherweise als Altlast markiert!"
    )

    # Setze legacy files für Phase 2
    cleanup_page.current_legacy_files = legacy_files

    # --- PHASE 2: Der Löschvorgang (LegacyDeleteWorker) ---
    # Wir übergeben die ermittelten Dateien an den Worker
    profile = {"protocol": "FTP"}

    # Wir müssen die _check_connection Methode mocken, damit der Worker den gemockten FTP nutzt
    cleanup_page._check_connection = MagicMock(return_value=(conn, []))

    worker = LegacyDeleteWorker(cleanup_page, profile, cleanup_page.current_legacy_files)
    worker.result_signal = MagicMock()
    worker.finished_signal = MagicMock()

    # Führe Worker synchron aus
    worker.run()

    # Verifizierung Phase 2:
    # Es darf nur delete("old_module.php") aufgerufen worden sein.
    conn.delete.assert_called_once_with("old_module.php")

    # Wir verifizieren explizit, dass delete nicht für Whitelist-Dateien aufgerufen wurde
    assert call("paypal3.php") not in conn.delete.call_args_list, "KRITISCHER FEHLER: Whitelist-Datei wurde gelöscht!"
    assert call("includes/configure.php") not in conn.delete.call_args_list, (
        "KRITISCHER FEHLER: Whitelist-Datei wurde gelöscht!"
    )
