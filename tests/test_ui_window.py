import pytest
import os
import ftplib
from datetime import timedelta
from unittest.mock import MagicMock, patch
from PySide6.QtWidgets import QApplication, QMessageBox
from ui.main_window import MainWindow, ConfigPage, HealthCheckPage, LegacyDeleteWorker
from core.hash_engine import HashCheckEngine
from security.master_password import MasterPasswordManager
from config.config_manager import ConfigManager


@pytest.fixture(scope="module")
def qapp():
    import sys

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture(autouse=True)
def mock_qmessagebox():
    with (
        patch("PySide6.QtWidgets.QMessageBox.information") as mock_info,
        patch("PySide6.QtWidgets.QMessageBox.question") as mock_quest,
        patch("PySide6.QtWidgets.QMessageBox.warning") as mock_warn,
    ):
        mock_info.return_value = QMessageBox.Ok
        mock_quest.return_value = QMessageBox.Yes
        mock_warn.return_value = QMessageBox.Yes
        yield


@pytest.fixture
def auth_and_config(tmp_path):
    auth = MasterPasswordManager()
    auth.set_password("test_pass")

    config_file = tmp_path / "config.dat"
    config = ConfigManager(config_path=str(config_file))
    # Pre-fill profile
    config.set_profiles(
        [
            {
                "shop_name": "TestShop",
                "host": "localhost",
                "port": 21,
                "username": "user",
                "password": "pwd",
                "protocol": "FTP",
                "shop_url": "https://localhost",
                "remote_path": "/html",
            }
        ]
    )
    return auth, config


def test_main_window_init(qapp, auth_and_config):
    auth, config = auth_and_config
    window = MainWindow(auth, config)
    assert window.windowTitle() == "Gambio Health Check"

    # Switch pages
    window._change_page(2)
    assert window.pages.currentIndex() == 2

    window._change_page(0)
    assert window.pages.currentIndex() == 0


def test_main_window_session_lock_reauth(qapp, auth_and_config):
    auth, config = auth_and_config
    window = MainWindow(auth, config)

    # Expiriere die Session
    auth._session_lock.timeout = timedelta(minutes=0)

    # Dialog mocken
    with (
        patch("ui.main_window.MasterPasswordDialog") as mock_dialog_class,
        patch("ui.main_window.show_error") as mock_err,
    ):
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = True
        mock_dialog.get_password.return_value = "test_pass"
        mock_dialog_class.return_value = mock_dialog

        # Zurücksetzen der Session durch Reauth bei Seitenwechsel
        window._change_page(2)
        assert window.pages.currentIndex() == 2


def test_config_page_actions(qapp, auth_and_config):
    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    # Check fields loaded
    assert page.edit_shop_name.text() == "TestShop"

    # Save profile
    page.edit_shop_name.setText("TestShopUpdated")
    page._save_profile()
    assert config.get_profiles()[0]["shop_name"] == "TestShopUpdated"

    # Save settings
    assert "mein_ordner" in page.edit_excluded_files.placeholderText()
    assert "images, cache, logs" in page.lbl_excluded_hint.text()
    page.edit_excluded_files.setText("test.php")
    page._save_general_settings()
    assert config.get_excluded_files() == "test.php"

    # Test path validation - relative paths are allowed but no traversal
    page.remote_path_input.setText("relative/path")
    page._save_profile()
    assert config.get_profiles()[0]["remote_path"] == "relative/path"

    with patch("ui.main_window.show_error") as mock_err:
        page.remote_path_input.setText("../traversal")
        page._save_profile()
        mock_err.assert_called_with("Der angegebene Shop-Pfad auf dem Server ist ungültig.")

    # New profile
    page._new_profile()
    assert page.edit_shop_name.text() == ""

    # Delete profile
    page.current_profile_index = 0
    with patch("PySide6.QtWidgets.QMessageBox.question") as mock_quest:
        mock_quest.return_value = QMessageBox.Yes
        page._delete_profile()


def test_health_check_page_history_and_logs(qapp, auth_and_config, tmp_path):
    auth, config = auth_and_config
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        page = HealthCheckPage(auth, config)
        # Load profiles
        page._load_profiles()
        assert page.combo_profiles.count() > 0

        # Test open log folder and file
        with patch("ui.main_window.open_path") as mock_open:
            page._open_log_folder()
            # Since no logs are generated yet, open_last_log will error
            with patch("ui.main_window.show_error") as mock_err:
                page._open_last_log()
                mock_err.assert_called_once()
    finally:
        os.chdir(old_cwd)


def test_health_check_page_finished_signals(qapp, auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    page.current_legacy_files = ["old.php"]

    worker = MagicMock()
    worker._is_cancelled = False
    page.worker = worker

    # Checkbox ankreuzen, damit der Button bei vorhandenen Dateien aktiv wird
    page.cb_backup_confirmed.setChecked(True)
    page.check_finished()

    assert page.btn_delete_legacy.isEnabled() is True
    # Hinweis für zukünftige Anpassungen: Der Text "Health-Check abgeschlossen."
    # wurde ursprünglich aus der alten check_finished erwartet. Wir lassen das hier.
    # Actually wait, let me look at the old code again, I didn't see where it set the text. But the old test had it, so we must keep it.
    assert page.status_label.text() == "Health-Check abgeschlossen."


def test_health_check_page_run(qapp, auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # Mock connection and other page methods
    page._check_connection = MagicMock(return_value=(MagicMock(), ["index.php", "system", "GXEngine", "admin"]))
    page._check_gambio_structure = MagicMock(return_value=True)
    page._check_write_permissions = MagicMock()
    page._check_php_version_via_ftp_http = MagicMock(
        return_value={
            "php": "8.1",
            "db": {
                "type": "MySQL",
                "version_full": "8.0.30",
                "version_number": "8.0.30",
            },
            "security": {
                "installer_exists": False,
                "config_writable": False,
                "admin_config_writable": False,
            },
            "env": {
                "session_auto_start": False,
                "soap_loaded": True,
                "intl_loaded": True,
            },
        }
    )
    page._check_version = MagicMock(return_value="4.9.1.0")
    page._run_php_compatibility_check_logic = MagicMock()
    page._check_integrity = MagicMock()
    page._run_legacy_delete_analysis_logic = MagicMock(return_value=[])

    page._load_profiles()
    page.combo_profiles.setCurrentIndex(0)

    # Start-Methode mocken, um den Thread synchron im selben Thread auszuführen und den Abschluss-Handler direkt zu rufen
    with patch("ui.main_window.HealthCheckWorker.start", autospec=True) as mock_start:

        def run_sync(*args, **kwargs):
            page.worker.run()
            page.check_finished()

        mock_start.side_effect = run_sync

        # Trigger full run
        page.run_health_check()

    assert page.status_label.text() == "Health-Check abgeschlossen."


def test_delete_buttons_require_backup_confirmation(qapp, auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # 1. Initiale Zustände
    assert page.cb_backup_confirmed.isChecked() is False
    assert page.btn_cleanup_logs.isEnabled() is False
    assert page.btn_delete_bak.isEnabled() is False
    assert page.btn_delete_legacy.isEnabled() is False

    # 2. Haken setzen (ohne Dateien)
    page.cb_backup_confirmed.setChecked(True)
    assert page.cb_backup_confirmed.isChecked() is True
    assert page.btn_cleanup_logs.isEnabled() is True
    assert page.btn_delete_bak.isEnabled() is False  # Noch keine Dateien
    assert page.btn_delete_legacy.isEnabled() is False  # Noch keine Altlasten

    # 3. Dateien simulieren
    page.current_bak_files = ["test.bak"]
    page.current_legacy_files = ["old.php"]
    page._update_delete_buttons_state()
    assert page.btn_delete_bak.isEnabled() is True
    assert page.btn_delete_legacy.isEnabled() is True

    # 4. Haken wieder entfernen
    page.cb_backup_confirmed.setChecked(False)
    assert page.btn_cleanup_logs.isEnabled() is False
    assert page.btn_delete_bak.isEnabled() is False
    assert page.btn_delete_legacy.isEnabled() is False


def test_manual_page_search(qapp):
    from ui.main_window import ManualPage

    page = ManualPage()

    # Definierten Inhalt setzen, um Unabhängigkeit vom echten Handbuch zu garantieren
    page.browser.setMarkdown("Das ist ein Test für die Suchfunktion. Test Wort Test.")

    # Suche vorbereiten
    page.search_input.setText("Test")

    # _search_next mehrfach aufrufen (inklusive Loop an den Anfang)
    page.btn_search_next.click()  # Findet erstes "Test"
    page.btn_search_next.click()  # Findet zweites "Test"
    page.btn_search_next.click()  # Findet drittes "Test"
    page.btn_search_next.click()  # Sollte zurückspringen (Loop) ohne Exception

    # _search_prev aufrufen (inklusive Loop ans Ende)
    page.btn_search_prev.click()
    page.btn_search_prev.click()
    page.btn_search_prev.click()
    page.btn_search_prev.click()  # Sollte ans Ende springen ohne Exception

    # Wenn wir hier ankommen, gab es keine AttributeError mehr
    assert True


def test_legacy_delete_worker(qapp, auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # Mock connection to return a mock FTP/SFTP
    conn = MagicMock(spec=ftplib.FTP)
    page._check_connection = MagicMock(return_value=(conn, []))

    worker = LegacyDeleteWorker(page, config.get_profiles()[0], ["old.php", "old.bak"])
    worker.result_signal = MagicMock()
    worker.progress_signal = MagicMock()
    worker.run()

    # Check delete was called on connection
    conn.delete.assert_any_call("old.php")
    conn.delete.assert_any_call("old.bak")

    # Check progress signal
    worker.progress_signal.emit.assert_any_call("Verbinde zum Server für Löschvorgang...")
    worker.progress_signal.emit.assert_any_call("Lösche Datei 1/2: old.php")
    worker.progress_signal.emit.assert_any_call("Lösche Datei 2/2: old.bak")
    worker.progress_signal.emit.assert_any_call("Löschvorgang abgeschlossen (2 Dateien bearbeitet).")


def test_hash_engine_malware_detection():
    # Test checking malware indicators in HashCheckEngine
    engine = HashCheckEngine("Test", None)

    # Mock logging
    engine.logger = MagicMock()
    engine.signal = MagicMock()

    # Check for eval in data
    engine._check_malware_indicators(b"<?php eval('secret'); ?>", "test.php")
    engine.signal.emit.assert_called_with("Verdächtiger Code in test.php (eval gefunden)", "error")


def test_check_php_version_via_ftp_http_ftp(auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    conn = MagicMock(spec=ftplib.FTP)
    conn.pwd.return_value = "/html"
    conn.size.return_value = 2500

    # Mock requests.get
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "php": "8.2",
            "db": {
                "type": "MySQL",
                "version_full": "8.0.30",
                "version_number": "8.0.30",
            },
        }
        mock_get.return_value = mock_response

        profile = config.get_profiles()[0]
        # Set dummy worker for cancellation check
        page.worker = MagicMock()
        page.worker._is_cancelled = False
        res = page._check_php_version_via_ftp_http(conn, profile)
        assert res["php"] == "8.2"


def test_run_update_analysis_logic(auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    conn = MagicMock(spec=ftplib.FTP)

    # Mock FTP folder listings
    conn.nlst.return_value = ["gambio_updater/updates/v4.9.2.0"]

    page._load_update_ini = MagicMock()
    page._check_update_php_compat = MagicMock()
    page._check_update_shop_compat = MagicMock()
    page._check_mysql_version = MagicMock()
    page._check_updated_files = MagicMock(return_value=True)
    page._check_files_to_delete = MagicMock(return_value=True)
    page._evaluate_completeness = MagicMock()

    page.worker = MagicMock()
    page.worker._is_cancelled = False

    page._run_update_analysis_logic(conn, "4.9.1.0", "8.1", "8.0.30", "MySQL", [])


def test_config_page_test_connection_ftp(qapp, auth_and_config):
    auth, config = auth_and_config
    page = ConfigPage(auth, config)
    page._get_current_profile_data = MagicMock(
        return_value={
            "protocol": "FTP",
            "host": "localhost",
            "port": 21,
            "username": "user",
            "password": "pwd",
            "remote_path": "/html",
            "shop_url": "https://localhost",
        }
    )

    # Mock ftplib.FTP_TLS und ftplib.FTP
    with (
        patch("ftplib.FTP_TLS") as mock_ftp_tls_class,
        patch("ftplib.FTP") as mock_ftp_class,
    ):
        mock_ftp = MagicMock()
        mock_ftp.nlst.return_value = ["system", "GXEngine"]
        mock_ftp_tls_class.return_value = mock_ftp
        mock_ftp_class.return_value = mock_ftp

        page._test_connection()


def test_config_page_change_master_password(qapp, auth_and_config):
    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    page.edit_old_master_password.setText("test_pass")
    page.edit_new_master_password.setText("new_pass")
    page.edit_repeat_new_master_password.setText("new_pass")

    with patch.object(config, "change_master_password") as mock_change:
        page._change_master_password()
        mock_change.assert_called_with("test_pass", "new_pass")


def test_on_bak_deleted(qapp, auth_and_config):
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # Mock elements
    page.btn_run = MagicMock()
    page.btn_scan_bak = MagicMock()
    page.btn_delete_bak = MagicMock()
    page.btn_delete_legacy = MagicMock()
    page.cb_backup_confirmed = MagicMock()
    page.cb_backup_confirmed.isChecked.return_value = True
    page.current_bak_files = ["file1.bak", "file2.bak"]
    page.auth_manager = MagicMock()

    page._on_bak_deleted()

    page.btn_run.setEnabled.assert_called_with(True)
    page.btn_scan_bak.setEnabled.assert_called_with(True)
    assert page.current_bak_files == []
    # Since current_bak_files is empty, delete_bak should be False
    page.btn_delete_bak.setEnabled.assert_called_with(False)
    page.auth_manager.update_activity.assert_called_once()


def test_global_cancel_button(qapp, auth_and_config):
    auth, config = auth_and_config
    window = MainWindow(auth, config)

    # Mock cancel_all on the first page (HealthCheckPage)
    health_page = window.pages.widget(0)
    health_page.cancel_all = MagicMock()

    # Simulate clicking the global cancel button
    window.btn_cancel_global.clicked.emit()

    # Verify cancel_all was called
    health_page.cancel_all.assert_called_once()


def test_config_page_toggle_password(qapp, auth_and_config):
    from PySide6.QtWidgets import QLineEdit

    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    # Initialzustand
    assert page.edit_password.echoMode() == QLineEdit.Password
    assert page.btn_toggle_password.text() == "Anzeigen"

    # Umschalten auf Klartext
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.Normal
    assert page.btn_toggle_password.text() == "Verbergen"

    # Umschalten zurück auf Maskiert
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.Password
    assert page.btn_toggle_password.text() == "Anzeigen"

    # Beim Setzen von Profildaten wird Maskierung wieder aktiviert
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.Normal
    page._set_profile_data({"password": "secret"})
    assert page.edit_password.echoMode() == QLineEdit.Password
    assert page.btn_toggle_password.text() == "Anzeigen"

    # Beim Leeren von Feldern wird Maskierung wieder aktiviert
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.Normal
    page._clear_profile_fields()
    assert page.edit_password.echoMode() == QLineEdit.Password
    assert page.btn_toggle_password.text() == "Anzeigen"


def test_open_path_nonexistent():
    from ui.main_window import open_path

    with patch("os.startfile") as mock_startfile, patch("subprocess.run") as mock_run:
        open_path("C:/pfad/der/nicht/existiert_12345.xyz")
        mock_startfile.assert_not_called()
        mock_run.assert_not_called()


def test_open_path_existing(tmp_path):
    from ui.main_window import open_path

    dummy_file = tmp_path / "test.txt"
    dummy_file.write_text("ok", encoding="utf-8")

    # Auf Windows os.startfile testen
    with patch("platform.system", return_value="Windows"), patch("os.startfile") as mock_start:
        open_path(str(dummy_file))
        mock_start.assert_called_once_with(str(dummy_file.resolve()))

    # Auf Linux subprocess testen
    with patch("platform.system", return_value="Linux"), patch("subprocess.run") as mock_run:
        open_path(str(dummy_file))
        mock_run.assert_called_once_with(["xdg-open", str(dummy_file.resolve())], check=True)
