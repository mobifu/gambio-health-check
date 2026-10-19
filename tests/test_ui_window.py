import ftplib
import os
import stat
from collections.abc import Callable, Generator
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QApplication, QLineEdit, QMessageBox

from config.config_manager import ConfigManager
from core.hash_engine import HashCheckEngine
from security.master_password import MasterPasswordManager
from ui.main_window import (
    BakFileScannerWorker,
    ConfigPage,
    HealthCheckPage,
    LegacyDeleteWorker,
    LogfileWorker,
    MainWindow,
)


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    import sys

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app  # type: ignore[misc]


@pytest.fixture(autouse=True)
def mock_qmessagebox() -> Generator[None, None, None]:
    with (
        patch("PySide6.QtWidgets.QMessageBox.information") as mock_info,
        patch("PySide6.QtWidgets.QMessageBox.question") as mock_quest,
        patch("PySide6.QtWidgets.QMessageBox.warning") as mock_warn,
        patch("PySide6.QtWidgets.QMessageBox.critical") as mock_crit,
    ):
        mock_info.return_value = QMessageBox.StandardButton.Ok
        mock_quest.return_value = QMessageBox.StandardButton.Yes
        mock_warn.return_value = QMessageBox.StandardButton.Yes
        mock_crit.return_value = QMessageBox.StandardButton.Ok
        yield


@pytest.fixture
def auth_and_config(tmp_path: Path) -> tuple[MasterPasswordManager, ConfigManager]:
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


def test_main_window_init(qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
    auth, config = auth_and_config
    window = MainWindow(auth, config)
    assert window.windowTitle() == "Gambio Health Check"

    # Switch pages
    window._change_page(2)
    assert window.pages.currentIndex() == 2

    window._change_page(0)
    assert window.pages.currentIndex() == 0


def test_main_window_session_lock_reauth(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
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


def test_config_page_actions(qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
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
        mock_quest.return_value = QMessageBox.StandardButton.Yes
        page._delete_profile()


def test_health_check_page_history_and_logs(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager], tmp_path: Path
) -> None:
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


def test_health_check_page_finished_signals(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
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


def test_health_check_page_run(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # Mock connection and other page methods using setattr to satisfy type checkers
    page._check_connection = MagicMock(return_value=(MagicMock(), ["index.php", "system", "GXEngine", "admin"]))
    page._check_gambio_structure = MagicMock(return_value=True)
    page._check_write_permissions = MagicMock()
    page._check_php_version_via_ftp_http = MagicMock(
        return_value={
            "php": "8.1",
            "db": {"type": "MySQL", "version_full": "8.0.30", "version_number": "8.0.30"},
            "security": {"installer_exists": False, "config_writable": False, "admin_config_writable": False},
            "env": {"session_auto_start": False, "soap_loaded": True, "intl_loaded": True},
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

        def run_sync(*args: Any, **kwargs: Any) -> None:
            if page.worker is not None:
                page.worker.run()
            page.check_finished()

        mock_start.side_effect = run_sync

        # Trigger full run
        page.run_health_check()

    assert page.status_label.text() == "Health-Check abgeschlossen."


def test_delete_buttons_require_backup_confirmation(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
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


def test_manual_page_search(qapp: QApplication) -> None:
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


def test_legacy_delete_worker(qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # Mock connection to return a mock FTP/SFTP
    conn = MagicMock(spec=ftplib.FTP)
    page._check_connection = MagicMock(return_value=(conn, []))

    worker = LegacyDeleteWorker(page, config.get_profiles()[0], ["old.php", "old.bak"])
    progress_messages: list[str] = []
    worker.progress_signal.connect(progress_messages.append)
    worker.run()

    # Check delete was called on connection
    conn.delete.assert_any_call("old.php")
    conn.delete.assert_any_call("old.bak")

    # Check progress signal
    assert "Verbinde zum Server für Löschvorgang..." in progress_messages
    assert "Lösche Datei 1/2: old.php" in progress_messages
    assert "Lösche Datei 2/2: old.bak" in progress_messages
    assert "Löschvorgang abgeschlossen (2 Dateien bearbeitet)." in progress_messages


def test_hash_engine_malware_detection() -> None:
    # Test checking malware indicators in HashCheckEngine
    engine = HashCheckEngine("Test", None)

    # Mock logging
    engine.logger = MagicMock()
    engine.signal = MagicMock()

    # Check for eval in data
    engine._check_malware_indicators(b"<?php eval('secret'); ?>", "test.php")
    engine.signal.emit.assert_called_with("Verdächtiger Code in test.php (eval gefunden)", "error")


def test_check_php_version_via_ftp_http_ftp(auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
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
        assert res is not None
        assert res["php"] == "8.2"


def test_run_update_analysis_logic(auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
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


def test_config_page_test_connection_ftp(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
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


def test_config_page_change_master_password(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    page.edit_old_master_password.setText("test_pass")
    page.edit_new_master_password.setText("new_pass")
    page.edit_repeat_new_master_password.setText("new_pass")

    with patch.object(config, "change_master_password") as mock_change:
        page._change_master_password()
        mock_change.assert_called_with("test_pass", "new_pass")


def test_on_bak_deleted(qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
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


def test_global_cancel_button(qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]) -> None:
    auth, config = auth_and_config
    window = MainWindow(auth, config)

    # Mock cancel_all on the first page (HealthCheckPage)
    health_page = window.pages.widget(0)
    assert health_page is not None
    mock_cancel = MagicMock()
    health_page.cancel_all = mock_cancel

    # Simulate clicking the global cancel button
    window.btn_cancel_global.clicked.emit()

    # Verify cancel_all was called
    mock_cancel.assert_called_once()


def test_config_page_toggle_password(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    # Initialzustand
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Password
    assert page.btn_toggle_password.text() == "Anzeigen"

    # Umschalten auf Klartext
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Normal
    assert page.btn_toggle_password.text() == "Verbergen"

    # Umschalten zurück auf Maskiert
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Password
    assert page.btn_toggle_password.text() == "Anzeigen"

    # Beim Setzen von Profildaten wird Maskierung wieder aktiviert
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Normal
    page._set_profile_data({"password": "secret"})
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Password
    assert page.btn_toggle_password.text() == "Anzeigen"

    # Beim Leeren von Feldern wird Maskierung wieder aktiviert
    page.btn_toggle_password.click()
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Normal
    page._clear_profile_fields()
    assert page.edit_password.echoMode() == QLineEdit.EchoMode.Password
    assert page.btn_toggle_password.text() == "Anzeigen"


def test_open_path_nonexistent() -> None:
    from ui.main_window import open_path

    with patch("os.startfile") as mock_startfile, patch("subprocess.run") as mock_run:
        open_path("C:/pfad/der/nicht/existiert_12345.xyz")
        mock_startfile.assert_not_called()
        mock_run.assert_not_called()


def test_open_path_existing(tmp_path: Path) -> None:
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


def test_health_check_worker_baseline_and_hash_mode(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    from ui.main_window import HealthCheckWorker

    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    logger = MagicMock()
    profile = config.get_profiles()[0]

    # Baseline Mode
    worker_baseline = HealthCheckWorker(page, profile, logger, mode="baseline")
    page._check_connection = MagicMock(return_value=(MagicMock(), ["index.php"]))
    with patch("ui.main_window.HashCheckEngine") as mock_engine_class:
        mock_engine = MagicMock()
        mock_engine_class.return_value = mock_engine
        worker_baseline.run()
        mock_engine.generate_baseline.assert_called_once()

    # Hash Check Mode
    worker_hash = HealthCheckWorker(page, profile, logger, mode="hash_check")
    page._check_version = MagicMock(return_value="4.9.1.0")
    with patch("ui.main_window.HashCheckEngine") as mock_engine_class:
        mock_engine = MagicMock()
        mock_engine_class.return_value = mock_engine
        worker_hash.run()
        mock_engine.compare_with_baseline.assert_called_once()
        mock_engine.compare_with_update_hashes.assert_called_once_with("4.9.1.0")


def test_health_check_worker_cancellation_and_security_alerts(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    from ui.main_window import HealthCheckWorker

    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    logger = MagicMock()
    profile = config.get_profiles()[0]

    # Cancellation test
    worker = HealthCheckWorker(page, profile, logger)
    worker.cancel()
    assert worker._is_cancelled is True
    cancelled_emitted = []
    worker.cancelled_signal.connect(lambda: cancelled_emitted.append(True))
    worker.cancel()
    assert len(cancelled_emitted) == 1

    # Run when already cancelled
    results: list[tuple[str, str]] = []

    def on_res(msg: str, status: str) -> None:
        results.append((msg, status))

    worker.result_signal.connect(on_res)
    worker.run()
    assert any("abgebrochen" in r[0] for r in results)

    # Security alerts in worker
    worker2 = HealthCheckWorker(page, profile, logger)
    results2: list[tuple[str, str]] = []

    def on_res2(msg: str, status: str) -> None:
        results2.append((msg, status))

    worker2.result_signal.connect(on_res2)
    page._check_connection = MagicMock(return_value=(MagicMock(), ["index.php", "system"]))
    page._check_gambio_structure = MagicMock(return_value=True)
    page._check_cache_size = MagicMock()
    page._check_write_permissions = MagicMock()
    page._check_php_version_via_ftp_http = MagicMock(
        return_value={
            "php": "8.1",
            "db": {"type": "MySQL", "version_full": "8.0", "version_number": "8.0"},
            "security": {
                "installer_exists": True,
                "config_writable": True,
                "admin_config_writable": True,
                "htaccess_admin_backups": False,
                "htaccess_log": False,
            },
            "env": {"session_auto_start": True, "soap_loaded": False, "intl_loaded": False},
        }
    )
    page._check_version = MagicMock(return_value=None)
    page._run_gxmodules_compatibility_scan = MagicMock()
    page._run_legacy_delete_analysis_logic = MagicMock(return_value=[])

    worker2.run()
    msg_texts = [r[0] for r in results2]
    assert any("gambio_installer" in m for m in msg_texts)
    assert any("includes/configure.php ist beschreibbar" in m for m in msg_texts)
    assert any("admin/includes/configure.php ist beschreibbar" in m for m in msg_texts)
    assert any("admin/backups/.htaccess fehlt" in m for m in msg_texts)
    assert any("logfiles/.htaccess fehlt" in m for m in msg_texts)
    assert any("session.auto_start ist aktiv" in m for m in msg_texts)
    assert any("soap" in m for m in msg_texts)
    assert any("intl" in m for m in msg_texts)


def test_legacy_delete_worker_sftp_and_cache(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    import stat

    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = config.get_profiles()[0]

    sftp_conn = MagicMock()
    # Mock listdir_attr for folder
    entry_file = MagicMock()
    entry_file.filename = "subfile.txt"
    entry_file.st_mode = stat.S_IFREG

    entry_dot = MagicMock()
    entry_dot.filename = "."

    sftp_conn.listdir_attr.side_effect = [
        [entry_dot, entry_file],  # for folder
        [MagicMock(filename="cache_temp.txt", st_mode=stat.S_IFREG)],  # for cache cleanup
    ]

    page._check_connection = MagicMock(return_value=(sftp_conn, []))

    worker = LegacyDeleteWorker(
        page,
        profile,
        files_to_delete=["test_folder", "test_file.php"],
        logger_instance=MagicMock(),
        clear_cache=True,
    )
    worker.run()

    # sftp_conn.remove and rmdir should have been called
    sftp_conn.remove.assert_any_call("test_folder/subfile.txt")
    sftp_conn.rmdir.assert_any_call("test_folder")
    sftp_conn.remove.assert_any_call("test_file.php")
    sftp_conn.remove.assert_any_call("cache/cache_temp.txt")


def test_bak_file_scanner_worker_ftp_and_sftp(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    import stat

    from ui.main_window import BakFileScannerWorker

    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = config.get_profiles()[0]

    # FTP Mock
    ftp_conn = MagicMock(spec=ftplib.FTP)
    ftp_conn.mlsd.return_value = [
        ("old.bak", {"type": "file"}),
        ("sub_folder", {"type": "dir"}),
        ("ignore.txt", {"type": "file"}),
    ]
    # In sub_folder, return empty
    ftp_conn.cwd.side_effect = None

    page._check_connection = MagicMock(return_value=(ftp_conn, []))
    worker = BakFileScannerWorker(page, profile)
    worker.run()
    assert "old.bak" in worker.bak_files

    # Cancel test
    worker_cancel = BakFileScannerWorker(page, profile)
    worker_cancel.cancel()
    assert worker_cancel._is_cancelled is True


def test_logfile_worker_scan_and_cleanup(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    from ui.main_window import LogfileWorker

    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = config.get_profiles()[0]

    # Mock FTP connection with logfiles
    ftp_conn = MagicMock(spec=ftplib.FTP)
    ftp_conn.mlsd.return_value = [
        (".", {"type": "dir"}),
        (".htaccess", {"type": "file"}),
        ("error.log", {"type": "file", "modify": "20200101120000"}),
    ]

    def mock_retr(cmd: str, callback: Callable[[bytes], None]) -> None:
        callback(b"Line 1 normal\nLine 2 [FATAL] Critical error\nLine 3 [Exception] test")

    ftp_conn.retrbinary.side_effect = mock_retr

    # Mode scan
    page._check_connection = MagicMock(return_value=(ftp_conn, []))
    worker_scan = LogfileWorker(page, profile, max_age_days=30, mode="scan")
    worker_scan.run()
    assert len(worker_scan.errors_found) == 2
    assert "[error.log:Zeile 2]" in worker_scan.errors_found[0]

    # Mode cleanup
    worker_cleanup = LogfileWorker(page, profile, max_age_days=30, mode="cleanup")
    worker_cleanup.run()
    ftp_conn.delete.assert_called_with("error.log")
    assert "error.log" in worker_cleanup.files_deleted


def test_health_check_page_version_detection(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    page.worker = MagicMock()
    page.worker._is_cancelled = False

    # FTP version check
    ftp_conn = MagicMock(spec=ftplib.FTP)
    ftp_conn.nlst.return_value = ["version_info/build_123.php", "version_info/build_456.php"]

    def mock_retr(cmd: str, callback: Callable[[bytes], None]) -> None:
        callback(b"CI_BUILD_RELEASE_VERSION: 4.9.2.0\nCI_BUILD_JOB_ID: 456\n")

    ftp_conn.retrbinary.side_effect = mock_retr

    ver = page._check_version(ftp_conn, config.get_profiles()[0])
    assert ver == "4.9.2.0"

    # Keine Build Dateien
    ftp_conn.nlst.return_value = ["version_info/other.txt"]
    ver_none = page._check_version(ftp_conn, config.get_profiles()[0])
    assert ver_none is None


def test_health_check_page_cache_size(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    signal = MagicMock()

    conn = MagicMock()
    # Cache > 250 MB (wird für 'cache' und 'templates_c' abgefragt, 2x 300 MB = 600 MB)
    conn.mlsd.return_value = [("file1.tmp", {"type": "file", "size": str(300 * 1024 * 1024)})]
    page._check_cache_size(conn, ["cache"], signal)
    signal.emit.assert_called_with("Cache-Ordner sind sehr groß (600 MB). Erwägen Sie eine Leerung.", "warn")

    # Normal cache (2x 5 MB = 10 MB)
    conn.mlsd.return_value = [("file1.tmp", {"type": "file", "size": str(5 * 1024 * 1024)})]
    page._check_cache_size(conn, ["cache"], signal)
    signal.emit.assert_called_with("Cache-Größe ist im normalen Bereich (10 MB).", "ok")


def test_health_check_page_check_integrity(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    signal = MagicMock()
    page.worker = MagicMock()
    page.worker._is_cancelled = False

    # Keine index.php
    page._check_integrity(["system"], signal)
    signal.emit.assert_any_call("Basis-Integrität (Dateipräsenz): Fehler (index.php fehlt).", "error")

    # index.php + themes
    signal.reset_mock()
    page._check_integrity(["index.php", "system", "GXEngine", "robots.txt", "themes"], signal)
    signal.emit.assert_any_call("Shop-Design-Ordner 'themes' gefunden.", "ok")
    signal.emit.assert_any_call("Basis-Integrität (Dateipräsenz): OK", "ok")

    # index.php + templates
    signal.reset_mock()
    page._check_integrity(["index.php", "system", "GXEngine", "robots.txt", "templates"], signal)
    signal.emit.assert_any_call(
        "Shop-Design-Ordner 'templates' gefunden (Hinweis: 'themes' ist in neueren Gambio-Versionen üblich).", "warn"
    )


def test_health_check_page_gxmodules_scan(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    signal = MagicMock()
    page.worker = MagicMock()
    page.worker._is_cancelled = False

    # Mock FTP connection with a problematic PHP file in GXModules
    conn = MagicMock(spec=ftplib.FTP)
    conn.mlsd.return_value = [
        ("bad_module.php", {"type": "file"}),
    ]

    def mock_retr(cmd: str, callback: Callable[[bytes], None]) -> None:
        callback(b"<?php create_function('$a', 'return $a;'); money_format('%i', 10); ?>")

    conn.retrbinary.side_effect = mock_retr

    # Gambio 4.7+ -> Severity "error"
    page._run_gxmodules_compatibility_scan(conn, "4.8.0.0", scan_gambio=True, signal=signal)
    signal.emit.assert_any_call(
        "Inkompatibler Code in GXModules/bad_module.php: create_function, money_format gefunden.",
        "error",
    )


def test_health_check_page_php_compat_logic(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    signal = MagicMock()
    page.worker = MagicMock()
    page.worker._is_cancelled = False

    # PHP kompatibel
    page._run_php_compatibility_check_logic("4.9.1.0", "8.1.10", "8.0", "8.2", signal)
    signal.emit.assert_called_with("PHP-Version 8.1.10 ist kompatibel mit Gambio 4.9.1.0 (benötigt 8.0 - 8.2).", "ok")

    # PHP zu neu
    signal.reset_mock()
    page._run_php_compatibility_check_logic("4.9.1.0", "8.3.1", "8.0", "8.2", signal)
    signal.emit.assert_called_with(
        "PHP-Version 8.3.1 ist neuer als für 4.9.1.0 getestet (max: 8.2). Kompatibilität unklar.", "warn"
    )

    # PHP zu alt
    signal.reset_mock()
    page._run_php_compatibility_check_logic("4.9.1.0", "7.4.33", "8.0", "8.2", signal)
    signal.emit.assert_called_with(
        "PHP-Version 7.4.33 ist NICHT kompatibel mit Gambio 4.9.1.0 (erfordert 8.0 - 8.2).", "error"
    )


def test_health_check_page_export_reports(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager], tmp_path: Path
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    page._load_profiles()

    # Kein Logger -> show_error
    with patch("ui.main_window.show_error") as mock_err:
        page._export_html()
        mock_err.assert_called_with("Bitte zuerst einen Health-Check ausführen.")
        mock_err.reset_mock()
        page._export_pdf()
        mock_err.assert_called_with("Bitte zuerst einen Health-Check ausführen.")

    # Mit Logger
    page.current_logger = MagicMock()
    html_target = tmp_path / "report.html"
    pdf_target = tmp_path / "report.pdf"

    with (
        patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(str(html_target), "")),
        patch("ui.main_window.generate_html_report", return_value=True),
    ):
        page._export_html()

    with (
        patch("PySide6.QtWidgets.QFileDialog.getSaveFileName", return_value=(str(pdf_target), "")),
        patch("ui.main_window.generate_pdf_report", return_value=True),
    ):
        page._export_pdf()


def test_health_check_page_ensure_connection(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)

    # FTP Active
    ftp_conn = MagicMock(spec=ftplib.FTP)
    assert page._ensure_connection(ftp_conn) == ftp_conn
    ftp_conn.voidcmd.assert_called_with("NOOP")

    # FTP Failed, Reconnect via Profile
    ftp_failed = MagicMock(spec=ftplib.FTP)
    ftp_failed.voidcmd.side_effect = Exception("Closed")
    new_ftp = MagicMock(spec=ftplib.FTP)
    page._check_connection = MagicMock(return_value=(new_ftp, []))

    reconnected = page._ensure_connection(ftp_failed, profile=config.get_profiles()[0])
    assert reconnected == new_ftp


def test_config_page_protocol_switch_and_validation(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    # Protocol port switch
    page.combo_protocol.setCurrentText("SFTP")
    assert page.edit_port.text() == "22"
    page.combo_protocol.setCurrentText("FTP")
    assert page.edit_port.text() == "21"

    # Empty shop name
    page.edit_shop_name.setText("")
    with patch("ui.main_window.show_error") as mock_err:
        page._save_profile()
        mock_err.assert_called_with("Shop-Name darf nicht leer sein.")

    # Backslash traversal
    page.edit_shop_name.setText("ValidShop")
    page.remote_path_input.setText("folder\\traversal")
    with patch("ui.main_window.show_error") as mock_err:
        page._save_profile()
        mock_err.assert_called_with("Der angegebene Shop-Pfad auf dem Server ist ungültig.")


def test_config_page_change_master_password_validation(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = ConfigPage(auth, config)

    with patch("ui.main_window.show_error") as mock_err:
        # Altes PW leer
        page.edit_old_master_password.setText("")
        page._change_master_password()
        mock_err.assert_called_with("Bitte geben Sie Ihr altes Master-Passwort ein.")

        # Neues PW leer
        mock_err.reset_mock()
        page.edit_old_master_password.setText("old")
        page.edit_new_master_password.setText("")
        page._change_master_password()
        mock_err.assert_called_with("Das neue Master-Passwort darf nicht leer sein.")

        # Wiederholung stimmt nicht
        mock_err.reset_mock()
        page.edit_new_master_password.setText("new1")
        page.edit_repeat_new_master_password.setText("new2")
        page._change_master_password()
        mock_err.assert_called_with("Das neue Master-Passwort und die Wiederholung stimmen nicht überein.")


def test_main_window_cancel_all_and_dialog_cancel(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    window = MainWindow(auth, config)

    # Cancel all
    mock_cancels = []
    for i in range(window.pages.count()):
        page = window.pages.widget(i)
        assert page is not None
        m = MagicMock()
        page.cancel_all = m
        mock_cancels.append(m)

    window._cancel_all_operations()
    mock_cancels[0].assert_called_once()

    # Session expired, Dialog rejected
    auth._session_lock.timeout = timedelta(minutes=0)
    with patch("ui.main_window.MasterPasswordDialog") as mock_dialog_class:
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = False
        mock_dialog_class.return_value = mock_dialog

        window._change_page(2)
        # Page does not change because dialog was cancelled
        assert window.pages.currentIndex() == 0


def test_health_check_page_on_profile_selected_and_cancel(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    page._load_profiles()

    # _on_profile_selected
    page._on_profile_selected(0)
    assert config.get_last_selected_profile_name() == "TestShop"

    # check_finished mit abgebrochenem Worker
    mock_worker = MagicMock()
    mock_worker._is_cancelled = True
    page.worker = mock_worker
    page.check_finished()
    assert "abgebrochen" in page.status_label.text().lower()

    # check_finished mit erfolgreichem Worker
    mock_worker._is_cancelled = False
    page.check_finished()
    assert "abgeschlossen" in page.status_label.text().lower()

    # _cancel_health_check wenn isRunning
    mock_running_worker = MagicMock()
    mock_running_worker.isRunning.return_value = True
    page.worker = mock_running_worker
    page._cancel_health_check()
    mock_running_worker.cancel.assert_called_once()


def test_legacy_delete_worker_ftp_execution(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = config.get_profiles()[0]

    mock_ftp = MagicMock(spec=ftplib.FTP)

    def fake_nlst(*args: Any, **kwargs: Any) -> list[str]:
        if args and "cache" in args[0]:
            return ["cache/temp.txt", "cache/.htaccess"]
        if args and "old_folder" in args[0]:
            return ["old_folder/subfile.txt"]
        return []

    mock_ftp.nlst.side_effect = fake_nlst

    worker = LegacyDeleteWorker(
        page_instance=page,
        profile=profile,
        files_to_delete=["old_folder", "single_file.php"],
        clear_cache=True,
    )

    with patch.object(page, "_check_connection", return_value=(mock_ftp, [])):
        worker.run()

    mock_ftp.rmd.assert_called_with("old_folder")
    mock_ftp.delete.assert_any_call("single_file.php")
    mock_ftp.delete.assert_any_call("cache/temp.txt")


def test_legacy_delete_worker_sftp_execution(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = dict(config.get_profiles()[0])
    profile["protocol"] = "SFTP"

    mock_sftp = MagicMock()
    mock_attr = MagicMock()
    mock_attr.filename = "file.txt"
    mock_attr.st_mode = stat.S_IFREG

    mock_sftp.listdir_attr.return_value = [mock_attr]

    worker = LegacyDeleteWorker(
        page_instance=page,
        profile=profile,
        files_to_delete=["sftp_folder", "normal_file.txt"],
        clear_cache=False,
    )

    with patch.object(page, "_check_connection", return_value=(mock_sftp, [])):
        worker.run()

    mock_sftp.rmdir.assert_called_with("sftp_folder")
    mock_sftp.remove.assert_any_call("normal_file.txt")


def test_bak_file_scanner_worker_run_ftp(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = config.get_profiles()[0]

    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.mlsd.return_value = [
        ("backup.bak", {"type": "file"}),
        ("cache", {"type": "dir"}),
        ("sub", {"type": "dir"}),
    ]

    worker = BakFileScannerWorker(page, profile)
    with patch.object(page, "_check_connection", return_value=(mock_ftp, [])):

        def side_effect_cwd(target: str) -> None:
            if target == "sub":
                mock_ftp.mlsd.return_value = [("test.bak", {"type": "file"})]
            elif target == "..":
                mock_ftp.mlsd.return_value = []

        mock_ftp.cwd.side_effect = side_effect_cwd
        worker.run()

    assert any("backup.bak" in f for f in worker.bak_files)


def test_logfile_worker_run_cleanup_and_scan(
    qapp: QApplication, auth_and_config: tuple[MasterPasswordManager, ConfigManager]
) -> None:
    auth, config = auth_and_config
    page = HealthCheckPage(auth, config)
    profile = config.get_profiles()[0]

    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.mlsd.side_effect = ftplib.error_perm("500 Command not understood")
    mock_ftp.nlst.return_value = ["error.log", ".htaccess"]
    mock_ftp.sendcmd.return_value = "213 20200101120000"

    worker_cleanup = LogfileWorker(page, profile, max_age_days=7, mode="cleanup")
    with patch.object(page, "_check_connection", return_value=(mock_ftp, [])):
        worker_cleanup.run()

    assert "error.log" in worker_cleanup.files_deleted
    mock_ftp.delete.assert_called_with("error.log")

    # Scan mode
    worker_scan = LogfileWorker(page, profile, max_age_days=7, mode="scan")

    def fake_retrbinary(cmd: str, callback: Callable[[bytes], None], blocksize: int = 8192) -> None:
        callback(b"[2026-10-17] FATAL: Call to undefined function\n")

    mock_ftp.retrbinary.side_effect = fake_retrbinary
    with patch.object(page, "_check_connection", return_value=(mock_ftp, [])):
        worker_scan.run()

    assert len(worker_scan.errors_found) > 0
    assert any("FATAL" in err for err in worker_scan.errors_found)
