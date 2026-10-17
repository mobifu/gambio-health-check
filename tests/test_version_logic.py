import pytest
import sys
import ftplib
import os
import json
import hashlib
from unittest.mock import MagicMock, ANY, patch, mock_open, call
from PySide6.QtWidgets import QApplication
from ui.main_window import HealthCheckPage


@pytest.fixture(scope="session")
def qapp():
    """Erstellt die notwendige QApplication Instanz für GUI-Tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture
def page(qapp):
    """Erstellt eine Instanz von HealthCheckPage für die Tests."""
    auth = MagicMock()
    config = MagicMock()
    test_page = HealthCheckPage(auth, config)
    test_page.status_label = MagicMock()
    test_page.spinner_bar = MagicMock()
    # Mock worker attribute to prevent AttributeError during tests
    test_page.worker = MagicMock()
    test_page.worker._is_cancelled = False
    return test_page


def test_parse_ver_tuple(page):
    assert page._parse_ver_tuple("4.9.2.1") == (4, 9, 2, 1)
    assert page._parse_ver_tuple("v2.10.0") == (2, 10, 0)
    assert page._parse_ver_tuple("8.1") == (8, 1)
    assert page._parse_ver_tuple("26.04.1-Gambio") == (26, 4, 1)
    assert page._parse_ver_tuple("Junk123Data") == (123,)
    assert page._parse_ver_tuple(None) == (0,)


def test_php_compatibility_matching(page):
    signal = MagicMock()

    # Fall 1: Exakter Match im mittleren Bereich
    page._run_php_compatibility_check_logic("4.9.1.0", "8.1.5", "7.4", "8.2", signal)
    # Suche nach Erfolgssignal
    success_calls = [call for call in signal.emit.call_args_list if "ist kompatibel" in call.args[0]]
    assert len(success_calls) > 0

    signal.emit.reset_mock()

    # Fall 2: Match im neuen Bereich (Service Pack 4.9.2.1)
    page._run_php_compatibility_check_logic("4.9.2.1", "8.3.0", "8.2", "8.4", signal)
    success_calls = [
        call for call in signal.emit.call_args_list if "8.3" in call.args[0] and "kompatibel" in call.args[0]
    ]
    assert len(success_calls) > 0


def test_php_compatibility_too_new(page):
    signal = MagicMock()

    # PHP 8.4 ist neuer als das max getestete 8.2
    page._run_php_compatibility_check_logic("4.9.5.0", "8.4.1", "8.1", "8.2", signal)
    warn_calls = [call for call in signal.emit.call_args_list if "neuer als" in call.args[0]]
    assert len(warn_calls) > 0


def test_php_compatibility_error(page):
    signal = MagicMock()

    # PHP 5.6 ist definitiv zu alt für Gambio 4.2 (welches 7.4 erwartet)
    page._run_php_compatibility_check_logic("4.2.0.0", "5.6.0", "7.4", "8.0", signal)
    error_calls = [call for call in signal.emit.call_args_list if "NICHT kompatibel" in call.args[0]]
    assert len(error_calls) > 0


def test_extract_version_number(page):
    """Testet die Extraktion von Versionsnummern aus Datenbank-Strings."""
    assert page._extract_version_number("mysqlnd 10.6.12-MariaDB") == "10.6.12"
    assert page._extract_version_number("8.0.32-0ubuntu0.22.04.2") == "8.0.32"
    assert page._extract_version_number("irgendwas 5.7.40") == "5.7.40"
    assert page._extract_version_number("keine zahl") is None


def test_check_gambio_structure(page):
    """Testet die Erkennung der Gambio-Ordnerstruktur."""
    signal = MagicMock()

    # Gültige Struktur
    files_ok = ["system", "GXEngine", "admin", "index.php"]
    assert page._check_gambio_structure(files_ok, signal) is True

    # Ungültige Struktur
    files_bad = ["wordpress", "wp-content", "index.php"]
    assert page._check_gambio_structure(files_bad, signal) is False


def test_check_update_php_compat(page):
    """Testet die PHP-Prüfung innerhalb der Update-Analyse."""
    config = MagicMock()
    config.has_section.return_value = True
    # Mockt config.get(section, option, fallback)
    config.get.side_effect = lambda s, o, fallback=None: {
        "php_version_min": "7.4",
        "php_version_max": "8.2",
    }.get(o, fallback)

    signal = MagicMock()

    # Fall: OK
    page._check_update_php_compat(config, "8.0.5", signal)
    assert any("ist im Bereich" in call.args[0] for call in signal.emit.call_args_list)

    # Fall: Zu neu (Warnung)
    signal.emit.reset_mock()
    page._check_update_php_compat(config, "8.3.0", signal)
    assert any("NEUER als getestet" in call.args[0] for call in signal.emit.call_args_list)


def test_check_update_shop_compat(page):
    """Testet, ob die Shop-Version für ein Update zulässig ist."""
    config = MagicMock()
    config.has_section.return_value = True
    config.get.side_effect = lambda s, o, fallback=None: {
        "shop_version_min": "4.8.0.0",
        "shop_version_max": "4.9.1.0",
    }.get(o, fallback)

    signal = MagicMock()

    # Shop ist im Bereich
    page._check_update_shop_compat(config, "4.9.0.0", "4.9.2.0", signal)
    assert any("ist kompatibel" in call.args[0] for call in signal.emit.call_args_list)

    # Shop ist bereits auf Zielversion
    signal.emit.reset_mock()
    page._check_update_shop_compat(config, "4.9.2.0", "4.9.2.0", signal)
    assert any("bereits vollständig installiert" in call.args[0] for call in signal.emit.call_args_list)


def test_evaluate_completeness(page):
    """Testet die abschließende Bewertung des Update-Status."""
    signal = MagicMock()

    # Alles perfekt
    page._evaluate_completeness("4.9.1.0", "4.9.1.0", True, True, signal)
    assert any(
        "vollständig installiert" in call.args[0] and call.args[1] == "ok" for call in signal.emit.call_args_list
    )

    # Dateien fehlen (Error)
    signal.emit.reset_mock()
    page._evaluate_completeness("4.9.1.0", "4.9.1.0", False, True, signal)
    assert any(
        "Dateien aus updated_files.txt fehlen" in call.args[0] and call.args[1] == "error"
        for call in signal.emit.call_args_list
    )

    # Update steht bereit (Warnung/Info)
    signal.emit.reset_mock()
    page._evaluate_completeness("4.8.0.0", "4.9.1.0", True, True, signal)
    assert any("steht bereit" in call.args[0] and call.args[1] == "warn" for call in signal.emit.call_args_list)


def test_check_integrity(page):
    """Testet die Prüfung auf kritische Dateien."""
    signal = MagicMock()

    # Fall: Alles okay
    files_ok = ["index.php", "robots.txt", "system", "GXEngine", "themes"]
    page._check_integrity(files_ok, signal)
    assert any("Basis-Integrität (Dateipräsenz): OK" in call.args[0] for call in signal.emit.call_args_list)

    # Fall: robots.txt fehlt (Warnung)
    signal.emit.reset_mock()
    files_missing_robots = ["index.php", "system", "GXEngine"]
    page._check_integrity(files_missing_robots, signal)
    assert any("robots.txt fehlt" in call.args[0] for call in signal.emit.call_args_list)

    # Fall: index.php fehlt (Error)
    signal.emit.reset_mock()
    files_no_index = ["system", "GXEngine"]
    page._check_integrity(files_no_index, signal)
    assert any("index.php fehlt" in call.args[0] for call in signal.emit.call_args_list)
    assert any("Basis-Integrität (Dateipräsenz): Fehler" in call.args[0] for call in signal.emit.call_args_list)


def test_load_update_ini_success(page):
    """Testet das erfolgreiche Laden und Parsen der configuration.ini."""
    conn = MagicMock(spec=ftplib.FTP)
    ini_content = b"[update_properties]\nversion=4.9.2.0\n[compatibility]\nphp_version_min=7.4"

    # Simuliere FTP-Download: Die callback-Funktion (r_io.write) wird mit den Daten aufgerufen
    def mock_retr(cmd, callback):
        callback(ini_content)
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr

    config = page._load_update_ini(conn, "gambio_updater/updates/v4.9.2.0")
    assert config is not None
    assert config.get("update_properties", "version") == "4.9.2.0"
    assert config.get("compatibility", "php_version_min") == "7.4"


def test_check_mysql_version_mariadb_handling(page):
    """Testet, dass MariaDB korrekt als Sonderfall behandelt wird."""
    signal = MagicMock()
    config = MagicMock()

    # MariaDB sollte den MySQL-Check überspringen und eine Warnung ausgeben
    page._check_mysql_version(config, "10.6.12", "MariaDB", signal)
    assert any(
        "MariaDB 10.6.12. MySQL-Kompatibilitätsprüfung übersprungen" in call.args[0]
        for call in signal.emit.call_args_list
    )


def test_check_write_permissions_fail(page):
    """Testet das Verhalten bei fehlenden Schreibrechten."""
    signal = MagicMock()
    conn = MagicMock(spec=ftplib.FTP)

    # Simuliere Fehler beim Upload (STOR)
    conn.storbinary.side_effect = ftplib.error_perm("550 Permission denied")

    page._check_write_permissions(conn, {}, signal)
    assert any("Eingeschränkte Schreibrechte" in call.args[0] for call in signal.emit.call_args_list)


def test_run_legacy_delete_analysis_logic(page):
    """
    Testet die komplexe Logik zur Identifizierung von Altlasten.
    Simuliert zwei Update-Pakete:
    v4.8.0.0 will 'old_file.php' und 'conflict.php' löschen.
    v4.9.0.0 führt 'conflict.php' wieder ein.
    """
    conn = MagicMock(spec=ftplib.FTP)
    # Simuliere Ordnerstruktur
    conn.nlst.side_effect = lambda p: (
        ["gambio_updater/updates/v4.8.0.0", "gambio_updater/updates/v4.9.0.0"] if p == "gambio_updater/updates" else []
    )

    def mock_retr(cmd, callback):
        if "v4.8.0.0/to_delete.php" in cmd:
            callback(b"<?php $files = ['old_file.php', 'conflict.php', 'ignored.php'];")
        elif "v4.9.0.0/updated_files.txt" in cmd:
            callback(b"conflict.php\nnew_logic.php")
        else:
            callback(b"")
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr

    # Simuliere, dass Dateien auf dem Server existieren
    # 'ignored.php' steht auf der Whitelist
    page.config_manager.get_excluded_files.return_value = "ignored.php"

    # Mock size: Nur old_file.php und conflict.php existieren
    # Muss ftplib.error_perm werfen (nicht generische Exception) damit Fallback greift
    def mock_size(p):
        if p in ["old_file.php", "conflict.php"]:
            return 100
        raise ftplib.error_perm("550 No such file")

    conn.size.side_effect = mock_size

    signal = MagicMock()
    legacy_files = page._run_legacy_delete_analysis_logic(conn, signal)

    # 1. old_file.php muss gefunden werden (sollte weg sein, ist noch da)
    assert "old_file.php" in legacy_files
    # 2. conflict.php darf NICHT gefunden werden (wurde in v4.9 wieder eingeführt)
    assert "conflict.php" not in legacy_files
    # 3. ignored.php darf NICHT gefunden werden (Whitelist)
    assert "ignored.php" not in legacy_files
    # 4. Die Version muss im Log-Text erscheinen (z.B. "v4.8.0.0")
    all_msgs = [call.args[0] for call in signal.emit.call_args_list]
    assert any("v4.8.0.0" in m and "old_file.php" in m for m in all_msgs), (
        f"Erwartete Version 'v4.8.0.0' und Pfad 'old_file.php' im Log. Gefunden: {all_msgs}"
    )


def test_run_legacy_delete_analysis_logic_folder(page):
    """
    Testet, dass auch Ordner (ohne Extension) im Altlasten-Check erkannt werden.
    Gambio-Update-Pakete können auch Ordnerpfade in to_delete.php enthalten.
    """
    conn = MagicMock(spec=ftplib.FTP)
    conn.nlst.side_effect = lambda p: (["gambio_updater/updates/v5.0.0.0"] if p == "gambio_updater/updates" else [])

    def mock_retr(cmd, callback):
        if "v5.0.0.0/to_delete.php" in cmd:
            # Enthält Ordner 'old_module' OHNE Extension
            callback(b"<?php $paths = ['old_module', 'legacy/cache', 'still_needed.php'];")
        else:
            callback(b"")
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr
    page.config_manager.get_excluded_files.return_value = ""

    # size() schlägt fehl → NLST-Fallback greift für Ordner
    def mock_size(p):
        raise ftplib.error_perm("550 No such file or directory")

    conn.size.side_effect = mock_size

    # NLST gibt für 'old_module' und 'legacy/cache' Einträge zurück (Ordner existiert)
    def mock_nlst(p):
        if p in ["old_module", "legacy/cache"]:
            return [p + "/some_file.php"]
        raise ftplib.error_perm("550 Not found")

    conn.nlst.side_effect = lambda p: (
        ["gambio_updater/updates/v5.0.0.0"] if p == "gambio_updater/updates" else mock_nlst(p)
    )

    signal = MagicMock()
    legacy_files = page._run_legacy_delete_analysis_logic(conn, signal)

    # Ordner 'old_module' und 'legacy/cache' müssen als Altlasten gefunden werden
    assert "old_module" in legacy_files
    assert "legacy/cache" in legacy_files
    # 'still_needed.php' hat size() Fehler und kein NLST-Ergebnis → soll NICHT als Altlast gelten
    assert "still_needed.php" not in legacy_files


def test_run_legacy_delete_analysis_file_exists_not_flagged(page):
    """
    Reproduziert den realen Gambio-Fall (v4.8.0.2):
    'GXModules/Gambio/Google/GA4' steht NUR in einem file_exists()-Aufruf
    als Bedingung, NICHT im $toDelete-Array → darf NICHT als Altlast gemeldet werden.
    Wildcard-Pfade wie 'GXModules/Gambio/GoogleAdWords/*' müssen als Verzeichnis geprüft werden.
    """
    conn = MagicMock(spec=ftplib.FTP)
    conn.nlst.side_effect = lambda p: (["gambio_updater/updates/v4.8.0.2"] if p == "gambio_updater/updates" else [])

    # Reales to_delete.php Format (vereinfacht)
    real_to_delete = b"""<?php
clearstatcache(true);
$toDelete = ['GXMainComponents/Shared/Precheck/Precheck.inc.php'];

// check if Google Services 3 exists
if ((file_exists(DIR_FS_CATALOG . 'GXModules/Gambio/Google/GA4')
     || file_exists(DIR_FS_CATALOG . 'GXModules/Gambio/Google/ECommerce'))
    && file_exists(DIR_FS_CATALOG . 'GXModules/Gambio/GoogleECommerce')) {
    $toDelete = array_merge($toDelete, [
        'GXModules/Gambio/Google/Admin/Classes/*',
        'GXModules/Gambio/GoogleAdWords/*',
        'GXModules/Gambio/GoogleECommerce/*',
    ]);
}
return $toDelete;
"""

    def mock_retr(cmd, callback):
        if "v4.8.0.2/to_delete.php" in cmd:
            callback(real_to_delete)
        else:
            callback(b"")
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr
    page.config_manager.get_excluded_files.return_value = ""

    # size() schlägt für Verzeichnisse fehl, gibt aber für .php-Dateien einen Wert zurück
    existing_files = {"GXMainComponents/Shared/Precheck/Precheck.inc.php"}

    def mock_size(p):
        if p in existing_files:
            return 512
        raise ftplib.error_perm("550")

    conn.size.side_effect = mock_size

    existing_dirs = {
        "GXModules/Gambio/Google/Admin/Classes",
        "GXModules/Gambio/GoogleAdWords",
        "GXModules/Gambio/GoogleECommerce",
        "GXMainComponents/Shared/Precheck",  # hat eine Extension im letzten Teil
    }

    def mock_nlst(p):
        if p in existing_dirs:
            return [p + "/file.php"]
        raise ftplib.error_perm("550 Not found")

    conn.nlst.side_effect = lambda p: (
        ["gambio_updater/updates/v4.8.0.2"] if p == "gambio_updater/updates" else mock_nlst(p)
    )

    signal = MagicMock()
    legacy_files = page._run_legacy_delete_analysis_logic(conn, signal)

    # 'GXModules/Gambio/Google/GA4' war NUR in file_exists() → darf NICHT als Altlast erscheinen!
    assert "GXModules/Gambio/Google/GA4" not in legacy_files
    assert "GXModules/Gambio/Google/ECommerce" not in legacy_files

    # Da Pfade mit '/*' nun direkt auf den übergeordneten Ordner gekürzt werden,
    # müssen diese Ordner selbst als Altlast gemeldet werden.
    assert "GXModules/Gambio/GoogleAdWords" in legacy_files
    assert "GXModules/Gambio/GoogleECommerce" in legacy_files
    assert "GXModules/Gambio/Google/Admin/Classes" in legacy_files

    # Datei mit Extension muss ebenfalls erkannt werden
    assert "GXMainComponents/Shared/Precheck/Precheck.inc.php" in legacy_files


def test_run_legacy_delete_analysis_filename_wildcard(page):
    """
    Testet, dass Wildcards im Dateinamen (z.B. 'security-update-*.php')
    korrekt aufgelöst werden und konkrete Dateinamen (z.B. 'security-update-2025-12-v1.0.0.php')
    in die Fundliste aufgenommen werden.
    """
    conn = MagicMock(spec=ftplib.FTP)
    conn.nlst.side_effect = lambda p: (
        ["gambio_updater/updates/v6.0.0.0"]
        if p == "gambio_updater/updates"
        # nlst('.') liefert die Liste der Dateien im Stammverzeichnis
        else [
            "index.php",
            "security-update-2025-12-v1.0.0.php",
            "security-update-old.php",
            "other.php",
        ]
    )

    def mock_retr(cmd, callback):
        if "v6.0.0.0/to_delete.php" in cmd:
            callback(b"<?php $files = ['security-update-*.php'];")
        else:
            callback(b"")
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr
    page.config_manager.get_excluded_files.return_value = ""

    signal = MagicMock()
    legacy_files = page._run_legacy_delete_analysis_logic(conn, signal)

    # Die konkreten passenden Dateien müssen als Altlasten gelistet werden
    assert "security-update-2025-12-v1.0.0.php" in legacy_files
    assert "security-update-old.php" in legacy_files
    # Andere Dateien dürfen nicht gemeldet werden
    assert "index.php" not in legacy_files
    assert "other.php" not in legacy_files


def test_check_connection_sftp(page, monkeypatch):
    """Testet die SFTP-Verbindungslogik via Paramiko."""
    import ui.main_window as mw

    if mw.paramiko is None:
        pytest.skip("Paramiko ist nicht installiert, überspringe SFTP-Test")

    # Mocks für die SSH- und SFTP-Objekte
    mock_ssh = MagicMock()
    mock_sftp = MagicMock()
    mock_ssh.open_sftp.return_value = mock_sftp
    mock_sftp.listdir.return_value = ["index.php", "system", "version.info"]

    # Patch den Konstruktor von paramiko.SSHClient
    monkeypatch.setattr(mw.paramiko, "SSHClient", lambda: mock_ssh)

    profile = {
        "protocol": "SFTP",
        "host": "sftp.example.com",
        "port": 22,
        "username": "tester",
        "password": "password123",
        "remote_path": "/var/www/shop",
    }

    signal = MagicMock()
    conn, files = page._check_connection(profile, signal)

    # Verifikation
    assert conn == mock_sftp
    assert "system" in files
    mock_ssh.connect.assert_called_with("sftp.example.com", 22, "tester", "password123", timeout=10)
    mock_sftp.chdir.assert_called_with("/var/www/shop")


def test_hash_engine_generate_hash_ftp(page):
    """Testet die Hash-Erzeugung für eine Datei via FTP."""
    from core.hash_engine import HashCheckEngine

    conn = MagicMock(spec=ftplib.FTP)
    file_content = b"<?php echo 'hello'; ?>"
    expected_hash = hashlib.sha256(file_content).hexdigest()

    def mock_retr(cmd, callback):
        callback(file_content)
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr

    engine = HashCheckEngine("TestShop", conn, logger=MagicMock())
    h, data = engine.generate_hash("index.php")

    assert h == expected_hash
    assert data == file_content
    conn.retrbinary.assert_called_with("RETR index.php", ANY)


def test_hash_engine_recursive_files_ftp(page):
    """
    Testet das rekursive Auflisten von Dateien via FTP.
    Prüft, ob Verzeichnisse korrekt von Dateien unterschieden werden.
    """
    from core.hash_engine import HashCheckEngine

    conn = MagicMock(spec=ftplib.FTP)

    # Mock-Struktur:
    # .
    # ├── index.php
    # ├── system/ (Verzeichnis)
    # │   └── config.php
    # └── images/ (Verzeichnis, soll übersprungen werden)

    current_dir = ["."]

    def mock_nlst(path=None):
        if current_dir[-1] == ".":
            return ["index.php", "system", "images"]
        if current_dir[-1] == "system":
            return ["config.php"]
        return []

    def mock_cwd(path):
        if path == "..":
            current_dir.pop()
        elif path in ["system", "images"]:
            current_dir.append(path)
        else:
            raise ftplib.error_perm("550 Not a directory")

    conn.nlst.side_effect = mock_nlst
    conn.cwd.side_effect = mock_cwd

    # Mock size für Dateien
    conn.size.side_effect = lambda p: 100 if p in ["index.php", "config.php"] else Exception("550")

    engine = HashCheckEngine("TestShop", conn)
    files = engine._get_remote_files_recursive(".")

    assert "index.php" in files
    assert "system/config.php" in files
    # 'images' ist in skip_dirs definiert
    assert not any("images" in f for f in files)


def test_hash_engine_baseline_generation(page, tmp_path):
    """Testet den kompletten Prozess der Baseline-Erstellung und JSON-Speicherung."""
    from core.hash_engine import HashCheckEngine

    # In ein temporäres Verzeichnis wechseln für die Datei-Operationen
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        conn = MagicMock(spec=ftplib.FTP)
        conn.nlst.return_value = ["index.php"]
        conn.cwd.side_effect = ftplib.error_perm()  # index.php ist kein Ordner

        content = b"content"
        conn.retrbinary.side_effect = lambda cmd, cb: cb(content)

        engine = HashCheckEngine("TestShop", conn, logger=MagicMock())
        engine.generate_baseline()

        assert os.path.exists(engine.baseline_path)
        with open(engine.baseline_path, "r") as f:
            data = json.load(f)
            assert "index.php" in data
            assert data["index.php"] == hashlib.sha256(content).hexdigest()
    finally:
        os.chdir(old_cwd)


def test_parse_ver_tuple_edge_cases(page):
    """Testet extreme und ungültige Versionszeichenfolgen."""
    # Völlig ungültige oder leere Eingaben
    assert page._parse_ver_tuple("") == (0,)
    assert page._parse_ver_tuple("   ") == (0,)
    assert page._parse_ver_tuple("beta-release") == (0,)

    # Sonderzeichen und komplexe Suffixe
    assert page._parse_ver_tuple("4.9.1.0-beta1") == (4, 9, 1, 0, 1)
    assert page._parse_ver_tuple("v1.0.0-rc3") == (1, 0, 0, 3)
    assert page._parse_ver_tuple("...1.2.3...") == (1, 2, 3)


def test_directory_traversal_prevention(page):
    """Verifiziert, dass Pfadmanipulationen mit Directory Traversal verhindert werden."""
    conn = MagicMock(spec=ftplib.FTP)

    # Wir erstellen eine Testinstanz der HashCheckEngine
    from core.hash_engine import HashCheckEngine

    engine = HashCheckEngine("TestShop", conn, logger=MagicMock())

    # Testen, ob relative Pfade, die nach oben zeigen, abgefangen oder nicht verarbeitet werden
    # generate_hash sollte bei solchen Pfaden None zurückgeben oder blockieren
    # Wenn wir einen manipulierten Pfad übergeben:
    traversal_path = "../../../etc/passwd"

    # generate_hash sollte hier sicherstellen, dass nicht außerhalb gearbeitet wird.
    # Da FTP relative Pfade auf dem Server nutzt, verhindern wir das Ausbrechen.
    h, data = engine.generate_hash(traversal_path)
    # Wenn die Engine das nicht explizit blockiert, stellen wir sicher, dass sie fehlschlägt oder abgewiesen wird
    # Falls das System unsicher ist, fangen wir das ab.
    assert h is None


def test_permission_denied_robustness(page):
    """Simuliert Berechtigungsfehler (Permission Denied) bei FTP-Zugriffen."""
    conn = MagicMock(spec=ftplib.FTP)
    conn.retrbinary.side_effect = ftplib.error_perm("550 Permission denied")

    from core.hash_engine import HashCheckEngine

    engine = HashCheckEngine("TestShop", conn, logger=MagicMock())

    # Darf nicht abstürzen, sondern muss None zurückgeben
    h, data = engine.generate_hash("secret.php")
    assert h is None
    assert data is None


def test_network_timeout_robustness(page):
    """Testet das Verhalten der Verbindungsprüfung bei Timeouts."""
    import socket

    profile = {
        "protocol": "FTP",
        "host": "ftp.example.com",
        "port": 21,
        "username": "tester",
        "password": "password123",
        "remote_path": "/var/www/shop",
    }

    # Simuliere socket timeout bei FTP connect
    signal = MagicMock()

    # Mock ftplib.FTP so dass ein Timeout geworfen wird
    with pytest.MonkeyPatch().context() as m:
        m.setattr(
            "ftplib.FTP",
            lambda *args, **kwargs: MagicMock(connect=MagicMock(side_effect=socket.timeout("Timeout!"))),
        )

        conn, files = page._check_connection(profile, signal)
        assert conn is None
        assert files == []
        assert any("Timeout" in call.args[0] or "Fehler" in call.args[0] for call in signal.emit.call_args_list)


def test_whitelist_wildcards_and_legacy_delete(page):
    """Testet den Whitelist-Schutz bei der Legacy-Bereinigung."""
    conn = MagicMock(spec=ftplib.FTP)
    conn.nlst.return_value = ["gambio_updater/updates/v4.8.0.0"]

    # Simuliere to_delete.php Datei
    def mock_retr(cmd, callback):
        callback(b"<?php $files = ['sensitive_user_addon.php', 'regular_old_file.php'];")
        return "226 Transfer complete"

    conn.retrbinary.side_effect = mock_retr

    # sensitive_user_addon.php ist ausgeschlossen
    page.config_manager.get_excluded_files.return_value = "sensitive_user_addon.php"

    conn.size.side_effect = (
        lambda p: 100 if p in ["sensitive_user_addon.php", "regular_old_file.php"] else Exception("550")
    )

    signal = MagicMock()
    legacy_files = page._run_legacy_delete_analysis_logic(conn, signal)

    assert "regular_old_file.php" in legacy_files
    assert "sensitive_user_addon.php" not in legacy_files


def test_hash_engine_excluded_files(page):
    """Testet, ob die HashCheckEngine die Liste der ausgeschlossenen Dateien berücksichtigt."""
    conn = MagicMock(spec=ftplib.FTP)

    # Mock den Worker, der eine Referenz auf die page und den config_manager hat
    mock_worker = MagicMock()
    mock_worker.page = page
    mock_worker._is_cancelled = False
    page.config_manager.get_excluded_files.return_value = "ignored_file.php, vendor/malware_false_positive.php"

    from core.hash_engine import HashCheckEngine

    engine = HashCheckEngine("TestShop", conn, worker=mock_worker)

    assert "ignored_file.php" in engine.excluded_list
    assert "vendor/malware_false_positive.php" in engine.excluded_list

    # Simuliere die Liste der Dateien auf dem Server
    current_files = [
        "index.php",
        "ignored_file.php",
        "vendor/malware_false_positive.php",
    ]

    # 1. Testen des Verhaltens in compare_with_baseline
    baseline = {
        "index.php": "somehash",
        "ignored_file.php": "somehash2",
        "vendor/malware_false_positive.php": "somehash3",
    }

    # Mock _get_remote_files_recursive und generate_hash
    engine._get_remote_files_recursive = MagicMock(return_value=current_files)
    engine.generate_hash = MagicMock(return_value=("differenthash", b"eval(base64_decode('somepayload'))"))
    engine._check_malware_indicators = MagicMock()
    engine._log = MagicMock()

    with patch("builtins.open", mock_open(read_data="{}")):
        engine.baseline_path = "dummy_baseline.json"
        with patch("os.path.exists", return_value=True):
            with patch("json.load", return_value=baseline):
                engine.compare_with_baseline()

                # Check that index.php was processed (it was different hash, so _check_malware_indicators and _log warnings are triggered)
                engine.generate_hash.assert_any_call("index.php")

                # Check that ignored files were NOT hashed/processed
                for ignored in [
                    "ignored_file.php",
                    "vendor/malware_false_positive.php",
                ]:
                    # generate_hash should not be called on ignored files
                    assert call(ignored) not in engine.generate_hash.call_args_list


@patch("ui.main_window.requests.get")
@patch("time.sleep", return_value=None)  # Speed up tests
def test_php_version_upload_retry_success(mock_sleep, mock_get, page):
    """Testet, ob der Upload nach einem Fehlschlag wiederholt wird und gelingt."""
    conn = MagicMock(spec=ftplib.FTP)
    profile = {"shop_url": "https://test.local"}
    signal = MagicMock()

    # Simulate first conn.size failing (or returning 0), then succeeding
    conn.size.side_effect = [0, 2500]

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"php": "8.1.0"}
    mock_get.return_value = mock_response

    res = page._check_php_version_via_ftp_http(conn, profile, signal)

    # Should have called storbinary twice
    assert conn.storbinary.call_count == 2
    assert res == {"php": "8.1"}

    # Check delete was called
    conn.delete.assert_called_once()


@patch("ui.main_window.requests.get")
@patch("time.sleep", return_value=None)
def test_php_version_upload_failure(mock_sleep, mock_get, page):
    """Testet das Verhalten, wenn der Upload endgültig fehlschlägt."""
    conn = MagicMock(spec=ftplib.FTP)
    profile = {"shop_url": "https://test.local"}
    signal = MagicMock()

    # Simulate size always 0
    conn.size.return_value = 0

    res = page._check_php_version_via_ftp_http(conn, profile, signal)

    # Should have called storbinary three times
    assert conn.storbinary.call_count == 3
    assert res is None  # Fails early

    # Check delete was called in finally
    conn.delete.assert_called_once()
    assert mock_get.call_count == 0


@patch("ui.main_window.requests.get")
@patch("time.sleep", return_value=None)
def test_php_version_http_retry(mock_sleep, mock_get, page):
    """Testet die Retry-Logik für den HTTP-Aufruf."""
    conn = MagicMock(spec=ftplib.FTP)
    profile = {"shop_url": "https://test.local"}
    signal = MagicMock()

    conn.size.return_value = 2500  # Upload always succeeds

    # Simulate HTTP failing twice, then succeeding
    mock_response_fail = MagicMock()
    mock_response_fail.status_code = 500

    mock_response_success = MagicMock()
    mock_response_success.status_code = 200
    mock_response_success.json.return_value = {"php": "8.2.0"}

    mock_get.side_effect = [
        mock_response_fail,
        mock_response_fail,
        mock_response_success,
    ]

    res = page._check_php_version_via_ftp_http(conn, profile, signal)

    assert mock_get.call_count == 3
    assert res == {"php": "8.2"}
    conn.delete.assert_called_once()


@patch("ui.main_window.requests.get")
@patch("time.sleep", return_value=None)
def test_php_version_delete_error_handling(mock_sleep, mock_get, page):
    """Testet, dass das Fehlschlagen des Löschens nicht abstürzt und 550 Fehler ignoriert werden."""
    conn = MagicMock(spec=ftplib.FTP)
    profile = {"shop_url": "https://test.local"}
    signal = MagicMock()

    conn.size.return_value = 2500
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"php": "8.0"}
    mock_get.return_value = mock_response

    # Simulate 550 error during delete
    conn.delete.side_effect = ftplib.error_perm("550 No such file or directory")

    res = page._check_php_version_via_ftp_http(conn, profile, signal)

    assert res == {"php": "8.0"}
    conn.delete.assert_called_once()
    # Warn should NOT have been called with the 550 error
    for call_obj in signal.emit.call_args_list:
        assert "550 No such file or directory" not in call_obj.args[0]


def test_legacy_delete_worker_recursive_ftp(page):
    """Testet, dass der LegacyDeleteWorker Ordner und Dateien rekursiv via FTP löschen kann."""
    from ui.main_window import LegacyDeleteWorker

    conn = MagicMock(spec=ftplib.FTP)
    page._check_connection = MagicMock(return_value=(conn, []))

    # Wir simulieren ein Verzeichnis 'old_folder' und eine Datei 'old_file.php'
    files_to_delete = ["old_folder", "old_file.php"]

    # Simuliere Inhalt des Ordners 'old_folder'
    # nlst('old_folder') liefert eine Datei 'old_folder/sub.php' und ein Unterverzeichnis 'old_folder/sub_dir'
    # nlst('old_folder/sub_dir') liefert 'old_folder/sub_dir/inner.php'
    def mock_nlst(p):
        if p == "old_folder":
            return ["sub.php", "sub_dir"]
        elif p == "old_folder/sub_dir":
            return ["inner.php"]
        return []

    conn.nlst.side_effect = mock_nlst

    # Simuliere, dass delete() bei Ordnern fehlschlägt
    def mock_delete(p):
        if p in ["old_folder", "old_folder/sub_dir"]:
            raise ftplib.error_perm("550 Is a directory")
        return "250 Deleted"

    conn.delete.side_effect = mock_delete

    worker = LegacyDeleteWorker(page, {"protocol": "FTP"}, files_to_delete)

    # Run synchronously
    worker.run()

    # delete() muss für alle Dateien aufgerufen worden sein
    conn.delete.assert_any_call("old_file.php")
    conn.delete.assert_any_call("old_folder/sub.php")
    conn.delete.assert_any_call("old_folder/sub_dir/inner.php")

    # rmd() muss für die leeren Ordner aufgerufen worden sein
    conn.rmd.assert_any_call("old_folder/sub_dir")
    conn.rmd.assert_any_call("old_folder")


def test_legacy_delete_worker_recursive_sftp(page):
    """Testet, dass der LegacyDeleteWorker Ordner und Dateien rekursiv via SFTP löschen kann."""
    from ui.main_window import LegacyDeleteWorker
    import stat

    # Mock paramiko SFTP connection
    conn = MagicMock()
    page._check_connection = MagicMock(return_value=(conn, []))

    files_to_delete = ["old_folder", "old_file.php"]

    # Simuliere Dateitypen
    # old_folder/entry1 (Ordner), old_folder/entry2 (Datei)
    entry1 = MagicMock()
    entry1.filename = "entry1"
    entry1.st_mode = stat.S_IFDIR

    entry2 = MagicMock()
    entry2.filename = "entry2"
    entry2.st_mode = stat.S_IFREG

    def mock_listdir_attr(p):
        if p == "old_folder":
            return [entry1, entry2]
        return []

    conn.listdir_attr.side_effect = mock_listdir_attr

    worker = LegacyDeleteWorker(page, {"protocol": "SFTP"}, files_to_delete)
    worker.run()

    # Dateien müssen gelöscht werden
    conn.remove.assert_any_call("old_file.php")
    conn.remove.assert_any_call("old_folder/entry2")

    # Ordner und Unterordner müssen gelöscht werden
    conn.rmdir.assert_any_call("old_folder/entry1")
    conn.rmdir.assert_any_call("old_folder")


def test_legacy_delete_worker_clear_cache_ftp(page):
    """Testet die automatische Cache-Löschung via FTP (nur Dateien, Ordner verschont, Ausnahmen geschützt)."""
    from ui.main_window import LegacyDeleteWorker

    conn = MagicMock(spec=ftplib.FTP)
    page._check_connection = MagicMock(return_value=(conn, []))

    files_to_delete = ["some_old_file.php"]

    # nlst("cache") liefert Cache-Dateien, Unterordner und geschützte Systemdateien
    def mock_nlst(p):
        if p == "cache":
            return [
                "temp_cache_1.php",
                "temp_cache_2.json",
                ".htaccess",
                "index.html",
                "index.php",
                "persistent_sub_folder",
            ]
        return []

    conn.nlst.side_effect = mock_nlst

    # Simuliere, dass das Löschen von Ordnern mit ftplib.error_perm fehlschlägt
    def mock_delete(p):
        if p == "cache/persistent_sub_folder":
            raise ftplib.error_perm("550 Is a directory")
        return "250 Deleted"

    conn.delete.side_effect = mock_delete

    worker = LegacyDeleteWorker(page, {"protocol": "FTP"}, files_to_delete, clear_cache=True)
    worker.run()

    # Altlast-Datei muss gelöscht worden sein
    conn.delete.assert_any_call("some_old_file.php")

    # Temporäre Cache-Dateien müssen gelöscht worden sein
    conn.delete.assert_any_call("cache/temp_cache_1.php")
    conn.delete.assert_any_call("cache/temp_cache_2.json")

    # Geschützte Systemdateien dürfen NICHT gelöscht worden sein
    for protected in [".htaccess", "index.html", "index.php"]:
        assert call(f"cache/{protected}") not in conn.delete.call_args_list


def test_legacy_delete_worker_clear_cache_sftp(page):
    """Testet die automatische Cache-Löschung via SFTP (nur Dateien, Ordner verschont, Ausnahmen geschützt)."""
    from ui.main_window import LegacyDeleteWorker
    import stat

    conn = MagicMock()
    page._check_connection = MagicMock(return_value=(conn, []))

    files_to_delete = ["some_old_file.php"]

    # Simuliere die Cache-Einträge
    # 1. Normale Cache-Dateien
    e1 = MagicMock()
    e1.filename = "temp_cache_1.php"
    e1.st_mode = stat.S_IFREG

    # 2. Unterordner (darf nicht gelöscht werden)
    e2 = MagicMock()
    e2.filename = "sub_folder"
    e2.st_mode = stat.S_IFDIR

    # 3. Geschützte Datei
    e3 = MagicMock()
    e3.filename = ".htaccess"
    e3.st_mode = stat.S_IFREG

    def mock_listdir_attr(p):
        if p == "cache":
            return [e1, e2, e3]
        return []

    conn.listdir_attr.side_effect = mock_listdir_attr

    worker = LegacyDeleteWorker(page, {"protocol": "SFTP"}, files_to_delete, clear_cache=True)
    worker.run()

    # Altlast-Datei gelöscht
    conn.remove.assert_any_call("some_old_file.php")

    # Cache-Datei gelöscht
    conn.remove.assert_any_call("cache/temp_cache_1.php")

    # Unterordner verschont (kein remove/rmdir für sub_folder)
    assert call("cache/sub_folder") not in conn.remove.call_args_list
    assert call("cache/sub_folder") not in conn.rmdir.call_args_list

    # Geschützte Systemdatei verschont
    assert call("cache/.htaccess") not in conn.remove.call_args_list


def test_analyze_delete_history_sftp_attributes():
    """Testet, dass SFTPAttributes nur '.filename' und kein '.name' besitzt."""
    import stat
    from unittest.mock import Mock

    # Paramiko SFTPAttributes besitzt 'filename', aber kein 'name'
    attr = Mock(spec=["filename", "st_mode"])
    attr.filename = "v4.0.0.0"
    attr.st_mode = stat.S_IFDIR

    conn = Mock()
    conn.listdir_attr.return_value = [attr]

    # Prüfung, dass f.filename korrekt ausgelesen wird
    folders = [f.filename for f in conn.listdir_attr("gambio_updater/updates") if stat.S_ISDIR(f.st_mode)]
    assert folders == ["v4.0.0.0"]

    # Sicherstellen, dass kein Zugriff auf das nicht existierende Attribut 'name' erfolgt
    try:
        _ = attr.name
        assert False, "Attribut 'name' sollte auf SFTPAttributes nicht existieren"
    except AttributeError:
        pass
