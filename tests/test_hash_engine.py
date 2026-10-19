"""
Unit-Tests für core.hash_engine (HashCheckEngine).
"""

import ftplib
import hashlib
import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from core.hash_engine import HashCheckEngine


@pytest.fixture
def temp_profiles_dir(tmp_path, monkeypatch):
    """Biegt das Arbeitsverzeichnis oder profiles-Verzeichnis für Tests um."""
    monkeypatch.chdir(tmp_path)
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    return profiles_dir


def test_init_path_security(temp_profiles_dir):
    """Testet die Absicherung des Hash-Verzeichnisses gegen Path Traversal."""
    mock_conn = MagicMock()

    # Normales Profil
    engine1 = HashCheckEngine(profile_name="MeinShop_01", conn=mock_conn)
    expected_path = (temp_profiles_dir / "MeinShop_01" / "hashes").resolve()
    assert Path(engine1.hash_dir).resolve() == expected_path
    assert expected_path.exists()

    # Ungültige Zeichen und Traversal
    engine2 = HashCheckEngine(profile_name="../../etc/evil:shop", conn=mock_conn)
    assert Path(engine2.hash_dir).resolve().is_relative_to(temp_profiles_dir.resolve())

    # Leerer Name
    engine3 = HashCheckEngine(profile_name="   ", conn=mock_conn)
    assert Path(engine3.hash_dir).resolve() == (temp_profiles_dir / "default" / "hashes").resolve()


def test_init_with_worker_excluded_files(temp_profiles_dir):
    """Testet das Laden der Ausschlussliste aus dem Config-Manager des Workers."""
    mock_conn = MagicMock()
    mock_worker = MagicMock()
    mock_worker.page.config_manager.get_excluded_files.return_value = "config.php, custom/*.log, "

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, worker=mock_worker)
    assert engine.excluded_list == ["config.php", "custom/*.log"]


def test_generate_hash_path_traversal_blocking(temp_profiles_dir):
    """Testet die Blockierung gefährlicher Pfade in generate_hash."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal)

    # Path traversal mit ..
    h, data = engine.generate_hash("../secret.txt")
    assert h is None
    assert data is None

    # Absoluter Pfad
    h, data = engine.generate_hash("/etc/passwd")
    assert h is None
    assert data is None

    # Windows Drive-Pfad
    h, data = engine.generate_hash("C:/Windows/win.ini")
    assert h is None
    assert data is None


def test_generate_hash_ftp_success(temp_profiles_dir):
    """Testet erfolgreichen Download und Hash-Berechnung via FTP."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    test_content = b"<?php echo 'Hello World'; ?>"
    expected_hash = hashlib.sha256(test_content).hexdigest()

    def fake_retrbinary(cmd, callback):
        callback(test_content)

    mock_ftp.retrbinary.side_effect = fake_retrbinary

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_ftp)
    h, data = engine.generate_hash("includes/header.php")

    assert h == expected_hash
    assert data == test_content
    mock_ftp.voidcmd.assert_called_with("TYPE I")
    mock_ftp.retrbinary.assert_called_once_with("RETR includes/header.php", mock_ftp.retrbinary.call_args[0][1])


def test_generate_hash_ftp_fallback(temp_profiles_dir):
    """Testet den Navigations-Fallback bei FTP-Downloads."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    test_content = b"<?php echo 'Fallback'; ?>"
    expected_hash = hashlib.sha256(test_content).hexdigest()

    # Versuch 1 schlägt fehl, Versuch 2 (im cwd) gelingt
    call_count = 0

    def fake_retrbinary(cmd, callback):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ftplib.error_perm("550 File not found in direct path")
        callback(test_content)

    mock_ftp.retrbinary.side_effect = fake_retrbinary
    mock_ftp.pwd.return_value = "/var/www"

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_ftp)
    h, data = engine.generate_hash("admin/includes/config.php")

    assert h == expected_hash
    assert data == test_content
    mock_ftp.cwd.assert_any_call("admin")
    mock_ftp.cwd.assert_any_call("includes")


def test_generate_hash_sftp(temp_profiles_dir):
    """Testet Download und Hashing über SFTP."""
    mock_sftp = MagicMock()
    test_content = b"SFTP Test Content"
    expected_hash = hashlib.sha256(test_content).hexdigest()

    # Fall 1: Verzeichnis
    mock_stat_dir = MagicMock()
    mock_stat_dir.st_mode = stat.S_IFDIR
    mock_sftp.stat.return_value = mock_stat_dir

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_sftp)
    h, data = engine.generate_hash("some_folder")
    assert h is None
    assert data is None

    # Fall 2: Normale Datei
    mock_stat_file = MagicMock()
    mock_stat_file.st_mode = stat.S_IFREG
    mock_sftp.stat.return_value = mock_stat_file

    mock_file_handle = MagicMock()
    mock_file_handle.read.return_value = test_content
    mock_sftp.open.return_value.__enter__.return_value = mock_file_handle

    h, data = engine.generate_hash("some_file.php")
    assert h == expected_hash
    assert data == test_content


def test_check_malware_indicators(temp_profiles_dir):
    """Testet die Erkennung von verdächtigen Malware-Mustern."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal)

    # Harmloser Code
    engine._check_malware_indicators(b"<?php echo 'Clean file'; ?>", "clean.php")
    mock_signal.emit.assert_not_called()

    # Verdächtige PHP-Funktionen
    engine._check_malware_indicators(b"<?php eval(base64_decode($_POST['cmd'])); ?>", "eval.php")
    mock_signal.emit.assert_called()
    msg, status = mock_signal.emit.call_args[0]
    assert status == "error"
    assert "eval" in msg and "base64_decode" in msg

    # Langer Base64-String
    long_b64 = b"a" * 130
    mock_signal.reset_mock()
    engine._check_malware_indicators(b"<?php $data = '" + long_b64 + b"'; ?>", "b64.php")
    mock_signal.emit.assert_called()
    assert "Langer Base64-Payload" in mock_signal.emit.call_args[0][0]


def test_get_remote_files_ftp_mlsd(temp_profiles_dir):
    """Testet die Dateierkennung über MLSD inkl. Filterung von Medien und Skip-Verzeichnissen."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.pwd.return_value = "/"

    # Simulation von MLSD
    def fake_mlsd():
        return [
            ("index.php", {"type": "file"}),
            ("banner.jpg", {"type": "file"}),  # Mediendatei -> ignorieren
            ("cache", {"type": "dir"}),  # Skip-Dir -> ignorieren
            ("admin", {"type": "dir"}),
        ]

    mock_ftp.mlsd.return_value = fake_mlsd()

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_ftp)

    # Wenn cwd in admin geht, geben wir in admin leeres mlsd zurück
    def fake_cwd(path):
        if path == "admin":
            mock_ftp.mlsd.return_value = [("start.php", {"type": "file"})]
        elif path == "..":
            mock_ftp.mlsd.return_value = []

    mock_ftp.cwd.side_effect = fake_cwd

    files = engine._get_remote_files_recursive(".")
    assert "index.php" in files
    assert "admin/start.php" in files
    assert not any("banner.jpg" in f for f in files)
    assert not any("cache" in f for f in files)


def test_get_remote_files_ftp_list_fallback(temp_profiles_dir):
    """Testet den Fallback auf LIST, wenn MLSD fehlschlägt."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.pwd.return_value = "/"
    mock_ftp.mlsd.side_effect = Exception("MLSD not supported")

    def fake_retrlines(cmd, callback):
        callback("drwxr-xr-x 2 root root 4096 Oct 17 12:00 cache")
        callback("-rw-r--r-- 1 root root  220 Oct 17 12:00 index.php")
        callback("-rw-r--r-- 1 root root  220 Oct 17 12:00 logo.png")

    mock_ftp.retrlines.side_effect = fake_retrlines

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_ftp)
    files = engine._get_remote_files_recursive(".")

    assert "index.php" in files
    assert not any("logo.png" in f for f in files)
    assert not any("cache" in f for f in files)


def test_get_remote_files_sftp(temp_profiles_dir):
    """Testet rekursives Auflisten über SFTP."""
    mock_sftp = MagicMock()

    entry_file = MagicMock()
    entry_file.filename = "script.php"
    entry_file.st_mode = stat.S_IFREG

    entry_media = MagicMock()
    entry_media.filename = "image.png"
    entry_media.st_mode = stat.S_IFREG

    entry_dir = MagicMock()
    entry_dir.filename = "logs"  # Skip dir
    entry_dir.st_mode = stat.S_IFDIR

    mock_sftp.listdir_attr.return_value = [entry_file, entry_media, entry_dir]

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_sftp)
    files = engine._get_remote_files_recursive(".")

    assert "script.php" in files
    assert len(files) == 1


def test_generate_baseline(temp_profiles_dir):
    """Testet die Erstellung einer baseline.json."""
    mock_conn = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn)

    with (
        patch.object(engine, "_get_remote_files_recursive", return_value=["index.php", "login.php"]),
        patch.object(
            engine,
            "generate_hash",
            side_effect=[("hash_index", b""), ("hash_login", b"")],
        ),
    ):
        engine.generate_baseline()

    assert Path(engine.baseline_path).exists()
    with open(engine.baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data == {"index.php": "hash_index", "login.php": "hash_login"}


def test_generate_baseline_empty_warning(temp_profiles_dir):
    """Testet die Warnung bei leerer Dateiliste."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal)

    with patch.object(engine, "_get_remote_files_recursive", return_value=[]):
        engine.generate_baseline()

    mock_signal.emit.assert_any_call(
        "Keine Dateien zum Hashen gefunden. Bitte prüfen Sie den Shop-Pfad und die Berechtigungen.",
        "warn",
    )


def test_compare_with_baseline(temp_profiles_dir):
    """Testet den Abgleich gegen eine vorhandene Baseline."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal)

    # 1. Baseline existiert nicht
    engine.compare_with_baseline()
    mock_signal.emit.assert_called_with("Keine Baseline vorhanden. Bitte zuerst erzeugen.", "warn")

    # 2. Baseline erstellen: index.php und deleted.php
    baseline_data = {
        "index.php": "original_hash_1234567890",
        "deleted.php": "del_hash_1234567890",
    }
    with open(engine.baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f)

    # Aktueller Server: index.php (modifiziert), new.php (neu), deleted.php fehlt
    current_files = ["index.php", "new.php"]
    hash_map = {
        "index.php": ("modified_hash_1234567890", b"<?php echo 'mod'; ?>"),
        "new.php": ("new_hash_1234567890", b"<?php eval('bad'); ?>"),
    }

    mock_signal.reset_mock()
    with patch.object(engine, "_get_remote_files_recursive", return_value=current_files):
        with patch.object(engine, "generate_hash", side_effect=lambda p: hash_map.get(p, (None, None))):
            engine.compare_with_baseline()

    emitted_msgs = [call_args[0][0] for call_args in mock_signal.emit.call_args_list]

    # Modifizierte Datei erkannt
    assert any("Datei verändert: index.php" in m for m in emitted_msgs)
    # Neue/Unbekannte Datei erkannt
    assert any("Unbekannte Datei gefunden: new.php" in m for m in emitted_msgs)
    # Fehlende Datei erkannt
    assert any("Datei fehlt: deleted.php" in m for m in emitted_msgs)
    # Malware in neuer Datei erkannt
    assert any("Verdächtiger Code in new.php" in m for m in emitted_msgs)


def test_update_hashes_lifecycle(temp_profiles_dir):
    """Testet Erstellung und Prüfung von Update-Hashes."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal)

    # 1. Generate update hashes
    file_list = ["update_core.php", "lib.php"]
    with patch.object(
        engine,
        "generate_hash",
        side_effect=[("hash1", b""), ("hash2", b"")],
    ):
        engine.generate_update_hashes("v2.0", file_list)

    update_file = Path(engine.hash_dir) / "update_v2.0.json"
    assert update_file.exists()

    # 2. Compare update hashes: update_core.php modifiziert, lib.php fehlt
    with patch.object(
        engine,
        "generate_hash",
        side_effect=[("hash_changed", b""), (None, None)],
    ):
        engine.compare_with_update_hashes("v2.0")

    emitted_msgs = [call_args[0][0] for call_args in mock_signal.emit.call_args_list]
    assert any("Update-Datei wurde nachträglich verändert: update_core.php" in m for m in emitted_msgs)
    assert any("Update-Datei fehlt: lib.php" in m for m in emitted_msgs)


def test_cancellation_handling(temp_profiles_dir):
    """Testet das Verhalten bei Abbruch (worker._is_cancelled = True)."""
    mock_conn = MagicMock()
    mock_worker = MagicMock()
    mock_worker._is_cancelled = True

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, worker=mock_worker)

    # In generate_baseline
    with patch.object(engine, "_get_remote_files_recursive", return_value=["file1.php", "file2.php"]):
        with patch.object(engine, "generate_hash") as mock_gen_hash:
            engine.generate_baseline()
            mock_gen_hash.assert_not_called()

    # In compare_with_baseline
    with open(engine.baseline_path, "w", encoding="utf-8") as f:
        json.dump({"file1.php": "h1"}, f)

    with patch.object(engine, "_get_remote_files_recursive", return_value=["file1.php"]):
        with patch.object(engine, "generate_hash") as mock_gen_hash:
            engine.compare_with_baseline()
            mock_gen_hash.assert_not_called()


def test_get_remote_files_ftp_nlst_fallback(temp_profiles_dir):
    """Testet den nlst-Fallback, wenn retrlines LIST leer bleibt."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.pwd.return_value = "/"
    mock_ftp.mlsd.side_effect = Exception("MLSD unavailable")
    # retrlines tut nichts -> lines bleibt leer
    mock_ftp.retrlines.side_effect = lambda cmd, cb: None
    mock_ftp.nlst.return_value = ["index.php", "image.gif", "cache", "subfolder"]

    # Für subfolder schlägt cwd fehl, also wird es als Datei behandelt oder bei cwd-Erfolg als Dir
    def fake_cwd(path):
        if path == "subfolder":
            # cwd klappt, in subfolder nlst liefert sub.php
            mock_ftp.nlst.return_value = ["sub.php"]
        elif path == "..":
            mock_ftp.nlst.return_value = []

    mock_ftp.cwd.side_effect = fake_cwd

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_ftp)
    files = engine._get_remote_files_recursive(".")

    assert "index.php" in files
    assert not any("image.gif" in f for f in files)
    assert not any(f == "cache" for f in files)


def test_compare_with_baseline_invalid_json(temp_profiles_dir):
    """Testet den Fehlerfall bei beschädigter baseline.json."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal)

    with open(engine.baseline_path, "w", encoding="utf-8") as f:
        f.write("{invalid json")

    engine.compare_with_baseline()
    mock_signal.emit.assert_called()
    msg, status = mock_signal.emit.call_args[0]
    assert status == "error"
    assert "Fehler beim Laden der Baseline" in msg


def test_compare_with_baseline_exclusions(temp_profiles_dir):
    """Testet, dass ausgeschlossene Dateien beim Baseline-Vergleich ignoriert werden."""
    mock_conn = MagicMock()
    mock_signal = MagicMock()
    mock_worker = MagicMock()
    mock_worker.page.config_manager.get_excluded_files.return_value = "ignored.php"

    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, signal=mock_signal, worker=mock_worker)

    baseline_data = {"ignored.php": "h1", "valid.php": "h2"}
    with open(engine.baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f)

    current_files = ["ignored.php", "valid.php"]
    with patch.object(engine, "_get_remote_files_recursive", return_value=current_files):
        with patch.object(engine, "generate_hash", return_value=("h2", b"")):
            engine.compare_with_baseline()

    emitted_msgs = [call_args[0][0] for call_args in mock_signal.emit.call_args_list]
    assert not any("ignored.php" in m for m in emitted_msgs)


def test_compare_with_update_hashes_missing_file_or_invalid_json(temp_profiles_dir):
    """Testet compare_with_update_hashes bei fehlender oder ungültiger Datei."""
    mock_conn = MagicMock()
    mock_logger = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, logger=mock_logger)

    # Nicht existierende Datei
    engine.compare_with_update_hashes("v9.9.9")
    mock_logger.error.assert_not_called()

    # Ungültiges JSON
    update_file = Path(engine.hash_dir) / "update_v9.9.9.json"
    with open(update_file, "w", encoding="utf-8") as f:
        f.write("corrupted json")

    engine.compare_with_update_hashes("v9.9.9")
    mock_logger.error.assert_called()
    assert "Fehler beim Laden der Update-Hashes" in mock_logger.error.call_args[0][0]


def test_file_write_io_errors(temp_profiles_dir):
    """Testet Fehlerbehandlung beim Schreiben von Dateien (Baseline / Update-Hashes)."""
    mock_conn = MagicMock()
    mock_logger = MagicMock()
    engine = HashCheckEngine(profile_name="TestShop", conn=mock_conn, logger=mock_logger)

    with patch("builtins.open", side_effect=OSError("Disk full")):
        with patch.object(engine, "_get_remote_files_recursive", return_value=["test.php"]):
            with patch.object(engine, "generate_hash", return_value=("h", b"")):
                engine.generate_baseline()
        mock_logger.error.assert_called()
        assert "Fehler beim Speichern der Baseline" in mock_logger.error.call_args[0][0]

        mock_logger.reset_mock()
        engine.generate_update_hashes("v1.0", ["test.php"])
        mock_logger.error.assert_called()
        assert "Fehler beim Speichern der Update-Hashes" in mock_logger.error.call_args[0][0]
