"""
Unit-Tests für ui/backup_manager.py und ui/backup_actions.py.
"""

from pathlib import Path
from unittest.mock import MagicMock
import zipfile
import pytest

from ui.backup_actions import BackupActions
from ui.backup_manager import BackupManager


def test_backup_manager_init(tmp_path: Path):
    bm = BackupManager(str(tmp_path / "custom_backups"))
    assert bm.base_dir.exists()
    assert bm.base_dir == (tmp_path / "custom_backups").resolve()


def test_backup_manager_create_and_list(tmp_path: Path):
    bm = BackupManager(str(tmp_path / "backups"))

    # Erstelle Testdateien
    src_dir = tmp_path / "source"
    src_dir.mkdir()
    f1 = src_dir / "test1.txt"
    f1.write_text("Inhalt 1", encoding="utf-8")
    f2 = src_dir / "test2.txt"
    f2.write_text("Inhalt 2", encoding="utf-8")

    archive = bm.create_archive([f1, f2], archive_name="my_backup.zip", base_source_dir=src_dir)
    assert archive.exists()
    assert archive.name == "my_backup.zip"

    # Liste prüfen
    backups = bm.list_backups()
    assert len(backups) == 1
    assert backups[0]["filename"] == "my_backup.zip"
    assert backups[0]["size_bytes"] > 0


def test_backup_manager_delete(tmp_path: Path):
    bm = BackupManager(str(tmp_path / "backups"))
    src = tmp_path / "file.txt"
    src.write_text("data", encoding="utf-8")

    archive = bm.create_archive([src], archive_name="to_delete.zip")
    assert archive.exists()

    success = bm.delete_backup("to_delete.zip")
    assert success is True
    assert not archive.exists()

    # Zweiter Aufruf liefert False
    assert bm.delete_backup("to_delete.zip") is False


def test_backup_manager_path_traversal_protection(tmp_path: Path):
    bm = BackupManager(str(tmp_path / "backups"))

    with pytest.raises(ValueError, match="Sicherheitsrisiko erkannt"):
        bm.delete_backup("../secret.txt")


def test_backup_manager_zip_slip_protection(tmp_path: Path):
    bm = BackupManager(str(tmp_path / "backups"))
    malicious_zip = bm.base_dir / "malicious.zip"

    # Manuell ein Archiv mit gefährlichem Dateipfad anlegen
    with zipfile.ZipFile(malicious_zip, "w") as z:
        z.writestr("../../evil.txt", "schädlicher Inhalt")

    restore_target = tmp_path / "extracted"
    with pytest.raises(ValueError, match="Zip Slip Versuch erkannt"):
        bm.restore_archive("malicious.zip", restore_target)


def test_backup_actions_ftp_download(tmp_path: Path):
    import ftplib

    mock_ftp = MagicMock(spec=ftplib.FTP)

    dest = tmp_path / "local" / "shop.php"
    success = BackupActions.download_remote_file(mock_ftp, "system/conf.php", dest)

    assert success is True
    mock_ftp.retrbinary.assert_called_once()


def test_backup_actions_sftp_download(tmp_path: Path):
    mock_sftp = MagicMock()

    dest = tmp_path / "local" / "file.txt"
    success = BackupActions.download_remote_file(mock_sftp, "/var/www/file.txt", dest)

    assert success is True
    mock_sftp.get.assert_called_once_with("/var/www/file.txt", str(dest))


def test_backup_actions_backup_remote_files(tmp_path: Path):
    import ftplib

    mock_ftp = MagicMock(spec=ftplib.FTP)
    progress_messages = []

    def on_progress(msg: str):
        progress_messages.append(msg)

    remote_files = ["includes/config.php", "admin/backup.sql", "../escape.txt"]
    dest_dir = tmp_path / "backup_dest"

    downloaded, failed = BackupActions.backup_remote_files(
        mock_ftp,
        remote_files,
        dest_dir,
        progress_callback=on_progress,
    )

    assert len(progress_messages) == 3
    assert len(downloaded) == 2
    assert "../escape.txt" in failed
