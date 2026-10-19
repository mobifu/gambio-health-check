"""
Unit-Tests für ui/backup_manager.py (BackupManager).
"""

import zipfile
from pathlib import Path

import pytest

from ui.backup_manager import BackupManager


def test_backup_manager_init_custom_dir(tmp_path: Path):
    """Prüft Initialisierung mit benutzerdefiniertem Backup-Verzeichnis."""
    custom_dir = tmp_path / "custom_backups"
    bm = BackupManager(str(custom_dir))
    assert bm.base_dir.exists()
    assert bm.base_dir == custom_dir.resolve()


def test_backup_manager_init_default_dir(monkeypatch, tmp_path: Path):
    """Prüft Initialisierung ohne Argumente (Standardpfad Path.cwd() / 'backups')."""
    monkeypatch.chdir(tmp_path)
    bm = BackupManager()
    expected = (tmp_path / "backups").resolve()
    assert bm.base_dir == expected
    assert expected.exists()


def test_backup_manager_create_and_list(tmp_path: Path):
    """Prüft Archiv-Erstellung und Metadaten-Auflistung."""
    bm = BackupManager(str(tmp_path / "backups"))

    src_dir = tmp_path / "source"
    src_dir.mkdir()
    f1 = src_dir / "test1.txt"
    f1.write_text("Inhalt 1", encoding="utf-8")
    f2 = src_dir / "test2.txt"
    f2.write_text("Inhalt 2", encoding="utf-8")

    archive = bm.create_archive([f1, f2], archive_name="my_backup.zip", base_source_dir=src_dir)
    assert archive.exists()
    assert archive.name == "my_backup.zip"

    backups = bm.list_backups()
    assert len(backups) == 1
    assert backups[0]["filename"] == "my_backup.zip"
    assert backups[0]["size_bytes"] > 0
    assert "size_mb" in backups[0]
    assert "created_at" in backups[0]


def test_backup_manager_create_archive_variations(tmp_path: Path):
    """Prüft Archiv-Erstellung mit Standardnamen, fehlender .zip-Endung und nicht existierenden Dateien."""
    bm = BackupManager(str(tmp_path / "backups"))

    src_dir = tmp_path / "source"
    src_dir.mkdir()
    existing_file = src_dir / "exists.txt"
    existing_file.write_text("Daten", encoding="utf-8")
    non_existing_file = src_dir / "missing.txt"

    # 1. Dateiname ohne .zip-Endung + nicht existierende Datei
    archive1 = bm.create_archive([existing_file, non_existing_file], archive_name="custom_name")
    assert archive1.name == "custom_name.zip"
    assert archive1.exists()

    with zipfile.ZipFile(archive1, "r") as zf:
        namelist = zf.namelist()
        assert "exists.txt" in namelist
        assert "missing.txt" not in namelist

    # 2. Ohne archive_name (automatischer Zeitstempel)
    archive2 = bm.create_archive([existing_file])
    assert archive2.name.startswith("gambio_backup_")
    assert archive2.name.endswith(".zip")
    assert archive2.exists()


def test_backup_manager_create_archive_relative_to_mismatch(tmp_path: Path):
    """Prüft Fallback auf Dateinamen, wenn Datei außerhalb von base_source_dir liegt."""
    bm = BackupManager(str(tmp_path / "backups"))

    dir_a = tmp_path / "dir_a"
    dir_a.mkdir()
    file_a = dir_a / "file_a.txt"
    file_a.write_text("A", encoding="utf-8")

    dir_b = tmp_path / "dir_b"
    dir_b.mkdir()

    # file_a liegt nicht in dir_b
    archive = bm.create_archive([file_a], archive_name="fallback.zip", base_source_dir=dir_b)
    assert archive.exists()

    with zipfile.ZipFile(archive, "r") as zf:
        assert zf.namelist() == ["file_a.txt"]


def test_backup_manager_list_backups_os_error(tmp_path: Path, monkeypatch):
    """Prüft Fehlerabfang bei OSError in list_backups."""
    bm = BackupManager(str(tmp_path / "backups"))
    dummy_zip = bm.base_dir / "corrupt.zip"
    dummy_zip.write_bytes(b"dummy")

    real_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        if self.suffix == ".zip":
            raise OSError("Dateizugriff verweigert")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)

    backups = bm.list_backups()
    assert backups == []


def test_backup_manager_delete(tmp_path: Path):
    """Prüft Löschen existierender und nicht-existierender Archive."""
    bm = BackupManager(str(tmp_path / "backups"))
    src = tmp_path / "file.txt"
    src.write_text("data", encoding="utf-8")

    archive = bm.create_archive([src], archive_name="to_delete.zip")
    assert archive.exists()

    assert bm.delete_backup("to_delete.zip") is True
    assert not archive.exists()
    assert bm.delete_backup("to_delete.zip") is False


def test_backup_manager_restore_success(tmp_path: Path):
    """Prüft erfolgreiche Wiederherstellung eines ZIP-Archivs."""
    bm = BackupManager(str(tmp_path / "backups"))

    src_dir = tmp_path / "source"
    src_dir.mkdir()
    sub_dir = src_dir / "subdir"
    sub_dir.mkdir()
    f1 = src_dir / "file1.txt"
    f1.write_text("Hello", encoding="utf-8")
    f2 = sub_dir / "file2.txt"
    f2.write_text("World", encoding="utf-8")

    archive = bm.create_archive([f1, f2], archive_name="restore_test.zip", base_source_dir=src_dir)
    assert archive.exists()

    restore_target = tmp_path / "restored"
    extracted = bm.restore_archive("restore_test.zip", restore_target)

    assert len(extracted) == 2
    restored_f1 = restore_target / "file1.txt"
    restored_f2 = restore_target / "subdir" / "file2.txt"
    assert restored_f1.exists() and restored_f1.read_text(encoding="utf-8") == "Hello"
    assert restored_f2.exists() and restored_f2.read_text(encoding="utf-8") == "World"


def test_backup_manager_path_traversal_protection(tmp_path: Path):
    """Prüft Erkennung und Abwehr von Path-Traversal-Angriffen."""
    bm = BackupManager(str(tmp_path / "backups"))

    with pytest.raises(ValueError, match="Sicherheitsrisiko erkannt"):
        bm.delete_backup("../secret.txt")

    with pytest.raises(ValueError, match="Sicherheitsrisiko erkannt"):
        bm.restore_archive("../../etc/passwd", tmp_path / "dest")


def test_backup_manager_zip_slip_protection(tmp_path: Path):
    """Prüft Erkennung und Abwehr von Zip-Slip-Angriffen beim Entpacken."""
    bm = BackupManager(str(tmp_path / "backups"))
    malicious_zip = bm.base_dir / "malicious.zip"

    with zipfile.ZipFile(malicious_zip, "w") as z:
        z.writestr("../../evil.txt", "schädlicher Inhalt")

    restore_target = tmp_path / "extracted"
    with pytest.raises(ValueError, match="Zip Slip Versuch erkannt"):
        bm.restore_archive("malicious.zip", restore_target)
