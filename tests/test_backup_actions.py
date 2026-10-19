"""
Unittests für ui/backup_actions.py (BackupActions).
"""

import ftplib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ui.backup_actions import BackupActions


def test_download_remote_file_ftp_success(tmp_path: Path):
    """Prüft erfolgreichen FTP-Download einer Remote-Datei."""
    mock_ftp = MagicMock(spec=ftplib.FTP)

    def fake_retrbinary(cmd, callback):
        callback(b"test content")

    mock_ftp.retrbinary.side_effect = fake_retrbinary

    dest = tmp_path / "subdir" / "downloaded.txt"
    result = BackupActions.download_remote_file(mock_ftp, "remote/dir/file.txt", dest)

    assert result is True
    assert dest.exists()
    assert dest.read_bytes() == b"test content"
    mock_ftp.retrbinary.assert_called_once_with("RETR remote/dir/file.txt", mock_ftp.retrbinary.call_args[0][1])


def test_download_remote_file_ftp_error(tmp_path: Path):
    """Prüft Fehlerbehandlung bei ftplib.Error."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.retrbinary.side_effect = ftplib.error_perm("550 File not found")

    dest = tmp_path / "dest.txt"
    result = BackupActions.download_remote_file(mock_ftp, "missing.txt", dest)

    assert result is False


def test_download_remote_file_ftp_os_error(tmp_path: Path):
    """Prüft Fehlerbehandlung bei OSError während des FTP-Downloads."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    mock_ftp.retrbinary.side_effect = OSError("Connection reset")

    dest = tmp_path / "dest.txt"
    result = BackupActions.download_remote_file(mock_ftp, "file.txt", dest)

    assert result is False


def test_download_remote_file_sftp_success(tmp_path: Path):
    """Prüft erfolgreichen SFTP-Download."""
    mock_sftp = MagicMock()
    dest = tmp_path / "nested" / "sftp_file.txt"

    result = BackupActions.download_remote_file(mock_sftp, "/var/www/data.sql", dest)

    assert result is True
    assert dest.parent.exists()
    mock_sftp.get.assert_called_once_with("/var/www/data.sql", str(dest))


def test_download_remote_file_sftp_failure(tmp_path: Path):
    """Prüft Fehlerbehandlung beim SFTP-Download."""
    mock_sftp = MagicMock()
    mock_sftp.get.side_effect = OSError("SFTP failure")

    dest = tmp_path / "failed.txt"
    result = BackupActions.download_remote_file(mock_sftp, "/remote/path.txt", dest)

    assert result is False


def test_download_remote_file_generic_exception(tmp_path: Path):
    """Prüft Abfangen unerwarteter Ausnahmen."""
    mock_sftp = MagicMock()
    mock_sftp.get.side_effect = RuntimeError("Fatal crash")

    dest = tmp_path / "error.txt"
    result = BackupActions.download_remote_file(mock_sftp, "/crash.txt", dest)

    assert result is False


def test_backup_remote_files_all_success(tmp_path: Path):
    """Prüft Sicherung mehrerer Remote-Dateien mit Fortschrittsrückmeldung."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    progress_updates: list[str] = []

    files = ["file1.txt", "sub/file2.txt", "/abs/file3.txt"]
    target = tmp_path / "backups"

    downloaded, failed = BackupActions.backup_remote_files(
        conn=mock_ftp,
        remote_files=files,
        target_dir=target,
        progress_callback=progress_updates.append,
    )

    assert len(downloaded) == 3
    assert len(failed) == 0
    assert len(progress_updates) == 3
    assert all(p.is_relative_to(target.resolve()) for p in downloaded)


def test_backup_remote_files_without_callback(tmp_path: Path):
    """Prüft Sicherung ohne Callback."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    target = tmp_path / "backup_nocallback"

    downloaded, failed = BackupActions.backup_remote_files(
        conn=mock_ftp,
        remote_files=["test.txt"],
        target_dir=target,
        progress_callback=None,
    )

    assert len(downloaded) == 1
    assert len(failed) == 0


def test_backup_remote_files_path_traversal_detection(tmp_path: Path):
    """Prüft Abwehr von Path-Traversal-Versuchen."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    target = tmp_path / "safe_dir"

    traversal_files = [
        "../evil.txt",
        "../../etc/passwd",
        r"..\..\windows\win.ini",
        "/../escape.txt",
        "",
    ]

    downloaded, failed = BackupActions.backup_remote_files(
        conn=mock_ftp,
        remote_files=traversal_files,
        target_dir=target,
    )

    assert len(downloaded) == 0
    assert len(failed) == len(traversal_files)


def test_backup_remote_files_traversal_exception(tmp_path: Path, monkeypatch):
    """Prüft Ausnahmebehandlung, wenn is_relative_to fehlschlägt."""
    mock_ftp = MagicMock(spec=ftplib.FTP)
    target = tmp_path / "safe_dir"

    def fake_is_relative_to(self, other):
        raise ValueError("Simulierter relativer Fehler")

    monkeypatch.setattr(Path, "is_relative_to", fake_is_relative_to)

    downloaded, failed = BackupActions.backup_remote_files(
        conn=mock_ftp,
        remote_files=["test.txt"],
        target_dir=target,
    )

    assert len(downloaded) == 0
    assert failed == ["test.txt"]


def test_backup_remote_files_partial_download_failure(tmp_path: Path):
    """Prüft Behandlung partieller Downloadfehler."""
    mock_ftp = MagicMock(spec=ftplib.FTP)

    def fake_download(conn, remote, dest):
        return "bad" not in remote

    original_download = BackupActions.download_remote_file
    try:
        BackupActions.download_remote_file = staticmethod(fake_download)

        files = ["good1.txt", "bad_file.txt", "good2.txt"]
        target = tmp_path / "mixed"

        downloaded, failed = BackupActions.backup_remote_files(
            conn=mock_ftp,
            remote_files=files,
            target_dir=target,
        )

        assert len(downloaded) == 2
        assert failed == ["bad_file.txt"]
    finally:
        BackupActions.download_remote_file = original_download
