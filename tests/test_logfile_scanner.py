import pytest
from unittest.mock import MagicMock
import datetime
import ftplib

# Mock UI classes and modules to import main_window
import sys
from PySide6.QtWidgets import QApplication

if not QApplication.instance():
    app = QApplication(sys.argv)

from ui.main_window import LogfileWorker


class MockPage:
    def __init__(self):
        self.connection = None

    def _check_connection(self, profile, result_signal):
        return self.connection, ""


@pytest.fixture
def mock_ftp():
    ftp = MagicMock(spec=ftplib.FTP)
    return ftp


def test_logfile_worker_scan_no_files(mock_ftp):
    page = MockPage()
    page.connection = mock_ftp

    # Mock mlsd to return empty
    mock_ftp.mlsd.return_value = []

    worker = LogfileWorker(page, {}, 7, mode="scan")
    worker.run()

    assert len(worker.errors_found) == 0


def test_logfile_worker_scan_finds_error(mock_ftp):
    page = MockPage()
    page.connection = mock_ftp

    now = datetime.datetime.now()
    modify_time = now.strftime("%Y%m%d%H%M%S")

    # Mock mlsd to return one file
    mock_ftp.mlsd.return_value = [("test.log", {"type": "file", "modify": modify_time})]

    # Mock file content with ERROR
    def mock_retrbinary(cmd, callback):
        callback(b"INFO: all good\nERROR: something failed\nWARNING: care")

    mock_ftp.retrbinary.side_effect = mock_retrbinary

    worker = LogfileWorker(page, {}, 7, mode="scan")
    worker.run()

    assert len(worker.errors_found) == 1
    assert "ERROR: something failed" in worker.errors_found[0]


def test_logfile_worker_cleanup_old_files(mock_ftp):
    page = MockPage()
    page.connection = mock_ftp

    # 10 days ago
    old_time = datetime.datetime.now() - datetime.timedelta(days=10)
    old_modify = old_time.strftime("%Y%m%d%H%M%S")

    # Mock mlsd to return one old file and .htaccess
    mock_ftp.mlsd.return_value = [
        ("old.log", {"type": "file", "modify": old_modify}),
        (".htaccess", {"type": "file", "modify": old_modify}),  # should not be deleted
    ]

    worker = LogfileWorker(page, {}, 7, mode="cleanup")
    worker.run()

    assert len(worker.files_deleted) == 1
    assert worker.files_deleted[0] == "old.log"

    mock_ftp.delete.assert_called_once_with("old.log")
