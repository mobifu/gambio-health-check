import ftplib
from unittest.mock import MagicMock

import pytest

from ui.main_window import BakFileScannerWorker


@pytest.fixture
def mock_page():
    page = MagicMock()
    # Mocking check_connection to return a mock FTP and empty remote_files
    mock_ftp = MagicMock(spec=ftplib.FTP)
    page._check_connection.return_value = (mock_ftp, [])
    return page, mock_ftp


def test_bak_file_scanner_mlsd(mock_page):
    page, mock_ftp = mock_page
    profile = {"shop_name": "TestShop"}

    # Configure mock FTP to use MLSD
    mock_ftp.mlsd.side_effect = [
        # Root dir
        [
            ("file1.php", {"type": "file"}),
            ("backup.bak", {"type": "file"}),
            ("subdir", {"type": "dir"}),
        ],
        # subdir
        [("old_config.BAK", {"type": "file"}), ("image.png", {"type": "file"})],
    ]

    worker = BakFileScannerWorker(page, profile)
    worker.run()

    # Check if bak files were found
    assert len(worker.bak_files) == 2
    assert "backup.bak" in worker.bak_files
    assert "subdir/old_config.BAK" in worker.bak_files


def test_bak_file_scanner_nlst(mock_page):
    page, mock_ftp = mock_page
    profile = {"shop_name": "TestShop"}

    # If MLSD fails, it falls back to nlst (and lists)
    mock_ftp.mlsd.side_effect = Exception("MLSD not supported")

    # Simple fallback test just with nlst simulating files in root
    mock_ftp.nlst.return_value = ["file1.php", "backup.bak", "another.BAK", "subdir"]

    # If it tries to cwd into subdir, it might raise an exception if it's a file, or succeed.
    def mock_cwd(path):
        if path == "subdir":
            # simulate empty dir for nlst
            mock_ftp.nlst.return_value = []
        elif path == "..":
            mock_ftp.nlst.return_value = [
                "file1.php",
                "backup.bak",
                "another.BAK",
                "subdir",
            ]
        else:
            raise Exception("Not a directory")

    mock_ftp.cwd.side_effect = mock_cwd

    worker = BakFileScannerWorker(page, profile)
    worker.run()

    assert "backup.bak" in worker.bak_files
    assert "another.BAK" in worker.bak_files
