import sys
from unittest.mock import MagicMock

import pytest
from PySide6.QtWidgets import QApplication

from ui.main_window import HealthCheckPage


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


def test_check_cache_size_normal(qapp):
    # Setup mocks
    mock_auth = MagicMock()
    mock_config = MagicMock()
    page = HealthCheckPage(mock_auth, mock_config)

    mock_conn = MagicMock()
    mock_conn.mlsd.return_value = [
        ("file1.txt", {"type": "file", "size": "1048576"}),  # 1 MB
        ("file2.txt", {"type": "file", "size": "1048576"}),  # 1 MB
    ]

    mock_signal = MagicMock()

    # Run
    page._check_cache_size(mock_conn, [], mock_signal)

    # Assert
    # 2 MB in 'cache', 2 MB in 'templates_c' = 4 MB total (which is > 0 and < 250 MB)
    mock_signal.emit.assert_called_with("Cache-Größe ist im normalen Bereich (4 MB).", "ok")


def test_check_cache_size_warning(qapp):
    mock_auth = MagicMock()
    mock_config = MagicMock()
    page = HealthCheckPage(mock_auth, mock_config)

    mock_conn = MagicMock()
    # Provide 150 MB for each dir, total 300 MB > 250 MB limit
    mock_conn.mlsd.return_value = [("bigfile", {"type": "file", "size": str(150 * 1024 * 1024)})]

    mock_signal = MagicMock()

    page._check_cache_size(mock_conn, [], mock_signal)

    mock_signal.emit.assert_called_with("Cache-Ordner sind sehr groß (300 MB). Erwägen Sie eine Leerung.", "warn")


def test_check_cache_size_empty(qapp):
    mock_auth = MagicMock()
    mock_config = MagicMock()
    page = HealthCheckPage(mock_auth, mock_config)

    mock_conn = MagicMock()
    mock_conn.mlsd.return_value = []

    mock_signal = MagicMock()

    page._check_cache_size(mock_conn, [], mock_signal)

    mock_signal.emit.assert_called_with("Konnte Cache-Größe nicht ermitteln oder leer.", "ok")
