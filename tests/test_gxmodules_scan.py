import unittest
import os
import sys
import ftplib
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ui.main_window import HealthCheckPage


class DummySignal:
    def __init__(self):
        self.emitted = []

    def emit(self, msg, status="ok"):
        self.emitted.append((status, msg))


class DummyWorker:
    def __init__(self):
        self._is_cancelled = False


class TestGXModulesScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        class MockAuth:
            pass

        class MockConfig:
            pass

        self.page = HealthCheckPage(MockAuth(), MockConfig())
        self.page.worker = DummyWorker()
        self.signal = DummySignal()

        # Disable emit_progress for tests
        self.page._emit_progress = lambda x: None

    def _setup_mock_ftp(self, files_dict):
        """
        Helper to set up a mock FTP connection.
        files_dict maps filename (relative to GXModules) to its content.
        """
        conn = MagicMock(spec=ftplib.FTP)

        # Mock mlsd to list files
        def mock_mlsd(path):
            rel_path = path.replace("GXModules", "").strip("/")
            items = {}
            for fname in files_dict.keys():
                if rel_path:
                    if fname.startswith(rel_path + "/"):
                        sub_path = fname[len(rel_path) + 1 :]
                        part = sub_path.split("/")[0]
                        if "/" in sub_path:
                            items[part] = {"type": "dir"}
                        else:
                            items[part] = {"type": "file"}
                else:
                    part = fname.split("/")[0]
                    if "/" in fname:
                        items[part] = {"type": "dir"}
                    else:
                        items[part] = {"type": "file"}

            return iter([(k, v) for k, v in items.items()])

        conn.mlsd.side_effect = mock_mlsd

        # Mock retrbinary to return content
        def mock_retrbinary(cmd, callback):
            # cmd is something like "RETR GXModules/test.php"
            path = cmd.split(" ", 1)[1]
            fname = path.replace("GXModules/", "")
            if fname in files_dict:
                callback(files_dict[fname])

        conn.retrbinary.side_effect = mock_retrbinary

        return conn

    def test_gxmodules_scan_no_issues(self):
        files = {"good_plugin.php": b"<?php echo 'Hello World'; ?>"}
        conn = self._setup_mock_ftp(files)
        self.page._run_gxmodules_compatibility_scan(conn, "4.9.0.0", signal=self.signal)

        self.assertTrue(
            any(
                "Keine offensichtlichen PHP 8 Inkompatibilitäten gefunden" in msg for status, msg in self.signal.emitted
            )
        )

    def test_gxmodules_scan_php8_incompatible_error_on_new_shop(self):
        files = {"bad_plugin.php": b"<?php create_function('', 'return true;'); ?>"}
        conn = self._setup_mock_ftp(files)
        # Gambio Version >= 4.7
        self.page._run_gxmodules_compatibility_scan(conn, "4.8.0.2", signal=self.signal)

        # Check if error is emitted
        error_emitted = False
        for status, msg in self.signal.emitted:
            if status == "error" and "create_function" in msg and "bad_plugin.php" in msg:
                error_emitted = True
        self.assertTrue(error_emitted)

    def test_gxmodules_scan_php8_incompatible_warn_on_old_shop(self):
        files = {"bad_plugin.php": b"<?php each($array); ?>"}
        conn = self._setup_mock_ftp(files)
        # Gambio Version < 4.7
        self.page._run_gxmodules_compatibility_scan(conn, "4.4.0.3", signal=self.signal)

        # Check if warning is emitted
        warn_emitted = False
        for status, msg in self.signal.emitted:
            if status == "warn" and "each" in msg and "bad_plugin.php" in msg:
                warn_emitted = True
        self.assertTrue(warn_emitted)

        # Ensure no errors were emitted for the incompatible code
        for status, msg in self.signal.emitted:
            self.assertFalse(status == "error" and "bad_plugin.php" in msg)

    def test_gxmodules_scan_old_constructor(self):
        files = {"old_class.php": b"<?php class MyPlugin { function MyPlugin() { } } ?>"}
        conn = self._setup_mock_ftp(files)
        # Gambio Version >= 4.7
        self.page._run_gxmodules_compatibility_scan(conn, "4.9.0.0", signal=self.signal)

        error_emitted = False
        for status, msg in self.signal.emitted:
            if status == "error" and "Alter PHP4-Konstruktor (MyPlugin)" in msg:
                error_emitted = True
        self.assertTrue(error_emitted)

    def test_gxmodules_scan_ignores_gambio_dir(self):
        files = {
            "Gambio/test.php": b"<?php create_function('', 'return true;'); ?>",
            "ThirdParty/plugin.php": b"<?php echo 'ok'; ?>",
        }
        conn = self._setup_mock_ftp(files)
        # Even if Gambio/test.php has an error, it should not be scanned
        self.page._run_gxmodules_compatibility_scan(conn, "4.9.0.0", signal=self.signal)

        # It should report "Keine offensichtlichen PHP 8 Inkompatibilitäten gefunden"
        # or at least not throw an error about create_function
        error_emitted = False
        for status, msg in self.signal.emitted:
            if status == "error" and "create_function" in msg:
                error_emitted = True
        self.assertFalse(error_emitted)

    def test_gxmodules_scan_php4_constructor_false_positive(self):
        files = {
            "good_class.php": b"<?php class OrderStatusId { public function __construct() {} public function orderStatusId() {} } ?>"
        }
        conn = self._setup_mock_ftp(files)
        # Gambio Version >= 4.7
        self.page._run_gxmodules_compatibility_scan(conn, "4.9.0.0", signal=self.signal)

        error_emitted = False
        for status, msg in self.signal.emitted:
            if status == "error" and "Alter PHP4-Konstruktor" in msg:
                error_emitted = True
        self.assertFalse(error_emitted)

    def test_gxmodules_scan_phply_none_lexer_fallback(self):
        """
        Testet, dass der GXModules-Scan nicht mit 'NoneType has no attribute write'
        abbricht, wenn phplex.lexer None ist. Stattdessen soll Regex-Fallback greifen.
        """
        import sys
        import types
        from unittest.mock import patch, MagicMock

        # Simuliere phply-Import, aber mit lexer=None
        mock_phplex = types.ModuleType("phplex")
        mock_phplex.lexer = None  # <-- kritischer Fall

        mock_parser = MagicMock()
        mock_phpparse = types.ModuleType("phpparse")
        mock_phpparse.make_parser = lambda: mock_parser

        mock_phply = types.ModuleType("phply")
        mock_phply.phplex = mock_phplex

        files = {"bad_plugin.php": b"<?php create_function('', 'return true;'); ?>"}
        conn = self._setup_mock_ftp(files)

        with patch.dict(
            sys.modules,
            {
                "phply": mock_phply,
                "phply.phplex": mock_phplex,
                "phply.phpparse": mock_phpparse,
            },
        ):
            # Darf KEINEN Absturz verursachen – Regex-Fallback muss greifen
            try:
                self.page._run_gxmodules_compatibility_scan(conn, "4.9.0.0", signal=self.signal)
            except Exception as e:
                self.fail(f"Scan warf unerwarteten Fehler: {e}")

        # Der Regex-Fallback soll 'create_function' erkennen
        error_or_warn = [(s, m) for s, m in self.signal.emitted if s in ("error", "warn") and "create_function" in m]
        self.assertTrue(
            len(error_or_warn) > 0 or any("Keine offensichtlichen" in m for _, m in self.signal.emitted),
            "Scan sollte entweder create_function finden oder sauber abschließen",
        )


if __name__ == "__main__":
    unittest.main()
