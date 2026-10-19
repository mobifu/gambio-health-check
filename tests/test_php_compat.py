import os
import sys
import unittest

# Füge das Hauptverzeichnis zum PYTHONPATH hinzu, damit wir ui importieren können
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ui.main_window import HealthCheckPage


class DummySignal:
    def emit(self, *args, **kwargs):
        pass


class DummyWorker:
    def __init__(self):
        self._is_cancelled = False
        self.progress_signal = DummySignal()

    def isRunning(self):
        return True


class TestPHPCompatLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        # Mock-Auth und Config Manager
        class MockAuth:
            pass

        class MockConfig:
            pass

        self.page = HealthCheckPage(MockAuth(), MockConfig())
        self.page.worker = DummyWorker()
        self.signal = DummySignal()

        # Ergebnisse sammeln
        self.results = []

        def mock_add_result(msg, status):
            self.results.append((msg, status))

        self.page._add_result = mock_add_result

    def test_run_php_compatibility_check_logic_valid(self):
        self.page._run_php_compatibility_check_logic("26.06.0", "8.1.10", "8.0", "8.3", signal=self.signal)
        # Es sollte kein Error generiert worden sein
        # Wir können das prüfen, wenn wir den log checken. Da wir hier nur DummySignal haben,
        # prüfen wir ob self.results leer ist (da wir signal=self.signal mitgegeben haben,
        # sollte es an signal.emit gehen, aber log_add_result nicht aufrufen. Wait, wir machen self.signal zu etwas, das speichert)

    def test_version_logic(self):
        # Hilfsfunktion, die wir testen können, ohne dass UI Signale triggern
        class SignalCatcher:
            def __init__(self):
                self.emitted = []

            def emit(self, msg, status="ok"):
                self.emitted.append((status, msg))

        catcher = SignalCatcher()
        self.page._run_php_compatibility_check_logic("26.06.0", "8.1.10", "8.0", "8.3", signal=catcher)
        self.assertTrue(any(status == "ok" and "ist kompatibel" in msg for status, msg in catcher.emitted))

        catcher = SignalCatcher()
        self.page._run_php_compatibility_check_logic("26.06.0", "7.4.30", "8.0", "8.3", signal=catcher)
        self.assertTrue(any(status == "error" and "NICHT kompatibel" in msg for status, msg in catcher.emitted))

        catcher = SignalCatcher()
        self.page._run_php_compatibility_check_logic("26.06.0", "8.4.1", "8.0", "8.3", signal=catcher)
        self.assertTrue(any(status == "warn" and "neuer als" in msg for status, msg in catcher.emitted))

        # Fehlende Min/Max-Version
        catcher = SignalCatcher()
        self.page._run_php_compatibility_check_logic("26.06.0", "8.1.10", None, None, signal=catcher)
        self.assertTrue(
            any(
                status == "warn" and "mangels Update-Dateien nicht geprüft werden" in msg
                for status, msg in catcher.emitted
            )
        )

    def test_get_php_compat_from_shop_exact_match(self):
        import ftplib
        from unittest.mock import MagicMock

        conn = MagicMock(spec=ftplib.FTP)
        conn.nlst.return_value = [
            "gambio_updater/updates/v4.9.1.0",
            "gambio_updater/updates/v4.9.2.0",
        ]

        # Mock _load_update_ini
        def mock_load(connection, path):
            config = MagicMock()
            config.has_section.return_value = True
            config.get.side_effect = lambda sec, key, fallback=None: "8.1" if key == "php_version_min" else "8.3"
            return config

        self.page._load_update_ini = mock_load

        p_min, p_max = self.page._get_php_compat_from_shop(conn, "4.9.2.0", signal=self.signal)
        self.assertEqual(p_min, "8.1")
        self.assertEqual(p_max, "8.3")

    def test_get_php_compat_from_shop_fallback_smaller(self):
        import ftplib
        from unittest.mock import MagicMock

        conn = MagicMock(spec=ftplib.FTP)
        # We ask for 4.9.2.5, but only 4.9.1.0 and 4.9.2.0 exist
        conn.nlst.return_value = [
            "gambio_updater/updates/v4.9.1.0",
            "gambio_updater/updates/v4.9.2.0",
        ]

        def mock_load(connection, path):
            config = MagicMock()
            config.has_section.return_value = True
            config.get.side_effect = lambda sec, key, fallback=None: "7.4" if key == "php_version_min" else "8.2"
            return config

        self.page._load_update_ini = mock_load

        p_min, p_max = self.page._get_php_compat_from_shop(conn, "4.9.2.5", signal=self.signal)
        # It should fallback to v4.9.2.0
        self.assertEqual(p_min, "7.4")
        self.assertEqual(p_max, "8.2")

    def test_get_php_compat_from_shop_no_updates_dir(self):
        import ftplib
        from unittest.mock import MagicMock

        conn = MagicMock(spec=ftplib.FTP)
        conn.nlst.side_effect = ftplib.error_perm("550 No such file or directory")

        p_min, p_max = self.page._get_php_compat_from_shop(conn, "4.9.2.0", signal=self.signal)
        self.assertIsNone(p_min)
        self.assertIsNone(p_max)

    def test_get_php_compat_from_shop_missing_section(self):
        import ftplib
        from unittest.mock import MagicMock

        conn = MagicMock(spec=ftplib.FTP)
        conn.nlst.return_value = ["gambio_updater/updates/v4.9.2.0"]

        def mock_load(connection, path):
            config = MagicMock()
            config.has_section.return_value = False
            return config

        self.page._load_update_ini = mock_load

        p_min, p_max = self.page._get_php_compat_from_shop(conn, "4.9.2.0", signal=self.signal)
        self.assertIsNone(p_min)
        self.assertIsNone(p_max)


if __name__ == "__main__":
    unittest.main()
