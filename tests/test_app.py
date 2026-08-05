import pytest
from unittest.mock import patch, MagicMock
from security.exceptions import InvalidMasterPasswordError
import app


def test_app_main_first_run():
    with (
        patch("app.QApplication") as mock_qapp,
        patch("app.os.path.exists") as mock_exists,
        patch("app.MasterPasswordDialog") as mock_dialog_class,
        patch("app.ConfigManager") as mock_config_manager_class,
        patch("app.MasterPasswordManager") as mock_auth_manager_class,
        patch("app.MainWindow") as mock_main_window_class,
        patch("app.sys.exit") as mock_exit,
    ):
        # Simuliere erste Ausführung (config.dat existiert nicht)
        mock_exists.return_value = False
        mock_exit.side_effect = SystemExit

        # Mock Dialog instance
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = True
        mock_dialog.get_password.return_value = "mypassword"
        mock_dialog_class.return_value = mock_dialog

        # Mock Managers
        mock_config_manager = MagicMock()
        mock_config_manager.config_path = "config.dat"
        mock_config_manager_class.return_value = mock_config_manager

        with pytest.raises(SystemExit):
            app.main()

        # Verifiziere Aufrufe
        mock_config_manager.load_config.assert_called_with("mypassword")
        mock_config_manager.save_config.assert_called_with({}, "mypassword")
        mock_main_window_class.assert_called_once()
        mock_exit.assert_called()


def test_app_main_empty_password():
    with (
        patch("app.QApplication") as mock_qapp,
        patch("app.os.path.exists") as mock_exists,
        patch("app.MasterPasswordDialog") as mock_dialog_class,
        patch("app.show_error") as mock_show_error,
        patch("app.sys.exit") as mock_exit,
    ):
        mock_exists.return_value = True
        mock_exit.side_effect = SystemExit
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = True
        mock_dialog.get_password.return_value = ""  # Leeres Passwort
        mock_dialog_class.return_value = mock_dialog

        with pytest.raises(SystemExit):
            app.main()

        mock_show_error.assert_called_with("Das Passwort darf nicht leer sein.")
        mock_exit.assert_called_with(0)


def test_app_main_invalid_password():
    with (
        patch("app.QApplication") as mock_qapp,
        patch("app.os.path.exists") as mock_exists,
        patch("app.MasterPasswordDialog") as mock_dialog_class,
        patch("app.ConfigManager") as mock_config_manager_class,
        patch("app.show_error") as mock_show_error,
        patch("app.sys.exit") as mock_exit,
    ):
        mock_exists.return_value = True
        mock_exit.side_effect = SystemExit
        mock_dialog = MagicMock()
        mock_dialog.exec.return_value = True
        mock_dialog.get_password.return_value = "wrongpassword"
        mock_dialog_class.return_value = mock_dialog

        mock_config_manager = MagicMock()
        mock_config_manager.load_config.side_effect = InvalidMasterPasswordError("Falsches Passwort")
        mock_config_manager_class.return_value = mock_config_manager

        with pytest.raises(SystemExit):
            app.main()

        mock_show_error.assert_called_with("Falsches Passwort")
        mock_exit.assert_called_with(0)
