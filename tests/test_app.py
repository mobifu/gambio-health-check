import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from security.exceptions import InvalidMasterPasswordError
import app


def test_is_initial_setup(tmp_path):
    config_file = tmp_path / "config.dat"
    mock_config_manager = MagicMock()
    mock_config_manager.config_path = str(config_file)

    # Datei existiert nicht -> Erstinstallation
    assert app.is_initial_setup(mock_config_manager) is True

    # Datei existiert -> Keine Erstinstallation
    config_file.write_text("test")
    assert app.is_initial_setup(mock_config_manager) is False


def test_authenticate_user_success_first_run():
    mock_auth_manager = MagicMock()
    mock_config_manager = MagicMock()

    mock_dialog = MagicMock()
    mock_dialog.exec.return_value = True
    mock_dialog.get_password.return_value = "secure_password"

    with patch("app.MasterPasswordDialog", return_value=mock_dialog):
        result = app.authenticate_user(mock_auth_manager, mock_config_manager, is_first_run=True)

    assert result is True
    mock_config_manager.load_config.assert_called_once_with("secure_password")
    mock_config_manager.save_config.assert_called_once_with({}, "secure_password")
    mock_auth_manager.set_password.assert_called_once_with("secure_password")
    mock_auth_manager.update_activity.assert_called_once()
    mock_auth_manager.require_active_session.assert_called_once()


def test_authenticate_user_success_existing_setup():
    mock_auth_manager = MagicMock()
    mock_config_manager = MagicMock()

    mock_dialog = MagicMock()
    mock_dialog.exec.return_value = True
    mock_dialog.get_password.return_value = "existing_password"

    with patch("app.MasterPasswordDialog", return_value=mock_dialog):
        result = app.authenticate_user(mock_auth_manager, mock_config_manager, is_first_run=False)

    assert result is True
    mock_config_manager.load_config.assert_called_once_with("existing_password")
    mock_config_manager.save_config.assert_not_called()
    mock_auth_manager.set_password.assert_called_once_with("existing_password")


def test_authenticate_user_dialog_cancelled():
    mock_auth_manager = MagicMock()
    mock_config_manager = MagicMock()

    mock_dialog = MagicMock()
    mock_dialog.exec.return_value = False

    with patch("app.MasterPasswordDialog", return_value=mock_dialog):
        result = app.authenticate_user(mock_auth_manager, mock_config_manager, is_first_run=False)

    assert result is False
    mock_config_manager.load_config.assert_not_called()


def test_authenticate_user_empty_password():
    mock_auth_manager = MagicMock()
    mock_config_manager = MagicMock()

    mock_dialog = MagicMock()
    mock_dialog.exec.return_value = True
    mock_dialog.get_password.return_value = ""

    with (
        patch("app.MasterPasswordDialog", return_value=mock_dialog),
        patch("app.show_error") as mock_show_error,
    ):
        result = app.authenticate_user(mock_auth_manager, mock_config_manager, is_first_run=False)

    assert result is False
    mock_show_error.assert_called_once_with("Das Passwort darf nicht leer sein.")
    mock_config_manager.load_config.assert_not_called()


def test_authenticate_user_invalid_password():
    mock_auth_manager = MagicMock()
    mock_config_manager = MagicMock()
    mock_config_manager.load_config.side_effect = InvalidMasterPasswordError("Falsches Passwort")

    mock_dialog = MagicMock()
    mock_dialog.exec.return_value = True
    mock_dialog.get_password.return_value = "wrong_password"

    with (
        patch("app.MasterPasswordDialog", return_value=mock_dialog),
        patch("app.show_error") as mock_show_error,
    ):
        result = app.authenticate_user(mock_auth_manager, mock_config_manager, is_first_run=False)

    assert result is False
    mock_show_error.assert_called_once_with("Falsches Passwort")


def test_authenticate_user_unexpected_exception():
    mock_auth_manager = MagicMock()
    mock_config_manager = MagicMock()
    mock_config_manager.load_config.side_effect = OSError("Dateifehler")

    mock_dialog = MagicMock()
    mock_dialog.exec.return_value = True
    mock_dialog.get_password.return_value = "any_password"

    with (
        patch("app.MasterPasswordDialog", return_value=mock_dialog),
        patch("app.show_error") as mock_show_error,
    ):
        result = app.authenticate_user(mock_auth_manager, mock_config_manager, is_first_run=False)

    assert result is False
    assert mock_show_error.call_count == 1
    assert "Unerwarteter Fehler bei der Authentifizierung" in mock_show_error.call_args[0][0]


def test_run_application():
    mock_app = MagicMock()
    mock_app.exec.return_value = 42
    mock_auth = MagicMock()
    mock_config = MagicMock()

    with patch("app.MainWindow") as mock_main_window_cls:
        mock_window = MagicMock()
        mock_main_window_cls.return_value = mock_window

        code = app.run_application(mock_app, mock_auth, mock_config)

    assert code == 42
    mock_main_window_cls.assert_called_once_with(mock_auth, mock_config)
    mock_window.show.assert_called_once()
    mock_app.exec.assert_called_once()


def test_app_main_first_run():
    with (
        patch("app.QApplication") as mock_qapp,
        patch("app.is_initial_setup", return_value=True) as mock_is_initial,
        patch("app.authenticate_user", return_value=True) as mock_auth,
        patch("app.run_application", return_value=0) as mock_run,
        patch("app.sys.exit") as mock_exit,
    ):
        mock_exit.side_effect = SystemExit

        with pytest.raises(SystemExit):
            app.main()

        mock_is_initial.assert_called_once()
        mock_auth.assert_called_once()
        mock_run.assert_called_once()
        mock_exit.assert_called_with(0)


def test_app_main_auth_failed():
    with (
        patch("app.QApplication") as mock_qapp,
        patch("app.is_initial_setup", return_value=False),
        patch("app.authenticate_user", return_value=False),
        patch("app.run_application") as mock_run,
        patch("app.sys.exit") as mock_exit,
    ):
        mock_exit.side_effect = SystemExit

        with pytest.raises(SystemExit):
            app.main()

        mock_run.assert_not_called()
        mock_exit.assert_called_with(0)
