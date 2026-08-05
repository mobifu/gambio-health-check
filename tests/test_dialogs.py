import pytest
from unittest.mock import patch
from ui.dialogs import MasterPasswordDialog, ShopProfileDialog, show_error
from PySide6.QtWidgets import QMessageBox


@pytest.fixture(scope="module")
def qapp():
    import sys
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


def test_master_password_dialog_new_setup(qapp):
    # Teste Dialog für erstes Setup
    dialog = MasterPasswordDialog(is_new_setup=True)
    assert dialog.is_new_setup is True

    dialog.edit_password.setText("pass123")
    dialog.edit_confirm.setText("pass123")
    assert dialog.get_password() == "pass123"


def test_master_password_dialog_accept_validation(qapp):
    dialog = MasterPasswordDialog(is_new_setup=True)
    dialog.edit_password.setText("pass123")
    dialog.edit_confirm.setText("different")

    # Mock show_error so it doesn't open a message box
    with patch("ui.dialogs.show_error") as mock_show_error:
        dialog.accept()
        mock_show_error.assert_called_with("Die Passwörter stimmen nicht überein. Bitte prüfen Sie Ihre Eingabe.")


def test_master_password_dialog_login(qapp):
    dialog = MasterPasswordDialog(is_new_setup=False)
    assert dialog.is_new_setup is False
    dialog.edit_password.setText("loginpass")
    assert dialog.get_password() == "loginpass"


def test_shop_profile_dialog(qapp):
    dialog = ShopProfileDialog()
    dialog.edit_shop_name.setText("My Shop")
    dialog.edit_host.setText("ftp.example.com")
    dialog.edit_port.setText("21")
    dialog.edit_username.setText("user")
    dialog.edit_password.setText("pwd")
    dialog.combo_protocol.setCurrentText("SFTP")

    # Simuliere Button Clicks
    dialog.btn_save.click()
    dialog.btn_cancel.click()


@patch.object(QMessageBox, "critical")
def test_show_error(mock_critical, qapp):
    show_error("Test Error Message")
    mock_critical.assert_called_once()
