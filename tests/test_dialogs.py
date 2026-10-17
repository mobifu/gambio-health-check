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


def test_shop_profile_dialog_toggle_password(qapp):
    from PySide6.QtWidgets import QLineEdit

    dialog = ShopProfileDialog()
    assert dialog.edit_password.echoMode() == QLineEdit.Password
    assert dialog.btn_toggle_password.text() == "Anzeigen"

    dialog.btn_toggle_password.click()
    assert dialog.edit_password.echoMode() == QLineEdit.Normal
    assert dialog.btn_toggle_password.text() == "Verbergen"

    dialog.btn_toggle_password.click()
    assert dialog.edit_password.echoMode() == QLineEdit.Password
    assert dialog.btn_toggle_password.text() == "Anzeigen"


def test_shop_profile_dialog_data_get_set(qapp):
    dialog = ShopProfileDialog()
    test_data = {
        "shop_name": "Mein Shop",
        "host": "sftp.meinedomain.de",
        "port": 2222,
        "username": "admin",
        "password": "geheim123",
        "protocol": "SFTP",
    }
    dialog.set_profile_data(test_data)
    extracted = dialog.get_profile_data()

    assert extracted["shop_name"] == "Mein Shop"
    assert extracted["host"] == "sftp.meinedomain.de"
    assert extracted["port"] == 2222
    assert extracted["username"] == "admin"
    assert extracted["password"] == "geheim123"
    assert extracted["protocol"] == "SFTP"


def test_shop_profile_dialog_protocol_auto_port(qapp):
    dialog = ShopProfileDialog()
    dialog.edit_port.setText("21")

    # Wechsel auf SFTP sollte Port auf 22 setzen
    dialog.combo_protocol.setCurrentText("SFTP")
    assert dialog.edit_port.text() == "22"

    # Wechsel auf HTTPS sollte Port auf 443 setzen
    dialog.combo_protocol.setCurrentText("HTTPS")
    assert dialog.edit_port.text() == "443"

    # Wechsel auf FTP sollte Port auf 21 setzen
    dialog.combo_protocol.setCurrentText("FTP")
    assert dialog.edit_port.text() == "21"


def test_shop_profile_dialog_validation_failures(qapp):
    dialog = ShopProfileDialog()

    with patch("ui.dialogs.show_error") as mock_err:
        # 1. Kein Shop-Name
        dialog.edit_shop_name.setText("")
        dialog.edit_host.setText("example.com")
        dialog.accept()
        mock_err.assert_called_with("Bitte geben Sie einen Shop-Namen an.", parent=dialog)

        # 2. Kein Host
        dialog.edit_shop_name.setText("Shop")
        dialog.edit_host.setText("")
        dialog.accept()
        mock_err.assert_called_with("Bitte geben Sie einen Server-Host an.", parent=dialog)

        # 3. Ungültiger Port
        dialog.edit_host.setText("example.com")
        dialog.edit_port.setText("99999")
        dialog.accept()
        mock_err.assert_called_with("Der Port muss zwischen 1 und 65535 liegen.", parent=dialog)

        dialog.edit_port.setText("abc")
        dialog.accept()
        mock_err.assert_called_with("Der Port muss eine gültige Ganzzahl sein.", parent=dialog)


def test_master_password_empty_validation(qapp):
    dialog = MasterPasswordDialog(is_new_setup=False)
    dialog.edit_password.setText("")

    with patch("ui.dialogs.show_error") as mock_err:
        dialog.accept()
        mock_err.assert_called_with("Bitte geben Sie ein Master-Passwort ein.")


def test_show_info_and_confirmation(qapp):
    from ui.dialogs import show_info, ask_confirmation
    from PySide6.QtWidgets import QMessageBox

    with patch.object(QMessageBox, "information") as mock_info:
        show_info("Nachricht", title="Titel")
        mock_info.assert_called_once()

    with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        assert ask_confirmation("Sicher?") is True

    with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No):
        assert ask_confirmation("Sicher?") is False
