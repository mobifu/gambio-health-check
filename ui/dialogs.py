"""
UI-Dialoge für das Gambio Health-Check-Modul.

Enthält modale Dialoge zur Passworteingabe, Profilverwaltung sowie
standardisierte Meldungsdialoge (Fehler, Info, Bestätigung).
"""

from typing import Any

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class MasterPasswordDialog(QDialog):
    """
    Dialog zur Abfrage des Master-Passworts beim Programmstart oder Entsperren.
    """

    def __init__(self, is_new_setup: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.is_new_setup: bool = is_new_setup
        self.setWindowTitle("Master-Passwort festlegen" if is_new_setup else "Master-Passwort eingeben")
        self.setMinimumWidth(320)

        self.layout_main: QVBoxLayout = QVBoxLayout(self)
        self.label_info: QLabel = QLabel(
            "Neues Master-Passwort festlegen:" if is_new_setup else "Bitte Master-Passwort eingeben:"
        )

        self.edit_password: QLineEdit = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.edit_password.setPlaceholderText("Master-Passwort...")

        self.layout_main.addWidget(self.label_info)
        self.layout_main.addWidget(self.edit_password)

        if self.is_new_setup:
            self.label_confirm: QLabel = QLabel("Passwort bestätigen:")
            self.edit_confirm: QLineEdit = QLineEdit()
            self.edit_confirm.setEchoMode(QLineEdit.Password)
            self.edit_confirm.setPlaceholderText("Passwort wiederholen...")
            self.layout_main.addWidget(self.label_confirm)
            self.layout_main.addWidget(self.edit_confirm)

        # Button-Bereich
        self.layout_buttons: QHBoxLayout = QHBoxLayout()
        self.btn_unlock: QPushButton = QPushButton("Festlegen" if is_new_setup else "Entsperren")
        self.btn_unlock.setDefault(True)
        self.btn_unlock.clicked.connect(self.accept)

        self.btn_cancel: QPushButton = QPushButton("Abbrechen")
        self.btn_cancel.clicked.connect(self.reject)

        self.layout_buttons.addWidget(self.btn_unlock)
        self.layout_buttons.addWidget(self.btn_cancel)
        self.layout_main.addLayout(self.layout_buttons)

    def get_password(self) -> str:
        """Gibt das eingegebene Passwort zurück."""
        return self.edit_password.text()

    def accept(self) -> None:
        """Validiert die Passworteingabe vor dem Schließen des Dialogs."""
        pwd = self.edit_password.text()
        if not pwd:
            show_error("Bitte geben Sie ein Master-Passwort ein.")
            return

        if self.is_new_setup:
            confirm_pwd = self.edit_confirm.text()
            if pwd != confirm_pwd:
                show_error("Die Passwörter stimmen nicht überein. Bitte prüfen Sie Ihre Eingabe.")
                return

        super().accept()


class ShopProfileDialog(QDialog):
    """
    Dialog zum Erstellen und Bearbeiten von Gambio-Shop-Profilen.
    Erfasst Shop-Name, Host, Port, Benutzername, Passwort und Protokoll.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Shop-Profil hinzufügen / bearbeiten")
        self.setMinimumWidth(380)

        self.layout_main: QVBoxLayout = QVBoxLayout(self)

        # Eingabefelder
        self.layout_main.addWidget(QLabel("Shop-Name:"))
        self.edit_shop_name: QLineEdit = QLineEdit()
        self.edit_shop_name.setPlaceholderText("z.B. Mein Gambio Shop")
        self.layout_main.addWidget(self.edit_shop_name)

        self.layout_main.addWidget(QLabel("Host:"))
        self.edit_host: QLineEdit = QLineEdit()
        self.edit_host.setPlaceholderText("z.B. ftp.example.com")
        self.layout_main.addWidget(self.edit_host)

        self.layout_main.addWidget(QLabel("Port:"))
        self.edit_port: QLineEdit = QLineEdit()
        self.edit_port.setText("21")
        self.layout_main.addWidget(self.edit_port)

        self.layout_main.addWidget(QLabel("Benutzername:"))
        self.edit_username: QLineEdit = QLineEdit()
        self.edit_username.setPlaceholderText("FTP/SFTP-Benutzername")
        self.layout_main.addWidget(self.edit_username)

        self.layout_main.addWidget(QLabel("Passwort:"))
        pwd_layout = QHBoxLayout()
        self.edit_password: QLineEdit = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.edit_password.setPlaceholderText("Zugangspasswort")
        self.btn_toggle_password: QPushButton = QPushButton("Anzeigen")
        self.btn_toggle_password.setFixedWidth(80)
        self.btn_toggle_password.clicked.connect(self._toggle_password_visibility)
        pwd_layout.addWidget(self.edit_password)
        pwd_layout.addWidget(self.btn_toggle_password)
        self.layout_main.addLayout(pwd_layout)

        self.layout_main.addWidget(QLabel("Protokoll:"))
        self.combo_protocol: QComboBox = QComboBox()
        self.combo_protocol.addItems(["FTP", "SFTP", "HTTPS"])
        self.combo_protocol.currentTextChanged.connect(self._on_protocol_changed)
        self.layout_main.addWidget(self.combo_protocol)

        # Aktions-Buttons
        self.layout_buttons: QHBoxLayout = QHBoxLayout()
        self.btn_save: QPushButton = QPushButton("Speichern")
        self.btn_save.setDefault(True)
        self.btn_cancel: QPushButton = QPushButton("Abbrechen")

        self.btn_save.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

        self.layout_buttons.addWidget(self.btn_save)
        self.layout_buttons.addWidget(self.btn_cancel)
        self.layout_main.addLayout(self.layout_buttons)

    def _toggle_password_visibility(self) -> None:
        """Schaltet die Anzeige des Passworts zwischen Klartext und Maskierung um."""
        if self.edit_password.echoMode() == QLineEdit.Password:
            self.edit_password.setEchoMode(QLineEdit.Normal)
            self.btn_toggle_password.setText("Verbergen")
        else:
            self.edit_password.setEchoMode(QLineEdit.Password)
            self.btn_toggle_password.setText("Anzeigen")

    def _on_protocol_changed(self, protocol: str) -> None:
        """Passt den Standard-Port bei Protokollwechsel automatisch an."""
        current_port = self.edit_port.text().strip()
        if protocol == "SFTP" and current_port in ["21", "443", "", "0"]:
            self.edit_port.setText("22")
        elif protocol == "FTP" and current_port in ["22", "443", "", "0"]:
            self.edit_port.setText("21")
        elif protocol == "HTTPS" and current_port in ["21", "22", "", "0"]:
            self.edit_port.setText("443")

    def get_profile_data(self) -> dict[str, Any]:
        """Gibt die eingegebenen Profildaten als Dictionary zurück."""
        port_text = self.edit_port.text().strip()
        try:
            port = int(port_text) if port_text else 21
        except ValueError:
            port = 21

        return {
            "shop_name": self.edit_shop_name.text().strip(),
            "host": self.edit_host.text().strip(),
            "port": port,
            "username": self.edit_username.text().strip(),
            "password": self.edit_password.text(),
            "protocol": self.combo_protocol.currentText(),
        }

    def set_profile_data(self, data: dict[str, Any]) -> None:
        """Befüllt die Formularfelder mit bestehenden Profildaten."""
        self.edit_shop_name.setText(str(data.get("shop_name", "")))
        self.edit_host.setText(str(data.get("host", "")))
        self.edit_port.setText(str(data.get("port", "21")))
        self.edit_username.setText(str(data.get("username", "")))
        self.edit_password.setText(str(data.get("password", "")))
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.btn_toggle_password.setText("Anzeigen")
        protocol = str(data.get("protocol", "FTP"))
        index = self.combo_protocol.findText(protocol)
        if index >= 0:
            self.combo_protocol.setCurrentIndex(index)

    def accept(self) -> None:
        """Validiert die eingegebenen Daten vor dem Akzeptieren."""
        shop_name = self.edit_shop_name.text().strip()
        host = self.edit_host.text().strip()
        port_text = self.edit_port.text().strip()

        if not shop_name:
            show_error("Bitte geben Sie einen Shop-Namen an.", parent=self)
            return

        if not host:
            show_error("Bitte geben Sie einen Server-Host an.", parent=self)
            return

        if port_text:
            try:
                port = int(port_text)
                if not (1 <= port <= 65535):
                    show_error("Der Port muss zwischen 1 und 65535 liegen.", parent=self)
                    return
            except ValueError:
                show_error("Der Port muss eine gültige Ganzzahl sein.", parent=self)
                return

        super().accept()


def show_error(
    message: str,
    title: str = "Fehler",
    parent: QWidget | None = None,
) -> None:
    """Zeigt eine Fehlermeldung in einem modalen Dialog an."""
    QMessageBox.critical(parent, title, message)


def show_info(
    message: str,
    title: str = "Information",
    parent: QWidget | None = None,
) -> None:
    """Zeigt einen Informationshinweis in einem modalen Dialog an."""
    QMessageBox.information(parent, title, message)


def ask_confirmation(
    message: str,
    title: str = "Bestätigung erforderlich",
    parent: QWidget | None = None,
) -> bool:
    """Zeigt einen Bestätigungsdialog mit Ja/Nein an."""
    result = QMessageBox.question(
        parent,
        title,
        message,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return result == QMessageBox.StandardButton.Yes
