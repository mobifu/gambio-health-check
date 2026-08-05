from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QHBoxLayout,
    QComboBox,
    QMessageBox,
)


class MasterPasswordDialog(QDialog):
    """
    Dialog zur Abfrage des Master-Passworts beim Programmstart.
    """

    def __init__(self, is_new_setup=False):
        super().__init__()
        self.is_new_setup = is_new_setup
        self.setWindowTitle("Master-Passwort festlegen" if is_new_setup else "Master-Passwort eingeben")
        self.setMinimumWidth(300)

        self.layout_main = QVBoxLayout()
        self.label_info = QLabel(
            "Neues Master-Passwort festlegen:" if is_new_setup else "Bitte Master-Passwort eingeben:"
        )

        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)

        if self.is_new_setup:
            self.label_confirm = QLabel("Passwort bestätigen:")
            self.edit_confirm = QLineEdit()
            self.edit_confirm.setEchoMode(QLineEdit.Password)
            self.layout_main.addWidget(self.label_info)
            self.layout_main.addWidget(self.edit_password)
            self.layout_main.addWidget(self.label_confirm)
            self.layout_main.addWidget(self.edit_confirm)
        else:
            self.layout_main.addWidget(self.label_info)
            self.layout_main.addWidget(self.edit_password)

        self.btn_unlock = QPushButton("Entsperren")
        self.btn_unlock.setDefault(True)
        self.btn_unlock.clicked.connect(self.accept)

        self.layout_main.addWidget(self.btn_unlock)
        self.setLayout(self.layout_main)

    def get_password(self):
        """Gibt das eingegebene Passwort zurück."""
        return self.edit_password.text()

    def accept(self):
        """Validiert die Eingabe beim Schließen des Dialogs."""
        if self.is_new_setup:
            if self.edit_password.text() != self.edit_confirm.text():
                show_error("Die Passwörter stimmen nicht überein. Bitte prüfen Sie Ihre Eingabe.")
                return
        super().accept()


class ShopProfileDialog(QDialog):
    """
    Dialog zum Erstellen und Bearbeiten von Shop-Profilen.
    Erfasst Host, Port, Benutzername, Passwort und Protokoll.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Shop-Profil hinzufügen/bearbeiten")
        self.setMinimumWidth(350)

        self.layout_main = QVBoxLayout(self)

        # Eingabefelder mit sprechenden Namen
        self.layout_main.addWidget(QLabel("Shop-Name:"))
        self.edit_shop_name = QLineEdit()
        self.layout_main.addWidget(self.edit_shop_name)

        self.layout_main.addWidget(QLabel("Host:"))
        self.edit_host = QLineEdit()
        self.layout_main.addWidget(self.edit_host)

        self.layout_main.addWidget(QLabel("Port:"))
        self.edit_port = QLineEdit()
        self.layout_main.addWidget(self.edit_port)

        self.layout_main.addWidget(QLabel("Benutzername:"))
        self.edit_username = QLineEdit()
        self.layout_main.addWidget(self.edit_username)

        self.layout_main.addWidget(QLabel("Passwort:"))
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.layout_main.addWidget(self.edit_password)

        self.layout_main.addWidget(QLabel("Protokoll:"))
        self.combo_protocol = QComboBox()
        self.combo_protocol.addItems(["FTP", "SFTP", "HTTPS"])
        self.layout_main.addWidget(self.combo_protocol)

        # Aktions-Buttons
        self.layout_buttons = QHBoxLayout()
        self.btn_save = QPushButton("Speichern")
        self.btn_cancel = QPushButton("Abbrechen")

        self.btn_save.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

        self.layout_buttons.addWidget(self.btn_save)
        self.layout_buttons.addWidget(self.btn_cancel)
        self.layout_main.addLayout(self.layout_buttons)


def show_error(message: str):
    """Zeigt eine Fehlermeldung in einem modalen Dialog an."""
    QMessageBox.critical(None, "Fehler", message)
