SOFTWARE_VERSION = "1.1.4"
import sys
import os

try:
    from PySide6.QtWidgets import QApplication, QMessageBox
except ImportError:
    # Fallback for environments without PySide6 – use simple console messages
    class QApplication:
        def __init__(self, *args, **kwargs):
            pass

        def exec(self):
            return 0

    class QMessageBox:
        @staticmethod
        def critical(parent, title, message):
            print(f"[ERROR] {title}: {message}")


from ui.main_window import MainWindow
from ui.dialogs import MasterPasswordDialog, show_error
from security.master_password import MasterPasswordManager
from security.exceptions import InvalidMasterPasswordError
from config.config_manager import ConfigManager
from logging_config import setup_logging


def main():
    setup_logging()
    app = QApplication(sys.argv)

    # Initialisierung der Manager
    auth_manager = MasterPasswordManager()
    config_manager = ConfigManager()

    # Prüfen, ob es die erste Ausführung ist (Datei existiert noch nicht)
    is_first_run = not os.path.exists(config_manager.config_path)

    # Login Flow
    login_dialog = MasterPasswordDialog(is_new_setup=is_first_run)

    if login_dialog.exec():
        password = login_dialog.get_password()

        if not password:
            show_error("Das Passwort darf nicht leer sein.")
            sys.exit(0)

        try:
            # Konfiguration laden
            config_manager.load_config(password)

            # Bei Neuinstallation: Leere Konfiguration speichern, um das Passwort zu "locken"
            if is_first_run:
                config_manager.save_config({}, password)

            auth_manager.set_password(password)

            # Session-Lock vorbereiten
            auth_manager.update_activity()
            auth_manager.require_active_session()

            # Hauptfenster starten
            window = MainWindow(auth_manager, config_manager)
            window.show()
            sys.exit(app.exec())

        except InvalidMasterPasswordError as e:
            show_error(str(e))

    sys.exit(0)


if __name__ == "__main__":
    main()
