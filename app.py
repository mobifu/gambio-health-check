"""
Haupt-Einstiegspunkt für die Gambio Health Check Desktop-Anwendung.
Initialisiert Logging, Authentifizierung, Konfiguration und die grafische Benutzeroberfläche.
"""

SOFTWARE_VERSION = "1.1.5"

import logging
import sys
from pathlib import Path

try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    # Fallback-Klasse für Umgebungen ohne PySide6 (z. B. Headless CI oder Testumgebungen)
    class QApplication:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def exec(self) -> int:
            return 0


from config.config_manager import ConfigManager
from logging_config import setup_logging
from security.exceptions import InvalidMasterPasswordError, SecurityError
from security.master_password import MasterPasswordManager
from ui.dialogs import MasterPasswordDialog, show_error
from ui.main_window import MainWindow

logger = logging.getLogger(__name__)


def is_initial_setup(config_manager: ConfigManager) -> bool:
    """
    Prüft abgesichert via pathlib.Path.resolve(), ob die Konfigurationsdatei bereits existiert.
    """
    config_file = Path(config_manager.config_path).resolve()
    return not config_file.exists()


def authenticate_user(
    auth_manager: MasterPasswordManager,
    config_manager: ConfigManager,
    is_first_run: bool,
) -> bool:
    """
    Führt den Authentifizierungs-Dialog aus, validiert das Masterpasswort
    und initialisiert die Konfiguration sowie die Benutzersitzung.

    Gibt True zurück, wenn die Authentifizierung erfolgreich war, sonst False.
    """
    login_dialog = MasterPasswordDialog(is_new_setup=is_first_run)
    if not login_dialog.exec():
        logger.info("Authentifizierungs-Dialog durch Benutzer abgebrochen.")
        return False

    password = login_dialog.get_password()
    if not password:
        logger.warning("Anmeldeversuch mit leerem Masterpasswort abgewiesen.")
        show_error("Das Passwort darf nicht leer sein.")
        return False

    try:
        # Konfiguration entschlüsseln und laden
        config_manager.load_config(password)

        # Bei Erstinstallation: Leere Konfiguration speichern, um Masterpasswort zu binden
        if is_first_run:
            config_manager.save_config({}, password)
            logger.info("Erstkonfiguration erfolgreich initialisiert.")

        auth_manager.set_password(password)
        auth_manager.update_activity()
        auth_manager.require_active_session()
        logger.info("Authentifizierung erfolgreich abgeschlossen.")
        return True

    except InvalidMasterPasswordError as err:
        logger.warning("Authentifizierung fehlgeschlagen: Ungültiges Masterpasswort.")
        show_error(str(err))
        return False
    except SecurityError as err:
        logger.error("Sicherheitsfehler während der Authentifizierung: %s", err)
        show_error(f"Sicherheitsfehler: {err}")
        return False
    except Exception as err:  # noqa: BLE001
        logger.error("Unerwarteter Fehler während der Authentifizierung: %s", err)
        show_error(f"Unerwarteter Fehler bei der Authentifizierung: {err}")
        return False


def run_application(
    app: QApplication,
    auth_manager: MasterPasswordManager,
    config_manager: ConfigManager,
) -> int:
    """
    Erstellt und öffnet das Hauptfenster und startet den Event-Loop der Anwendung.
    """
    window = MainWindow(auth_manager, config_manager)
    window.show()
    return app.exec()


def main() -> int:
    """
    Zentraler Einstiegspunkt der Anwendung.
    """
    setup_logging()
    logger.info("Starte Gambio Health Check v%s", SOFTWARE_VERSION)

    app = QApplication(sys.argv)

    auth_manager = MasterPasswordManager()
    config_manager = ConfigManager()

    first_run = is_initial_setup(config_manager)

    if not authenticate_user(auth_manager, config_manager, is_first_run=first_run):
        sys.exit(0)

    exit_code = run_application(app, auth_manager, config_manager)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
