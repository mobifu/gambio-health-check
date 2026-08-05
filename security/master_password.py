import time
import getpass
from pathlib import Path
from datetime import datetime, timedelta
from typing import Callable, Optional
from security.exceptions import (
    InvalidMasterPasswordError,
    TooManyFailedAttemptsError,
    SessionExpiredError,
)


class MasterPasswordManager:
    """
    Verwaltet die Abfrage und Validierung des Master-Passworts.
    Implementiert Brute-Force-Schutz durch exponentielle Verzögerung.
    Das Passwort wird nur im RAM vorgehalten und niemals geloggt.
    """

    def __init__(self, is_new_setup=False):
        super().__init__()
        self.is_new_setup = is_new_setup
        self._master_password: Optional[str] = None
        self._failed_attempts: int = 0
        self._max_attempts_before_delay: int = 3
        self._session_lock = SessionLock()

    def prompt_password(self) -> str:
        """
        Fragt das Passwort sicher über das Terminal ab (ohne Echo).
        """
        return getpass.getpass("Master-Passwort eingeben: ")

    def set_password(self, password: str):
        """
        Speichert das Passwort im RAM. Sollte nur nach erfolgreicher Validierung aufgerufen werden.
        Das Passwort wird nach Gebrauch aus dem Speicher gelöscht, um Risiken zu minimieren.
        """
        self._master_password = password
        self.reset_attempts()
        self.update_activity()
        # Sicheres Löschen des Passworts aus der lokalen Variable nach Verwendung
        # Hinweis: In Python ist das komplette Zeroing nicht garantiert, aber wir entfernen Referenzen.
        # Der Aufrufer (z.B. app.py) sollte das Passwort-Objekt nach Nutzung auf None setzen.

    def get_password(self) -> Optional[str]:
        """
        Gibt das aktuell im RAM befindliche Passwort zurück.
        """
        return self._master_password

    def verify_password(self, password: str, test_func: Callable[[str], bool]) -> bool:
        """
        Prüft das Passwort mit einer bereitgestellten Test-Funktion (z.B. Entschlüsselungs-Check).
        Bei Erfolg wird True zurückgegeben, bei Fehler wird der Brute-Force-Schutz ausgelöst.
        """
        if test_func(password):
            self.reset_attempts()
            return True

        self._handle_failure()
        return False

    def _handle_failure(self):
        """
        Interner Mechanismus für Fehlversuche.
        Erzwingt ab dem 3. Versuch eine exponentiell steigende Verzögerung.
        """
        self._failed_attempts += 1

        if self._failed_attempts >= self._max_attempts_before_delay:
            # Verzögerung: 2s, 4s, 8s, 16s, 32s
            delay = min(32, 2 ** (self._failed_attempts - 2))
            time.sleep(delay)

            if self._failed_attempts >= 10:
                raise TooManyFailedAttemptsError("Maximale Anzahl an Versuchen erreicht. System gesperrt.")

        raise InvalidMasterPasswordError("Ungültiges Master-Passwort.")

    def clear(self):
        """Löscht das Passwort aus dem RAM und entfernt Referenzen für den Garbage Collector."""
        # Versuchen, das Passwort zu überschreiben, bevor die Referenz gelöscht wird
        if self._master_password is not None:
            try:
                # Convert to mutable bytearray if possible
                pwd_bytes = bytearray(self._master_password.encode("utf-8"))
                for i in range(len(pwd_bytes)):
                    pwd_bytes[i] = 0
            finally:
                pass
        self._master_password = None

    def reset_attempts(self):
        """Setzt den Fehlversuch-Zähler zurück."""
        self._failed_attempts = 0

    def is_session_expired(self) -> bool:
        """Prüft über den internen SessionLock, ob die Session abgelaufen ist."""
        return self._session_lock.is_expired()

    def update_activity(self):
        """Aktualisiert den Zeitstempel der letzten Aktivität im SessionLock."""
        self._session_lock.update_activity()

    def require_active_session(self):
        """Prüft die Session, löscht bei Ablauf das Passwort aus dem RAM und wirft ggf. SessionExpiredError."""
        if self.is_session_expired():
            self.clear()
            raise SessionExpiredError("Session abgelaufen. Bitte erneut anmelden.")


class SessionLock:
    """
    Verwaltet den Session-Status basierend auf zeitlicher Inaktivität.
    """

    def __init__(self, config_path="config.dat", timeout_minutes: int = 10):
        # Verwende absoluten Pfad, um Pfadmanipulation zu verhindern
        self.config_path = str(Path(config_path).resolve())
        self.timeout = timedelta(minutes=timeout_minutes)
        self.last_activity = datetime.now()

    def update_activity(self):
        """Aktualisiert den Zeitstempel der letzten Aktivität."""
        self.last_activity = datetime.now()

    def is_expired(self) -> bool:
        """Prüft, ob der Inaktivitätszeitraum überschritten wurde."""
        return datetime.now() - self.last_activity > self.timeout

    def require_active_session(self):
        """Wirft eine SessionExpiredError, wenn die Session nicht mehr gültig ist."""
        if self.is_expired():
            raise SessionExpiredError("Session abgelaufen. Bitte erneut anmelden.")
