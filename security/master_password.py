"""
security/master_password.py

Verwaltet das Master-Passwort, Brute-Force-Schutz und Session-Locking.
"""

from __future__ import annotations

import getpass
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional, Union

from security.exceptions import (
    InvalidMasterPasswordError,
    SessionExpiredError,
    TooManyFailedAttemptsError,
)


class SessionLock:
    """Verwaltet den Session-Status basierend auf zeitlicher Inaktivität."""

    DEFAULT_TIMEOUT_MINUTES: int = 10

    def __init__(
        self,
        config_path: Union[str, Path] = "config.dat",
        timeout_minutes: Union[int, float] = DEFAULT_TIMEOUT_MINUTES,
    ) -> None:
        # Pfad strikt via pathlib.Path.resolve() absichern
        self.config_path: str = str(Path(config_path).resolve())
        self.timeout: timedelta = timedelta(minutes=timeout_minutes)
        self.last_activity: datetime = datetime.now()

    def update_activity(self) -> None:
        """Aktualisiert den Zeitstempel der letzten Aktivität."""
        self.last_activity = datetime.now()

    def is_expired(self) -> bool:
        """Prüft, ob der Inaktivitätszeitraum überschritten wurde."""
        return datetime.now() - self.last_activity > self.timeout

    def remaining_seconds(self) -> float:
        """Gibt die verbleibende Session-Gültigkeit in Sekunden zurück (mindestens 0.0)."""
        elapsed = datetime.now() - self.last_activity
        remaining = self.timeout.total_seconds() - elapsed.total_seconds()
        return max(0.0, remaining)

    def require_active_session(self) -> None:
        """Wirft SessionExpiredError, falls die Session nicht mehr gültig ist."""
        if self.is_expired():
            raise SessionExpiredError("Session abgelaufen. Bitte erneut anmelden.")


class MasterPasswordManager:
    """
    Verwaltet die Abfrage und Validierung des Master-Passworts.
    Implementiert Brute-Force-Schutz durch exponentielle Verzögerung.
    Das Passwort wird nur im RAM vorgehalten und niemals geloggt.
    """

    MAX_ATTEMPTS_BEFORE_DELAY: int = 3
    MAX_FAILED_ATTEMPTS: int = 10
    MAX_DELAY_SECONDS: int = 32

    def __init__(
        self,
        is_new_setup: bool = False,
        session_lock: Optional[SessionLock] = None,
        timeout_minutes: int = SessionLock.DEFAULT_TIMEOUT_MINUTES,
    ) -> None:
        self.is_new_setup: bool = is_new_setup
        self._master_password: Optional[str] = None
        self._failed_attempts: int = 0
        self._max_attempts_before_delay: int = self.MAX_ATTEMPTS_BEFORE_DELAY
        self._session_lock: SessionLock = (
            session_lock if session_lock is not None else SessionLock(timeout_minutes=timeout_minutes)
        )

    @property
    def failed_attempts(self) -> int:
        """Gibt die Anzahl bisheriger Fehlversuche zurück."""
        return self._failed_attempts

    @property
    def session_lock(self) -> SessionLock:
        """Gibt das zugeordnete SessionLock-Objekt zurück."""
        return self._session_lock

    def has_password(self) -> bool:
        """Prüft, ob aktuell ein Passwort im Speicher hinterlegt ist."""
        return self._master_password is not None

    def prompt_password(self, prompt: str = "Master-Passwort eingeben: ") -> str:
        """Fragt das Passwort sicher über das Terminal ab (ohne Echo)."""
        return getpass.getpass(prompt)

    def set_password(self, password: str) -> None:
        """
        Speichert das Passwort im RAM.
        Setzt Fehlversuche zurück und aktualisiert die Session-Aktivität.
        """
        self._master_password = password
        self.reset_attempts()
        self.update_activity()

    def get_password(self) -> Optional[str]:
        """Gibt das aktuell im RAM befindliche Passwort zurück."""
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

    def _handle_failure(self) -> None:
        """
        Interner Mechanismus für Fehlversuche.
        Erzwingt ab dem 3. Versuch eine exponentiell steigende Verzögerung.
        """
        self._failed_attempts += 1

        if self._failed_attempts >= self._max_attempts_before_delay:
            # Verzögerung: 2s, 4s, 8s, 16s, 32s (gedeckelt bei MAX_DELAY_SECONDS)
            delay = min(self.MAX_DELAY_SECONDS, 2 ** (self._failed_attempts - 2))
            time.sleep(delay)

            if self._failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                raise TooManyFailedAttemptsError("Maximale Anzahl an Versuchen erreicht. System gesperrt.")

        raise InvalidMasterPasswordError("Ungültiges Master-Passwort.")

    def clear(self) -> None:
        """Löscht das Passwort aus dem RAM und überschreibt temporäre Speicherbereiche."""
        if self._master_password is not None:
            try:
                pwd_bytes = bytearray(self._master_password.encode("utf-8"))
                for i in range(len(pwd_bytes)):
                    pwd_bytes[i] = 0
                del pwd_bytes
            except Exception:
                pass
        self._master_password = None

    def reset_attempts(self) -> None:
        """Setzt den Fehlversuch-Zähler zurück."""
        self._failed_attempts = 0

    def is_session_expired(self) -> bool:
        """Prüft über das interne SessionLock, ob die Session abgelaufen ist."""
        return self._session_lock.is_expired()

    def update_activity(self) -> None:
        """Aktualisiert den Zeitstempel der letzten Aktivität im SessionLock."""
        self._session_lock.update_activity()

    def require_active_session(self) -> None:
        """Prüft die Session, löscht bei Ablauf das Passwort aus dem RAM und wirft ggf. SessionExpiredError."""
        if self.is_session_expired():
            self.clear()
            raise SessionExpiredError("Session abgelaufen. Bitte erneut anmelden.")
