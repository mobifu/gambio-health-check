"""
Sicherheits- und Krypto-Ausnahmen für das Health-Check-Modul.
"""

from typing import Any, Dict, Optional


class SecurityError(Exception):
    """Basis-Klasse für alle sicherheitsrelevanten Ausnahmen."""

    DEFAULT_MESSAGE: str = "Ein sicherheitsrelevanter Fehler ist aufgetreten."

    def __init__(
        self,
        message: Optional[str] = None,
        *args: Any,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message if message is not None else self.DEFAULT_MESSAGE
        self.details = details if details is not None else {}
        super().__init__(self.message, *args)

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        if self.details:
            return f"{self.__class__.__name__}({self.message!r}, details={self.details!r})"
        return f"{self.__class__.__name__}({self.message!r})"


class AuthenticationError(SecurityError):
    """Wird geworfen bei Fehlern während der Benutzer- oder Passwort-Authentifizierung."""

    DEFAULT_MESSAGE: str = "Authentifizierungsfehler aufgetreten."


class CryptoError(SecurityError):
    """Basis-Ausnahme für kryptographische Operationen."""

    DEFAULT_MESSAGE: str = "Kryptographische Operation fehlgeschlagen."


class KeyDerivationError(CryptoError):
    """Wird geworfen, wenn die Schlüsselableitung (z. B. PBKDF2) fehlschlägt."""

    DEFAULT_MESSAGE: str = "Schlüsselableitung fehlgeschlagen."


class EncryptionError(CryptoError):
    """Wird geworfen, wenn ein Verschlüsselungsvorgang fehlschlägt."""

    DEFAULT_MESSAGE: str = "Verschlüsselung der Daten fehlgeschlagen."


class DecryptionError(CryptoError):
    """Wird geworfen, wenn ein Entschlüsselungsvorgang fehlschlägt."""

    DEFAULT_MESSAGE: str = "Entschlüsselung fehlgeschlagen."


class IntegrityError(SecurityError):
    """Wird geworfen, wenn Integritätsprüfungen (z. B. MAC, Hash oder GCM-Tag) fehlschlagen."""

    DEFAULT_MESSAGE: str = "Integritätsprüfung fehlgeschlagen. Daten wurden manipuliert oder beschädigt."


class InvalidMasterPasswordError(AuthenticationError, CryptoError):
    """Wird geworfen, wenn das Master-Passwort falsch ist oder die verschlüsselte Datei manipuliert wurde."""

    DEFAULT_MESSAGE: str = "Das Master-Passwort ist ungültig oder die verschlüsselten Daten sind korrupt."


class TooManyFailedAttemptsError(AuthenticationError):
    """
    Wird geworfen, wenn zu viele Fehlversuche beim Master-Passwort auftreten
    und der Brute-Force-Schutz das System sperrt.
    """

    DEFAULT_MESSAGE: str = "Maximale Anzahl an Fehlversuchen erreicht. Das System wurde temporär gesperrt."

    def __init__(
        self,
        message: Optional[str] = None,
        *args: Any,
        failed_attempts: Optional[int] = None,
        lockout_duration: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged_details = dict(details) if details else {}
        if failed_attempts is not None:
            merged_details["failed_attempts"] = failed_attempts
        if lockout_duration is not None:
            merged_details["lockout_duration"] = lockout_duration

        self.failed_attempts = failed_attempts
        self.lockout_duration = lockout_duration
        super().__init__(message, *args, details=merged_details)


class SessionExpiredError(AuthenticationError):
    """Wird geworfen, wenn die Session-Zeit durch Inaktivität überschritten wurde."""

    DEFAULT_MESSAGE: str = "Die Session ist durch Inaktivität abgelaufen. Bitte erneut authentifizieren."

    def __init__(
        self,
        message: Optional[str] = None,
        *args: Any,
        timeout_minutes: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged_details = dict(details) if details else {}
        if timeout_minutes is not None:
            merged_details["timeout_minutes"] = timeout_minutes

        self.timeout_minutes = timeout_minutes
        super().__init__(message, *args, details=merged_details)


__all__ = [
    "SecurityError",
    "AuthenticationError",
    "CryptoError",
    "KeyDerivationError",
    "EncryptionError",
    "DecryptionError",
    "IntegrityError",
    "InvalidMasterPasswordError",
    "TooManyFailedAttemptsError",
    "SessionExpiredError",
]
