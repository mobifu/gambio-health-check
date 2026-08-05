import base64
import os
from typing import ClassVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from security.exceptions import InvalidMasterPasswordError


class CryptoManager:
    """
    Verwaltet die Schlüsselableitung und symmetrische Verschlüsselung mittels Fernet (AES + HMAC).
    """

    ITERATIONS: ClassVar[int] = 600_000  # OWASP Empfehlung

    @staticmethod
    def generate_salt() -> bytes:
        """
        Erzeugt ein zufälliges 16-Byte Salt für die Schlüsselableitung.
        """
        return os.urandom(16)

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Leitet einen Fernet-kompatiblen Schlüssel aus Passwort und Salt mittels PBKDF2-HMAC-SHA256 ab.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=CryptoManager.ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def encrypt(data: bytes, password: str, salt: bytes) -> str:
        """
        Verschlüsselt Rohdaten (Bytes) und gibt einen Fernet-Token als UTF-8 String zurück.
        """
        key = CryptoManager.derive_key(password, salt)
        f = Fernet(key)
        token = f.encrypt(data)
        return token.decode("utf-8")

    @staticmethod
    def decrypt(token: str, password: str, salt: bytes) -> bytes:
        """
        Entschlüsselt einen Fernet-Token (String) und gibt die Rohdaten (Bytes) zurück.
        Wirft InvalidMasterPasswordError, wenn das Passwort falsch oder der Token manipuliert ist.
        """
        try:
            key = CryptoManager.derive_key(password, salt)
            f = Fernet(key)
            # Fernet benötigt Bytes für die Entschlüsselung
            return f.decrypt(token.encode("utf-8"))
        except (InvalidToken, ValueError):
            # InvalidToken = Falsches Passwort/Daten manipuliert
            # ValueError = Token-Format ungültig
            raise InvalidMasterPasswordError("Master-Passwort ist falsch oder die Konfigurationsdaten sind korrupt.")
