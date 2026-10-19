"""
Kryptographisches Modul für Schlüsselableitung, Fernet- und AES-256-GCM-Verschlüsselung.
"""

import base64
import secrets
from typing import ClassVar, Optional

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from security.exceptions import InvalidMasterPasswordError


class CryptoManager:
    """
    Verwaltet die kryptographische Schlüsselableitung und symmetrische Verschlüsselung.
    Unterstützt Fernet (AES-128-CBC + HMAC) für Konfigurationscontainer sowie
    natives AES-256-GCM für hochsensible Daten und API-Keys.
    """

    ITERATIONS: ClassVar[int] = 600_000  # OWASP-Empfehlung für PBKDF2-HMAC-SHA256
    SALT_LENGTH: ClassVar[int] = 16  # 128-Bit Standard-Salt
    GCM_NONCE_LENGTH: ClassVar[int] = 12  # 96-Bit Standard-Nonce für AES-GCM
    AES_KEY_LENGTH: ClassVar[int] = 32  # 256-Bit Schlüssellänge

    @staticmethod
    def generate_salt(length: int = SALT_LENGTH) -> bytes:
        """
        Erzeugt ein kryptographisch sicheres Zufalls-Salt über das secrets-Modul.
        """
        if length < 16:
            raise ValueError("Salt-Länge muss mindestens 16 Bytes betragen.")
        return secrets.token_bytes(length)

    @staticmethod
    def derive_key_raw(password: str, salt: bytes, length: int = AES_KEY_LENGTH) -> bytes:
        """
        Leitet rohe Schlüssel-Bytes aus Passwort und Salt mittels PBKDF2-HMAC-SHA256 ab.
        """
        if not isinstance(password, str) or not password:
            raise ValueError("Passwort darf nicht leer sein und muss ein String sein.")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("Salt muss mindestens 16 Bytes lang sein.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=bytes(salt),
            iterations=CryptoManager.ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Leitet einen Fernet-kompatiblen (URL-safe base64) Schlüssel aus Passwort und Salt ab.
        """
        raw_key = CryptoManager.derive_key_raw(password, salt, length=32)
        return base64.urlsafe_b64encode(raw_key)

    @staticmethod
    def encrypt(data: bytes, password: str, salt: bytes) -> str:
        """
        Verschlüsselt Rohdaten (Bytes) mit Fernet und gibt einen Token als UTF-8 String zurück.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Zu verschlüsselnde Daten müssen als Bytes übergeben werden.")
        key = CryptoManager.derive_key(password, salt)
        f = Fernet(key)
        token = f.encrypt(bytes(data))
        return token.decode("utf-8")

    @staticmethod
    def decrypt(token: str, password: str, salt: bytes) -> bytes:
        """
        Entschlüsselt einen Fernet-Token (String) und gibt die Rohdaten (Bytes) zurück.
        Wirft InvalidMasterPasswordError, wenn das Passwort falsch, der Token manipuliert oder ungültig ist.
        """
        if not isinstance(token, str) or not token.strip():
            raise InvalidMasterPasswordError("Master-Passwort ist falsch oder die Konfigurationsdaten sind korrupt.")
        try:
            key = CryptoManager.derive_key(password, salt)
            f = Fernet(key)
            return f.decrypt(token.strip().encode("utf-8"))
        except (InvalidToken, ValueError, TypeError):
            raise InvalidMasterPasswordError("Master-Passwort ist falsch oder die Konfigurationsdaten sind korrupt.")

    @staticmethod
    def encrypt_aes_gcm(data: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
        """
        Verschlüsselt Rohdaten mit AES-256-GCM.
        Erzeugt eine kryptographisch sichere 12-Byte-Nonce über secrets und gibt Nonce + Chiffretext (+ 16-Byte Tag) zurück.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Zu verschlüsselnde Daten müssen als Bytes übergeben werden.")
        if not isinstance(key, (bytes, bytearray)) or len(key) != CryptoManager.AES_KEY_LENGTH:
            raise ValueError(f"AES-256 Schlüssel muss exakt {CryptoManager.AES_KEY_LENGTH} Bytes lang sein.")

        nonce = secrets.token_bytes(CryptoManager.GCM_NONCE_LENGTH)
        aesgcm = AESGCM(bytes(key))
        ciphertext = aesgcm.encrypt(nonce, bytes(data), associated_data)
        return nonce + ciphertext

    @staticmethod
    def decrypt_aes_gcm(payload: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
        """
        Entschlüsselt ein mit AES-256-GCM verschlüsseltes Datenpaket (12-Byte Nonce + Chiffretext + Tag).
        Wirft InvalidMasterPasswordError, wenn der Schlüssel ungültig oder die Daten manipuliert wurden.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise InvalidMasterPasswordError("Verschlüsselte Nutzdaten müssen Bytes sein.")
        if len(payload) < CryptoManager.GCM_NONCE_LENGTH + 16:
            raise InvalidMasterPasswordError("Nutzdaten sind zu kurz für AES-GCM (Nonce/Tag fehlen).")
        if not isinstance(key, (bytes, bytearray)) or len(key) != CryptoManager.AES_KEY_LENGTH:
            raise ValueError(f"AES-256 Schlüssel muss exakt {CryptoManager.AES_KEY_LENGTH} Bytes lang sein.")

        nonce = payload[: CryptoManager.GCM_NONCE_LENGTH]
        ciphertext = payload[CryptoManager.GCM_NONCE_LENGTH :]

        try:
            aesgcm = AESGCM(bytes(key))
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except (InvalidTag, ValueError, TypeError) as exc:
            raise InvalidMasterPasswordError(
                "Entschlüsselung fehlgeschlagen: Ungültiger Schlüssel oder manipulierte Daten."
            ) from exc

    @staticmethod
    def encrypt_gcm(data: bytes, password: str, salt: bytes, associated_data: bytes | None = None) -> str:
        """
        Komfort-Methode: Leitet einen 256-Bit Schlüssel ab, verschlüsselt mit AES-256-GCM und gibt
        einen URL-sicheren Base64-String zurück.
        """
        key = CryptoManager.derive_key_raw(password, salt, length=CryptoManager.AES_KEY_LENGTH)
        payload = CryptoManager.encrypt_aes_gcm(data, key, associated_data)
        return base64.urlsafe_b64encode(payload).decode("utf-8")

    @staticmethod
    def decrypt_gcm(token: str, password: str, salt: bytes, associated_data: bytes | None = None) -> bytes:
        """
        Komfort-Methode: Dekodiert den Base64-Token, leitet den 256-Bit Schlüssel ab und entschlüsselt mit AES-256-GCM.
        """
        if not isinstance(token, str) or not token.strip():
            raise InvalidMasterPasswordError("Token darf nicht leer sein.")
        try:
            payload = base64.urlsafe_b64decode(token.strip().encode("utf-8"))
            key = CryptoManager.derive_key_raw(password, salt, length=CryptoManager.AES_KEY_LENGTH)
            return CryptoManager.decrypt_aes_gcm(payload, key, associated_data)
        except InvalidMasterPasswordError:
            raise
        except (ValueError, TypeError) as exc:
            raise InvalidMasterPasswordError("Ungültiges Token-Format für AES-GCM.") from exc
