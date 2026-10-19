import pytest

from security.crypto import CryptoManager
from security.exceptions import InvalidMasterPasswordError


def test_encryption_decryption_cycle():
    """
    Testet den vollständigen Verschlüsselungs- und Entschlüsselungszyklus (Fernet).
    Stellt sicher, dass Bytes korrekt verarbeitet werden und der Token ein UTF-8 String ist.
    """
    password = "SafePassword123!"
    salt = CryptoManager.generate_salt()
    original_data = b"Secret API Key"

    encrypted_token = CryptoManager.encrypt(original_data, password, salt)
    decrypted_data = CryptoManager.decrypt(encrypted_token, password, salt)

    assert decrypted_data == original_data
    assert isinstance(encrypted_token, str)
    assert encrypted_token != original_data.decode("utf-8")


def test_wrong_password_fails():
    """
    Testet, ob die Entschlüsselung mit einem falschen Passwort fehlschlägt
    und InvalidMasterPasswordError geworfen wird.
    """
    password = "correct"
    wrong_password = "wrong"
    salt = CryptoManager.generate_salt()
    original_data = b"some data"
    encrypted_token = CryptoManager.encrypt(original_data, password, salt)

    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt(encrypted_token, wrong_password, salt)


def test_manipulated_token_fails():
    """
    Testet, ob die Entschlüsselung eines manipulierten Tokens fehlschlägt
    und InvalidMasterPasswordError geworfen wird.
    """
    password = "SafePassword123!"
    salt = CryptoManager.generate_salt()
    original_data = b"Secret API Key"

    encrypted_token = CryptoManager.encrypt(original_data, password, salt)

    manipulated_token = list(encrypted_token)
    manipulated_token[0] = "X" if manipulated_token[0] != "X" else "Y"
    manipulated_token = "".join(manipulated_token)

    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt(manipulated_token, password, salt)


def test_salt_changes_key():
    """
    Testet, ob unterschiedliche Salts bei gleichem Passwort und Klartext
    zu unterschiedlichen verschlüsselten Tokens führen.
    """
    password = "MySecurePassword"
    original_data = b"Sensitive Information"

    salt1 = CryptoManager.generate_salt()
    salt2 = CryptoManager.generate_salt()

    token1 = CryptoManager.encrypt(original_data, password, salt1)
    token2 = CryptoManager.encrypt(original_data, password, salt2)

    assert token1 != token2


def test_key_derivation_is_deterministic():
    """
    Testet, ob die Schlüsselableitung deterministisch ist:
    Gleiches Passwort und gleiches Salt müssen den gleichen Schlüssel ergeben.
    """
    password = "DeterministicPassword"
    salt = b"16bytesalt123456"

    key1 = CryptoManager.derive_key(password, salt)
    key2 = CryptoManager.derive_key(password, salt)

    assert key1 == key2


def test_generate_salt_custom_length_and_validation():
    """
    Testet die Erzeugung von Salts mit individueller Länge sowie Validierungsfehler.
    """
    salt = CryptoManager.generate_salt(32)
    assert len(salt) == 32
    assert isinstance(salt, bytes)

    with pytest.raises(ValueError):
        CryptoManager.generate_salt(8)


def test_derive_key_input_validation():
    """
    Testet Validierungsprüfungen für derive_key und derive_key_raw.
    """
    salt = b"16bytesalt123456"

    with pytest.raises(ValueError):
        CryptoManager.derive_key_raw("", salt)

    with pytest.raises(ValueError):
        CryptoManager.derive_key_raw("password", b"tooshort")


def test_fernet_data_validation():
    """
    Testet Validierung des Datentyps für Fernet-Verschlüsselung und Entschlüsselung.
    """
    salt = CryptoManager.generate_salt()

    with pytest.raises(TypeError):
        CryptoManager.encrypt("nicht_bytes", "pwd", salt)  # type: ignore

    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt("", "pwd", salt)

    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt("ungueltiger_token", "pwd", salt)


def test_aes_gcm_raw_cycle():
    """
    Testet den Rohdaten-Verschlüsselungszyklus mit AES-256-GCM.
    """
    salt = CryptoManager.generate_salt()
    raw_key = CryptoManager.derive_key_raw("GcmSecretPassword123", salt)
    data = b"Hochsensible API-Credentials und Tokens"

    payload = CryptoManager.encrypt_aes_gcm(data, raw_key)
    # Nonce (12 Bytes) + Ciphertext + Tag (16 Bytes)
    assert len(payload) == len(data) + 12 + 16

    decrypted = CryptoManager.decrypt_aes_gcm(payload, raw_key)
    assert decrypted == data


def test_aes_gcm_associated_data():
    """
    Testet AES-256-GCM mit Authenticated Associated Data (AAD).
    """
    salt = CryptoManager.generate_salt()
    raw_key = CryptoManager.derive_key_raw("GcmSecretPassword123", salt)
    data = b"Geheime Konfiguration"
    aad = b"context=profile_123"

    payload = CryptoManager.encrypt_aes_gcm(data, raw_key, associated_data=aad)
    decrypted = CryptoManager.decrypt_aes_gcm(payload, raw_key, associated_data=aad)
    assert decrypted == data

    # Falsche AAD muss Entschlüsselung verweigern
    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt_aes_gcm(payload, raw_key, associated_data=b"wrong_context")


def test_aes_gcm_tampering():
    """
    Testet, dass Manipulation an Nonce oder Chiffretext zur Zurückweisung führt.
    """
    salt = CryptoManager.generate_salt()
    raw_key = CryptoManager.derive_key_raw("GcmSecretPassword123", salt)
    data = b"Payload for tampering test"

    payload = bytearray(CryptoManager.encrypt_aes_gcm(data, raw_key))

    # Ciphertext manipulieren
    payload[-1] ^= 0x01
    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt_aes_gcm(bytes(payload), raw_key)

    # Zu kurzes Payload
    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt_aes_gcm(b"short", raw_key)


def test_aes_gcm_key_validation():
    """
    Testet, dass ungültige Schlüssellängen bei AES-GCM abgewiesen werden.
    """
    data = b"Secret data"
    with pytest.raises(ValueError):
        CryptoManager.encrypt_aes_gcm(data, b"16_byte_key_only")

    with pytest.raises(ValueError):
        CryptoManager.decrypt_aes_gcm(b"123456789012" + b"1234567890123456", b"invalid_key")


def test_gcm_convenience_methods():
    """
    Testet die High-Level-Methoden encrypt_gcm und decrypt_gcm.
    """
    password = "MasterPasswordSecure"
    salt = CryptoManager.generate_salt()
    data = b"Database password and API tokens"

    token = CryptoManager.encrypt_gcm(data, password, salt)
    assert isinstance(token, str)

    decrypted = CryptoManager.decrypt_gcm(token, password, salt)
    assert decrypted == data

    # Falsches Passwort
    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt_gcm(token, "WrongPassword", salt)

    # Leerer oder manipulierter Token
    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt_gcm("", password, salt)

    manipulated_token = token[:-2] + "AA"
    with pytest.raises(InvalidMasterPasswordError):
        CryptoManager.decrypt_gcm(manipulated_token, password, salt)
