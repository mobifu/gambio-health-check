import pytest
from security.crypto import CryptoManager
from security.exceptions import InvalidMasterPasswordError


def test_encryption_decryption_cycle():
    """
    Testet den vollständigen Verschlüsselungs- und Entschlüsselungszyklus.
    Stellt sicher, dass Bytes korrekt verarbeitet werden und der Token ein UTF-8 String ist.
    """
    password = "SafePassword123!"
    salt = CryptoManager.generate_salt()
    original_data = b"Secret API Key"  # Muss Bytes sein

    encrypted_token = CryptoManager.encrypt(original_data, password, salt)
    decrypted_data = CryptoManager.decrypt(encrypted_token, password, salt)

    # Prüfen, ob die entschlüsselten Daten den Originaldaten entsprechen
    assert decrypted_data == original_data
    # Prüfen, ob der Token ein String ist
    assert isinstance(encrypted_token, str)
    # Prüfen, ob der Token nicht gleich den Originaldaten ist (verschlüsselt)
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

    # Token manipulieren (z.B. ein Zeichen ändern)
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
    salt = b"16bytesalt123456"  # Festes Salt für Determinismus

    key1 = CryptoManager.derive_key(password, salt)
    key2 = CryptoManager.derive_key(password, salt)

    assert key1 == key2
