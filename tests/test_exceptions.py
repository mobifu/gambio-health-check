"""
Unittests für die Sicherheits- und Krypto-Ausnahmen in security.exceptions.
"""

import pytest
from security.exceptions import (
    AuthenticationError,
    CryptoError,
    DecryptionError,
    EncryptionError,
    IntegrityError,
    InvalidMasterPasswordError,
    KeyDerivationError,
    SecurityError,
    SessionExpiredError,
    TooManyFailedAttemptsError,
)


def test_security_error_defaults_and_custom_message():
    err_default = SecurityError()
    assert str(err_default) == SecurityError.DEFAULT_MESSAGE
    assert err_default.message == SecurityError.DEFAULT_MESSAGE
    assert err_default.details == {}
    assert repr(err_default) == f"SecurityError({SecurityError.DEFAULT_MESSAGE!r})"

    err_custom = SecurityError("Benutzerdefinierter Fehler", details={"code": 403})
    assert str(err_custom) == "Benutzerdefinierter Fehler"
    assert err_custom.details == {"code": 403}
    assert "details={'code': 403}" in repr(err_custom)


def test_inheritance_hierarchy():
    assert issubclass(AuthenticationError, SecurityError)
    assert issubclass(CryptoError, SecurityError)
    assert issubclass(KeyDerivationError, CryptoError)
    assert issubclass(EncryptionError, CryptoError)
    assert issubclass(DecryptionError, CryptoError)
    assert issubclass(IntegrityError, SecurityError)

    # InvalidMasterPasswordError erbt sowohl von AuthenticationError als auch CryptoError
    assert issubclass(InvalidMasterPasswordError, AuthenticationError)
    assert issubclass(InvalidMasterPasswordError, CryptoError)
    assert issubclass(InvalidMasterPasswordError, SecurityError)

    assert issubclass(TooManyFailedAttemptsError, AuthenticationError)
    assert issubclass(TooManyFailedAttemptsError, SecurityError)

    assert issubclass(SessionExpiredError, AuthenticationError)
    assert issubclass(SessionExpiredError, SecurityError)


def test_invalid_master_password_error():
    err = InvalidMasterPasswordError()
    assert str(err) == InvalidMasterPasswordError.DEFAULT_MESSAGE
    assert isinstance(err, AuthenticationError)
    assert isinstance(err, CryptoError)
    assert isinstance(err, SecurityError)

    err_custom = InvalidMasterPasswordError("Falsches Passwort eingegeben")
    assert str(err_custom) == "Falsches Passwort eingegeben"


def test_too_many_failed_attempts_error():
    err = TooManyFailedAttemptsError(failed_attempts=5, lockout_duration=16.0)
    assert str(err) == TooManyFailedAttemptsError.DEFAULT_MESSAGE
    assert err.failed_attempts == 5
    assert err.lockout_duration == 16.0
    assert err.details == {"failed_attempts": 5, "lockout_duration": 16.0}

    err_with_custom = TooManyFailedAttemptsError(
        "Konto gesperrt",
        failed_attempts=10,
        lockout_duration=32.0,
        details={"ip": "127.0.0.1"},
    )
    assert str(err_with_custom) == "Konto gesperrt"
    assert err_with_custom.details["ip"] == "127.0.0.1"
    assert err_with_custom.details["failed_attempts"] == 10
    assert err_with_custom.details["lockout_duration"] == 32.0


def test_session_expired_error():
    err = SessionExpiredError(timeout_minutes=15)
    assert str(err) == SessionExpiredError.DEFAULT_MESSAGE
    assert err.timeout_minutes == 15
    assert err.details == {"timeout_minutes": 15}

    err_custom = SessionExpiredError("Session abgelaufen", timeout_minutes=30)
    assert str(err_custom) == "Session abgelaufen"
    assert err_custom.timeout_minutes == 30


def test_crypto_specific_errors():
    kdf_err = KeyDerivationError()
    assert isinstance(kdf_err, CryptoError)
    assert str(kdf_err) == KeyDerivationError.DEFAULT_MESSAGE

    enc_err = EncryptionError()
    assert isinstance(enc_err, CryptoError)
    assert str(enc_err) == EncryptionError.DEFAULT_MESSAGE

    dec_err = DecryptionError()
    assert isinstance(dec_err, CryptoError)
    assert str(dec_err) == DecryptionError.DEFAULT_MESSAGE

    integ_err = IntegrityError()
    assert isinstance(integ_err, SecurityError)
    assert str(integ_err) == IntegrityError.DEFAULT_MESSAGE
