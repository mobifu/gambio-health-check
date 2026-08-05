import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock
from security.master_password import MasterPasswordManager, SessionLock
from security.exceptions import (
    InvalidMasterPasswordError,
    TooManyFailedAttemptsError,
    SessionExpiredError,
)


def test_master_password_setting():
    manager = MasterPasswordManager()
    manager.set_password("test_pass")
    assert manager.get_password() == "test_pass"


def test_failed_attempts_delay(monkeypatch):
    # Mock time.sleep um die Tests nicht zu verlangsamen
    mock_sleep = MagicMock()
    monkeypatch.setattr(time, "sleep", mock_sleep)

    manager = MasterPasswordManager()

    # 2 Fehlversuche (noch keine Verzögerung)
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    assert mock_sleep.call_count == 0

    # 3. Fehlversuch (Verzögerung startet: 2^(3-2) = 2s)
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(2)


def test_too_many_attempts():
    manager = MasterPasswordManager()
    # Simuliere 10 Fehlversuche
    manager._failed_attempts = 9
    with pytest.raises(TooManyFailedAttemptsError):
        manager._handle_failure()


def test_session_lock_expiration(monkeypatch):
    # Session mit 0 Minuten Timeout für sofortigen Ablauf
    lock = SessionLock(timeout_minutes=0)
    assert lock.is_expired() is True

    with pytest.raises(SessionExpiredError):
        lock.require_active_session()


def test_session_activity_update():
    lock = SessionLock(timeout_minutes=10)
    old_time = lock.last_activity
    time.sleep(0.01)
    lock.update_activity()
    assert lock.last_activity > old_time


def test_verify_password_success():
    manager = MasterPasswordManager()
    manager._failed_attempts = 5

    success = manager.verify_password("correct", lambda p: p == "correct")
    assert success is True
    assert manager._failed_attempts == 0


def test_session_expired_clears_password():
    manager = MasterPasswordManager()
    manager.set_password("mypassword")

    # Simuliere Inaktivität (Timeout auf 0 setzen)
    manager._session_lock.timeout = timedelta(minutes=0)

    assert manager.is_session_expired() is True
    with pytest.raises(SessionExpiredError):
        manager.require_active_session()

    # Passwort muss aus dem RAM genullt sein!
    assert manager.get_password() is None


def test_prompt_password(monkeypatch):
    manager = MasterPasswordManager()
    monkeypatch.setattr("getpass.getpass", lambda prompt: "secret_input")
    assert manager.prompt_password() == "secret_input"


def test_clear_method_robustness():
    manager = MasterPasswordManager()
    manager.set_password("abc")
    manager.clear()
    assert manager.get_password() is None


def test_brute_force_exponential_backoff_steps(monkeypatch):
    mock_sleep = MagicMock()
    monkeypatch.setattr(time, "sleep", mock_sleep)

    manager = MasterPasswordManager()
    # Versuche 1 & 2: Keine Verzögerung
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    assert mock_sleep.call_count == 0

    # Versuch 3: 2s Verzögerung (2^(3-2))
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(2)

    # Versuch 4: 4s Verzögerung (2^(4-2))
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(4)

    # Versuch 5: 8s Verzögerung (2^(5-2))
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(8)

    # Versuch 6: 16s Verzögerung (2^(6-2))
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(16)

    # Versuch 7: 32s Verzögerung (2^(7-2))
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(32)

    # Versuch 8 & 9: Gedeckelt auf maximal 32s Verzögerung
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(32)
    with pytest.raises(InvalidMasterPasswordError):
        manager.verify_password("wrong", lambda p: False)
    mock_sleep.assert_called_with(32)

    # Versuch 10: TooManyFailedAttemptsError sperrt das System
    with pytest.raises(TooManyFailedAttemptsError):
        manager.verify_password("wrong", lambda p: False)


def test_session_lock_inactivity_clears_ram():
    manager = MasterPasswordManager()
    manager.set_password("highly_sensitive_master_pwd")

    # Simuliere Inaktivität durch Zurücksetzen des last_activity Timestamps
    manager._session_lock.last_activity = datetime.now() - timedelta(minutes=11)

    # require_active_session muss fehlschlagen und das Passwort im RAM nullen
    with pytest.raises(SessionExpiredError):
        manager.require_active_session()

    assert manager.get_password() is None
