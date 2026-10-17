import pytest
import json
import os
from unittest.mock import patch
from config.config_manager import ConfigManager


@pytest.fixture
def config_manager(tmp_path):
    config_file = tmp_path / "config.dat"
    return ConfigManager(config_path=str(config_file))


def test_initial_config(config_manager):
    assert config_manager.get_profiles() == []
    assert config_manager.get_excluded_files() == "paypal3.php"


def test_profile_management(config_manager):
    new_profiles = [{"shop_name": "Test Shop", "host": "localhost"}]
    config_manager.set_profiles(new_profiles)
    assert config_manager.get_profiles() == new_profiles


def test_excluded_files_management(config_manager):
    config_manager.set_excluded_files("custom.php, test.php")
    assert config_manager.get_excluded_files() == "custom.php, test.php"


@patch("security.crypto.CryptoManager.encrypt")
@patch("security.crypto.CryptoManager.generate_salt")
def test_save_config_logic(mock_salt, mock_encrypt, config_manager, tmp_path):
    mock_salt.return_value = b"16_byte_salt____"
    mock_encrypt.return_value = "encrypted_token"

    data = {"profiles": [], "excluded_files": "none"}
    config_manager.save_config(data, "password")

    assert os.path.exists(config_manager.config_path)

    with open(config_manager.config_path, "r") as f:
        saved_data = json.load(f)
        assert saved_data["token"] == "encrypted_token"
        assert "salt" in saved_data


@patch("security.crypto.CryptoManager.decrypt")
def test_load_config_logic(mock_decrypt, config_manager, tmp_path):
    mock_decrypt.return_value = json.dumps({"profiles": [{"name": "loaded"}], "excluded_files": "test"}).encode("utf-8")

    # Erstelle dummy config file
    payload = {"version": 1, "salt": "c2FsdA==", "token": "dummy"}
    with open(config_manager.config_path, "w") as f:
        json.dump(payload, f)

    loaded = config_manager.load_config("password")
    assert loaded["profiles"][0]["name"] == "loaded"
    assert config_manager.get_excluded_files() == "test"


def test_load_config_non_existent(config_manager):
    # Wenn die Datei nicht existiert, sollte ein leeres Dict zurückgegeben werden
    assert config_manager.load_config("any_password") == {}


def test_load_config_corrupt_or_wrong_password(config_manager):
    from security.exceptions import InvalidMasterPasswordError

    # Erstelle eine ungültige Config-Datei (kein gültiges JSON oder falsche Struktur)
    with open(config_manager.config_path, "w") as f:
        f.write("not-json")

    with pytest.raises(InvalidMasterPasswordError):
        config_manager.load_config("password")


@patch("os.chmod")
def test_save_config_chmod_failure(mock_chmod, config_manager):
    # chmod schlägt fehl (z.B. Windows) - sollte abgefangen werden und nicht abstürzen
    mock_chmod.side_effect = Exception("chmod not allowed")
    data = {"profiles": []}
    config_manager.save_config(data, "password")
    assert os.path.exists(config_manager.config_path)


def test_save_config_write_error(config_manager):
    # Provoziere IOError durch ungültigen Pfad
    bad_manager = ConfigManager(config_path="/invalid_dir/config.dat")
    with pytest.raises(IOError):
        bad_manager.save_config({}, "password")


@patch("security.crypto.CryptoManager.decrypt")
@patch("security.crypto.CryptoManager.encrypt")
@patch("security.crypto.CryptoManager.generate_salt")
def test_change_master_password(mock_salt, mock_encrypt, mock_decrypt, config_manager):
    mock_salt.return_value = b"16_byte_salt____"
    mock_encrypt.return_value = "new_encrypted_token"
    mock_decrypt.return_value = json.dumps({"profiles": [], "excluded_files": "paypal3.php"}).encode("utf-8")

    # Erstelle dummy config file
    payload = {"version": 1, "salt": "c2FsdA==", "token": "old_token"}
    with open(config_manager.config_path, "w") as f:
        json.dump(payload, f)

    config_manager.change_master_password("old_password", "new_password")

    # Verifiziere das Speichern der aktuellen Config
    config_manager.save_current_config("new_password")
    assert os.path.exists(config_manager.config_path)


def test_last_selected_profile_name(config_manager):
    assert config_manager.get_last_selected_profile_name() == ""
    config_manager.set_last_selected_profile_name("Test Shop Profile")
    assert config_manager.get_last_selected_profile_name() == "Test Shop Profile"


def test_exists(config_manager):
    assert not config_manager.exists()
    config_manager.save_config({"profiles": []}, "password")
    assert config_manager.exists()


def test_get_all_data(config_manager):
    data = config_manager.get_all_data()
    assert isinstance(data, dict)
    assert "profiles" in data
    assert "excluded_files" in data
    assert "max_log_age" in data
    # Sicherstellen, dass Kopie zurückgegeben wird
    data["profiles"].append({"test": 1})
    assert config_manager.get_profiles() == []


def test_setter_validations(config_manager):
    # set_profiles
    with pytest.raises(TypeError):
        config_manager.set_profiles("ungueltig")

    # set_excluded_files
    with pytest.raises(TypeError):
        config_manager.set_excluded_files(123)

    # set_max_log_age
    with pytest.raises(ValueError):
        config_manager.set_max_log_age(-1)
    with pytest.raises(ValueError):
        config_manager.set_max_log_age("sieben")

    # set_last_selected_profile_name
    with pytest.raises(TypeError):
        config_manager.set_last_selected_profile_name(12345)


def test_save_config_invalid_password(config_manager):
    with pytest.raises(ValueError):
        config_manager.save_config({}, "")

    with pytest.raises(ValueError):
        config_manager.save_config({}, None)


def test_load_config_invalid_password(config_manager):
    from security.exceptions import InvalidMasterPasswordError

    with pytest.raises(InvalidMasterPasswordError):
        config_manager.load_config("")

    with pytest.raises(InvalidMasterPasswordError):
        config_manager.load_config(None)


@patch("security.crypto.CryptoManager.decrypt")
def test_load_config_merging_with_defaults(mock_decrypt, config_manager):
    # Ältere Konfiguration ohne neuere Keys
    old_data = {"profiles": [{"shop_name": "Old Shop"}]}
    mock_decrypt.return_value = json.dumps(old_data).encode("utf-8")

    payload = {"version": 1, "salt": "c2FsdA==", "token": "dummy"}
    with open(config_manager.config_path, "w") as f:
        json.dump(payload, f)

    loaded = config_manager.load_config("password")
    assert loaded["profiles"] == [{"shop_name": "Old Shop"}]
    # Standardwerte müssen automatisch gemergt worden sein
    assert loaded["excluded_files"] == "paypal3.php"
    assert loaded["max_log_age"] == 7
    assert loaded["last_selected_profile_name"] == ""


@patch("json.dump", side_effect=Exception("Disk full"))
def test_save_config_temp_file_cleanup(mock_dump, config_manager):
    tmp_path = config_manager._path.with_name(f"{config_manager._path.name}.tmp")
    with pytest.raises(IOError):
        config_manager.save_config({}, "password")

    # Sicherstellen, dass keine verwaiste .tmp-Datei zurückbleibt
    assert not tmp_path.exists()
