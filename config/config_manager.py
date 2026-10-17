"""
Modul zur sicheren Verwaltung verschlüsselter Konfigurationsdaten.
"""

import base64
import copy
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Union

from security.crypto import CryptoManager
from security.exceptions import InvalidMasterPasswordError

logger = logging.getLogger(__name__)

# Standardkonfiguration
DEFAULT_CONFIG: Dict[str, Any] = {
    "profiles": [],
    "excluded_files": "paypal3.php",
    "max_log_age": 7,
    "last_selected_profile_name": "",
}

CONFIG_VERSION: int = 1


class ConfigManager:
    """
    Verwaltet das Laden und Speichern der verschlüsselten Konfiguration.
    Nutzt CryptoManager für die Verschlüsselung und stellt atomares Schreiben sicher.
    """

    def __init__(self, config_path: Union[str, Path] = "config.dat") -> None:
        """
        Initialisiert den ConfigManager mit einem gesicherten Pfad.
        """
        self._path: Path = Path(config_path).resolve()
        self.config_path: str = str(self._path)
        self._data: Dict[str, Any] = self._get_default_config()

    @staticmethod
    def _get_default_config() -> Dict[str, Any]:
        """
        Gibt eine frische Kopie der Standardkonfiguration zurück.
        """
        return copy.deepcopy(DEFAULT_CONFIG)

    def exists(self) -> bool:
        """
        Prüft, ob die Konfigurationsdatei physisch existiert.
        """
        return self._path.is_file()

    def get_all_data(self) -> Dict[str, Any]:
        """
        Gibt eine vollständige Kopie der aktuellen internen Konfigurationsdaten zurück.
        """
        return copy.deepcopy(self._data)

    def save_config(self, data: Dict[str, Any], password: str) -> None:
        """
        Verschlüsselt und speichert die Konfigurationsdaten atomar.
        """
        if not isinstance(password, str) or not password:
            raise ValueError("Das Passwort für die Verschlüsselung darf nicht leer sein.")

        tmp_path: Path = self._path.with_name(f"{self._path.name}.tmp")
        try:
            salt = CryptoManager.generate_salt()
            # Konvertierung des Dicts in UTF-8 Bytes
            raw_json = json.dumps(data).encode("utf-8")

            # CryptoManager.encrypt liefert einen UTF-8 String (Fernet-Token)
            token = CryptoManager.encrypt(raw_json, password, salt)

            payload = {
                "version": CONFIG_VERSION,
                "salt": base64.b64encode(salt).decode("utf-8"),
                "token": token,
            }

            # Atomares Schreiben über temporäre Datei
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            os.replace(tmp_path, self._path)

            # Restriktive Dateizugriffsrechte (nur Besitzer)
            try:
                os.chmod(self.config_path, 0o600)
            except Exception:
                # chmod schlägt auf einigen Systemen (z.B. Windows) fehl
                pass

            logger.info("Konfiguration erfolgreich verschlüsselt und atomar gespeichert.")
        except Exception as e:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            logger.error("Fehler beim Speichern der Konfiguration: %s", type(e).__name__)
            raise IOError(f"Fehler beim Speichern der Konfiguration: {str(e)}") from e

    def load_config(self, password: str) -> Dict[str, Any]:
        """
        Lädt und entschlüsselt die Konfiguration.
        Gibt ein leeres Dict zurück, wenn die Datei nicht existiert.
        """
        if not isinstance(password, str) or not password:
            raise InvalidMasterPasswordError("Das Master-Passwort darf nicht leer sein.")

        if not self._path.exists():
            logger.debug("Konfigurationsdatei existiert nicht; Standardkonfiguration bleibt erhalten.")
            return {}

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                container = json.load(f)

            if not isinstance(container, dict) or "salt" not in container or "token" not in container:
                raise ValueError("Ungültiges Konfigurationscontainer-Format.")

            # Salt zurückgewinnen
            salt = base64.b64decode(container["salt"])
            token = container["token"]

            # Entschlüsselung (liefert bytes)
            decrypted = CryptoManager.decrypt(token, password, salt)

            # JSON Deserialisierung
            loaded_json = json.loads(decrypted.decode("utf-8"))
            if not isinstance(loaded_json, dict):
                raise ValueError("Entschlüsselte Nutzdaten müssen ein JSON-Objekt sein.")

            # Merge mit Defaults, damit neu hinzugefügte Standardeinstellungen existieren
            merged_data = self._get_default_config()
            merged_data.update(loaded_json)
            self._data = merged_data

            logger.info("Konfiguration erfolgreich entschlüsselt und geladen.")
            return self._data
        except (
            json.JSONDecodeError,
            KeyError,
            ValueError,
            base64.binascii.Error,
            InvalidMasterPasswordError,
        ):
            logger.warning("Ungültiges Master-Passwort oder beschädigte Konfigurationsdatei.")
            raise InvalidMasterPasswordError(
                "Das Master-Passwort ist falsch oder die Konfigurationsdaten sind beschädigt."
            )
        except Exception as e:
            logger.error("Unerwarteter Fehler beim Laden der Konfiguration: %s", type(e).__name__)
            raise InvalidMasterPasswordError(f"Ein unerwarteter Fehler ist aufgetreten: {type(e).__name__}") from e

    def get_profiles(self) -> List[Dict[str, Any]]:
        """
        Gibt die Liste der gespeicherten Shop-Profile zurück.
        """
        return self._data.get("profiles", [])

    def set_profiles(self, profiles: List[Dict[str, Any]]) -> None:
        """
        Setzt die Liste der Shop-Profile im internen Datenmodell.
        """
        if not isinstance(profiles, list):
            raise TypeError("Profile müssen als Liste übergeben werden.")
        self._data["profiles"] = profiles

    def get_excluded_files(self) -> str:
        """
        Gibt die kommagetrennte Liste der zu ignorierenden Dateien zurück.
        """
        return self._data.get("excluded_files", DEFAULT_CONFIG["excluded_files"])

    def set_excluded_files(self, files_str: str) -> None:
        """
        Setzt die Liste der zu ignorierenden Dateien.
        """
        if not isinstance(files_str, str):
            raise TypeError("files_str muss ein String sein.")
        self._data["excluded_files"] = files_str

    def get_max_log_age(self) -> int:
        """
        Gibt das maximale Alter der Logfiles in Tagen zurück.
        """
        return self._data.get("max_log_age", DEFAULT_CONFIG["max_log_age"])

    def set_max_log_age(self, days: int) -> None:
        """
        Setzt das maximale Alter der Logfiles in Tagen.
        """
        if not isinstance(days, int) or days < 0:
            raise ValueError("max_log_age muss ein nicht-negativer Integer sein.")
        self._data["max_log_age"] = days

    def get_last_selected_profile_name(self) -> str:
        """
        Gibt den Namen des zuletzt ausgewählten Profils zurück.
        """
        return self._data.get("last_selected_profile_name", "")

    def set_last_selected_profile_name(self, name: str) -> None:
        """
        Setzt den Namen des zuletzt ausgewählten Profils.
        """
        if not isinstance(name, str):
            raise TypeError("name muss ein String sein.")
        self._data["last_selected_profile_name"] = name

    def save_current_config(self, password: str) -> None:
        """
        Speichert die aktuelle interne Konfiguration mit dem gegebenen Passwort.
        """
        self.save_config(self._data, password)

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """
        Ändert das Master-Passwort, indem die Konfiguration mit dem alten Passwort geladen
        und dann mit dem neuen Passwort gespeichert wird.
        """
        current_data = self.load_config(old_password)
        self.save_config(current_data, new_password)
