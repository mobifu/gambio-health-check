import json
import os
import base64
from pathlib import Path
from security.crypto import CryptoManager
from security.exceptions import InvalidMasterPasswordError


class ConfigManager:
    """
    Verwaltet das Laden und Speichern der verschlüsselten Konfiguration.
    Nutzt CryptoManager für die Verschlüsselung und stellt atomares Schreiben sicher.
    """

    def __init__(self, config_path="config.dat"):
        # Verwende absoluten Pfad, um Manipulation zu verhindern
        self.config_path = str(Path(config_path).resolve())
        self._data = {
            "profiles": [],
            "excluded_files": "paypal3.php",
            "max_log_age": 7,
        }  # Initialisiert mit Standardwerten

    def save_config(self, data: dict, password: str):
        """
        Verschlüsselt und speichert die Konfigurationsdaten atomar.
        """
        try:
            salt = CryptoManager.generate_salt()
            # Konvertierung des Dicts in UTF-8 Bytes
            raw_json = json.dumps(data).encode("utf-8")

            # CryptoManager.encrypt liefert einen UTF-8 String (Fernet-Token)
            token = CryptoManager.encrypt(raw_json, password, salt)

            payload = {
                "version": 1,
                "salt": base64.b64encode(salt).decode("utf-8"),
                "token": token,
            }

            # Atomares Schreiben über temporäre Datei
            tmp_path = self.config_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            os.replace(tmp_path, self.config_path)

            # Sicherer Dateizugriff (nur Besitzer)
            try:
                os.chmod(self.config_path, 0o600)
            except Exception:
                # chmod schlägt auf einigen Systemen (z.B. Windows) fehl
                pass
        except Exception as e:
            # Fallback bei Schreibfehlern (z.B. Berechtigungen)
            raise IOError(f"Fehler beim Speichern der Konfiguration: {str(e)}")

    def load_config(self, password: str) -> dict:
        """
        Lädt und entschlüsselt die Konfiguration.
        Gibt ein leeres Dict zurück, wenn die Datei nicht existiert.
        """
        if not os.path.exists(self.config_path):
            return {}

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                container = json.load(f)

            # Salt zurückgewinnen
            salt = base64.b64decode(container["salt"])
            token = container["token"]

            # Entschlüsselung (liefert bytes)
            decrypted = CryptoManager.decrypt(token, password, salt)

            # JSON Deserialisierung
            self._data = json.loads(decrypted.decode("utf-8"))
            return self._data
        except (
            json.JSONDecodeError,
            KeyError,
            ValueError,
            base64.binascii.Error,
            InvalidMasterPasswordError,
        ):
            # Vereinheitlichte Fehlerbehandlung für falsche Passwörter oder korrupte Daten
            raise InvalidMasterPasswordError(
                "Das Master-Passwort ist falsch oder die Konfigurationsdaten sind beschädigt."
            )
        except Exception as e:
            # Verhindert das Durchreichen technischer Stacktraces bei unerwarteten Systemfehlern
            raise InvalidMasterPasswordError(f"Ein unerwarteter Fehler ist aufgetreten: {type(e).__name__}")

    def get_profiles(self) -> list:
        """
        Gibt die Liste der gespeicherten Shop-Profile zurück.
        """
        return self._data.get("profiles", [])

    def get_excluded_files(self) -> str:
        """
        Gibt die kommagetrennte Liste der zu ignorierenden Dateien zurück.
        """
        return self._data.get("excluded_files", "paypal3.php")

    def set_excluded_files(self, files_str: str):
        """
        Setzt die Liste der zu ignorierenden Dateien.
        """
        self._data["excluded_files"] = files_str

    def get_max_log_age(self) -> int:
        """
        Gibt das maximale Alter der Logfiles in Tagen zurück.
        """
        return self._data.get("max_log_age", 7)

    def set_max_log_age(self, days: int):
        """
        Setzt das maximale Alter der Logfiles in Tagen.
        """
        self._data["max_log_age"] = days

    def set_profiles(self, profiles: list):
        """
        Setzt die Liste der Shop-Profile im internen Datenmodell.
        """
        self._data["profiles"] = profiles

    def get_last_selected_profile_name(self) -> str:
        """
        Gibt den Namen des zuletzt ausgewählten Profils zurück.
        """
        return self._data.get("last_selected_profile_name", "")

    def set_last_selected_profile_name(self, name: str):
        """
        Setzt den Namen des zuletzt ausgewählten Profils.
        """
        self._data["last_selected_profile_name"] = name

    def save_current_config(self, password: str):
        """
        Speichert die aktuelle interne Konfiguration mit dem gegebenen Passwort.
        """
        self.save_config(self._data, password)

    def change_master_password(self, old_password: str, new_password: str):
        """
        Ändert das Master-Passwort, indem die Konfiguration mit dem alten Passwort geladen
        und dann mit dem neuen Passwort gespeichert wird.
        """
        current_data = self.load_config(old_password)  # Dies verifiziert das alte Passwort implizit
        self.save_config(current_data, new_password)  # Speichert die gleichen Daten mit dem neuen Passwort
