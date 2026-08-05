import os
import re
import json
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


class HealthCheckLogger:
    """
    Engine für das strukturierte Logging pro Shop-Profil.
    Schreibt JSON-Lines für einfache maschinelle Auswertung.
    """

    def __init__(self, profile_name: str):
        # Dateisystem-freundlicher Name für den Profil-Ordner
        safe_name = re.sub(r'[\\/*?:"<>| &]', "_", profile_name)
        self.log_dir = os.path.join("profiles", safe_name, "logs")
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            logger.info(f"Log-Verzeichnis bereit: {self.log_dir}")
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Log-Verzeichnisses {self.log_dir}: {e}")
        self.current_file = None
        self.file_handle = None
        self._lock = threading.Lock()

    def start_session(self):
        """Erzeugt eine neue Log-Datei für den aktuellen Durchlauf."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.current_file = os.path.join(self.log_dir, f"{timestamp}.log")
        try:
            self.file_handle = open(self.current_file, "a", encoding="utf-8")
            self.log("INFO", "Health-Check gestartet")
            logger.info(f"Sitzungs-Log erstellt: {self.current_file}")
        except Exception as e:
            logger.error(f"Fehler beim Öffnen der Log-Datei {self.current_file}: {e}")
            self.file_handle = None  # Ensure it's None if opening failed

    def _sanitize(self, msg: str) -> str:
        """Anonymisiert sensible Daten in Log-Nachrichten."""
        msg = str(msg)
        msg = re.sub(
            r'(pass|pwd|password|key|token|auth)=[^&\s"\']+',
            r"\1=********",
            msg,
            flags=re.IGNORECASE,
        )
        msg = re.sub(
            r'("?(?:pass|pwd|password|key|token|auth)"?\s*[:=]\s*)(["\']).*?\2',
            r"\1\2********\2",
            msg,
            flags=re.IGNORECASE,
        )
        return msg

    def log(self, level: str, message: str):
        """Schreibt einen JSON-Eintrag (JSON-Line) thread-sicher in die Datei."""
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": level.upper(),
            "msg": self._sanitize(message),
        }
        with self._lock:
            if not self.file_handle or self.file_handle.closed:
                logger.warning(
                    f"Versuch, in geschlossene oder nicht vorhandene Log-Datei zu schreiben: {self.current_file} - Nachricht: {message}"
                )
                return
            try:
                self.file_handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                self.file_handle.flush()
            except Exception as e:
                logger.error(f"Fehler beim Schreiben in Log-Datei {self.current_file}: {e} - Nachricht: {message}")

    def info(self, message):
        self.log("INFO", message)

    def warning(self, message):
        self.log("WARN", message)

    def error(self, message):
        self.log("ERROR", message)

    def end_session(self):
        """Schließt die Log-Datei nach Abschluss der Prüfung."""
        if self.file_handle:
            self.log("INFO", "Health-Check abgeschlossen")
            with self._lock:
                if self.file_handle:
                    self.file_handle.close()
                    self.file_handle = None

    def get_log_dir(self):
        return self.log_dir

    def get_last_log_file(self):
        try:
            files = [os.path.join(self.log_dir, f) for f in os.listdir(self.log_dir) if f.endswith(".log")]
            return max(files, key=os.path.getctime) if files else None
        except:
            return None
