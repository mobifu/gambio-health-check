import json
import logging
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Self

from logging_config import sanitize_sensitive_data

logger = logging.getLogger(__name__)


class HealthCheckLogger:
    """
    Engine für das strukturierte Logging pro Shop-Profil.
    Schreibt JSON-Lines für einfache maschinelle Auswertung thread-sicher in Log-Dateien.
    Unterstützt auch Context-Manager-Protokoll (with HealthCheckLogger(...) as log:).
    """

    def __init__(self, profile_name: str):
        # Pfadsicherheit via pathlib und Path Traversal Absicherung
        base_profiles_dir = Path("profiles").resolve()
        safe_name = re.sub(r'[\\/*?:"<>| &]', "_", profile_name.strip())
        if not safe_name:
            safe_name = "default"

        resolved_log_dir = (base_profiles_dir / safe_name / "logs").resolve()
        # Sicherstellen, dass das Zielverzeichnis innerhalb von base_profiles_dir liegt
        if not resolved_log_dir.is_relative_to(base_profiles_dir):
            resolved_log_dir = (base_profiles_dir / "default" / "logs").resolve()

        self.log_dir = str(resolved_log_dir)
        try:
            resolved_log_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Log-Verzeichnis bereit: {self.log_dir}")
        except OSError as e:
            logger.error(f"Fehler beim Erstellen des Log-Verzeichnisses {self.log_dir}: {e}")

        self.current_file: str | None = None
        self.file_handle = None
        self._lock = threading.Lock()

    def __enter__(self) -> Self:
        self.start_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.end_session()

    def start_session(self) -> None:
        """Erzeugt eine neue Log-Datei für den aktuellen Durchlauf."""
        with self._lock:
            if self.file_handle and not self.file_handle.closed:
                try:
                    self.file_handle.close()
                except OSError:
                    pass
                self.file_handle = None

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.current_file = str(Path(self.log_dir) / f"{timestamp}.log")
            try:
                self.file_handle = open(self.current_file, "a", encoding="utf-8")
                logger.info(f"Sitzungs-Log erstellt: {self.current_file}")
            except OSError as e:
                logger.error(f"Fehler beim Öffnen der Log-Datei {self.current_file}: {e}")
                self.file_handle = None

        if self.file_handle:
            self.log("INFO", "Health-Check gestartet")

    def _sanitize(self, msg: str) -> str:
        """Anonymisiert sensible Daten in Log-Nachrichten."""
        return sanitize_sensitive_data(str(msg))

    def log(self, level: str, message: str) -> None:
        """Schreibt einen JSON-Eintrag (JSON-Line) thread-sicher in die Datei."""
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": str(level).upper(),
            "msg": self._sanitize(message),
        }
        with self._lock:
            if not self.file_handle or self.file_handle.closed:
                logger.debug(
                    f"Versuch, in geschlossene oder nicht vorhandene Log-Datei zu schreiben: {self.current_file} - Nachricht: {message}"
                )
                return
            try:
                self.file_handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                self.file_handle.flush()
            except OSError as e:
                logger.error(f"Fehler beim Schreiben in Log-Datei {self.current_file}: {e} - Nachricht: {message}")

    def info(self, message: str) -> None:
        self.log("INFO", message)

    def warning(self, message: str) -> None:
        self.log("WARN", message)

    def error(self, message: str) -> None:
        self.log("ERROR", message)

    def end_session(self) -> None:
        """Schließt die Log-Datei nach Abschluss der Prüfung."""
        if self.file_handle and not self.file_handle.closed:
            self.log("INFO", "Health-Check abgeschlossen")
            with self._lock:
                if self.file_handle and not self.file_handle.closed:
                    try:
                        self.file_handle.close()
                    except OSError:
                        pass
                    self.file_handle = None

    def get_log_dir(self) -> str:
        return self.log_dir

    def get_last_log_file(self) -> str | None:
        """Gibt den Pfad zur neuesten Log-Datei zurück oder None."""
        try:
            log_path = Path(self.log_dir)
            if not log_path.exists():
                return None
            files = [p for p in log_path.glob("*.log") if p.is_file()]
            if not files:
                return None
            latest = max(files, key=lambda f: f.stat().st_ctime)
            return str(latest)
        except OSError as e:
            logger.warning(f"Fehler beim Ermitteln der neuesten Log-Datei in {self.log_dir}: {e}")
            return None
