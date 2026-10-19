"""
ui/workers.py
=============
Hintergrund-Worker-Threads (QThread) für das Gambio Health-Check-Modul.

Ausgelagert aus ui/main_window.py, um die Testbarkeit, Übersichtlichkeit
und Wartbarkeit zu maximieren.
"""

from __future__ import annotations

import datetime
import ftplib  # nosec B402 # Typ-Prüfungen für FTP-Verbindungen
import io
import logging
import stat
from typing import Any, Optional

from PySide6.QtCore import QThread, Signal

from core.hash_engine import HashCheckEngine
from core.logger import HealthCheckLogger
from ui.network_service import NetworkService, RemoteFileService

logger = logging.getLogger(__name__)


class HealthCheckWorker(QThread):
    """
    Worker-Thread für den Health-Check, um die GUI während
    der Netzwerkoperationen reaktionsfähig zu halten.
    """

    result_signal = Signal(str, str)  # (Nachricht, Status)
    legacy_files_signal = Signal(list)  # Liste der gefundenen Altlasten
    progress_signal = Signal(str)  # Für den Status-Text
    cancelled_signal = Signal()  # Signal, wenn der Worker abgebrochen wurde
    finished_signal = Signal()

    def __init__(
        self,
        page_instance: Any,
        profile: dict[str, Any],
        logger_instance: HealthCheckLogger,
        mode: str = "full",
        scan_gambio: bool = False,
    ) -> None:
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self.logger = logger_instance
        self.mode = mode
        self.scan_gambio = scan_gambio
        self._is_cancelled: bool = False

    def cancel(self) -> None:
        """Setzt das Abbruch-Flag und sendet ein Signal."""
        self._is_cancelled = True
        self.cancelled_signal.emit()

    def run(self) -> None:
        conn = None
        self.logger.start_session()
        self.progress_signal.emit(f"Starte Prüfung für: {self.profile.get('shop_name')}")
        try:
            if self._is_cancelled:
                self.result_signal.emit("Prüfung durch Benutzer abgebrochen.", "warn")
                return

            # 1. Verbindungstest
            self.progress_signal.emit("Prüfe Verbindung...")
            conn, remote_files = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                return

            # Hash-Engine Initialisierung
            import sys

            main_window_mod = sys.modules.get("ui.main_window")
            engine_cls = getattr(main_window_mod, "HashCheckEngine", HashCheckEngine)
            hash_engine = engine_cls(
                str(self.profile.get("shop_name") or "default"),
                conn,
                self.result_signal,
                self.logger,
                self,
            )

            if self.mode == "baseline":
                hash_engine.generate_baseline()
                return

            if self.mode == "hash_check":
                hash_engine.compare_with_baseline()
                g_ver = self.page._check_version(conn, self.profile)
                if g_ver:
                    hash_engine.compare_with_update_hashes(g_ver)
                return

            # --- Standard Full Health Check ---
            # 2. Gambio Erkennung
            if self._is_cancelled:
                return
            is_gambio = self.page._check_gambio_structure(remote_files, self.result_signal)

            # Cache Prüfung
            if is_gambio and not self._is_cancelled:
                self.progress_signal.emit("Prüfe Cache-Größe...")
                self.page._check_cache_size(conn, remote_files, self.result_signal)
            if not is_gambio:
                self.progress_signal.emit("Keine eindeutige Gambio-Struktur gefunden.")
                self.result_signal.emit("Keine eindeutige Gambio-Struktur im Verzeichnis gefunden.", "error")
                return

            # 4. Schreibrechte
            if self._is_cancelled:
                return
            self.progress_signal.emit("Prüfe Schreibrechte...")
            self.page._check_write_permissions(conn, self.profile, self.result_signal)

            # 5. PHP & MySQL Versionen (HTTP via JSON)
            if self._is_cancelled:
                return
            self.progress_signal.emit("Ermittle PHP- und Datenbank-Versionen...")
            versions = self.page._check_php_version_via_ftp_http(conn, self.profile, self.result_signal)
            if self._is_cancelled:
                return
            php_ver = versions.get("php")
            db_info = versions.get("db", {})
            db_type = db_info.get("type")
            mysql_ver_full = db_info.get("version_full")
            self.progress_signal.emit(f"PHP: {php_ver}, DB: {db_type} {mysql_ver_full}")

            security_info = versions.get("security", {})
            env_info = versions.get("env", {})

            if security_info.get("installer_exists"):
                self.result_signal.emit(
                    "Sicherheitsrisiko: Verzeichnis 'gambio_installer' existiert noch!",
                    "error",
                )
            else:
                self.result_signal.emit("Installationsverzeichnis (gambio_installer) ist gelöscht.", "ok")

            if security_info.get("config_writable"):
                self.result_signal.emit(
                    "Sicherheitsrisiko: includes/configure.php ist beschreibbar!",
                    "warn",
                )
            else:
                self.result_signal.emit("includes/configure.php ist korrekt schreibgeschützt.", "ok")

            if security_info.get("admin_config_writable"):
                self.result_signal.emit(
                    "Sicherheitsrisiko: admin/includes/configure.php ist beschreibbar!",
                    "warn",
                )
            else:
                self.result_signal.emit("admin/includes/configure.php ist korrekt schreibgeschützt.", "ok")

            if security_info.get("htaccess_admin_backups") is False:
                self.result_signal.emit(
                    "Sicherheitsrisiko: admin/backups/.htaccess fehlt (Backups könnten öffentlich zugänglich sein)!",
                    "error",
                )
            elif security_info.get("htaccess_admin_backups") is True:
                self.result_signal.emit("Verzeichnis admin/backups/ ist durch .htaccess geschützt.", "ok")

            if security_info.get("htaccess_log") is False:
                self.result_signal.emit(
                    "Sicherheitsrisiko: logfiles/.htaccess fehlt (Logs könnten öffentlich zugänglich sein)!",
                    "warn",
                )
            elif security_info.get("htaccess_log") is True:
                self.result_signal.emit("Verzeichnis logfiles/ ist durch .htaccess geschützt.", "ok")

            if env_info.get("session_auto_start"):
                self.result_signal.emit(
                    "Server-Konfiguration: session.auto_start ist aktiv (sollte deaktiviert sein).",
                    "warn",
                )

            if env_info.get("soap_loaded") is False:
                self.result_signal.emit("Fehlende PHP-Erweiterung: 'soap' ist nicht geladen.", "error")
            if env_info.get("intl_loaded") is False:
                self.result_signal.emit("Fehlende PHP-Erweiterung: 'intl' ist nicht geladen.", "error")

            # 6. Versionsprüfung
            if self._is_cancelled:
                return
            self.progress_signal.emit("Ermittle Gambio-Version...")
            gambio_ver = self.page._check_version(conn, self.profile, self.result_signal)

            # 7. PHP-Kompatibilitätsprüfung
            if php_ver and gambio_ver:
                self.progress_signal.emit("Lese Kompatibilitätsdaten aus Shop...")
                min_php, max_php = self.page._get_php_compat_from_shop(conn, gambio_ver, self.result_signal)
                self.progress_signal.emit("Prüfe PHP-Kompatibilität...")
                self.page._run_php_compatibility_check_logic(gambio_ver, php_ver, min_php, max_php, self.result_signal)
            if self._is_cancelled:
                return

            # Integrität
            if self._is_cancelled:
                return
            self.progress_signal.emit("Prüfe Shop-Integrität...")
            self.page._check_integrity(remote_files, self.result_signal)

            # GXModules Plugin Kompatibilitäts-Scan
            if self._is_cancelled:
                return
            self.page._run_gxmodules_compatibility_scan(conn, gambio_ver, self.scan_gambio, self.result_signal)

            # 9. Detaillierte Delete-Analyse (Altlasten)
            if self._is_cancelled:
                return
            self.progress_signal.emit("Analysiere Altlasten...")
            legacy_files = self.page._run_legacy_delete_analysis_logic(conn, self.result_signal, profile=self.profile)
            self.legacy_files_signal.emit(legacy_files)

        except Exception as e:
            self.progress_signal.emit(f"Fehler: {e!s}")
            logger.error("Health-Check Worker Fehler: %s", e)
            self.result_signal.emit(f"Unerwarteter Fehler: {e!s}", "error")
        finally:
            self.logger.end_session()
            NetworkService.close_connection(conn)
            self.finished_signal.emit()
            if self._is_cancelled:
                self.result_signal.emit("Health-Check abgebrochen.", "warn")


class LegacyDeleteWorker(QThread):
    """
    Worker-Thread zum Löschen von Altlasten oder .bak Dateien.
    """

    result_signal = Signal(str, str)
    finished_signal = Signal()
    progress_signal = Signal(str)

    def __init__(
        self,
        page_instance: Any,
        profile: dict[str, Any],
        files_to_delete: list[str],
        logger_instance: Optional[HealthCheckLogger] = None,
        clear_cache: bool = False,
    ) -> None:
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self.files = files_to_delete
        self.logger = logger_instance
        self.clear_cache = clear_cache
        self._is_cancelled: bool = False

    def cancel(self) -> None:
        """Setzt das Abbruch-Flag."""
        self._is_cancelled = True

    def run(self) -> None:
        conn = None
        try:
            if self._is_cancelled:
                return

            self.progress_signal.emit("Verbinde zum Server für Löschvorgang...")
            conn, _ = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                self.progress_signal.emit("Verbindung für Löschvorgang fehlgeschlagen.")
                return

            total = len(self.files)
            for i, file_path in enumerate(self.files, 1):
                if self._is_cancelled:
                    break
                try:
                    last_part = file_path.split("/")[-1]
                    entry_type = "Ordner" if "." not in last_part else "Datei"
                    self.progress_signal.emit(f"Lösche {entry_type} {i}/{total}: {file_path}")
                    success, entry_type = RemoteFileService.delete_remote_item(
                        conn, file_path, is_cancelled=lambda: self._is_cancelled
                    )
                    if success:
                        if self.logger:
                            self.logger.info(f"{entry_type} erfolgreich gelöscht: {file_path}")
                        self.result_signal.emit(f"{entry_type} gelöscht: {file_path}", "ok")
                except Exception as e:
                    last_part = file_path.split("/")[-1]
                    entry_type = "Ordner" if "." not in last_part else "Datei"
                    if getattr(self, "logger", None):
                        self.logger.error(f"Fehler beim Löschen von {entry_type} {file_path}: {e!s}")
                    self.result_signal.emit(
                        f"Fehler beim Löschen von {entry_type} {file_path}: {e!s}",
                        "error",
                    )

            # Optionale automatische Cache-Bereinigung
            if self.clear_cache and not self._is_cancelled:
                self.progress_signal.emit("Bereinige System-Cache (Ordner 'cache')...")
                deleted_cache_count = RemoteFileService.clean_remote_cache(conn, cache_dir="cache")
                if deleted_cache_count > 0:
                    self.result_signal.emit(
                        f"System-Cache bereinigt ({deleted_cache_count} temporäre Cache-Dateien gelöscht).",
                        "ok",
                    )
                else:
                    self.result_signal.emit(
                        "System-Cache bereinigt (keine zu löschenden Cache-Dateien gefunden).",
                        "ok",
                    )

            self.result_signal.emit("Löschvorgang abgeschlossen.", "ok")
            self.progress_signal.emit(f"Löschvorgang abgeschlossen ({total} Dateien bearbeitet).")
        except Exception as e:
            self.result_signal.emit(f"Kritischer Fehler beim Löschen: {e!s}", "error")
            self.progress_signal.emit("Fehler beim Löschvorgang.")
        finally:
            if getattr(self, "logger", None):
                self.logger.end_session()
            NetworkService.close_connection(conn)
            self.finished_signal.emit()


class BakFileScannerWorker(QThread):
    """
    Worker-Thread zum Scannen nach .bak Dateien auf dem Server.
    """

    progress_signal = Signal(str)
    result_signal = Signal(str, str)
    finished_signal = Signal(list)
    cancelled_signal = Signal()

    def __init__(self, page_instance: Any, profile: dict[str, Any]) -> None:
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self._is_cancelled: bool = False
        self.bak_files: list[str] = []

    def cancel(self) -> None:
        self._is_cancelled = True
        self.cancelled_signal.emit()

    def run(self) -> None:
        conn = None
        try:
            self.progress_signal.emit(f"Verbinde für .bak-Scan: {self.profile.get('shop_name')}")
            conn, _ = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                self.finished_signal.emit([])
                return

            if self._is_cancelled:
                return

            self.progress_signal.emit("Starte rekursiven Scan nach .bak Dateien...")

            def on_match(file_item: str) -> None:
                self.bak_files.append(file_item)
                self.result_signal.emit(f".bak Datei gefunden: {file_item}", "warn")

            self.bak_files = RemoteFileService.scan_bak_files(
                conn=conn,
                current_path=".",
                is_cancelled=lambda: self._is_cancelled,
                progress_cb=self.progress_signal.emit,
                match_cb=on_match,
            )

            if not self._is_cancelled:
                self.result_signal.emit(
                    f".bak-Scan abgeschlossen: {len(self.bak_files)} Dateien gefunden.",
                    "ok" if not self.bak_files else "warn",
                )
                self.progress_signal.emit(f".bak-Scan fertig ({len(self.bak_files)} gefunden).")
            self.finished_signal.emit(self.bak_files)
        except Exception as e:
            self.result_signal.emit(f"Fehler beim .bak-Scan: {e!s}", "error")
            self.progress_signal.emit("Fehler beim .bak-Scan.")
            self.finished_signal.emit([])
        finally:
            NetworkService.close_connection(conn)


class LogfileWorker(QThread):
    """
    Worker-Thread zum Scannen und Bereinigen von Logfiles auf dem Server.
    """

    progress_signal = Signal(str)
    result_signal = Signal(str, str)
    finished_signal = Signal(list, list)  # (errors_found, files_deleted)
    cancelled_signal = Signal()

    def __init__(
        self,
        page_instance: Any,
        profile: dict[str, Any],
        max_age_days: int,
        mode: str = "scan",
    ) -> None:
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self.max_age_days = max_age_days
        self.mode = mode  # 'scan' or 'cleanup'
        self._is_cancelled: bool = False
        self.errors_found: list[str] = []
        self.files_deleted: list[str] = []

    def cancel(self) -> None:
        self._is_cancelled = True
        self.cancelled_signal.emit()

    def run(self) -> None:
        conn = None
        try:
            self.progress_signal.emit(f"Verbinde für Logfile-{self.mode}...")
            conn, _ = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                self.finished_signal.emit([], [])
                return

            if self._is_cancelled:
                return

            self.progress_signal.emit("Lese Logfiles...")
            files = RemoteFileService.fetch_logfiles(
                conn, log_dir="logfiles", max_age_days=self.max_age_days, is_cancelled=lambda: self._is_cancelled
            )

            if self._is_cancelled:
                return

            now = datetime.datetime.now(datetime.timezone.utc)
            max_age_seconds = self.max_age_days * 86400

            if self.mode == "cleanup":
                self.progress_signal.emit("Lösche alte Logfiles...")
                for f in files:
                    if self._is_cancelled:
                        break
                    name = str(f["name"])
                    if name in [".htaccess", "index.html"]:
                        continue
                    file_time = f.get("time")
                    if isinstance(file_time, datetime.datetime):
                        age_seconds = (now - file_time).total_seconds()
                        if age_seconds > max_age_seconds:
                            try:
                                if isinstance(conn, ftplib.FTP):
                                    conn.delete(name)
                                else:
                                    conn.remove(name)
                                self.files_deleted.append(name)
                                self.result_signal.emit(f"Gelöscht: {name}", "ok")
                            except Exception as e:
                                self.result_signal.emit(f"Fehler beim Löschen von {name}: {e}", "error")

            elif self.mode == "scan":
                self.progress_signal.emit("Analysiere Logfiles...")
                keywords = [b"ERROR", b"FATAL", b"Exception", b"Parse error"]

                for f in files:
                    if self._is_cancelled:
                        break
                    name = str(f["name"])
                    if name in [".htaccess", "index.html"]:
                        continue
                    if not name.endswith((".log", ".txt")):
                        continue

                    try:
                        content = b""
                        if isinstance(conn, ftplib.FTP):
                            r_io = io.BytesIO()
                            conn.retrbinary(f"RETR {name}", r_io.write)
                            content = r_io.getvalue()
                        else:
                            with conn.open(name, "rb") as remote_file:
                                content = remote_file.read()

                        lines_content = content.splitlines()
                        for i, line in enumerate(lines_content):
                            if any(k in line for k in keywords):
                                try:
                                    decoded_line = line.decode("utf-8", errors="ignore")
                                except Exception:
                                    decoded_line = str(line)
                                self.errors_found.append(f"[{name}:Zeile {i + 1}] {decoded_line}")
                    except Exception as e:
                        self.result_signal.emit(f"Fehler beim Lesen von {name}: {e}", "warn")

        except Exception as e:
            self.result_signal.emit(f"Fehler bei Logfile-{self.mode}: {e!s}", "error")
        finally:
            NetworkService.close_connection(conn)
            self.finished_signal.emit(self.errors_found, self.files_deleted)


__all__ = [
    "BakFileScannerWorker",
    "HealthCheckWorker",
    "LegacyDeleteWorker",
    "LogfileWorker",
]
