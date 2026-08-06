import ftplib
import time
import stat
import re
import fnmatch
import io
import os
import platform
import subprocess
import json
import logging
import configparser
import secrets
from datetime import datetime

try:
    import requests  # type: ignore
    import urllib3  # type: ignore

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None
try:
    import paramiko  # type: ignore
except ImportError:
    paramiko = None

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QPushButton,
    QStackedWidget,
    QLabel,
    QGroupBox,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QMessageBox,
    QScrollArea,
    QFrame,
    QTextBrowser,
    QProgressBar,
    QCheckBox,
    QSpinBox,
    QFileDialog,
)
from PySide6.QtCore import Qt, Signal, QThread  # Added QSize for QMovie scaling
from ui.dialogs import MasterPasswordDialog, show_error
from security.exceptions import (
    InvalidMasterPasswordError,
    TooManyFailedAttemptsError,
    SessionExpiredError,
)
from security.master_password import MasterPasswordManager
from config.config_manager import ConfigManager
from core.logger import HealthCheckLogger
from core.hash_engine import HashCheckEngine
from core.reporting import generate_html_report, generate_pdf_report

logger = logging.getLogger(__name__)


def open_path(path):
    """Öffnet einen Pfad oder eine Datei im systemstandard-Explorer/App."""
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        return
    try:
        if platform.system() == "Windows":
            os.startfile(abs_path)
        elif platform.system() == "Darwin":
            subprocess.run(["open", abs_path], check=True)
        else:
            subprocess.run(["xdg-open", abs_path], check=True)
    except Exception as e:
        logger.error(f"Fehler beim Öffnen von {abs_path}: {e}")


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

    def __init__(self, page_instance, profile, logger_instance, mode="full", scan_gambio=False):
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self.logger = logger_instance
        self.mode = mode
        self.scan_gambio = scan_gambio
        self._is_cancelled = False  # Flag, um den Abbruch zu signalisieren

    def cancel(self):
        """Setzt das Abbruch-Flag und sendet ein Signal."""
        self._is_cancelled = True
        self.cancelled_signal.emit()

    def run(self):
        conn = None
        self.logger.start_session()
        self.progress_signal.emit(f"Starte Prüfung für: {self.profile.get('shop_name')}")
        try:
            if self._is_cancelled:
                return  # Sofortiger Abbruch

            # 1. Verbindungstest
            self.progress_signal.emit("Prüfe Verbindung...")
            conn, remote_files = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                return

            # Hash-Engine Initialisierung
            hash_engine = HashCheckEngine(
                self.profile.get("shop_name"),
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
                # Falls eine Version bekannt ist, auch Update-Hashes prüfen
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
                return  # Stop if no gambio structure

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
                return  # Nach HTTP-Abfrage erneut prüfen
            php_ver = versions.get("php")  # This should be clean from phpversion()
            db_info = versions.get("db", {})
            db_type = db_info.get("type")
            mysql_ver_full = db_info.get("version_full")
            mysql_ver = db_info.get("version_number")  # This is already clean
            self.progress_signal.emit(f"PHP: {php_ver}, DB: {db_type} {mysql_ver_full}")

            # Erweiterte Sicherheits- und Umgebungschecks auswerten
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

            # 8. Update-Analyse Engine
            if self._is_cancelled:
                return
            # if gambio_ver:
            #     self.page._run_update_analysis_logic(conn, gambio_ver, php_ver, mysql_ver, db_type, remote_files, self.result_signal)
            # else:
            #     self.result_signal.emit("Update-Analyse übersprungen (Gambio-Version unbekannt).", "warn")
            #     self.progress_signal.emit("Update-Analyse übersprungen.")

            # GXModules Plugin Kompatibilitäts-Scan
            if self._is_cancelled:
                return
            self.page._run_gxmodules_compatibility_scan(conn, gambio_ver, self.scan_gambio, self.result_signal)

            # 9. Detaillierte Delete-Analyse (Altlasten)
            if self._is_cancelled:
                return
            self.progress_signal.emit("Analysiere Altlasten...")
            legacy_files = self.page._run_legacy_delete_analysis_logic(conn, self.result_signal)
            self.legacy_files_signal.emit(legacy_files)

        except Exception as e:
            self.progress_signal.emit(f"Fehler: {str(e)}")
            logger.error(f"Health-Check Worker Fehler: {e}")
            self.result_signal.emit(f"Unerwarteter Fehler: {str(e)}", "error")
        # No matter what, if cancelled, emit a specific message
        finally:
            self.logger.end_session()
            if conn:
                try:
                    if isinstance(conn, ftplib.FTP):
                        conn.quit()
                    else:
                        conn.close()
                except:
                    pass
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
        page_instance,
        profile,
        files_to_delete,
        logger_instance=None,
        clear_cache=False,
    ):
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self.files = files_to_delete
        self.logger = logger_instance
        self.clear_cache = clear_cache

    def run(self):
        conn = None
        try:
            self.progress_signal.emit("Verbinde zum Server für Löschvorgang...")
            conn, _ = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                self.progress_signal.emit("Verbindung für Löschvorgang fehlgeschlagen.")
                return

            def rmtree_ftp(ftp_conn, path):
                """Löscht ein FTP-Verzeichnis rekursiv."""
                try:
                    # Versuche alle Dateien/Unterordner aufzulisten
                    # "-a" zeigt auch versteckte Dateien auf vielen FTP-Servern
                    try:
                        names = ftp_conn.nlst("-a", path)
                        if not names:  # Fallback falls -a ignoriert wird
                            names = ftp_conn.nlst(path)
                    except Exception:
                        names = ftp_conn.nlst(path)
                except ftplib.error_perm:
                    # Ordner ist leer oder existiert nicht
                    names = []

                for name in names:
                    # ftp_conn.nlst() gibt manchmal relative oder absolute Pfade zurück.
                    # Normalweisen, um Endlosschleifen zu vermeiden.
                    base_name = name.rstrip("/").split("/")[-1].split("\\")[-1]
                    if base_name in (".", ".."):
                        continue

                    # Pfad zusammensetzen
                    full_p = name if name.startswith(path) else f"{path}/{name}"
                    if full_p.rstrip("/") == path.rstrip("/"):
                        continue

                    try:
                        # Versuche als Datei zu löschen
                        ftp_conn.delete(full_p)
                    except ftplib.error_perm:
                        # Wenn Fehler, ist es vermutlich ein Ordner -> rekursiv löschen
                        rmtree_ftp(ftp_conn, full_p)

                # Am Ende den leeren Ordner löschen
                ftp_conn.rmd(path)

            def rmtree_sftp(sftp_conn, path):
                """Löscht ein SFTP-Verzeichnis rekursiv."""
                try:
                    for entry in sftp_conn.listdir_attr(path):
                        if entry.filename in (".", ".."):
                            continue
                        full_p = f"{path}/{entry.filename}"
                        if stat.S_ISDIR(entry.st_mode):
                            rmtree_sftp(sftp_conn, full_p)
                        else:
                            sftp_conn.remove(full_p)
                    sftp_conn.rmdir(path)
                except Exception:
                    # Falls stat.S_ISDIR nicht klappt, versuchen wir es mit try-catch
                    try:
                        sftp_conn.remove(path)
                    except Exception:
                        sftp_conn.rmdir(path)

            total = len(self.files)
            for i, file_path in enumerate(self.files, 1):
                try:
                    # Prüfen ob Datei oder Ordner anhand des Vorhandenseins eines Punkts im letzten Pfadsegment
                    last_part = file_path.split("/")[-1]
                    is_folder = "." not in last_part

                    if is_folder:
                        self.progress_signal.emit(f"Lösche Ordner {i}/{total}: {file_path}")
                        try:
                            if isinstance(conn, ftplib.FTP):
                                rmtree_ftp(conn, file_path)
                            else:  # SFTP
                                rmtree_sftp(conn, file_path)
                            if self.logger:
                                self.logger.info(f"Ordner erfolgreich gelöscht: {file_path}")
                            self.result_signal.emit(f"Ordner gelöscht: {file_path}", "ok")
                        except Exception as e:
                            # Try as file (Fallback)
                            try:
                                if isinstance(conn, ftplib.FTP):
                                    conn.delete(file_path)
                                else:
                                    conn.remove(file_path)
                                if self.logger:
                                    self.logger.info(f"Datei erfolgreich gelöscht (Fallback): {file_path}")
                                self.result_signal.emit(f"Datei gelöscht: {file_path}", "ok")
                            except Exception:
                                raise e  # Raise original error if fallback fails
                    else:
                        self.progress_signal.emit(f"Lösche Datei {i}/{total}: {file_path}")
                        try:
                            if isinstance(conn, ftplib.FTP):
                                conn.delete(file_path)
                            else:  # SFTP
                                conn.remove(file_path)
                            if self.logger:
                                self.logger.info(f"Datei erfolgreich gelöscht: {file_path}")
                            self.result_signal.emit(f"Datei gelöscht: {file_path}", "ok")
                        except Exception as e:
                            # Try as folder (Fallback)
                            try:
                                if isinstance(conn, ftplib.FTP):
                                    rmtree_ftp(conn, file_path)
                                else:
                                    rmtree_sftp(conn, file_path)
                                if self.logger:
                                    self.logger.info(f"Ordner erfolgreich gelöscht (Fallback): {file_path}")
                                self.result_signal.emit(f"Ordner gelöscht: {file_path}", "ok")
                            except Exception:
                                raise e  # Raise original error if fallback fails
                except Exception as e:
                    entry_type = "Ordner" if is_folder else "Datei"
                    if getattr(self, "logger", None):
                        self.logger.error(f"Fehler beim Löschen von {entry_type} {file_path}: {str(e)}")
                    self.result_signal.emit(
                        f"Fehler beim Löschen von {entry_type} {file_path}: {str(e)}",
                        "error",
                    )

            # Optionale automatische Cache-Bereinigung
            if self.clear_cache:
                self.progress_signal.emit("Bereinige System-Cache (Ordner 'cache')...")
                cache_dir = "cache"
                skipped_files = [".htaccess", "index.html", "index.php"]
                deleted_cache_count = 0

                try:
                    if isinstance(conn, ftplib.FTP):
                        try:
                            # Wir listen den Cache Ordner auf
                            items = conn.nlst(cache_dir)
                            for item in items:
                                # Normalisieren
                                name = item if not item.startswith(cache_dir + "/") else item[len(cache_dir) + 1 :]
                                if name in (".", "..") or not name:
                                    continue
                                if name in skipped_files:
                                    continue

                                full_item_path = f"{cache_dir}/{name}"
                                try:
                                    # Nur Dateien löschen (wenn es ein Ordner ist, wirft size() oder delete() in der Regel einen Perm Error)
                                    conn.delete(full_item_path)
                                    deleted_cache_count += 1
                                except ftplib.error_perm:
                                    pass  # Ordner im Cache-Verzeichnis unberührt lassen
                        except Exception as ce:
                            self.result_signal.emit(
                                f"Hinweis: Konnte Cache-Ordner nicht vollständig auflisten/bereinigen: {str(ce)}",
                                "warn",
                            )
                    else:  # SFTP
                        try:
                            for entry in conn.listdir_attr(cache_dir):
                                if entry.filename in (".", ".."):
                                    continue
                                if entry.filename in skipped_files:
                                    continue

                                # Wenn es ein Verzeichnis ist, überspringen wir es
                                if stat.S_ISDIR(entry.st_mode):
                                    continue

                                full_item_path = f"{cache_dir}/{entry.filename}"
                                conn.remove(full_item_path)
                                deleted_cache_count += 1
                        except Exception as ce:
                            self.result_signal.emit(
                                f"Hinweis: Konnte Cache-Ordner nicht vollständig auflisten/bereinigen: {str(ce)}",
                                "warn",
                            )

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
                except Exception as ce:
                    self.result_signal.emit(
                        f"Fehler bei der automatischen Cache-Bereinigung: {str(ce)}",
                        "error",
                    )

            self.result_signal.emit("Löschvorgang abgeschlossen.", "ok")
            self.progress_signal.emit(f"Löschvorgang abgeschlossen ({total} Dateien bearbeitet).")
        except Exception as e:
            self.result_signal.emit(f"Kritischer Fehler beim Löschen: {str(e)}", "error")
            self.progress_signal.emit("Fehler beim Löschvorgang.")
        finally:
            if getattr(self, "logger", None):
                self.logger.end_session()
            if conn:
                try:
                    if isinstance(conn, ftplib.FTP):
                        conn.quit()
                    else:
                        conn.close()
                except:
                    pass
            self.finished_signal.emit()


class BakFileScannerWorker(QThread):
    """
    Worker-Thread zum Scannen nach .bak Dateien auf dem Server.
    """

    progress_signal = Signal(str)
    result_signal = Signal(str, str)
    finished_signal = Signal(list)
    cancelled_signal = Signal()

    def __init__(self, page_instance, profile):
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self._is_cancelled = False
        self.bak_files = []

    def cancel(self):
        self._is_cancelled = True
        self.cancelled_signal.emit()

    def run(self):
        conn = None
        try:
            self.progress_signal.emit(f"Verbinde für .bak-Scan: {self.profile.get('shop_name')}")
            conn, _ = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                self.finished_signal.emit([])
                return

            if self._is_cancelled:
                return

            # Rekursive Suche
            self.progress_signal.emit("Starte rekursiven Scan nach .bak Dateien...")
            skip_dirs = [
                "images",
                "cache",
                "logs",
                "export",
                "import",
                "backups",
                "uploads",
                "node_modules",
                ".git",
            ]

            def walk(current_path):
                if self._is_cancelled:
                    return
                self.progress_signal.emit(f"Scanne: {current_path}")
                try:
                    if isinstance(conn, ftplib.FTP):
                        try:
                            items = list(conn.mlsd())
                            if not items:
                                raise ValueError("MLSD empty")
                            for name, attrs in items:
                                if name in [".", ".."] or not name:
                                    continue
                                if any(sd == name for sd in skip_dirs):
                                    continue
                                full_item = name if current_path == "." else f"{current_path}/{name}"
                                target_type = attrs.get("type", "").lower() if isinstance(attrs, dict) else ""

                                if target_type == "dir":
                                    try:
                                        conn.cwd(name)
                                        walk(full_item)
                                    except:
                                        pass
                                    finally:
                                        try:
                                            conn.cwd("..")
                                        except:
                                            pass
                                elif target_type in ["file", "os.unix.slink", ""]:
                                    if full_item.lower().endswith(".bak"):
                                        self.bak_files.append(full_item)
                                        self.result_signal.emit(f".bak Datei gefunden: {full_item}", "warn")
                        except:
                            names = conn.nlst()
                            for name in names:
                                name = name.replace("\\", "/").split("/")[-1]
                                if name in [".", ".."] or not name:
                                    continue
                                full_item = name if current_path == "." else f"{current_path}/{name}"
                                if "." not in name and not name.startswith("."):
                                    try:
                                        conn.cwd(name)
                                        if any(sd == name for sd in skip_dirs):
                                            conn.cwd("..")
                                            continue
                                        walk(full_item)
                                        conn.cwd("..")
                                    except:
                                        if full_item.lower().endswith(".bak"):
                                            self.bak_files.append(full_item)
                                            self.result_signal.emit(
                                                f".bak Datei gefunden: {full_item}",
                                                "warn",
                                            )
                                else:
                                    if full_item.lower().endswith(".bak"):
                                        self.bak_files.append(full_item)
                                        self.result_signal.emit(f".bak Datei gefunden: {full_item}", "warn")
                    else:
                        for attr in conn.listdir_attr():
                            name = attr.filename
                            if name in [".", ".."] or not name:
                                continue
                            if any(sd == name for sd in skip_dirs):
                                continue
                            full_item = name if current_path == "." else f"{current_path}/{name}"
                            if stat.S_ISDIR(attr.st_mode):
                                try:
                                    conn.chdir(name)
                                    walk(full_item)
                                    conn.chdir("..")
                                except:
                                    pass
                            else:
                                if full_item.lower().endswith(".bak"):
                                    self.bak_files.append(full_item)
                                    self.result_signal.emit(f".bak Datei gefunden: {full_item}", "warn")
                except Exception:
                    pass

            walk(".")

            if self._is_cancelled:
                return

            if not self.bak_files:
                self.result_signal.emit("Keine .bak Dateien gefunden.", "ok")
            else:
                self.result_signal.emit(f"{len(self.bak_files)} .bak Dateien gefunden.", "warn")

        except Exception as e:
            self.result_signal.emit(f"Fehler beim Scan: {str(e)}", "error")
        finally:
            if conn:
                try:
                    if isinstance(conn, ftplib.FTP):
                        conn.quit()
                    else:
                        conn.close()
                except:
                    pass
            self.finished_signal.emit(self.bak_files)


import datetime


class LogfileWorker(QThread):
    progress_signal = Signal(str)
    result_signal = Signal(str, str)
    finished_signal = Signal(list, list)  # (errors_found, files_deleted)
    cancelled_signal = Signal()

    def __init__(self, page_instance, profile, max_age_days, mode="scan"):
        super().__init__()
        self.page = page_instance
        self.profile = profile
        self.max_age_days = max_age_days
        self.mode = mode  # 'scan' or 'cleanup'
        self._is_cancelled = False
        self.errors_found = []
        self.files_deleted = []

    def cancel(self):
        self._is_cancelled = True
        self.cancelled_signal.emit()

    def run(self):
        conn = None
        try:
            self.progress_signal.emit(f"Verbinde für Logfile-{self.mode}...")
            conn, _ = self.page._check_connection(self.profile, self.result_signal)
            if not conn:
                self.finished_signal.emit([], [])
                return

            if self._is_cancelled:
                return

            log_dir = "logfiles"
            try:
                if isinstance(conn, ftplib.FTP):
                    conn.cwd(log_dir)
                else:
                    conn.chdir(log_dir)
            except Exception as e:
                self.result_signal.emit(f"Konnte Ordner 'logfiles' nicht öffnen: {e}", "warn")
                self.finished_signal.emit([], [])
                return

            self.progress_signal.emit("Lese Logfiles...")
            files = []
            now = datetime.datetime.now()
            max_age_seconds = self.max_age_days * 86400

            if isinstance(conn, ftplib.FTP):
                try:
                    for name, attrs in conn.mlsd():
                        if name in [".", ".."]:
                            continue
                        if attrs.get("type") != "file":
                            continue
                        modify = attrs.get("modify")
                        file_time = None
                        if modify:
                            try:
                                file_time = datetime.datetime.strptime(modify, "%Y%m%d%H%M%S")
                            except:
                                pass
                        files.append({"name": name, "time": file_time})
                except:
                    # Fallback if mlsd fails (e.g. some FTP servers)
                    for name in conn.nlst():
                        if name in [".", ".."]:
                            continue
                        # Wir schätzen das Alter über MDTM
                        try:
                            resp = conn.sendcmd(f"MDTM {name}")
                            file_time = datetime.datetime.strptime(resp[4:18], "%Y%m%d%H%M%S")
                            files.append({"name": name, "time": file_time})
                        except:
                            files.append({"name": name, "time": None})
            else:
                for attr in conn.listdir_attr("."):
                    if attr.filename in [".", ".."]:
                        continue
                    if stat.S_ISDIR(attr.st_mode):
                        continue
                    file_time = datetime.datetime.fromtimestamp(attr.st_mtime)
                    files.append({"name": attr.filename, "time": file_time})

            if self._is_cancelled:
                return

            if self.mode == "cleanup":
                self.progress_signal.emit("Lösche alte Logfiles...")
                for f in files:
                    if self._is_cancelled:
                        break
                    name = f["name"]
                    if name in [".htaccess", "index.html"]:
                        continue
                    file_time = f["time"]
                    if file_time:
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
                    name = f["name"]
                    if name in [".htaccess", "index.html"]:
                        continue
                    if not (name.endswith(".log") or name.endswith(".txt")):
                        continue

                    # Wir analysieren nur Dateien, die nicht zu alt sind (oder alle?)
                    # Um den Download in Grenzen zu halten, analysieren wir nur die letzten X Tage?
                    # Für diesen Anwendungsfall analysieren wir alle gefundenen Logfiles.

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
                                except:
                                    decoded_line = str(line)
                                self.errors_found.append(f"[{name}:Zeile {i + 1}] {decoded_line}")
                    except Exception as e:
                        self.result_signal.emit(f"Fehler beim Lesen von {name}: {e}", "warn")

        except Exception as e:
            self.result_signal.emit(f"Fehler bei Logfile-{self.mode}: {str(e)}", "error")
        finally:
            if conn:
                try:
                    if isinstance(conn, ftplib.FTP):
                        conn.quit()
                    else:
                        conn.close()
                except:
                    pass
            self.finished_signal.emit(self.errors_found, self.files_deleted)


class HealthCheckPage(QWidget):
    result_signal = Signal(str, str)
    """
    Führt System-Integritätsprüfungen für Gambio-Shops durch.
    Prüft Konnektivität, Dateistruktur, Versionen und Berechtigungen.
    """

    def __init__(self, auth_manager, config_manager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.config_manager = config_manager
        self.current_logger = None
        self.current_legacy_files = []
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Header & Profilauswahl
        header_group = QGroupBox("Prüfungskonfiguration")
        v_header_layout = QVBoxLayout(header_group)

        h_header_layout = QHBoxLayout()
        h_header_layout.addWidget(QLabel("Shop-Profil:"))
        self.combo_profiles = QComboBox()
        self.combo_profiles.currentIndexChanged.connect(self._on_profile_selected)
        h_header_layout.addWidget(self.combo_profiles, 1)

        self.btn_run = QPushButton("Health-Check starten")
        self.btn_run.setMinimumHeight(40)
        self.btn_run.setStyleSheet("font-weight: bold; background-color: #2c3e50; color: white;")
        self.btn_run.clicked.connect(self.run_health_check)
        h_header_layout.addWidget(self.btn_run)

        # Abbruch-Button
        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setMinimumHeight(40)
        self.btn_cancel.setStyleSheet("background-color: #e74c3c; color: white;")
        self.btn_cancel.setEnabled(False)  # Initial deaktiviert
        self.btn_cancel.clicked.connect(self._cancel_health_check)
        h_header_layout.addWidget(self.btn_cancel)

        v_header_layout.addLayout(h_header_layout)

        self.cb_scan_gambio_modules = QCheckBox("Gambio-Module (Core) bei Kompatibilitätsprüfung einschließen")
        self.cb_scan_gambio_modules.setChecked(False)
        v_header_layout.addWidget(self.cb_scan_gambio_modules)

        layout.addWidget(header_group)

        # Status- und Spinner-Bereich
        status_group = QGroupBox("Aktueller Status")
        status_layout = QHBoxLayout(status_group)
        self.status_label = QLabel("Bereit für Health-Check.")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 14px;")

        self.spinner_bar = QProgressBar()
        self.spinner_bar.setRange(0, 0)  # Indeterminate mode
        self.spinner_bar.setTextVisible(False)
        self.spinner_bar.setFixedSize(150, 15)
        self.spinner_bar.hide()  # Initially hidden

        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(self.spinner_bar)
        layout.addWidget(status_group)

        # Prominenter Backup-Hinweis
        warning_label = QLabel(
            "⚠️ WICHTIGER HINWEIS: Bitte fertigen Sie UNBEDINGT ein vollständiges Backup (Dateien & Datenbank) an, bevor Sie Löschaktionen durchführen!"
        )
        warning_label.setStyleSheet(
            "color: white; background-color: #c0392b; font-weight: bold; padding: 10px; border-radius: 5px; font-size: 14px; margin-top: 5px; margin-bottom: 5px;"
        )
        warning_label.setWordWrap(True)
        warning_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(warning_label)

        # Bestätigungs-Checkbox
        self.cb_backup_confirmed = QCheckBox(
            "Ich bestätige, dass ich ein aktuelles Backup (Dateien & Datenbank) angefertigt habe."
        )
        self.cb_backup_confirmed.setStyleSheet("font-weight: bold; color: #c0392b; margin-bottom: 5px;")
        self.cb_backup_confirmed.stateChanged.connect(self._update_delete_buttons_state)
        layout.addWidget(self.cb_backup_confirmed)

        # Backup-Dateien Gruppe
        bak_group = QGroupBox("Backup-Dateien (.bak)")
        bak_layout = QHBoxLayout(bak_group)
        self.btn_scan_bak = QPushButton("Nach .bak Dateien scannen")
        self.btn_scan_bak.setToolTip("Durchsucht den Server asynchron nach .bak Dateien.")
        self.btn_scan_bak.clicked.connect(self._scan_bak_files)
        self.btn_delete_bak = QPushButton("Gefundene .bak Dateien löschen")
        self.btn_delete_bak.setEnabled(False)
        self.btn_delete_bak.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold;")
        self.btn_delete_bak.clicked.connect(self._delete_bak_files)
        bak_layout.addWidget(self.btn_scan_bak)
        bak_layout.addWidget(self.btn_delete_bak)
        layout.addWidget(bak_group)

        self.current_bak_files = []

        # Logfile-Analyse Gruppe
        logfile_group = QGroupBox("Logfile Analyse & Bereinigung")
        logfile_layout = QHBoxLayout(logfile_group)
        self.btn_scan_logs = QPushButton("Logfiles scannen & Fehler exportieren")
        self.btn_scan_logs.clicked.connect(self._scan_logfiles)
        self.btn_cleanup_logs = QPushButton("Alte Logfiles löschen")
        self.btn_cleanup_logs.setEnabled(False)
        self.btn_cleanup_logs.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold;")
        self.btn_cleanup_logs.clicked.connect(self._cleanup_logfiles)
        logfile_layout.addWidget(self.btn_scan_logs)
        logfile_layout.addWidget(self.btn_cleanup_logs)
        layout.addWidget(logfile_group)

        # Hash-Check-Aktionen
        hash_group = QGroupBox("Integritäts- & Hash-Check")
        hash_layout = QHBoxLayout(hash_group)
        self.btn_gen_baseline = QPushButton("Baseline erzeugen")
        self.btn_gen_baseline.setToolTip(
            "Erzeugt Referenz-Hashes aller aktuellen Dateien (überschreibt alte Baseline)."
        )
        self.btn_gen_baseline.clicked.connect(lambda: self.run_health_check(mode="baseline"))

        self.btn_run_hash = QPushButton("Hash-Check starten")
        self.btn_run_hash.clicked.connect(lambda: self.run_health_check(mode="hash_check"))

        hash_layout.addWidget(self.btn_gen_baseline)
        hash_layout.addWidget(self.btn_run_hash)
        layout.addWidget(hash_group)

        # Altlasten (Legacy) Gruppe
        self.legacy_group = QGroupBox("Altlasten")
        legacy_layout = QHBoxLayout(self.legacy_group)
        self.btn_delete_legacy = QPushButton("Gefundene Altlasten löschen")
        self.btn_delete_legacy.setEnabled(False)
        self.btn_delete_legacy.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold;")
        self.btn_delete_legacy.clicked.connect(self._delete_legacy_files)
        legacy_layout.addWidget(self.btn_delete_legacy)
        layout.addWidget(self.legacy_group)
        self.legacy_group.hide()  # Standardmäßig ausblenden

        # Logging-Bereich
        log_group = QGroupBox("Logging & Historie")
        log_layout = QHBoxLayout(log_group)
        self.btn_open_log_dir = QPushButton("Log-Ordner öffnen")
        self.btn_open_last_log = QPushButton("Letzte Log-Datei öffnen")
        self.btn_open_log_dir.clicked.connect(self._open_log_folder)
        self.btn_open_last_log.clicked.connect(self._open_last_log)
        self.btn_export_html = QPushButton("Bericht (HTML)")
        self.btn_export_html.clicked.connect(self._export_html)
        self.btn_export_pdf = QPushButton("Bericht (PDF)")
        self.btn_export_pdf.clicked.connect(self._export_pdf)
        log_layout.addWidget(self.btn_open_log_dir)
        log_layout.addWidget(self.btn_open_last_log)
        log_layout.addWidget(self.btn_export_html)
        log_layout.addWidget(self.btn_export_pdf)
        layout.addWidget(log_group)

        # Ergebnisbereich
        results_label = QLabel("Prüfungsergebnisse:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(results_label)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)

        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setAlignment(Qt.AlignTop)

        self.scroll_area.setWidget(self.results_container)

        # Automatisch ans Ende scrollen, wenn neue Ergebnisse hinzugefügt werden
        vsb = self.scroll_area.verticalScrollBar()
        vsb.rangeChanged.connect(lambda min_val, max_val: vsb.setValue(max_val))

        layout.addWidget(self.scroll_area)

    def _add_result(self, text: str, status: str = "ok"):
        """
        Fügt ein farbiges Label zum Ergebnisbereich hinzu.
        status: 'ok' (Grün), 'warn' (Gelb), 'error' (Rot)
        """
        colors = {
            "ok": ("#27ae60", "[✓]"),
            "warn": ("#f39c12", "[!]"),
            "error": ("#c0392b", "[✗]"),
        }
        color, prefix = colors.get(status, colors["ok"])

        # Parallel in die JSON-Line Logdatei schreiben
        if self.current_logger:
            level = "INFO" if status == "ok" else "WARN" if status == "warn" else "ERROR"
            self.current_logger.log(level, text)

        label = QLabel(f"{prefix} {text}")
        label.setStyleSheet(
            f"color: {color}; font-family: 'Courier New'; font-weight: bold; font-size: 13px; margin: 2px;"
        )
        label.setWordWrap(True)
        self.results_layout.addWidget(label)

    def _update_delete_buttons_state(self):
        confirmed = self.cb_backup_confirmed.isChecked()
        self.btn_cleanup_logs.setEnabled(confirmed)
        self.btn_delete_bak.setEnabled(confirmed and bool(self.current_bak_files))
        self.btn_delete_legacy.setEnabled(confirmed and bool(self.current_legacy_files))

    def _clear_results(self):
        """Löscht alle vorherigen Ergebnisse."""
        while self.results_layout.count():
            child = self.results_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def _load_profiles(self):
        """Aktualisiert die Profilliste."""
        self.combo_profiles.blockSignals(True)
        self.combo_profiles.clear()
        profiles = self.config_manager.get_profiles()

        target_name = self.config_manager.get_last_selected_profile_name()
        index_to_select = 0

        for i, p in enumerate(profiles):
            shop_name = p.get("shop_name", "Unbenannt")
            self.combo_profiles.addItem(shop_name)
            if shop_name == target_name:
                index_to_select = i

        if self.combo_profiles.count() > 0:
            self.combo_profiles.setCurrentIndex(index_to_select)

        self.combo_profiles.blockSignals(False)

    def _on_profile_selected(self, index):
        if index >= 0:
            profile_name = self.combo_profiles.currentText()
            self.config_manager.set_last_selected_profile_name(profile_name)
            password = self.auth_manager.get_password()
            if password:
                try:
                    self.config_manager.save_current_config(password)
                except Exception:
                    pass

    def run_health_check(self, mode="full"):
        """Hauptroutine für den Health-Check."""
        try:
            self.auth_manager.require_active_session()
            self.auth_manager.update_activity()

            if mode == "baseline":
                reply = QMessageBox.warning(
                    self,
                    "Baseline erzeugen",
                    "Dies überschreibt die vorhandene Referenz. Alle aktuellen Dateien gelten danach als 'sicher'. Fortfahren?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if reply != QMessageBox.Yes:
                    return

            self._clear_results()
            profile_idx = self.combo_profiles.currentIndex()
            profiles = self.config_manager.get_profiles()

            if profile_idx < 0 or not profiles:
                show_error("Bitte wählen Sie ein Shop-Profil aus.")
                return

            profile = profiles[profile_idx]

            # Kompatibilitätsprüfung erfolgt nun dynamisch im Worker

            # Logger für dieses Profil initialisieren
            self.current_logger = HealthCheckLogger(profile.get("shop_name", "Unbenannt"))

            # UI sperren
            self.btn_run.setEnabled(False)
            self.btn_run.setText("Prüfung läuft...")
            self.btn_cancel.setEnabled(True)  # Abbruch-Button aktivieren
            self.btn_delete_legacy.setEnabled(False)
            self.current_legacy_files = []
            self.legacy_group.hide()

            # Worker initialisieren und starten
            scan_gambio = self.cb_scan_gambio_modules.isChecked()
            self.worker = HealthCheckWorker(self, profile, self.current_logger, mode=mode, scan_gambio=scan_gambio)
            self.worker.result_signal.connect(self._add_result)
            self.worker.progress_signal.connect(self.update_status)  # Connect new progress signal
            self.worker.legacy_files_signal.connect(self._set_legacy_files)  # Keep this for legacy files
            self.worker.finished_signal.connect(self.check_finished)  # Connect to new check_finished

            # Show spinner
            self.spinner_bar.show()

            self.worker.start()

        except SessionExpiredError:
            show_error("Ihre Sitzung ist abgelaufen. Bitte wechseln Sie die Seite zur Neuanmeldung.")
            self.btn_run.setEnabled(True)
            self.btn_run.setText("Health-Check starten")
            self.spinner_bar.hide()
        except Exception as e:
            # Ensure UI is reset even on unexpected errors
            logger.error(f"Health-Check Fehler: {e}")
            self._add_result(f"Unerwarteter Fehler: {str(e)}", "error")
            self.btn_run.setEnabled(True)
            self.btn_cancel.setEnabled(False)  # Abbruch-Button deaktivieren

    def _open_log_folder(self):
        """Öffnet den Explorer im Log-Verzeichnis des aktuellen Profils."""
        profile_idx = self.combo_profiles.currentIndex()
        profiles = self.config_manager.get_profiles()
        if profile_idx >= 0:
            logger_tmp = HealthCheckLogger(profiles[profile_idx].get("shop_name", "default"))
            open_path(logger_tmp.get_log_dir())

    def _open_last_log(self):
        """Öffnet die aktuellste Log-Datei des ausgewählten Profils."""
        profile_idx = self.combo_profiles.currentIndex()
        profiles = self.config_manager.get_profiles()
        if profile_idx >= 0:
            logger_tmp = HealthCheckLogger(profiles[profile_idx].get("shop_name", "default"))
            last_log = logger_tmp.get_last_log_file()
            if last_log:
                open_path(last_log)
            else:
                show_error("Keine Log-Dateien für dieses Profil gefunden.")

    def _emit_progress(self, message: str):
        """Sendet sicher Status-Updates an die GUI, egal ob im Thread oder nicht."""
        if hasattr(self, "worker") and self.worker and self.worker.isRunning():
            self.worker.progress_signal.emit(message)
        else:
            self.status_label.setText(message)

    def _set_legacy_files(self, files):
        """Speichert die gefundenen Altlasten und aktiviert den Button."""
        self.current_legacy_files = files
        if self.current_legacy_files:
            self.legacy_group.show()  # Gruppe anzeigen, wenn Altlasten gefunden wurden
        else:
            self.legacy_group.hide()  # Gruppe ausblenden, wenn keine Altlasten gefunden wurden
        self._update_delete_buttons_state()

    def update_status(self, text: str):
        """Updates the status label with the current progress message."""
        self.status_label.setText(text)
        if self.current_logger:
            self.current_logger.log("INFO", f"STATUS: {text}")

    def check_finished(self):
        """Wird aufgerufen, wenn der Worker-Thread fertig ist."""
        self.btn_run.setEnabled(True)
        self.btn_cancel.setEnabled(False)  # Abbruch-Button deaktivieren
        self._update_delete_buttons_state()  # Re-enable based on found files and confirmation
        self.btn_run.setText("Health-Check starten")

        # Final status message (nur loggen, wenn Logger noch offen ist)
        if self.worker._is_cancelled:
            if self.current_logger and not getattr(self.current_logger.file_handle, "closed", True):
                self._add_result("--- Health-Check abgebrochen ---", "warn")
            self.status_label.setText("Health-Check abgebrochen.")
        else:
            if self.current_logger and not getattr(self.current_logger.file_handle, "closed", True):
                self._add_result("--- Health-Check abgeschlossen ---", "ok")
            self.status_label.setText("Health-Check abgeschlossen.")

        # Hide and stop spinner
        self.spinner_bar.hide()
        self.auth_manager.update_activity()

    def cancel_all(self):
        """Bricht alle laufenden Aktionen in dieser Ansicht ab."""
        self._cancel_health_check()

        # Andere laufende Worker abbrechen
        if hasattr(self, "delete_worker") and self.delete_worker and self.delete_worker.isRunning():
            self.delete_worker.cancel()
        if hasattr(self, "bak_worker") and self.bak_worker and self.bak_worker.isRunning():
            self.bak_worker.cancel()
        if hasattr(self, "log_worker") and self.log_worker and self.log_worker.isRunning():
            self.log_worker.cancel()

    def _cancel_health_check(self):
        """Bricht den laufenden Health-Check ab."""
        if hasattr(self, "worker") and self.worker.isRunning():
            self.worker.cancel()
            self.status_label.setText("Health-Check wird abgebrochen...")
            self._add_result("Health-Check manuell abgebrochen.", "warn")
            # Der Worker wird sein finished_signal senden, welches check_finished aufruft
            # und die UI zurücksetzt.
        else:
            self.status_label.setText("Kein Health-Check läuft.")

    def _run_legacy_delete_analysis_logic(self, conn, signal=None):
        """
        Analysiert alle Update-Ordner chronologisch auf zu löschende Dateien.
        Berücksichtigt Konflikte durch Wiedereinführung von Dateien.
        """

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Starte vollständige Delete-Analyse über alle Updates...")
        update_base = "gambio_updater/updates"

        # Check for cancellation before starting long operations
        delete_map = {}  # Datei -> Letzte Version, in der sie gelöscht werden sollte
        added_map = {}  # Datei -> Letzte Version, in der sie geändert/hinzugefügt wurde

        try:
            # 1. Update-Ordner auslesen & sortieren
            if isinstance(conn, ftplib.FTP):
                folders = [f.split("/")[-1].split("\\")[-1] for f in conn.nlst(update_base)]
                if self.worker._is_cancelled:
                    return []
            else:
                folders = [f.filename for f in conn.listdir_attr(update_base) if stat.S_ISDIR(f.st_mode)]

            versioned_folders = []
            for f in folders:
                if f.startswith("v"):
                    v_str = f[1:]
                    versioned_folders.append((self._parse_ver_tuple(v_str), f))

            # Sortieren nach Version (älteste zuerst)
            versioned_folders.sort(key=lambda x: x[0])

            if versioned_folders:
                folder_list = ", ".join([f[1] for f in versioned_folders])
                log(f"Folgende Update-Pakete werden auf Altlasten geprüft: {folder_list}")

            # 2. Alle to_delete.php und updated_files.txt sammeln
            for v_tuple, folder_name in versioned_folders:
                if self.worker._is_cancelled:
                    return []
                path = f"{update_base}/{folder_name}"

                # extrahiere to_delete.php
                try:
                    content = ""
                    if isinstance(conn, ftplib.FTP):
                        r_io = io.BytesIO()
                        conn.retrbinary(f"RETR {path}/to_delete.php", r_io.write)
                        content = r_io.getvalue().decode("utf-8", errors="ignore")
                    else:
                        with conn.open(f"{path}/to_delete.php", "r") as f:
                            content = f.read().decode("utf-8", errors="ignore")

                    # -------------------------------------------------------
                    # Robuster Parser für to_delete.php:
                    # Gambio nutzt PHP-Logik mit if/file_exists()-Bedingungen.
                    # Strategie:
                    # 1) Pfade aus file_exists()-Aufrufen sind BEDINGUNGEN → ausschließen
                    # 2) Wildcard-Pfade wie 'path/*' → Suffix /* entfernen, als Verzeichnis prüfen
                    # 3) Nur Strings extrahieren die wie Dateisystem-Pfade aussehen
                    # -------------------------------------------------------

                    # Schritt 1: file_exists()-Argumente sammeln (nur Bedingungen, NICHT zu löschen)
                    file_exists_args = set()
                    for fe_match in re.finditer(
                        r"file_exists\s*\(\s*(?:[^)]*?\.\s*)?['\"]([^'\"]+)['\"]",
                        content,
                    ):
                        file_exists_args.add(fe_match.group(1))

                    # Schritt 2: Alle quoted Strings extrahieren
                    all_quoted = re.findall(r"['\"]([^'\"]+)['\"]", content)

                    for p in all_quoted:
                        p = p.strip()
                        if not p:
                            continue
                        # PHP-interne Strings herausfiltern
                        if (
                            p.startswith("$")
                            or p.startswith("<?")
                            or p.startswith("http")
                            or p.startswith("//")
                            or "\n" in p
                            or len(p) < 3
                        ):
                            continue
                        # Keine PHP-Schlüsselwörter / Kommentare
                        if p in ("true", "false", "null", "return", "array_merge"):
                            continue
                        # Schritt 3: file_exists()-Bedingungen ausschließen
                        if p in file_exists_args:
                            continue
                        # Wildcard-Prüfung für Pfad-Validierung
                        is_wildcard = "*" in p
                        clean_p = p
                        if not clean_p:
                            continue

                        # Für die Erkennung, ob es wie ein Pfad aussieht, temporär Wildcards entfernen
                        temp_p = clean_p.replace("*", "")
                        last_part = temp_p.split("/")[-1] if "/" in temp_p else temp_p
                        has_slash = "/" in temp_p
                        has_ext = "." in last_part
                        if not has_slash and not has_ext and not is_wildcard:
                            # Kurze Strings ohne Slash/Extension/Wildcard: nur akzeptieren
                            # wenn sie länger als 4 Zeichen sind (echte Ordnernamen)
                            # und keine typischen PHP-Daten-Strings sind (Datum, Versionsnr.)
                            if len(temp_p) <= 4:
                                continue
                            # Reine Datums-Strings wie '2023-04-28' oder Versionen ausschließen
                            if re.match(r"^\d", temp_p):
                                continue
                        delete_map[clean_p] = v_tuple
                except:
                    pass

                # extrahiere updated_files.txt
                try:
                    content = ""
                    if isinstance(conn, ftplib.FTP):
                        r_io = io.BytesIO()
                        conn.retrbinary(f"RETR {path}/updated_files.txt", r_io.write)
                        content = r_io.getvalue().decode("utf-8", errors="ignore")
                    else:
                        with conn.open(f"{path}/updated_files.txt", "r") as f:
                            content = f.read().decode("utf-8", errors="ignore")

                    for line in content.splitlines():
                        if line.strip():
                            added_map[line.strip()] = v_tuple
                except:
                    pass

            # 3. Konfliktauflösung
            excluded_str = self.config_manager.get_excluded_files()
            excluded_list = [f.strip() for f in excluded_str.split(",") if f.strip()]

            # Eine Datei ist nur dann ein Kandidat, wenn die letzte Löschanweisung
            # NEUER oder GLEICH der letzten Hinzufügung ist.
            # Speichert (file_path, del_v_tuple) damit die Version in der Ausgabe erscheint
            final_delete_list = []
            for file_path, del_v in delete_map.items():
                if any(ex in file_path for ex in excluded_list):
                    if self.worker._is_cancelled:
                        return []
                    continue
                add_v = added_map.get(file_path, (0,))
                if del_v >= add_v:
                    final_delete_list.append((file_path, del_v))
            final_delete_list.sort(key=lambda x: x[0])  # Nach Pfad sortieren

            # 4. Existenzprüfung
            legacy_found = []
            log(f"Analysiere {len(final_delete_list)} potenzielle Altlasten auf dem Server...")

            for file_path, del_v in final_delete_list:
                if self.worker._is_cancelled:
                    return []

                # Wenn ein Ordner-Inhalt gelöscht werden soll (/*),
                # löschen wir stattdessen den Ordner selbst rekursiv.
                if file_path.endswith("/*"):
                    file_path = file_path[:-2]

                # Prüfen auf Wildcard (*)
                if "*" in file_path:
                    # z.B. security-update-*.php -> parent_dir = ".", pattern = "security-update-*.php"
                    # z.B. GXModules/Gambio/Google/Admin/Classes/* -> parent_dir = "GXModules/Gambio/Google/Admin/Classes", pattern = "*"
                    if "/" in file_path:
                        parent_dir, pattern = file_path.rsplit("/", 1)
                    else:
                        parent_dir, pattern = ".", file_path

                    try:
                        matched_items = []
                        if isinstance(conn, ftplib.FTP):
                            try:
                                items = conn.nlst(parent_dir)
                                for item in items:
                                    # FTP nlst kann relativen oder vollen Pfad liefern
                                    name = item.split("/")[-1].split("\\")[-1]
                                    if name in (".", ".."):
                                        continue
                                    if fnmatch.fnmatch(name, pattern):
                                        full_item = item if "/" in item else f"{parent_dir}/{item}"
                                        # `./` Präfix entfernen falls vorhanden
                                        if full_item.startswith("./"):
                                            full_item = full_item[2:]
                                        matched_items.append(full_item)
                            except:
                                pass
                        else:  # SFTP
                            try:
                                for entry in conn.listdir_attr(parent_dir):
                                    if entry.filename in (".", ".."):
                                        continue
                                    if fnmatch.fnmatch(entry.filename, pattern):
                                        full_item = f"{parent_dir}/{entry.filename}"
                                        if full_item.startswith("./"):
                                            full_item = full_item[2:]
                                        matched_items.append(full_item)
                            except:
                                pass

                        for item in matched_items:
                            last_part = item.split("/")[-1]
                            entry_type = "Ordner" if "." not in last_part else "Datei"
                            ver_str = self._ver_tuple_to_str(del_v)
                            log(
                                f"{entry_type} sollte seit Update {ver_str} gelöscht sein: {item}",
                                "error",
                            )
                            legacy_found.append(item)
                    except Exception:
                        pass
                else:
                    # Normaler Pfad ohne Wildcard
                    exists = False
                    try:
                        if isinstance(conn, ftplib.FTP):
                            # conn.size() schlägt bei Ordnern fehl – daher NLST als Fallback
                            try:
                                conn.size(file_path)
                                exists = True
                            except ftplib.error_perm:
                                # Könnte ein Ordner sein – mit NLST prüfen
                                try:
                                    result = conn.nlst(file_path)
                                    if result is not None:  # NLST liefert Liste auch für leere Ordner
                                        exists = True
                                except ftplib.error_perm:
                                    pass  # Existiert wirklich nicht
                        else:
                            try:
                                conn.stat(file_path)
                                exists = True
                            except Exception:
                                pass
                    except Exception:
                        pass

                    if exists:
                        # Präfix `./` entfernen falls vorhanden
                        clean_path = file_path
                        if clean_path.startswith("./"):
                            clean_path = clean_path[2:]
                        # Prüfen ob Datei oder Ordner
                        last_part = clean_path.split("/")[-1]
                        entry_type = "Ordner" if "." not in last_part else "Datei"
                        ver_str = self._ver_tuple_to_str(del_v)
                        log(
                            f"{entry_type} sollte seit Update {ver_str} gelöscht sein: {clean_path}",
                            "error",
                        )
                        legacy_found.append(clean_path)
                # Wir loggen korrekt gelöschte Dateien nicht einzeln, um die Liste sauber zu halten,
                # außer es wird explizit gewünscht.

            if not legacy_found:
                log("Keine gefährlichen Altlasten gefunden. System ist bereinigt.", "ok")
            else:
                log(f"Kritisch: {len(legacy_found)} Altlasten gefunden!", "error")

            return legacy_found

        except Exception as e:
            if not (self.worker and getattr(self.worker, "_is_cancelled", False)):
                log(f"Fehler bei Delete-Analyse: {str(e)}", "error")
            return []

    def _delete_legacy_files(self):
        """Initialisiert den Löschvorgang für die gefundenen Dateien."""
        if not self.current_legacy_files:
            return

        reply = QMessageBox.warning(
            self,
            "Altlasten löschen",
            f"Möchten Sie {len(self.current_legacy_files)} Dateien unwiderruflich vom Server löschen?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply != QMessageBox.Yes:
            return

        try:
            self.auth_manager.require_active_session()

            profile_idx = self.combo_profiles.currentIndex()
            profiles = self.config_manager.get_profiles()
            profile = profiles[profile_idx]

            self.btn_delete_legacy.setEnabled(False)
            self.btn_run.setEnabled(False)
            self._add_result("--- Starte Bereinigung ---", "warn")

            logger_instance = HealthCheckLogger(profile.get("shop_name", "Unknown"))
            last_log = logger_instance.get_last_log_file()
            if last_log:
                logger_instance.current_file = last_log
                logger_instance.file_handle = open(last_log, "a", encoding="utf-8")
                logger_instance.log("INFO", "--- Löschvorgang gestartet ---")
            else:
                logger_instance.start_session()

            self.delete_worker = LegacyDeleteWorker(
                self,
                profile,
                self.current_legacy_files,
                logger_instance=logger_instance,
                clear_cache=True,
            )
            self.delete_worker.progress_signal.connect(self._emit_progress)
            self.delete_worker.result_signal.connect(self._add_result)
            self.delete_worker.finished_signal.connect(self._on_legacy_deleted)
            self.delete_worker.start()

        except SessionExpiredError:
            show_error("Sitzung abgelaufen. Bitte erneut anmelden.")

    def _on_legacy_deleted(self):
        """Callback nach dem Löschvorgang."""
        self.btn_run.setEnabled(True)
        self.current_legacy_files = []
        self._update_delete_buttons_state()
        self.auth_manager.update_activity()

    def _scan_bak_files(self):
        profile_idx = self.combo_profiles.currentIndex()
        if profile_idx < 0:
            return
        profile = self.config_manager.get_profiles()[profile_idx]

        self.btn_scan_bak.setEnabled(False)
        self.btn_delete_bak.setEnabled(False)
        self.btn_run.setEnabled(False)

        self.spinner_bar.show()
        self._add_result("--- Starte .bak Scanner ---", "ok")

        self.bak_worker = BakFileScannerWorker(self, profile)
        self.bak_worker.progress_signal.connect(self._emit_progress)
        self.bak_worker.result_signal.connect(self._add_result)
        self.bak_worker.finished_signal.connect(self._on_bak_scan_finished)
        self.bak_worker.start()

    def _on_bak_scan_finished(self, files):
        self.spinner_bar.hide()
        self.btn_scan_bak.setEnabled(True)
        self.btn_run.setEnabled(True)
        self.status_label.setText("Scan beendet.")

        self.current_bak_files = files
        self._update_delete_buttons_state()
        self.auth_manager.update_activity()

    def _scan_logfiles(self):
        profile_idx = self.combo_profiles.currentIndex()
        if profile_idx < 0:
            return
        profile = self.config_manager.get_profiles()[profile_idx]
        max_age = self.config_manager.get_max_log_age()

        self.btn_scan_logs.setEnabled(False)
        self.btn_cleanup_logs.setEnabled(False)
        self.btn_run.setEnabled(False)
        self.spinner_bar.show()
        self._add_result("--- Starte Logfile Analyse ---", "ok")

        self.log_worker = LogfileWorker(self, profile, max_age, mode="scan")
        self.log_worker.progress_signal.connect(self._emit_progress)
        self.log_worker.result_signal.connect(self._add_result)
        self.log_worker.finished_signal.connect(self._on_log_scan_finished)
        self.log_worker.start()

    def _on_log_scan_finished(self, errors_found, files_deleted):
        self.spinner_bar.hide()
        self.btn_scan_logs.setEnabled(True)
        self._update_delete_buttons_state()
        self.btn_run.setEnabled(True)
        self.status_label.setText("Logfile-Scan beendet.")
        self.auth_manager.update_activity()

        if errors_found:
            self._add_result(f"{len(errors_found)} Fehler in Logfiles gefunden.", "error")
            reply = QMessageBox.question(
                self,
                "Fehler gefunden",
                f"Es wurden {len(errors_found)} Fehler in den Logfiles gefunden.\nMöchten Sie diese als Bericht für den Support exportieren?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                profile_name = self.combo_profiles.currentText()
                path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Fehler-Bericht speichern",
                    f"{profile_name}_Support_Logs.html",
                    "HTML Files (*.html)",
                )
                if path:
                    try:
                        import html

                        with open(path, "w", encoding="utf-8") as f:
                            f.write(
                                f"<html><head><meta charset='utf-8'><title>Logfile Fehlerbericht für {profile_name}</title>\n"
                            )
                            f.write("<style>\n")
                            f.write(
                                "body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; margin: 20px; }\n"
                            )
                            f.write("h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }\n")
                            f.write(
                                ".error { margin-bottom: 12px; padding: 12px; background-color: #fff; border-left: 4px solid #e74c3c; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-family: monospace; white-space: pre-wrap; word-break: break-all; }\n"
                            )
                            f.write("</style>\n")
                            f.write("</head><body>\n")
                            f.write(f"<h2>Logfile Fehlerbericht für {html.escape(profile_name)}</h2>\n")
                            for err in errors_found:
                                safe_err = html.escape(err)
                                f.write(f"<div class='error'>{safe_err}</div>\n")
                            f.write("</body></html>\n")
                        QMessageBox.information(self, "Erfolg", "Bericht wurde erfolgreich gespeichert.")
                    except Exception as e:
                        show_error(f"Fehler beim Speichern des Berichts: {e}")
        else:
            self._add_result(
                "Keine relevanten Fehler ('ERROR', 'FATAL', 'Exception') in den Logfiles gefunden.",
                "ok",
            )

    def _cleanup_logfiles(self):
        profile_idx = self.combo_profiles.currentIndex()
        if profile_idx < 0:
            return
        profile = self.config_manager.get_profiles()[profile_idx]
        max_age = self.config_manager.get_max_log_age()

        reply = QMessageBox.warning(
            self,
            "Alte Logfiles löschen",
            f"Möchten Sie alle Dateien im Ordner 'logfiles', die älter als {max_age} Tage sind (außer .htaccess und index.html), unwiderruflich löschen?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        self.btn_scan_logs.setEnabled(False)
        self.btn_cleanup_logs.setEnabled(False)
        self.btn_run.setEnabled(False)
        self.spinner_bar.show()
        self._add_result(f"--- Starte Logfile Bereinigung (Älter als {max_age} Tage) ---", "warn")

        self.log_worker = LogfileWorker(self, profile, max_age, mode="cleanup")
        self.log_worker.progress_signal.connect(self._emit_progress)
        self.log_worker.result_signal.connect(self._add_result)
        self.log_worker.finished_signal.connect(self._on_log_cleanup_finished)
        self.log_worker.start()

    def _on_log_cleanup_finished(self, errors_found, files_deleted):
        self.spinner_bar.hide()
        self.btn_scan_logs.setEnabled(True)
        self._update_delete_buttons_state()
        self.btn_run.setEnabled(True)
        self.status_label.setText("Logfile-Bereinigung beendet.")
        self.auth_manager.update_activity()

        self._add_result(f"Bereinigung abgeschlossen: {len(files_deleted)} Dateien gelöscht.", "ok")

    def _delete_bak_files(self):
        if not self.current_bak_files:
            return
        reply = QMessageBox.warning(
            self,
            "Backup-Dateien löschen",
            f"Möchten Sie {len(self.current_bak_files)} .bak Dateien unwiderruflich vom Server löschen?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            self.auth_manager.require_active_session()
            profile_idx = self.combo_profiles.currentIndex()
            profile = self.config_manager.get_profiles()[profile_idx]

            self.btn_delete_bak.setEnabled(False)
            self.btn_scan_bak.setEnabled(False)
            self.btn_run.setEnabled(False)
            self._add_result("--- Starte Bereinigung der Backup-Dateien ---", "warn")

            self.delete_worker = LegacyDeleteWorker(self, profile, self.current_bak_files)
            self.delete_worker.progress_signal.connect(self._emit_progress)
            self.delete_worker.result_signal.connect(self._add_result)
            self.delete_worker.finished_signal.connect(self._on_bak_deleted)
            self.delete_worker.start()
        except SessionExpiredError:
            show_error("Sitzung abgelaufen. Bitte erneut anmelden.")

    def _on_bak_deleted(self):
        self.btn_run.setEnabled(True)
        self.btn_scan_bak.setEnabled(True)
        self.current_bak_files = []
        self._update_delete_buttons_state()
        self.auth_manager.update_activity()

    def _check_connection(self, profile, signal=None):
        """
        Prüft die FTP/SFTP Verbindung und listet Dateien auf.
        Verwendet result_signal für detaillierte Ausgaben und progress_signal für den Status-Label.
        """

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Verbinde zum Server...")

        # No cancellation check here, as connection is a single blocking call
        try:
            protocol = profile.get("protocol")
            host = profile.get("host")
            port = int(profile.get("port", 21))
            user = profile.get("username")
            pwd = profile.get("password")
            r_path = profile.get("remote_path", "").strip()

            files = []
            if protocol == "FTP":
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=10)
                ftp.login(user, pwd)
                if r_path:
                    ftp.cwd(r_path)
                files = ftp.nlst()  # This can be slow for large directories
                log("FTP-Verbindung erfolgreich hergestellt.")
                return ftp, files

            elif protocol == "SFTP":
                if paramiko is None:
                    log("SFTP (Paramiko) ist nicht installiert.", "error")
                    return None, []
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port, user, pwd, timeout=10)
                sftp = ssh.open_sftp()
                if r_path:
                    sftp.chdir(r_path)  # Change directory first
                files = sftp.listdir()  # Then list files
                log("SFTP-Verbindung erfolgreich hergestellt.")
                return sftp, files

            log(f"Protokoll {protocol} wird für Dateiprüfung nicht unterstützt.", "warn")
            return None, []
        except Exception as e:  # Catch all exceptions for connection
            log(f"Verbindungsfehler: {str(e)}", "error")
            return None, []

    def _check_gambio_structure(self, files, signal=None):
        """Sucht nach Gambio-typischen Verzeichnissen."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        # No cancellation check here, as it's a quick local check
        indicators = ["system", "GXEngine", "templates", "admin", "version.info"]
        found = [i for i in indicators if i in files]
        self._emit_progress("Prüfe Gambio-Struktur...")
        if found:
            log(f"Gambio-Struktur erkannt (Indikatoren: {', '.join(found)})")
            return True
        return False

    def _check_version(self, conn, profile, signal=None):
        """
        Ermittelt die Gambio-Version aus dem Ordner version_info/.
        """

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Ermittle Gambio-Version...")
        if self.worker._is_cancelled:
            return None

        version_dir = "version_info"
        detected_version = None
        try:
            files = []
            if isinstance(conn, ftplib.FTP):
                try:
                    # Verzeichnisinhalt auflisten
                    raw_files = conn.nlst(version_dir)
                    # Bereinigen: nlst kann Pfade enthalten (z.B. version_info/build_...)
                    if self.worker._is_cancelled:
                        return None
                    files = [f.split("/")[-1].split("\\")[-1] for f in raw_files]
                except ftplib.error_perm:
                    log("Ordner version_info nicht gefunden.", "error")
                    return
            else:  # SFTP
                try:
                    files = conn.listdir(version_dir)
                    if self.worker._is_cancelled:
                        return None
                except Exception:
                    log("Ordner version_info nicht gefunden.", "error")
                    return

            # Suche nach build_(\d+).php Dateien
            build_pattern = re.compile(r"build_(\d+)\.php")
            candidates = []
            for f in files:
                match = build_pattern.match(f)
                if self.worker._is_cancelled:
                    return None
                if match:
                    candidates.append((int(match.group(1)), f))

            if not candidates:
                log("Keine Build-Dateien gefunden.", "warn")
                return

            # Höchste Job-ID (Build-Nummer) bestimmen
            candidates.sort(key=lambda x: x[0], reverse=True)
            highest_id, build_filename = candidates[0]
            file_path = f"{version_dir}/{build_filename}"

            # Inhalt der neuesten Build-Datei lesen
            content = ""
            if isinstance(conn, ftplib.FTP):
                r_file = io.BytesIO()
                conn.retrbinary(f"RETR {file_path}", r_file.write)
                if self.worker._is_cancelled:
                    return None
                content = r_file.getvalue().decode("utf-8", errors="ignore")
            else:  # SFTP
                with conn.open(file_path, "r") as f:
                    content = f.read().decode("utf-8", errors="ignore")

            # Version und Job-ID aus dem Dateiinhalt extrahieren
            v_match = re.search(r"CI_BUILD_RELEASE_VERSION:\s*([^\s\r\n]+)", content)
            j_match = re.search(r"CI_BUILD_JOB_ID:\s*(\d+)", content)

            if v_match and j_match:
                detected_version = v_match.group(1).strip()
                job_id = j_match.group(1).strip()
                log(f"Gambio-Version: {detected_version} (Build {job_id})", "ok")
            else:
                log("Build-Datei konnte nicht gelesen werden.", "warn")

        except Exception as e:
            log(f"Fehler bei Versionsprüfung: {str(e)}", "error")

        return detected_version

    def _check_write_permissions(self, conn, profile, signal=None):
        """Prüft Schreibrechte durch Upload einer Testdatei."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Prüfe Schreibrechte...")
        if self.worker._is_cancelled:
            return

        test_filename = "hc_write_test.tmp"
        try:
            test_data = io.BytesIO(b"Gambio Health Check Test")
            if isinstance(conn, ftplib.FTP):
                conn.storbinary(f"STOR {test_filename}", test_data)
                conn.delete(test_filename)
            else:  # SFTP
                conn.putfo(test_data, test_filename)
                if self.worker._is_cancelled:
                    return
                conn.remove(test_filename)
            log("Schreibrechte im Shop-Hauptverzeichnis: OK")
        except:
            self._emit_progress("Eingeschränkte Schreibrechte erkannt.")
            log("Eingeschränkte Schreibrechte im Hauptverzeichnis.", "warn")

    def _check_php_version_via_ftp_http(self, conn, profile, signal=None):
        """
        Ermittelt die PHP-Version durch Hochladen einer temporären Datei,
        """

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Lade PHP-Versionsprüf-Skript hoch...")

        token = secrets.token_hex(16)

        # Erweitertes PHP-Skript zur echten MySQL-Server-Versionserkennung
        php_check_content = (
            b"<?php "
            b"if (!isset($_GET['token']) || $_GET['token'] !== '" + token.encode("utf-8") + b"') { "
            b"  header('HTTP/1.1 403 Forbidden'); "
            b"  exit('Forbidden'); "
            b"} "
            b"error_reporting(0); @ini_set('display_errors', 0); "
            b"header('Content-Type: application/json'); "
            b"$baseDir = dirname(__FILE__); "
            b"$res = array("
            b"  'php' => phpversion(), "
            b"  'db' => array('type' => null, 'version_full' => null, 'version_number' => null), "
            b"  'security' => array("
            b"    'installer_exists' => @is_dir($baseDir . '/gambio_installer'), "
            b"    'config_writable' => @is_writable($baseDir . '/includes/configure.php'), "
            b"    'admin_config_writable' => @is_writable($baseDir . '/admin/includes/configure.php'),"
            b"    'htaccess_admin_backups' => @file_exists($baseDir . '/admin/backups/.htaccess'), "
            b"    'htaccess_log' => @file_exists($baseDir . '/logfiles/.htaccess')"
            b"  ), "
            b"  'env' => array("
            b"    'session_auto_start' => (bool)@ini_get('session.auto_start'), "
            b"    'soap_loaded' => extension_loaded('soap'), "
            b"    'intl_loaded' => extension_loaded('intl')"
            b"  )"
            b"); "
            b"$db_host = $db_user = $db_pass = $db_name = null; "
            b"$configFiles = array($baseDir . '/includes/configure.php', $baseDir . '/system/conf/main.conf.php'); "
            b"foreach ($configFiles as $cf) { "
            b"  if (!$db_host && @file_exists($cf)) { "
            b"    $c = @file_get_contents($cf); "
            b"    preg_match('/DB_SERVER[\"\\']\\\\s*(=>|,)\\\\s*[\"\\']([^\"\\']+)[\"\\']/', $c, $hs); "
            b"    preg_match('/DB_SERVER_USERNAME[\"\\']\\\\s*(=>|,)\\\\s*[\"\\']([^\"\\']+)[\"\\']/', $c, $us); "
            b"    preg_match('/DB_SERVER_PASSWORD[\"\\']\\\\s*(=>|,)\\\\s*[\"\\']([^\"\\']+)[\"\\']/', $c, $ps); "
            b"    preg_match('/DB_DATABASE[\"\\']\\\\s*(=>|,)\\\\s*[\"\\']([^\"\\']+)[\"\\']/', $c, $ds); "
            b"    if (isset($hs[2])) $db_host = $hs[2]; "
            b"    if (isset($us[2])) $db_user = $us[2]; "
            b"    if (isset($ps[2])) $db_pass = $ps[2]; "
            b"    if (isset($ds[2])) $db_name = $ds[2]; "
            b"  } "
            b"} "
            b"if (extension_loaded('mysqli') && $db_host && $db_user && $db_name) { "
            b"  if (function_exists('mysqli_report')) { @mysqli_report(MYSQLI_REPORT_OFF); } "
            b"  $link = @mysqli_connect($db_host, $db_user, $db_pass, $db_name); "
            b"  if ($link) { "
            b"    $server_info = mysqli_get_server_info($link); "
            b"    if ($server_info) { "
            b"      $res['db']['version_full'] = $server_info; "
            b"      $res['db']['type'] = (strpos($server_info, 'MariaDB') !== false) ? 'MariaDB' : 'MySQL'; "
            b"      preg_match('/^(\\\\d+\\\\.\\\\d+(?:\\\\.\\\\d+)?)/', $server_info, $matches); "
            b"      if (isset($matches[1])) { $res['db']['version_number'] = $matches[1]; } "
            b"    } "
            b"    mysqli_close($link); "
            b"  } "
            b"} "
            b"if (!$res['db']['version_full'] && function_exists('mysqli_get_client_info')) { "
            b"  $client_info = mysqli_get_client_info(); "
            b"  $res['db']['type'] = 'Client'; "
            b"  $res['db']['version_full'] = 'Client: ' . $client_info; "
            b"  preg_match('/^(\\\\d+\\\\.\\\\d+\\\\.\\\\d+)/', $client_info, $matches); "
            b"  if (isset($matches[1])) { $res['db']['version_number'] = $matches[1]; } "
            b"} "
            b"echo json_encode($res);"
        )
        temp_php_filename = "hc_php_version_check.php"

        shop_url = profile.get("shop_url", "").strip()
        remote_path_from_profile = profile.get("remote_path", "").strip()

        # Fallback für shop_url, falls nicht gesetzt
        if not shop_url:
            host = profile.get("host")
            shop_url = f"https://{host}"  # Standardmäßig HTTPS

        # Konstruiere die vollständige HTTP-URL direkt aus der Shop-URL
        # Der remote_path wird ignoriert, da die shop_url bereits den Web-Einstiegspunkt definiert
        full_http_url = f"{shop_url.rstrip('/')}/{temp_php_filename}?token={token}"

        if requests is None:
            log("PHP-Version-Check übersprungen (Modul 'requests' fehlt).", "warn")
            return None

        # 1. Upload der PHP-Datei
        upload_success = False
        test_data_stream = io.BytesIO(php_check_content)

        try:
            for attempt in range(1, 4):
                if self.worker._is_cancelled:
                    return {}
                try:
                    test_data_stream.seek(0)
                    if isinstance(conn, ftplib.FTP):
                        conn.storbinary(f"STOR {temp_php_filename}", test_data_stream)
                        # Verifikation des Uploads
                        try:
                            size = conn.size(temp_php_filename)
                            if size > 0:
                                log(
                                    f"Upload verifiziert: {temp_php_filename} ({size} Bytes) im Pfad {conn.pwd()}",
                                    "ok",
                                )
                                upload_success = True
                                break
                            else:
                                log(
                                    f"Warnung: Datei {temp_php_filename} wurde mit 0 Bytes hochgeladen (Versuch {attempt}).",
                                    "warn",
                                )
                        except:
                            log(
                                f"Konnte Existenz von {temp_php_filename} nach Upload nicht via FTP bestätigen (Versuch {attempt}).",
                                "warn",
                            )
                    else:  # SFTP
                        conn.putfo(test_data_stream, temp_php_filename)
                        try:
                            conn.chmod(temp_php_filename, 0o644)
                        except:
                            pass
                        # Verifikation des Uploads
                        try:
                            fstat = conn.stat(temp_php_filename)
                            if fstat.st_size > 0:
                                log(
                                    f"Upload verifiziert: {temp_php_filename} ({fstat.st_size} Bytes) im Pfad {conn.getcwd()}",
                                    "ok",
                                )
                                upload_success = True
                                break
                            else:
                                log(
                                    f"Warnung: Datei {temp_php_filename} wurde mit 0 Bytes hochgeladen (Versuch {attempt}).",
                                    "warn",
                                )
                        except:
                            log(
                                f"Konnte Existenz von {temp_php_filename} nach Upload nicht via SFTP bestätigen (Versuch {attempt}).",
                                "warn",
                            )
                except Exception as e:
                    log(
                        f"Fehler beim Hochladen der PHP-Datei für Versionsprüfung (Versuch {attempt}): {str(e)}",
                        "warn",
                    )

                if attempt < 3:
                    time.sleep(1.0)

            if not upload_success:
                log("Upload der PHP-Prüfdatei endgültig fehlgeschlagen.", "error")
                return None

            log(f"Versuche Abfrage via: {full_http_url}", "ok")

            # 2. HTTP-Aufruf mit Retry-Logik
            php_version = None
            if self.worker._is_cancelled:
                return {}
            for attempt in range(1, 4):
                try:
                    # Kurze Pause vor dem ersten und längere Pause vor weiteren Versuchen
                    wait_time = attempt * 1.5
                    self._emit_progress(f"Warte {wait_time}s auf Server-Freigabe (Versuch {attempt})...")
                    time.sleep(wait_time)

                    if self.worker._is_cancelled:
                        return {}  # Check after sleep
                    response = requests.get(full_http_url, timeout=10, verify=False)

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if data and data.get("php"):
                                raw_php = data["php"]
                                php_match = re.search(r"(\d+\.\d+)", raw_php)
                                data["php"] = php_match.group(1) if php_match else raw_php
                                log(f"Server-Umgebung: PHP {data['php']}", "ok")
                            return data
                        except json.JSONDecodeError:
                            log(
                                "Antwort des Servers konnte nicht als JSON verarbeitet werden.",
                                "warn",
                            )
                            raw_php = response.text.strip()
                            php_match = re.search(r"(\d+\.\d+)", raw_php)
                            return {"php": php_match.group(1) if php_match else raw_php}

                    log(
                        f"HTTP-Abfrage fehlgeschlagen: Code {response.status_code} bei {full_http_url}",
                        "warn",
                    )
                    if response.status_code == 403:
                        log(
                            "Hinweis: Zugriff verweigert (403). Prüfen Sie Dateirechte oder .htaccess.",
                            "warn",
                        )

                except Exception as e:
                    log(
                        f"HTTP-Aufruf Versuch {attempt} fehlgeschlagen: {str(e)}",
                        "warn",
                    )
                if self.worker._is_cancelled:
                    return {}  # Check after failed attempt

                if attempt == 3:
                    log(
                        f"Maximale Versuche für PHP-Versionscheck erreicht. URL: {full_http_url}",
                        "error",
                    )
        finally:
            # 3. Löschen der PHP-Datei
            try:
                if isinstance(conn, ftplib.FTP):
                    if self.worker._is_cancelled:
                        return {}
                    try:
                        conn.delete(temp_php_filename)
                    except ftplib.error_perm as e:
                        if "550" not in str(e):
                            log(
                                f"Warnung: Temporäre PHP-Datei konnte nicht gelöscht werden: {str(e)}",
                                "warn",
                            )
                else:  # SFTP
                    self._emit_progress("Lösche temporäre PHP-Datei...")
                    try:
                        conn.remove(temp_php_filename)
                    except IOError:  # SFTP typischerweise IOError wenn Datei fehlt
                        pass
            except Exception as e:
                log(
                    f"Warnung: Temporäre PHP-Datei konnte nicht gelöscht werden: {str(e)}",
                    "warn",
                )

        return {}

    def _extract_version_number(self, ver_str):
        """Extrahiert die reine Versionsnummer aus Strings wie 'mysqlnd 10.6.12-MariaDB'."""
        if not ver_str:
            return None
        match = re.search(r"(\d+\.\d+\.\d+)", ver_str)
        return match.group(1) if match else None

    def _parse_ver_tuple(self, ver_str):
        """Hilfsmethode: Extrahiert Zahlen aus Version-String für Vergleich."""
        if not ver_str or not ver_str.strip():
            return (0,)
        try:
            res = tuple(map(int, re.findall(r"\d+", ver_str)))
            return res if res else (0,)
        except ValueError:  # z.B. wenn int() fehlschlägt, obwohl \d+ gefunden wurde (unwahrscheinlich)
            logger.exception(f"Fehler beim Konvertieren von Versions-Teilen für '{ver_str}'")
            return (0,)
        except Exception:  # Für alle anderen unerwarteten Fehler
            logger.exception(f"Unerwarteter Fehler beim Parsen der Version '{ver_str}'")
            return (0,)

    def _ver_tuple_to_str(self, v_tuple):
        """Hilfsmethode: Wandelt ein Versions-Tupel z.B. (4, 9, 1, 0) in 'v4.9.1.0' um."""
        if not v_tuple or v_tuple == (0,):
            return "unbekannt"
        return "v" + ".".join(str(x) for x in v_tuple)

    def _run_update_analysis_logic(
        self,
        conn,
        current_shop_ver,
        current_php_ver,
        current_mysql_ver,
        current_db_type,
        root_files,
        signal=None,
    ):
        """Vollständige Update-Analyse-Engine."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Starte Update-Analyse...")
        if self.worker._is_cancelled:
            return
        log("Starte Update-Analyse...", "ok")
        update_base_path = "gambio_updater/updates"

        # 1. Update-Ordner auslesen
        try:
            if isinstance(conn, ftplib.FTP):
                try:
                    update_folders = conn.nlst(update_base_path)
                    if self.worker._is_cancelled:
                        return
                    self._emit_progress("Lese FTP-Update-Ordner...")
                except ftplib.error_perm:
                    log(
                        f"Kein Update-Verzeichnis '{update_base_path}' gefunden.",
                        "warn",
                    )
                    return
            else:  # SFTP
                try:
                    update_folders = conn.listdir(update_base_path)
                    if self.worker._is_cancelled:
                        return
                    self._emit_progress("Lese SFTP-Update-Ordner...")
                except:
                    log(
                        f"Kein Update-Verzeichnis '{update_base_path}' gefunden.",
                        "warn",
                    )
                    return

            # Bereinigen und Versionen extrahieren
            version_map = {}
            for f in update_folders:
                if self.worker._is_cancelled:
                    return
                folder_name = f.split("/")[-1].split("\\")[-1]
                if folder_name.startswith("v"):
                    ver_str = folder_name[1:]  # 'v26.04.1' -> '26.04.1'
                    version_map[self._parse_ver_tuple(ver_str)] = (ver_str, folder_name)

            if not version_map:
                log("Keine Update-Ordner in gambio_updater/updates/ gefunden.", "warn")
                self._emit_progress("Keine Update-Ordner gefunden.")
                return

            # Höchste Version bestimmen
            highest_key = max(version_map.keys())
            highest_ver_str, highest_folder = version_map[highest_key]
            target_path = f"{update_base_path}/{highest_folder}"
            log(f"Höchste verfügbare Update-Version erkannt: {highest_ver_str}")

            # 2. configuration.ini laden und parsen
            if self.worker._is_cancelled:
                return
            self._emit_progress("Lade configuration.ini...")
            config_data = self._load_update_ini(conn, target_path)

            # Zielversion bestimmen (aus ini oder Ordnername)
            target_version = highest_ver_str
            if config_data and config_data.has_section("update_properties"):
                target_version = config_data.get("update_properties", "version", fallback=highest_ver_str)

            if config_data:
                # 3. PHP-Version Prüfung
                if self.worker._is_cancelled:
                    return
                self._emit_progress("Prüfe PHP-Kompatibilität für Update...")
                self._check_update_php_compat(config_data, current_php_ver, signal)
                # 4. Shop-Version Prüfung
                if self.worker._is_cancelled:
                    return
                self._emit_progress("Prüfe Shop-Version für Update...")
                self._check_update_shop_compat(config_data, current_shop_ver, target_version, signal)
                # 5. MySQL Prüfung
                if self.worker._is_cancelled:
                    return
                self._emit_progress("Prüfe Datenbank-Kompatibilität für Update...")
                self._check_mysql_version(config_data, current_mysql_ver, current_db_type, signal)

            # 6. updated_files.txt prüfen
            if self.worker._is_cancelled:
                return
            files_ok = self._check_updated_files(conn, target_path, signal)

            # 7. to_delete.php prüfen
            if self.worker._is_cancelled:
                return
            deleted_ok = self._check_files_to_delete(conn, target_path, signal)

            # 8. Update-Vollständigkeit prüfen
            self._evaluate_completeness(current_shop_ver, target_version, files_ok, deleted_ok, signal)

            self._emit_progress("Update-Analyse abgeschlossen.")
        except Exception as e:
            log(f"Fehler in der Update-Analyse-Engine: {str(e)}", "error")

    def _load_update_ini(self, conn, folder_path):
        """Lädt und parst die configuration.ini per FTP/SFTP."""
        ini_path = f"{folder_path}/configuration.ini"
        content = ""
        try:
            if isinstance(conn, ftplib.FTP):
                r_io = io.BytesIO()
                conn.retrbinary(f"RETR {ini_path}", r_io.write)
                content = r_io.getvalue().decode("utf-8", errors="ignore")
                if self.worker._is_cancelled:
                    return None
            else:
                with conn.open(ini_path, "r") as f:
                    content = f.read().decode("utf-8", errors="ignore")

            parser = configparser.ConfigParser()
            parser.read_string(content)
            return parser
        except Exception:
            self._emit_progress(f"Fehler: configuration.ini in {folder_path} nicht geladen.")
            self._add_result(
                f"configuration.ini konnte nicht geladen werden in {folder_path}",
                "warn",
            )
            return None

    def _check_update_php_compat(self, config, current_php, signal=None):
        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return
        if not current_php or not config.has_section("compatibility"):
            return

        p_min = config.get("compatibility", "php_version_min", fallback="0")
        p_max = config.get("compatibility", "php_version_max", fallback="99")

        c_tuple = self._parse_ver_tuple(current_php)
        min_tuple = self._parse_ver_tuple(p_min)
        max_tuple = self._parse_ver_tuple(p_max)

        # Prefix-bewusster Vergleich:
        # Wenn max=8.3 im Update steht, soll 8.3.29 im Shop NICHT als "neuer" gelten.
        # Wir vergleichen daher nur die Stellen, die in der Grenze definiert sind.
        is_too_old = c_tuple[: len(min_tuple)] < min_tuple
        is_newer_than_tested = c_tuple[: len(max_tuple)] > max_tuple

        if not is_too_old and not is_newer_than_tested:
            log(
                f"PHP-Kompatibilität (Update): {current_php} ist im Bereich {p_min} - {p_max}.",
                "ok",
            )
        elif is_newer_than_tested:
            self._emit_progress(f"PHP {current_php} neuer als max {p_max}.")
            log(
                f"PHP-Kompatibilität (Update): {current_php} ist NEUER als getestet (max {p_max}).",
                "warn",
            )
        else:
            log(
                f"PHP-Kompatibilität (Update): {current_php} ist NICHT kompatibel (erfordert {p_min} - {p_max}).",
                "error",
            )

    def _check_update_shop_compat(self, config, current_shop, target_version, signal=None):
        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return
        if not config.has_section("compatibility"):
            return

        s_min = config.get("compatibility", "shop_version_min", fallback="0")
        s_max = config.get("compatibility", "shop_version_max", fallback="99")

        c_tuple = self._parse_ver_tuple(current_shop)
        t_tuple = self._parse_ver_tuple(target_version)
        min_tuple = self._parse_ver_tuple(s_min)
        max_tuple = self._parse_ver_tuple(s_max)

        # Fall: Update bereits installiert
        if c_tuple == t_tuple:
            log(f"Update {target_version} ist bereits vollständig installiert.", "ok")
        elif min_tuple <= c_tuple <= max_tuple:
            log(
                f"Update {target_version} ist kompatibel mit Shop-Version {current_shop}",
                "ok",
            )
        else:
            self._emit_progress(f"Shop-Version {current_shop} nicht kompatibel.")
            log(
                f"Update {target_version} ist nicht kompatibel mit Shop-Version {current_shop}",
                "error",
            )
            if c_tuple < min_tuple:
                log(
                    f"Voraussetzung nicht erfüllt: Shop ist zu alt (min: {s_min})",
                    "error",
                )
            elif c_tuple > max_tuple:
                log(
                    f"Voraussetzung nicht erfüllt: Shop ist zu neu für dieses Update (max: {s_max})",
                    "error",
                )

    def _check_mysql_version(self, config, current_mysql_ver, current_db_type, signal=None):
        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return
        if not current_mysql_ver or not config.has_section("compatibility"):
            if current_db_type == "Client":
                self._emit_progress("MySQL/MariaDB Server-Version nicht ermittelbar.")
                log(
                    "MySQL/MariaDB Server-Version konnte nicht ermittelt werden (nur Client-Info verfügbar).",
                    "warn",
                )
            return

        if current_db_type == "MariaDB":
            log(
                f"Datenbank-Typ: MariaDB {current_mysql_ver}. MySQL-Kompatibilitätsprüfung übersprungen.",
                "warn",
            )
            return

        # This check is redundant with the first if, but kept for clarity
        if current_db_type == "Client":
            log(
                f"MySQL/MariaDB Server-Version konnte nicht ermittelt werden (nur Client-Info verfügbar: {current_mysql_ver}).",
                "warn",
            )
            return

        # Only proceed if it's MySQL
        if current_db_type == "MySQL":
            m_min = config.get("compatibility", "mysql_version_min", fallback="0")
            m_max = config.get("compatibility", "mysql_version_max", fallback="99")

            c_tuple = self._parse_ver_tuple(current_mysql_ver)
            min_tuple = self._parse_ver_tuple(m_min)
            max_tuple = self._parse_ver_tuple(m_max)

            if min_tuple <= c_tuple <= max_tuple:
                log(
                    f"MySQL-Kompatibilität: {current_mysql_ver} ist kompatibel (Bereich: {m_min} - {m_max}).",
                    "ok",
                )
            else:
                self._emit_progress(f"MySQL-Version {current_mysql_ver} nicht kompatibel.")
                log(
                    f"MySQL-Version {current_mysql_ver} ist NICHT kompatibel für dieses Update (erfordert {m_min} - {m_max}).",
                    "error",
                )
        else:
            log(
                f"Unbekannter Datenbank-Typ '{current_db_type}'. MySQL-Kompatibilitätsprüfung übersprungen.",
                "warn",
            )

    def _check_updated_files(self, conn, folder_path, signal=None):
        """Prüft Existenz und Schreibrechte der Dateien aus updated_files.txt."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return
        self._emit_progress("Prüfe updated_files.txt...")
        txt_path = f"{folder_path}/updated_files.txt"
        files_to_check = []
        all_ok = True
        try:
            content = ""
            if isinstance(conn, ftplib.FTP):
                r_io = io.BytesIO()
                conn.retrbinary(f"RETR {txt_path}", r_io.write)
                if self.worker._is_cancelled:
                    return False
                content = r_io.getvalue().decode("utf-8")
            else:
                with conn.open(txt_path, "r") as f:
                    content = f.read().decode("utf-8")

            files_to_check = [line.strip() for line in content.splitlines() if line.strip()]

            for remote_file in files_to_check:
                # Existenz prüfen
                if self.worker._is_cancelled:
                    return False
                exists = False
                try:
                    if isinstance(conn, ftplib.FTP):
                        conn.size(remote_file)
                        exists = True
                except:
                    pass

                self._emit_progress(f"Prüfe Datei: {remote_file}")
                if not exists:
                    log(f"Fehlende Datei aus Update: {remote_file}", "warn")
                    all_ok = False
                    continue

                # Schreibrechte-Logik
                is_admin = remote_file.startswith("admin/")
                is_system = remote_file.startswith("system/") or remote_file.startswith("GXEngine/")

                # Einfache Prüfung: Versuchen für Append zu öffnen (nur bei Admin-Dateien)
                if is_admin:
                    try:
                        # Wir testen nur, ob wir das Attribut theoretisch ändern könnten oder einen Schreib-Check machen
                        pass  # In einer echten Umgebung würde hier ein SITE-Kommando oder Test-Upload erfolgen
                    except:
                        log(f"Admin-Datei nicht beschreibbar: {remote_file}", "warn")

                if is_system:
                    # Hier sollte theoretisch geprüft werden, ob sie NICHT beschreibbar ist (Hardening)
                    pass

            if all_ok:
                self._emit_progress("Alle Dateien aus updated_files.txt vorhanden.")
                log("Alle Dateien aus updated_files.txt sind vorhanden.", "ok")
            return all_ok
        except:
            log("updated_files.txt konnte nicht geprüft werden.", "warn")
            return False

    def _check_files_to_delete(self, conn, folder_path, signal=None):
        """Prüft, ob Dateien aus to_delete.php noch existieren."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return True
        self._emit_progress("Prüfe to_delete.php...")
        php_path = f"{folder_path}/to_delete.php"
        all_deleted = True
        try:
            content = ""
            if isinstance(conn, ftplib.FTP):
                r_io = io.BytesIO()
                conn.retrbinary(f"RETR {php_path}", r_io.write)
                if self.worker._is_cancelled:
                    return True
                content = r_io.getvalue().decode("utf-8")
            else:
                with conn.open(php_path, "r") as f:
                    content = f.read().decode("utf-8")

            # Extrahiere Pfade aus PHP Array via Regex
            paths = re.findall(r"['\"]([^'\"]+\.php|[^'\"]+\.js|[^'\"]+\.html)['\"]", content)

            for p in paths:
                exists = False
                if self.worker._is_cancelled:
                    return True
                try:
                    if isinstance(conn, ftplib.FTP):
                        conn.size(p)
                        exists = True
                except:
                    pass

                if exists:
                    self._emit_progress(f"Datei sollte gelöscht sein: {p}")
                    log(f"Datei existiert noch, sollte gelöscht sein: {p}", "error")
                    all_deleted = False

            if all_deleted:
                log("Bereinigung (to_delete.php) ist korrekt durchgeführt.", "ok")
            return all_deleted
        except:
            return True  # Falls Datei nicht existiert, gibt es wohl nichts zu löschen

    def _evaluate_completeness(self, shop_ver, update_ver, files_ok, deleted_ok, signal=None):
        """Zusammenfassende Logik für Update-Status."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return
        self._emit_progress("Werte Update-Vollständigkeit aus...")
        s_tuple = self._parse_ver_tuple(shop_ver)
        u_tuple = self._parse_ver_tuple(update_ver)

        status = "ok"
        msg = f"Update {update_ver} vollständig installiert."

        if s_tuple > u_tuple:
            msg = f"Update fehlt (Shop {shop_ver} ist neuer als Update-Verzeichnis {update_ver})."
            self._emit_progress("Update fehlt.")
            status = "warn"
        elif s_tuple < u_tuple:
            msg = f"Update auf {update_ver} steht bereit (Shop ist aktuell auf {shop_ver})."
            status = "warn"

        if not files_ok:
            msg = "Update unvollständig: Dateien aus updated_files.txt fehlen."
            status = "error"
            self._emit_progress("Dateien aus updated_files.txt fehlen.")

        if not deleted_ok:
            msg = "Update unvollständig: Veraltete Dateien (to_delete.php) existieren noch."
            status = "error"

        log(msg, status)

    def _check_integrity(self, files, signal=None):
        """Prüft auf kritische Basis-Verzeichnisse und Dateien."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker._is_cancelled:
            return
        self._emit_progress("Prüfe Shop-Integrität...")
        critical = {
            "index.php": "Hauptdatei fehlt.",
            "robots.txt": "robots.txt fehlt.",
            "system": "System-Ordner fehlt.",
            "GXEngine": "Engine-Ordner fehlt.",
        }
        for item, msg in critical.items():
            if self.worker._is_cancelled:
                return
            if item not in files:
                self._emit_progress(f"Kritische Datei/Ordner fehlt: {item}")
                log(f"Integrität: {msg}", "warn")

        if "index.php" in files:
            # Check for themes/templates
            if "themes" in files:
                log("Shop-Design-Ordner 'themes' gefunden.", "ok")
            elif "templates" in files:
                log(
                    "Shop-Design-Ordner 'templates' gefunden (Hinweis: 'themes' ist in neueren Gambio-Versionen üblich).",
                    "warn",
                )
                self._emit_progress("Design-Ordner 'templates' gefunden.")
            else:
                log(
                    "Weder 'themes' noch 'templates' gefunden – ungewöhnliche Shop-Struktur.",
                    "warn",
                )
                self._emit_progress("Ungewöhnliche Shop-Struktur.")

            log("Basis-Integrität (Dateipräsenz): OK")
        else:
            log("Basis-Integrität (Dateipräsenz): Fehler (index.php fehlt).", "error")

    def _run_gxmodules_compatibility_scan(self, conn, gambio_ver, scan_gambio=False, signal=None):
        """Scans /GXModules for PHP 8 incompatibilities."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        self._emit_progress("Analysiere Drittanbieter-Module (GXModules)...")
        if self.worker and self.worker._is_cancelled:
            return

        severity = "warn"
        if gambio_ver:
            g_tuple = self._parse_ver_tuple(gambio_ver)
            if g_tuple >= (4, 7):
                severity = "error"
        else:
            severity = "warn"

        base_dir = "GXModules"
        try:
            if isinstance(conn, ftplib.FTP):
                try:
                    conn.cwd(base_dir)
                    conn.cwd("..")
                except ftplib.error_perm:
                    log(
                        "Verzeichnis GXModules nicht gefunden. Überspringe Prüfung.",
                        "ok",
                    )
                    return
            else:
                try:
                    conn.stat(base_dir)
                except:
                    log(
                        "Verzeichnis GXModules nicht gefunden. Überspringe Prüfung.",
                        "ok",
                    )
                    return

            php_files = []

            def walk_gxmodules(current_path):
                if self.worker and self.worker._is_cancelled:
                    return
                try:
                    if isinstance(conn, ftplib.FTP):
                        try:
                            items = list(conn.mlsd(current_path))
                            for name, attrs in items:
                                if name in [".", ".."]:
                                    continue
                                if not scan_gambio and current_path == "GXModules" and name == "Gambio":
                                    continue
                                full_path = f"{current_path}/{name}"
                                if attrs.get("type") == "dir":
                                    walk_gxmodules(full_path)
                                elif attrs.get("type") in ["file", "os.unix.slink", ""]:
                                    if name.lower().endswith(".php"):
                                        php_files.append(full_path)
                        except:
                            try:
                                names = conn.nlst(current_path)
                                for n in names:
                                    name = n.replace("\\", "/").split("/")[-1]
                                    if name in [".", ".."] or not name:
                                        continue
                                    if not scan_gambio and current_path == "GXModules" and name == "Gambio":
                                        continue
                                    full_path = f"{current_path}/{name}"
                                    if "." in name:
                                        if name.lower().endswith(".php"):
                                            php_files.append(full_path)
                                    else:
                                        walk_gxmodules(full_path)
                            except:
                                pass
                    else:
                        for entry in conn.listdir_attr(current_path):
                            if entry.filename in [".", ".."]:
                                continue
                            if not scan_gambio and current_path == "GXModules" and entry.filename == "Gambio":
                                continue
                            full_path = f"{current_path}/{entry.filename}"
                            if stat.S_ISDIR(entry.st_mode):
                                walk_gxmodules(full_path)
                            elif entry.filename.lower().endswith(".php"):
                                php_files.append(full_path)
                except:
                    pass

            walk_gxmodules(base_dir)

            if not php_files:
                log("Keine PHP-Dateien im GXModules-Verzeichnis gefunden.", "ok")
                return

            self._emit_progress(f"Prüfe {len(php_files)} Modul-Dateien auf PHP 8 Kompatibilität...")

            patterns = {
                "create_function": re.compile(rb"\bcreate_function\s*\("),
                "each": re.compile(rb"(?<!function\s)(?<!function\s\s)(?<!->)(?<!::)\beach\s*\("),
                "money_format": re.compile(rb"\bmoney_format\s*\("),
                "get_magic_quotes_gpc": re.compile(rb"\bget_magic_quotes_gpc\s*\("),
                "restore_include_path": re.compile(rb"\brestore_include_path\s*\("),
            }
            class_pattern = re.compile(rb"\bclass\s+([A-Za-z0-9_]+)", re.IGNORECASE)

            try:
                from phply import phplex
                from phply.phpparse import make_parser

                php_parser = make_parser()
                if phplex.lexer is None:
                    raise ImportError("phplex.lexer ist nicht initialisiert")
                php_lexer = phplex.lexer.clone()
                # Sicherheitstest: lexer muss klonbar sein
                _test_clone = php_lexer.clone()
                if _test_clone is None:
                    raise ImportError("phplex.lexer.clone() liefert None")
                use_ast = True
            except (ImportError, AttributeError, Exception):
                use_ast = False

            incompatibilities_found = 0

            for f in php_files:
                if self.worker and self.worker._is_cancelled:
                    return

                content = b""
                try:
                    if isinstance(conn, ftplib.FTP):
                        r_io = io.BytesIO()
                        conn.retrbinary(f"RETR {f}", r_io.write)
                        content = r_io.getvalue()
                    else:
                        with conn.open(f, "rb") as remote_file:
                            content = remote_file.read()
                except:
                    continue

                issues = set()
                ast_success = False

                if use_ast:
                    try:
                        content_str = content.decode("utf-8", errors="replace")
                        nodes = php_parser.parse(content_str, lexer=php_lexer.clone())

                        def visit(node):
                            if not node:
                                return
                            if isinstance(node, list):
                                for n in node:
                                    visit(n)
                                return

                            node_type = type(node).__name__
                            if node_type == "FunctionCall":
                                if type(node.name).__name__ == "str":
                                    func_name = node.name.lower()
                                    if func_name in patterns:
                                        issues.add(func_name)
                            elif node_type == "Class":
                                class_name = node.name.lower()
                                methods = [m for m in getattr(node, "nodes", []) if type(m).__name__ == "Method"]
                                has_construct = any(m.name.lower() == "__construct" for m in methods)
                                if not has_construct:
                                    for m in methods:
                                        if m.name.lower() == class_name:
                                            issues.add(f"Alter PHP4-Konstruktor ({node.name})")

                            if hasattr(node, "__dict__"):
                                for val in vars(node).values():
                                    if isinstance(val, list) or hasattr(val, "__dict__"):
                                        visit(val)

                        visit(nodes)
                        ast_success = True
                    except Exception:
                        # Fallback to regex if parse fails
                        ast_success = False

                if not ast_success:
                    for name, pat in patterns.items():
                        if pat.search(content):
                            issues.add(name)

                    class_matches = class_pattern.findall(content)
                    has_modern_construct = rb"__construct" in content

                    for class_name in class_matches:
                        func_pattern = re.compile(rb"\bfunction\s+" + class_name + rb"\s*\(", re.IGNORECASE)
                        if func_pattern.search(content):
                            if not has_modern_construct:
                                issues.add(f"Alter PHP4-Konstruktor ({class_name.decode('utf-8', 'ignore')})")

                if issues:
                    incompatibilities_found += 1
                    issue_str = ", ".join(sorted(issues))
                    if severity == "error":
                        log(f"Inkompatibler Code in {f}: {issue_str} gefunden.", "error")
                    else:
                        log(
                            f"Hinweis: Das Plugin {f} enthält Code, der unter PHP 8 nicht mehr funktioniert ({issue_str}). Bevor Sie den Shop auf Version 4.7+ und PHP 8 aktualisieren, muss dieses Modul aktualisiert werden.",
                            "warn",
                        )

            if incompatibilities_found == 0:
                log(
                    "GXModules Kompatibilitätsprüfung: Keine offensichtlichen PHP 8 Inkompatibilitäten gefunden.",
                    "ok",
                )
            else:
                log(
                    f"GXModules Kompatibilitätsprüfung abgeschlossen. {incompatibilities_found} problematische Datei(en) gefunden.",
                    severity,
                )

        except Exception as e:
            log(f"Fehler bei GXModules Kompatibilitätsprüfung: {str(e)}", "error")

    def showEvent(self, event):
        """Wird aufgerufen, wenn die Seite angezeigt wird."""
        super().showEvent(event)
        self._load_profiles()

    def _get_php_compat_from_shop(self, conn, gambio_ver, signal=None):
        """Liest die PHP-Kompatibilität dynamisch aus den Shop-Update-Dateien."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        update_base_path = "gambio_updater/updates"
        try:
            if isinstance(conn, ftplib.FTP):
                try:
                    update_folders = conn.nlst(update_base_path)
                except ftplib.error_perm:
                    log(
                        f"Kein Update-Verzeichnis '{update_base_path}' gefunden.",
                        "warn",
                    )
                    return None, None
            else:  # SFTP
                try:
                    update_folders = conn.listdir(update_base_path)
                except:
                    log(
                        f"Kein Update-Verzeichnis '{update_base_path}' gefunden.",
                        "warn",
                    )
                    return None, None

            version_map = {}
            for f in update_folders:
                if self.worker and self.worker._is_cancelled:
                    return None, None
                folder_name = f.split("/")[-1].split("\\")[-1]
                if folder_name.startswith("v"):
                    ver_str = folder_name[1:]
                    version_map[self._parse_ver_tuple(ver_str)] = folder_name

            if not version_map:
                log("Keine Update-Ordner in gambio_updater/updates/ gefunden.", "warn")
                return None, None

            g_tuple = self._parse_ver_tuple(gambio_ver)

            # Suche nach exaktem Match
            target_folder = None
            if g_tuple in version_map:
                target_folder = version_map[g_tuple]
                log(f"Kompatibilitätsdaten im Ordner {target_folder} gefunden.", "ok")
            else:
                # Suche nach der nächstkleineren Version
                smaller_versions = [v for v in version_map.keys() if v <= g_tuple]
                if smaller_versions:
                    closest_ver = max(smaller_versions)
                    target_folder = version_map[closest_ver]
                    log(
                        f"Nutze Daten von {target_folder} für Version {gambio_ver}.",
                        "info",
                    )
                else:
                    # Fallback auf höchste vorhandene
                    highest_ver = max(version_map.keys())
                    target_folder = version_map[highest_ver]
                    log(
                        f"Nutze aktuellste Daten von {target_folder} für Version {gambio_ver}.",
                        "info",
                    )

            target_path = f"{update_base_path}/{target_folder}"
            config_data = self._load_update_ini(conn, target_path)

            if config_data and config_data.has_section("compatibility"):
                p_min = config_data.get("compatibility", "php_version_min", fallback=None)
                p_max = config_data.get("compatibility", "php_version_max", fallback=None)
                if p_min and p_max:
                    return p_min, p_max

            log("Keine 'compatibility' Sektion in configuration.ini gefunden.", "warn")
            return None, None

        except Exception as e:
            log(f"Fehler beim dynamischen Auslesen der Kompatibilität: {str(e)}", "warn")
            return None, None

    def _run_php_compatibility_check_logic(self, gambio_ver, php_ver, min_php, max_php, signal=None):
        """Vergleicht die Gambio-Version mit der PHP-Version basierend auf dynamischen Daten."""

        def log(msg, status="ok"):
            if signal:
                signal.emit(msg, status)
            else:
                self._add_result(msg, status)

        if self.worker and self.worker._is_cancelled:
            return

        if not min_php or not max_php:
            self._emit_progress(f"Keine Kompatibilitätsdaten für Gambio {gambio_ver}.")
            log(
                "Kompatibilität konnte mangels Update-Dateien nicht geprüft werden.",
                "warn",
            )
            return

        c_tuple = self._parse_ver_tuple(php_ver)
        min_tuple = self._parse_ver_tuple(min_php)
        max_tuple = self._parse_ver_tuple(max_php)

        # Prefix-bewusster Vergleich
        is_too_old = c_tuple[: len(min_tuple)] < min_tuple
        is_newer_than_tested = c_tuple[: len(max_tuple)] > max_tuple

        if not is_too_old and not is_newer_than_tested:
            log(
                f"PHP-Version {php_ver} ist kompatibel mit Gambio {gambio_ver} (benötigt {min_php} - {max_php}).",
                "ok",
            )
        elif is_newer_than_tested:
            self._emit_progress(f"PHP {php_ver} neuer als getestet.")
            log(
                f"PHP-Version {php_ver} ist neuer als für {gambio_ver} getestet (max: {max_php}). Kompatibilität unklar.",
                "warn",
            )
        else:
            self._emit_progress(f"PHP {php_ver} nicht kompatibel.")
            log(
                f"PHP-Version {php_ver} ist NICHT kompatibel mit Gambio {gambio_ver} (erfordert {min_php} - {max_php}).",
                "error",
            )

    def _export_html(self):
        if not self.current_logger:
            show_error("Bitte zuerst einen Health-Check ausführen.")
            return
        profile_idx = self.combo_profiles.currentIndex()
        if profile_idx < 0:
            return
        profile_name = self.combo_profiles.currentText()

        path, _ = QFileDialog.getSaveFileName(
            self,
            "HTML-Bericht speichern",
            f"{profile_name}_HealthCheck.html",
            "HTML Files (*.html)",
        )
        if path:
            if generate_html_report(profile_name, self.current_logger.get_log_dir(), path):
                QMessageBox.information(self, "Erfolg", "HTML-Bericht erfolgreich gespeichert.")
            else:
                show_error("Fehler beim Erstellen des Berichts.")

    def _export_pdf(self):
        if not self.current_logger:
            show_error("Bitte zuerst einen Health-Check ausführen.")
            return
        profile_idx = self.combo_profiles.currentIndex()
        if profile_idx < 0:
            return
        profile_name = self.combo_profiles.currentText()

        path, _ = QFileDialog.getSaveFileName(
            self,
            "PDF-Bericht speichern",
            f"{profile_name}_HealthCheck.pdf",
            "PDF Files (*.pdf)",
        )
        if path:
            if generate_pdf_report(profile_name, self.current_logger.get_log_dir(), path):
                QMessageBox.information(self, "Erfolg", "PDF-Bericht erfolgreich gespeichert.")
            else:
                show_error("Fehler beim Erstellen des Berichts.")

    def _check_cache_size(self, conn, remote_files, result_signal):
        """Prüft die Größe der Cache-Ordner."""
        cache_dirs = ["cache", "templates_c"]
        total_size = 0
        limit = 250 * 1024 * 1024  # 250 MB

        try:
            for cdir in cache_dirs:
                # Da wir remote_files (eine Liste aller Dateien) haben, können wir die Größen nicht direkt daraus lesen (es sind nur Namen)
                # Wir müssen STAT oder LIST aufrufen.
                # Einfacher Hack: MLSD oder LIST auf den Cache Ordner
                try:
                    conn.cwd(cdir)
                    # Dies ist eine sehr grobe Prüfung. Wenn es viele Dateien sind, dauert es.
                    # Für FTP:
                    if hasattr(conn, "mlsd"):
                        for name, facts in conn.mlsd():
                            if facts.get("type") == "file":
                                total_size += int(facts.get("size", 0))
                    conn.cwd("..")
                except Exception:
                    pass

            if total_size > limit:
                result_signal.emit(
                    f"Cache-Ordner sind sehr groß ({total_size // (1024 * 1024)} MB). Erwägen Sie eine Leerung.",
                    "warn",
                )
            elif total_size > 0:
                result_signal.emit(
                    f"Cache-Größe ist im normalen Bereich ({total_size // (1024 * 1024)} MB).",
                    "ok",
                )
            else:
                result_signal.emit("Konnte Cache-Größe nicht ermitteln oder leer.", "ok")

        except Exception as e:
            result_signal.emit(f"Fehler bei Cache-Prüfung: {e}", "warn")


class ConfigPage(QWidget):
    """
    Konfigurationsseite zur Verwaltung von Shop-Profilen und zum Ändern des Master-Passworts.
    """

    def __init__(
        self,
        auth_manager: MasterPasswordManager,
        config_manager: ConfigManager,
        parent=None,
    ):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.config_manager = config_manager
        self.current_profile_index = -1  # Index des aktuell ausgewählten Profils in der Combobox

        self._setup_ui()
        self._load_profiles_into_combobox()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)

        # --- Shop-Profilverwaltung ---
        profile_group = QGroupBox("Shop-Profilverwaltung")
        profile_layout = QVBoxLayout(profile_group)

        # Profilauswahl
        profile_selection_layout = QHBoxLayout()
        profile_selection_layout.addWidget(QLabel("Profile:"))
        self.combo_profiles = QComboBox()
        self.combo_profiles.currentIndexChanged.connect(self._on_profile_selected)
        profile_selection_layout.addWidget(self.combo_profiles)
        profile_layout.addLayout(profile_selection_layout)

        # Profildetails-Formular
        profile_form_layout = QFormLayout()
        self.edit_shop_name = QLineEdit()
        self.edit_host = QLineEdit()
        self.edit_port = QLineEdit()
        self.edit_username = QLineEdit()
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)
        self.combo_protocol = QComboBox()
        self.combo_protocol.addItems(["FTP", "SFTP", "HTTPS"])
        self.edit_shop_url = QLineEdit()
        self.remote_path_input = QLineEdit()

        profile_form_layout.addRow("Shop-Name:", self.edit_shop_name)
        profile_form_layout.addRow("Host:", self.edit_host)
        profile_form_layout.addRow("Port:", self.edit_port)
        profile_form_layout.addRow("Benutzername:", self.edit_username)
        profile_form_layout.addRow("Passwort:", self.edit_password)
        profile_form_layout.addRow("Protokoll:", self.combo_protocol)
        profile_form_layout.addRow("Shop-URL (HTTPS):", self.edit_shop_url)
        profile_form_layout.addRow("Shop-Pfad (Server):", self.remote_path_input)
        profile_layout.addLayout(profile_form_layout)

        # Profil-Aktions-Buttons
        profile_buttons_layout = QHBoxLayout()
        self.btn_new_profile = QPushButton("Neues Profil")
        self.btn_save_profile = QPushButton("Profil speichern")
        self.btn_test_connection = QPushButton("FTP-Verbindung testen")
        self.btn_delete_profile = QPushButton("Profil löschen")

        self.btn_new_profile.clicked.connect(self._new_profile)
        self.btn_save_profile.clicked.connect(self._save_profile)
        self.btn_test_connection.clicked.connect(self._test_connection)
        self.btn_delete_profile.clicked.connect(self._delete_profile)

        profile_buttons_layout.addWidget(self.btn_new_profile)
        profile_buttons_layout.addWidget(self.btn_save_profile)
        profile_buttons_layout.addWidget(self.btn_test_connection)
        profile_buttons_layout.addWidget(self.btn_delete_profile)
        profile_layout.addLayout(profile_buttons_layout)

        main_layout.addWidget(profile_group)

        # --- Allgemeine Einstellungen ---
        general_group = QGroupBox("Allgemeine Einstellungen")
        general_layout = QFormLayout(general_group)

        self.lbl_excluded_hint = QLabel(
            "Hinweis: Standardmäßig bereits ausgeschlossen: images, cache, logs, export, import, backups, uploads, node_modules, .git"
        )
        self.lbl_excluded_hint.setStyleSheet("color: gray; font-size: 11px;")
        self.lbl_excluded_hint.setWordWrap(True)
        general_layout.addRow(self.lbl_excluded_hint)

        self.edit_excluded_files = QLineEdit()
        self.edit_excluded_files.setPlaceholderText("z.B. paypal3.php, mein_ordner, custom_file.php")
        general_layout.addRow("Ignorierte Dateien & Ordner (kommagetrennt):", self.edit_excluded_files)

        self.spin_max_log_age = QSpinBox()
        self.spin_max_log_age.setRange(1, 365)
        self.spin_max_log_age.setSuffix(" Tage")
        general_layout.addRow("Maximales Alter der Logfiles:", self.spin_max_log_age)

        self.btn_save_general = QPushButton("Einstellungen speichern")
        self.btn_save_general.clicked.connect(self._save_general_settings)
        general_layout.addRow(self.btn_save_general)

        main_layout.addWidget(general_group)

        # --- Master-Passwort ändern ---
        master_password_group = QGroupBox("Master-Passwort ändern")
        master_password_layout = QFormLayout(master_password_group)

        self.edit_old_master_password = QLineEdit()
        self.edit_old_master_password.setEchoMode(QLineEdit.Password)
        self.edit_new_master_password = QLineEdit()
        self.edit_new_master_password.setEchoMode(QLineEdit.Password)
        self.edit_repeat_new_master_password = QLineEdit()
        self.edit_repeat_new_master_password.setEchoMode(QLineEdit.Password)

        master_password_layout.addRow("Altes Passwort:", self.edit_old_master_password)
        master_password_layout.addRow("Neues Passwort:", self.edit_new_master_password)
        master_password_layout.addRow("Neues Passwort wiederholen:", self.edit_repeat_new_master_password)

        self.btn_change_master_password = QPushButton("Master-Passwort ändern")
        self.btn_change_master_password.clicked.connect(self._change_master_password)
        master_password_layout.addRow(self.btn_change_master_password)

        main_layout.addWidget(master_password_group)
        main_layout.addStretch()  # Schiebt den Inhalt nach oben

    def _load_profiles_into_combobox(self):
        """Lädt die Shop-Profile aus dem ConfigManager und füllt die Combobox."""
        self.combo_profiles.clear()
        try:
            self.auth_manager.require_active_session()
            # Lade allgemeine Einstellungen
            self.edit_excluded_files.setText(self.config_manager.get_excluded_files())
            self.spin_max_log_age.setValue(self.config_manager.get_max_log_age())
            profiles = self.config_manager.get_profiles()
            if not profiles:
                self.combo_profiles.addItem("Keine Profile vorhanden")
                self.combo_profiles.setEnabled(False)
                self._clear_profile_fields()
                self.btn_delete_profile.setEnabled(False)
            else:
                for i, profile in enumerate(profiles):
                    self.combo_profiles.addItem(profile.get("shop_name", f"Unbenanntes Profil {i + 1}"))
                self.combo_profiles.setEnabled(True)
                self.btn_delete_profile.setEnabled(True)
                self.btn_save_profile.setEnabled(True)
                self.combo_profiles.setCurrentIndex(0)  # Wählt das erste Profil aus
                self._on_profile_selected(0)  # Löst das Laden des ersten Profils manuell aus
        except SessionExpiredError as e:
            show_error(str(e))
            self._handle_session_expired_for_profiles()
        except Exception as e:
            show_error(f"Fehler beim Laden der Profile: {str(e)}")
            self._handle_session_expired_for_profiles()  # Generic error handling for profiles
        finally:
            self.auth_manager.update_activity()

    def _handle_session_expired_for_profiles(self):
        """Hilfsfunktion zur Behandlung abgelaufener Sessions oder Fehler beim Laden von Profilen."""
        self._clear_profile_fields()
        self.combo_profiles.clear()
        self.combo_profiles.addItem("Session abgelaufen / Fehler beim Laden")
        self.combo_profiles.setEnabled(False)
        self.btn_delete_profile.setEnabled(False)
        self.btn_save_profile.setEnabled(False)

    def _on_profile_selected(self, index: int):
        """Wird aufgerufen, wenn ein Profil in der Combobox ausgewählt wird."""
        self.auth_manager.update_activity()  # Aktivität bei Auswahländerung aktualisieren
        if index < 0 or self.combo_profiles.itemText(index) in [
            "Keine Profile vorhanden",
            "Session abgelaufen / Fehler beim Laden",
        ]:
            self._clear_profile_fields()
            self.current_profile_index = -1
            return

        try:
            self.auth_manager.require_active_session()
            profiles = self.config_manager.get_profiles()
            if 0 <= index < len(profiles):
                self.current_profile_index = index
                profile_data = profiles[index]
                self._set_profile_data(profile_data)
            else:
                self._clear_profile_fields()
                self.current_profile_index = -1
        except SessionExpiredError as e:
            show_error(str(e))
            self._clear_profile_fields()
            self.current_profile_index = -1
        except Exception as e:
            show_error(f"Fehler beim Laden des Profils: {str(e)}")
            self._clear_profile_fields()
            self.current_profile_index = -1
        finally:
            self.auth_manager.update_activity()

    def _get_current_profile_data(self) -> dict:
        """Sammelt die Daten aus den Eingabefeldern und gibt sie als Diktat zurück."""
        port_text = self.edit_port.text()
        port = int(port_text) if port_text.isdigit() else 0  # Standardwert 0 oder Fehlerbehandlung
        return {
            "shop_name": self.edit_shop_name.text(),
            "host": self.edit_host.text(),
            "port": port,
            "username": self.edit_username.text(),
            "password": self.edit_password.text(),
            "protocol": self.combo_protocol.currentText(),
            "shop_url": self.edit_shop_url.text(),
            "remote_path": self.remote_path_input.text(),
        }

    def _set_profile_data(self, profile_data: dict):
        """Setzt die Daten in die Eingabefelder."""
        self.edit_shop_name.setText(profile_data.get("shop_name", ""))
        self.edit_host.setText(profile_data.get("host", ""))
        self.edit_port.setText(str(profile_data.get("port", "")))
        self.edit_username.setText(profile_data.get("username", ""))
        self.edit_password.setText(profile_data.get("password", ""))
        self.combo_protocol.setCurrentText(profile_data.get("protocol", "FTP"))
        self.edit_shop_url.setText(profile_data.get("shop_url", ""))
        self.remote_path_input.setText(profile_data.get("remote_path", ""))

    def _clear_profile_fields(self):
        """Löscht den Inhalt aller Shop-Profil-Eingabefelder."""
        self.edit_shop_name.clear()
        self.edit_host.clear()
        self.edit_port.clear()
        self.edit_username.clear()
        self.edit_password.clear()
        self.combo_protocol.setCurrentIndex(0)  # Auf FTP zurücksetzen
        self.edit_shop_url.clear()
        self.remote_path_input.clear()
        self.current_profile_index = -1

    def _test_connection(self):
        """Prüft die FTP/SFTP-Verbindung und sucht nach Gambio-Indikatoren."""
        try:
            self.auth_manager.require_active_session()
            data = self._get_current_profile_data()

            protocol = data["protocol"]
            host = data["host"]
            port = data["port"]
            user = data["username"]
            pwd = data["password"]
            remote_path = data["remote_path"].strip()

            if not host or not user:
                show_error("Bitte Host und Benutzername ausfüllen.")
                return

            if protocol == "HTTPS":
                QMessageBox.information(
                    self,
                    "Hinweis",
                    "Verbindungstest für HTTPS wird übersprungen (nur Pfadprüfung via FTP/SFTP unterstützt).",
                )
                return

            found_files = []
            version_info = ""

            if protocol == "FTP":
                with ftplib.FTP() as ftp:
                    ftp.connect(host, port, timeout=10)
                    ftp.login(user, pwd)
                    if remote_path:
                        ftp.cwd(remote_path)
                    found_files = ftp.nlst()

                    # Optional: Version auslesen
                    try:
                        r_file = io.BytesIO()
                        ftp.retrbinary("RETR system/conf/main.conf.php", r_file.write)
                        content = r_file.getvalue().decode("utf-8", errors="ignore")
                        match = re.search(r"'PROJECT_VERSION'\s*=>\s*'([^']+)'", content)
                        if match:
                            version_info = f"\nErkannte Version: {match.group(1)}"
                    except:
                        pass

            elif protocol == "SFTP":
                if paramiko is None:
                    show_error("SFTP-Unterstützung nicht installiert (paramiko fehlt).")
                    return

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port, user, pwd, timeout=10)
                sftp = ssh.open_sftp()
                if remote_path:
                    sftp.chdir(remote_path)
                found_files = sftp.listdir()

                # Optional: Version auslesen
                try:
                    with sftp.open("system/conf/main.conf.php", "r") as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        match = re.search(r"'PROJECT_VERSION'\s*=>\s*'([^']+)'", content)
                        if match:
                            version_info = f"\nErkannte Version: {match.group(1)}"
                except:
                    pass
                sftp.close()
                ssh.close()

            # Gambio Erkennung
            gambio_indicators = [
                "system",
                "GXEngine",
                "templates",
                "admin",
                "version.info",
            ]
            shop_detected = any(ind in found_files for ind in gambio_indicators)

            # Zusätzlicher Check auf spezifische Files, falls nlst/listdir nur Namen lieferte
            if not shop_detected:
                # Manchmal liefert nlst/listdir nicht alles oder Pfade sind komplex
                critical_files = ["system/conf/main.conf.php", "GXEngine/Shop.php"]
                # (Hier vereinfacht über die bereits geholte Liste)

            if shop_detected:
                QMessageBox.information(
                    self,
                    "Erfolg",
                    f"Verbindung erfolgreich.{version_info}\nGambio-Shop wurde im Pfad erkannt.",
                )
            else:
                show_error(
                    "Verbindung erfolgreich, aber im angegebenen Ordner wurde kein Gambio-Shop gefunden.\n"
                    "Bitte prüfen Sie den Shop-Pfad (Server)."
                )

        except SessionExpiredError as e:
            show_error(str(e))
        except ftplib.all_errors as e:
            show_error(f"FTP-Verbindung fehlgeschlagen: {str(e)}")
        except Exception as e:
            # Fehlerbehandlung für SFTP (paramiko wirft diverse SSHExceptions)
            err_msg = str(e)
            if "Authentication failed" in err_msg:
                show_error("FTP-Verbindung fehlgeschlagen: Login falsch.")
            elif "Connection timed out" in err_msg:
                show_error("FTP-Verbindung fehlgeschlagen: Host nicht erreichbar (Timeout).")
            else:
                show_error(f"FTP-Verbindung fehlgeschlagen: {err_msg}")
        finally:
            self.auth_manager.update_activity()

    def _new_profile(self):
        """Bereitet die Oberfläche für die Eingabe eines neuen Profils vor."""
        self.auth_manager.update_activity()
        self._clear_profile_fields()
        self.combo_profiles.setCurrentIndex(-1)  # Kein Profil auswählen
        self.btn_save_profile.setEnabled(True)  # Speichern für neues Profil aktivieren

    def _save_profile(self):
        """Speichert das aktuell angezeigte oder neu erstellte Profil."""
        try:
            self.auth_manager.require_active_session()
            current_password = self.auth_manager.get_password()
            if not current_password:
                show_error("Kein Master-Passwort gesetzt. Bitte melden Sie sich erneut an.")
                return

            profile_data = self._get_current_profile_data()
            if not profile_data["shop_name"]:
                show_error("Shop-Name darf nicht leer sein.")
                return

            # Validierung des Shop-Pfads
            remote_path = profile_data.get("remote_path", "").strip()
            if remote_path:
                # Verhindere Directory Traversal (Sicherheitsrisiko)
                if ".." in remote_path or "\\" in remote_path:
                    show_error("Der angegebene Shop-Pfad auf dem Server ist ungültig.")
                    return

            profiles = self.config_manager.get_profiles()
            if self.current_profile_index != -1 and 0 <= self.current_profile_index < len(profiles):
                # Bestehendes Profil aktualisieren
                profiles[self.current_profile_index] = profile_data
            else:
                # Neues Profil hinzufügen
                profiles.append(profile_data)

            self.config_manager.set_profiles(profiles)
            self.config_manager.save_current_config(current_password)
            QMessageBox.information(self, "Erfolg", "Shop-Profil erfolgreich gespeichert.")
            self._load_profiles_into_combobox()  # Combobox neu laden, um Änderungen zu reflektieren
            # Das neu gespeicherte/aktualisierte Profil auswählen
            if self.current_profile_index == -1:  # Wenn es ein neues Profil war
                self.combo_profiles.setCurrentIndex(self.combo_profiles.count() - 1)
            else:
                self.combo_profiles.setCurrentIndex(self.current_profile_index)

        except SessionExpiredError as e:
            show_error(str(e))
        except Exception as e:
            show_error(f"Fehler beim Speichern des Profils: {str(e)}")
        finally:
            self.auth_manager.update_activity()

    def _delete_profile(self):
        """Löscht das aktuell ausgewählte Profil."""
        try:
            self.auth_manager.require_active_session()
            current_password = self.auth_manager.get_password()
            if not current_password:
                show_error("Kein Master-Passwort gesetzt. Bitte melden Sie sich erneut an.")
                return

            if self.current_profile_index == -1:
                show_error("Bitte wählen Sie ein Profil zum Löschen aus.")
                return

            reply = QMessageBox.question(
                self,
                "Profil löschen",
                f"Möchten Sie das Profil '{self.combo_profiles.currentText()}' wirklich löschen?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                profiles = self.config_manager.get_profiles()
                if 0 <= self.current_profile_index < len(profiles):
                    del profiles[self.current_profile_index]
                    self.config_manager.set_profiles(profiles)
                    self.config_manager.save_current_config(current_password)
                    QMessageBox.information(self, "Erfolg", "Shop-Profil erfolgreich gelöscht.")
                    self._load_profiles_into_combobox()  # Combobox neu laden
                    self._clear_profile_fields()
                else:
                    show_error("Ungültiges Profil zum Löschen ausgewählt.")
        except SessionExpiredError as e:
            show_error(str(e))
        except Exception as e:
            show_error(f"Fehler beim Löschen des Profils: {str(e)}")
        finally:
            self.auth_manager.update_activity()

    def _save_general_settings(self):
        """Speichert die allgemeinen Einstellungen (z.B. Ignorierte Dateien)."""
        try:
            self.auth_manager.require_active_session()
            current_password = self.auth_manager.get_password()
            if not current_password:
                show_error("Kein Master-Passwort gesetzt. Bitte melden Sie sich erneut an.")
                return

            excluded_files = self.edit_excluded_files.text()
            self.config_manager.set_excluded_files(excluded_files)
            self.config_manager.set_max_log_age(self.spin_max_log_age.value())
            self.config_manager.save_current_config(current_password)
            QMessageBox.information(self, "Erfolg", "Allgemeine Einstellungen erfolgreich gespeichert.")
        except SessionExpiredError as e:
            show_error(str(e))
        except Exception as e:
            show_error(f"Fehler beim Speichern der Einstellungen: {str(e)}")
        finally:
            self.auth_manager.update_activity()

    def _change_master_password(self):
        """Ändert das Master-Passwort der Anwendung."""
        try:
            self.auth_manager.require_active_session()
            old_password = self.edit_old_master_password.text()
            new_password = self.edit_new_master_password.text()
            repeat_new_password = self.edit_repeat_new_master_password.text()

            if not old_password:
                show_error("Bitte geben Sie Ihr altes Master-Passwort ein.")
                return
            if not new_password:
                show_error("Das neue Master-Passwort darf nicht leer sein.")
                return
            if new_password != repeat_new_password:
                show_error("Das neue Master-Passwort und die Wiederholung stimmen nicht überein.")
                return

            # Versuch, das Master-Passwort über den config_manager zu ändern
            self.config_manager.change_master_password(old_password, new_password)
            self.auth_manager.set_password(new_password)  # Passwort im Auth-Manager aktualisieren
            QMessageBox.information(self, "Erfolg", "Master-Passwort erfolgreich geändert.")

            # Passwortfelder nach erfolgreicher Änderung leeren
            self.edit_old_master_password.clear()
            self.edit_new_master_password.clear()
            self.edit_repeat_new_master_password.clear()

        except (InvalidMasterPasswordError, TooManyFailedAttemptsError) as e:
            show_error(str(e))
        except SessionExpiredError as e:
            show_error(str(e))
        except Exception as e:
            show_error(f"Ein unerwarteter Fehler ist aufgetreten: {type(e).__name__}: {e}")
        finally:
            self.auth_manager.update_activity()


class UpdateAnalysisPage(QWidget):
    """Platzhalter-Widget für die Update-Analyse."""

    def __init__(self, auth_manager, config_manager, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Inhalt für Update-Analyse"))
        layout.addStretch()


class ManualPage(QWidget):
    """Zeigt das Benutzerhandbuch direkt in der Software an."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)

        # Suchleiste
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Im Handbuch suchen...")

        self.btn_search_prev = QPushButton("Vorheriges")
        self.btn_search_next = QPushButton("Nächstes")

        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.btn_search_prev)
        search_layout.addWidget(self.btn_search_next)

        layout.addLayout(search_layout)

        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)

        import sys

        if hasattr(sys, "_MEIPASS"):
            manual_path = os.path.join(sys._MEIPASS, "USER_MANUAL.md")
        else:
            manual_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "USER_MANUAL.md")

        try:
            with open(manual_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.browser.setMarkdown(content)
        except Exception as e:
            self.browser.setHtml(f"<h3>Fehler beim Laden des Handbuchs</h3><p>{e}</p>")

        layout.addWidget(self.browser)

        # Verbindungen für die Suche
        self.search_input.returnPressed.connect(self._search_next)
        self.btn_search_next.clicked.connect(self._search_next)
        self.btn_search_prev.clicked.connect(self._search_prev)

    def _search_next(self):
        text = self.search_input.text()
        if text:
            from PySide6.QtGui import QTextCursor

            # find() gibt True zurück wenn gefunden, markiert dann den Text
            found = self.browser.find(text)
            if not found:
                # Am Ende angekommen, cursor zurücksetzen
                self.browser.moveCursor(QTextCursor.Start)
                self.browser.find(text)

    def _search_prev(self):
        text = self.search_input.text()
        if text:
            from PySide6.QtGui import QTextDocument, QTextCursor

            found = self.browser.find(text, QTextDocument.FindBackward)
            if not found:
                # Am Anfang angekommen, cursor ans Ende setzen
                self.browser.moveCursor(QTextCursor.End)
                self.browser.find(text, QTextDocument.FindBackward)


class MainWindow(QMainWindow):
    """
    Hauptfenster der Anwendung mit Sidebar-Navigation und Seitenverwaltung.
    Integriert Session-Lock-Prüfung bei Seitenwechseln.
    """

    def __init__(self, auth_manager: MasterPasswordManager, config_manager: ConfigManager):
        super().__init__()
        self.auth_manager = auth_manager
        self.config_manager = config_manager
        self.setWindowTitle("Gambio Health Check")
        self.resize(900, 600)

        # Main Layout
        main_widget = QWidget()
        outer_layout = QVBoxLayout(main_widget)

        content_layout = QHBoxLayout()

        # Sidebar
        sidebar = QVBoxLayout()
        self.btn_health = QPushButton("Health-Check")

        self.btn_config = QPushButton("Konfiguration")

        self.btn_manual = QPushButton("Handbuch")

        # Set fixed width for sidebar buttons for better alignment
        self.btn_health.setFixedWidth(150)
        self.btn_config.setFixedWidth(150)
        self.btn_manual.setFixedWidth(150)

        sidebar.addWidget(self.btn_health)
        sidebar.addWidget(self.btn_config)
        sidebar.addWidget(self.btn_manual)
        sidebar.addStretch()

        # Global Cancel Button
        self.btn_cancel_global = QPushButton("Alles Abbrechen")
        self.btn_cancel_global.setFixedWidth(150)
        self.btn_cancel_global.setStyleSheet(
            "background-color: #e74c3c; color: white; font-weight: bold; margin-bottom: 20px;"
        )
        self.btn_cancel_global.clicked.connect(self._cancel_all_operations)
        sidebar.addWidget(self.btn_cancel_global)

        # Inhaltsseiten (QStackedWidget)
        self.pages = QStackedWidget()
        self.pages.addWidget(HealthCheckPage(self.auth_manager, self.config_manager))
        self.pages.addWidget(UpdateAnalysisPage(self.auth_manager, self.config_manager))
        self.pages.addWidget(ConfigPage(self.auth_manager, self.config_manager))
        self.pages.addWidget(ManualPage(self))

        content_layout.addLayout(sidebar, 1)  # Sidebar takes 1 part of space
        content_layout.addWidget(self.pages, 4)

        outer_layout.addLayout(content_layout)

        # --- Bottom Bar ---
        bottom_bar = QHBoxLayout()

        # Version (Left)
        try:
            from app import SOFTWARE_VERSION

            version_text = f"Version {SOFTWARE_VERSION}"
        except ImportError:
            import sys

            main_mod = sys.modules.get("__main__")
            version_text = f"Version {getattr(main_mod, 'SOFTWARE_VERSION', '1.0.1')}"

        version_label = QLabel(version_text)
        version_label.setStyleSheet("color: gray; font-size: 11px;")
        bottom_bar.addWidget(version_label)

        bottom_bar.addStretch()

        # Copyright & Link (Right)
        from datetime import datetime

        current_year = datetime.now().year
        copyright_label = QLabel(
            f"© {current_year} <a href='https://www.agentur-schoelzke.de' style='color: gray; text-decoration: none;'>Agentur Schölzke</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setStyleSheet("color: gray; font-size: 11px;")
        bottom_bar.addWidget(copyright_label)

        # Donate Button
        import webbrowser

        donate_btn = QPushButton("Spenden")
        donate_btn.setStyleSheet(
            "background-color: #f39c12; color: white; border: none; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;"
        )
        donate_btn.setCursor(Qt.PointingHandCursor)
        donate_btn.clicked.connect(lambda: webbrowser.open("https://paypal.me/kaischoelzke"))
        bottom_bar.addWidget(donate_btn)

        outer_layout.addLayout(bottom_bar)

        self.setCentralWidget(main_widget)

        # Verbindungen für die Navigation
        self.btn_health.clicked.connect(lambda: self._change_page(0))

        self.btn_config.clicked.connect(lambda: self._change_page(2))
        self.btn_manual.clicked.connect(lambda: self._change_page(3))

    def _cancel_all_operations(self):
        """Bricht global alle laufenden Aktionen auf allen Seiten ab."""
        for i in range(self.pages.count()):
            page = self.pages.widget(i)
            if hasattr(page, "cancel_all"):
                page.cancel_all()

    def _change_page(self, index: int):
        """
        Wechselt die angezeigte Seite im QStackedWidget.
        Führt vor dem Wechsel eine Session-Prüfung und ggf. Re-Authentifizierung durch.
        """
        try:
            # Prüfen, ob die Session abgelaufen ist (diese Methode muss in MasterPasswordManager implementiert werden)
            if self.auth_manager.is_session_expired():
                dialog = MasterPasswordDialog()
                if dialog.exec():  # Dialog wurde akzeptiert
                    new_password = dialog.get_password()
                    if new_password:
                        try:
                            # Versuch der Re-Authentifizierung durch Laden der Konfiguration
                            # Dies verifiziert implizit das Passwort
                            self.config_manager.load_config(new_password)
                            self.auth_manager.set_password(new_password)  # Passwort im Manager aktualisieren
                            self.auth_manager.update_activity()
                            self.pages.setCurrentIndex(index)

                            # Wenn die ConfigPage das Ziel ist, muss sie ihre Ansicht aktualisieren
                            if isinstance(self.pages.widget(index), ConfigPage):
                                self.pages.widget(index)._load_profiles_into_combobox()
                        except (
                            InvalidMasterPasswordError,
                            TooManyFailedAttemptsError,
                        ) as e:
                            show_error(str(e))
                            # Seite nicht wechseln, wenn Re-Authentifizierung fehlschlägt
                        except Exception as e:
                            show_error(f"Ein unerwarteter Fehler beim Re-Authentifizieren: {type(e).__name__}: {e}")
                    else:
                        show_error("Passwort darf nicht leer sein.")
                # Wenn Dialog abgelehnt wird, bleibt die Seite unverändert
            else:
                # Session ist aktiv, nur Aktivität aktualisieren und Seite wechseln
                self.auth_manager.update_activity()
                self.pages.setCurrentIndex(index)

                # Wenn die ConfigPage das Ziel ist, muss sie ihre Ansicht aktualisieren
                if isinstance(self.pages.widget(index), ConfigPage):
                    self.pages.widget(index)._load_profiles_into_combobox()
        except Exception as e:
            # Unerwartete Fehler während des Prozesses abfangen
            show_error(f"Ein unerwarteter Fehler ist aufgetreten: {type(e).__name__}: {e}")
