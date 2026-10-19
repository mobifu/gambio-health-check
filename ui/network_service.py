"""
ui/network_service.py
=====================
Netzwerk- und FTP/SFTP-Service-Modul für das Gambio Health-Check-Modul.

Zentralisiert Verbindungsaufbau, Protokollprüfung, TLS-Erzwingung sowie
entfernte Datei- und Wartungsoperationen.
"""

from __future__ import annotations

import datetime
import ftplib  # nosec B402 # Für FTPS und explizit erlaubten Legacy-FTP-Support
import io
import logging
import re
import stat
from typing import Any, Callable

try:
    import paramiko  # type: ignore
except ImportError:
    paramiko = None

from security.exceptions import InsecureFTPError

logger = logging.getLogger(__name__)

GAMBIO_INDICATORS: list[str] = [
    "system",
    "GXEngine",
    "templates",
    "admin",
    "version.info",
]

DEFAULT_SKIP_DIRS: list[str] = [
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


class NetworkService:
    """
    Zentraler Dienst für Netzwerk- und FTP/SFTP-Verbindungslogik.
    Erzwingt standardmäßig TLS für FTP und verhindert unverschlüsselte Klartext-Fallbacks,
    sofern diese nicht explizit im Profil durch den Nutzer freigegeben wurden.
    """

    @staticmethod
    def parse_connection_params(profile: dict[str, Any]) -> dict[str, Any]:
        """
        Bereinigt und normalisiert Verbindungsdaten aus einem Shop-Profil.
        """
        protocol = str(profile.get("protocol", "FTP")).strip().upper()
        raw_host = str(profile.get("host", "")).strip()
        host = re.sub(r"^[a-zA-Z]+://", "", raw_host).strip("/")

        raw_port = profile.get("port")
        default_port = 22 if protocol == "SFTP" else 21
        port = default_port
        if raw_port is not None:
            try:
                p = int(raw_port)
                if p > 0:
                    port = p
            except (ValueError, TypeError):
                port = default_port

        user = str(profile.get("username", "")).strip()
        pwd = str(profile.get("password", ""))
        remote_path = str(profile.get("remote_path", "")).strip()
        timeout = int(profile.get("timeout", 25 if protocol == "FTP" else 10))
        allow_insecure_ftp = bool(profile.get("allow_insecure_ftp", False))

        return {
            "protocol": protocol,
            "host": host,
            "port": port,
            "username": user,
            "password": pwd,
            "remote_path": remote_path,
            "timeout": timeout,
            "allow_insecure_ftp": allow_insecure_ftp,
        }

    @classmethod
    def create_remote_connection(
        cls,
        profile: dict[str, Any],
        log_callback: Callable[[str, str], None] | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> tuple[Any, list[str]]:
        """
        Stellt eine Verbindung zu einem FTP- oder SFTP-Server her und listet Dateien im Zielverzeichnis auf.

        :param profile: Shop-Profil-Dictionary.
        :param log_callback: Optionaler Callback zur Ausgabe von Statusnachrichten (Nachricht, Status).
        :param progress_callback: Optionaler Callback für Status-Label.
        :return: (Verbindungsobjekt, Liste der Dateinamen) oder (None, []).
        """

        def log(msg: str, status: str = "ok") -> None:
            if log_callback:
                log_callback(msg, status)
            else:
                if status == "error":
                    logger.error(msg)
                elif status == "warn":
                    logger.warning(msg)
                else:
                    logger.info(msg)

        params = cls.parse_connection_params(profile)
        protocol = params["protocol"]
        host = params["host"]
        port = params["port"]
        user = params["username"]
        pwd = params["password"]
        r_path = params["remote_path"]
        timeout = params["timeout"]
        allow_insecure_ftp = params["allow_insecure_ftp"]

        if progress_callback:
            progress_callback(f"Verbinde zu {host}:{port} ({protocol})...")
        log(f"Starte Verbindung zu {host}:{port} über {protocol}...")

        try:
            if protocol == "FTP":
                log(f"Verbinde via FTP mit {host}:{port}...")
                use_tls = False
                ftp: ftplib.FTP | None = None

                # 1. Bevorzugt verschlüsselt via FTPS (FTP_TLS)
                try:
                    ftp_tls = ftplib.FTP_TLS()
                    ftp_tls.connect(host, port, timeout=timeout)
                    ftp_tls.auth()
                    use_tls = True
                    ftp = ftp_tls
                    log("Explizites TLS aktiviert (FTPS).")
                except Exception as tls_err:
                    if not allow_insecure_ftp:
                        err_msg = (
                            f"FTPS/TLS-Fehler bei Verbindung mit {host}:{port}: {tls_err}. "
                            "Unverschlüsselter Klartext-Fallback standardmäßig verworfen (Sicherheitsrichtlinie). "
                            "Aktivieren Sie 'Unverschlüsseltes FTP erlauben' im Profil, falls Legacy-Support erforderlich ist."
                        )
                        log(err_msg, "error")
                        raise InsecureFTPError(err_msg) from tls_err

                    log(
                        f"WARNUNG: FTPS fehlgeschlagen ({tls_err}). Verbinde über unverschlüsseltes Standard-FTP (Klartext) "
                        "gemäß Nutzerkonfiguration...",
                        "warn",
                    )
                    # Legacy-Fallback mit gezielter Bandit-Annotation und Begründung
                    ftp = ftplib.FTP()  # nosec B321 # Legacy-Support: Explizit durch Nutzerkonfiguration ('allow_insecure_ftp') autorisierter Klartext-Fallback
                    ftp.connect(host, port, timeout=timeout)

                setattr(ftp, "trust_server_pasv_ipv4_address", True)
                log(f"Netzwerkverbindung zu {host}:{port} hergestellt. Authentifiziere...")
                ftp.login(user, pwd)

                prot_p_fn = getattr(ftp, "prot_p", None)
                if use_tls and callable(prot_p_fn):
                    try:
                        prot_p_fn()  # TLS für den Datenkanal
                        log("TLS-Schutz für Datenverbindung aktiviert (PROT P).")
                    except Exception as p_err:
                        logger.debug("PROT P konnte nicht aktiviert werden: %s", p_err)

                log(f"FTP-Login als '{user}' erfolgreich.")
                if r_path:
                    ftp.cwd(r_path)
                    log(f"FTP-Verzeichnis gewechselt zu '{r_path}'.")

                log("Lese Verzeichnisinhalt...")
                files = ftp.nlst()
                log(f"FTP-Verbindung erfolgreich hergestellt ({len(files)} Einträge gefunden).")
                return ftp, files

            elif protocol == "SFTP":
                if paramiko is None:
                    log("SFTP (Paramiko) ist nicht installiert.", "error")
                    return None, []

                ssh = paramiko.SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
                ssh.connect(host, port, user, pwd, timeout=timeout)
                log(f"SSH-Verbindung zu {host}:{port} hergestellt. Öffne SFTP-Kanal...")
                sftp = ssh.open_sftp()
                if r_path:
                    sftp.chdir(r_path)
                    log(f"SFTP-Verzeichnis gewechselt zu '{r_path}'.")
                files = sftp.listdir()
                log(f"SFTP-Verbindung erfolgreich hergestellt ({len(files)} Einträge gefunden).")
                return sftp, files

            log(f"Protokoll {protocol} wird für Dateiprüfung nicht unterstützt.", "warn")
            return None, []

        except Exception as e:
            err_type = type(e).__name__
            log(f"Fehler bei Verbindung [{protocol}://{host}:{port}] ({err_type}): {e!s}", "error")
            return None, []

    @classmethod
    def test_connection(cls, profile: dict[str, Any]) -> dict[str, Any]:
        """
        Führt einen Verbindungstest für ein Shop-Profil aus, sucht nach Gambio-Indikatoren
        und liest optional die Versionsnummer aus. Schließt die Verbindung danach sicher.

        :param profile: Profildaten.
        :return: Dict mit Ergebnissen (success, shop_detected, version, error, etc.)
        """
        params = cls.parse_connection_params(profile)
        protocol = params["protocol"]
        host = params["host"]
        port = params["port"]
        user = params["username"]
        pwd = params["password"]
        remote_path = params["remote_path"]
        timeout = params["timeout"]
        allow_insecure_ftp = params["allow_insecure_ftp"]

        result: dict[str, Any] = {
            "success": False,
            "protocol": protocol,
            "host": host,
            "port": port,
            "remote_path": remote_path,
            "shop_detected": False,
            "detected_indicators": [],
            "version": None,
            "error": None,
            "tls_used": False,
            "insecure_fallback": False,
            "files": [],
        }

        if protocol == "HTTPS":
            result["error"] = "Verbindungstest für HTTPS wird übersprungen (nur Pfadprüfung via FTP/SFTP unterstützt)."
            return result

        if not host or not user:
            result["error"] = "Bitte Host und Benutzername ausfüllen."
            return result

        conn: Any = None
        found_files: list[str] = []
        version_info: str | None = None

        try:
            if protocol == "FTP":
                use_tls = False
                insecure_fallback = False
                ftp: ftplib.FTP | None = None
                try:
                    ftp_tls = ftplib.FTP_TLS()
                    ftp_tls.connect(host, port, timeout=timeout)
                    ftp_tls.auth()
                    use_tls = True
                    ftp = ftp_tls
                except Exception as tls_err:
                    if not allow_insecure_ftp:
                        result["error"] = (
                            f"FTPS/TLS-Verbindung fehlgeschlagen: {tls_err}. "
                            "Unverschlüsselter Klartext-Fallback ist standardmäßig deaktiviert. "
                            "Bitte Serverkonfiguration prüfen oder unverschlüsseltes FTP explizit im Profil erlauben."
                        )
                        return result
                    # Legacy-Fallback mit Annotation
                    ftp = ftplib.FTP()  # nosec B321 # Legacy-Support: Explizit durch Nutzerkonfiguration ('allow_insecure_ftp') autorisierter Klartext-Fallback
                    ftp.connect(host, port, timeout=timeout)
                    insecure_fallback = True

                conn = ftp
                result["tls_used"] = use_tls
                result["insecure_fallback"] = insecure_fallback

                setattr(ftp, "trust_server_pasv_ipv4_address", True)
                ftp.login(user, pwd)
                prot_p_fn = getattr(ftp, "prot_p", None)
                if use_tls and callable(prot_p_fn):
                    try:
                        prot_p_fn()
                    except Exception:
                        pass
                if remote_path:
                    ftp.cwd(remote_path)
                found_files = ftp.nlst()

                # Versionserkennung
                try:
                    r_file = io.BytesIO()
                    ftp.retrbinary("RETR system/conf/main.conf.php", r_file.write)
                    content = r_file.getvalue().decode("utf-8", errors="ignore")
                    match = re.search(r"'PROJECT_VERSION'\s*=>\s*'([^']+)'", content)
                    if match:
                        version_info = match.group(1)
                except Exception:
                    pass

            elif protocol == "SFTP":
                if paramiko is None:
                    result["error"] = "SFTP-Unterstützung nicht installiert (paramiko fehlt)."
                    return result

                ssh = paramiko.SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
                ssh.connect(host, port, user, pwd, timeout=timeout)
                sftp = ssh.open_sftp()
                conn = (ssh, sftp)
                if remote_path:
                    sftp.chdir(remote_path)
                found_files = sftp.listdir()

                try:
                    with sftp.open("system/conf/main.conf.php", "r") as f:
                        content = f.read().decode("utf-8", errors="ignore")
                        match = re.search(r"'PROJECT_VERSION'\s*=>\s*'([^']+)'", content)
                        if match:
                            version_info = match.group(1)
                except Exception:
                    pass

            detected = [ind for ind in GAMBIO_INDICATORS if ind in found_files]
            result["success"] = True
            result["files"] = found_files
            result["version"] = version_info
            result["detected_indicators"] = detected
            result["shop_detected"] = len(detected) > 0

        except Exception as e:
            result["error"] = str(e)
        finally:
            cls.close_connection(conn)

        return result

    @staticmethod
    def close_connection(conn: Any) -> None:
        """
        Schließt eine FTP- oder SFTP-Verbindung sicher ohne Ausnahmen.
        """
        if not conn:
            return
        try:
            if isinstance(conn, tuple):
                # (ssh, sftp)
                ssh, sftp = conn
                try:
                    sftp.close()
                except Exception:
                    pass
                try:
                    ssh.close()
                except Exception:
                    pass
            elif isinstance(conn, ftplib.FTP) or hasattr(conn, "quit"):
                try:
                    conn.quit()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
            elif hasattr(conn, "close"):
                conn.close()
        except Exception as e:
            logger.debug("Fehler beim Schließen der Verbindung ignoriert: %s", e)


class RemoteFileService:
    """
    Service für rekursive Remote-Dateioperationen (Löschen, Scannen, Cache-Bereinigung).
    """

    @staticmethod
    def rmtree_ftp(
        ftp_conn: ftplib.FTP,
        path: str,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> None:
        """Löscht ein FTP-Verzeichnis rekursiv."""
        if is_cancelled and is_cancelled():
            return
        try:
            try:
                names = ftp_conn.nlst("-a", path)
                if not names:
                    names = ftp_conn.nlst(path)
            except Exception:
                names = ftp_conn.nlst(path)
        except ftplib.error_perm:
            names = []

        for name in names:
            if is_cancelled and is_cancelled():
                return
            base_name = name.rstrip("/").split("/")[-1].split("\\")[-1]
            if base_name in (".", ".."):
                continue

            full_p = name if name.startswith(path) else f"{path}/{name}"
            if full_p.rstrip("/") == path.rstrip("/"):
                continue

            try:
                ftp_conn.delete(full_p)
            except ftplib.error_perm:
                RemoteFileService.rmtree_ftp(ftp_conn, full_p, is_cancelled)

        try:
            ftp_conn.rmd(path)
        except Exception:
            pass

    @staticmethod
    def rmtree_sftp(
        sftp_conn: Any,
        path: str,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> None:
        """Löscht ein SFTP-Verzeichnis rekursiv."""
        if is_cancelled and is_cancelled():
            return
        try:
            for entry in sftp_conn.listdir_attr(path):
                if is_cancelled and is_cancelled():
                    return
                if entry.filename in (".", ".."):
                    continue
                full_p = f"{path}/{entry.filename}"
                if stat.S_ISDIR(entry.st_mode):
                    RemoteFileService.rmtree_sftp(sftp_conn, full_p, is_cancelled)
                else:
                    sftp_conn.remove(full_p)
            sftp_conn.rmdir(path)
        except Exception:
            try:
                sftp_conn.remove(path)
            except Exception:
                sftp_conn.rmdir(path)

    @classmethod
    def delete_remote_item(
        cls,
        conn: Any,
        file_path: str,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> tuple[bool, str]:
        """
        Löscht eine Datei oder ein Verzeichnis (mit automatischem Fallback).
        :return: (Erfolg, Typ: "Datei" oder "Ordner")
        """
        last_part = file_path.split("/")[-1]
        is_folder = "." not in last_part
        entry_type = "Ordner" if is_folder else "Datei"

        if is_folder:
            try:
                if isinstance(conn, ftplib.FTP):
                    cls.rmtree_ftp(conn, file_path, is_cancelled)
                else:
                    cls.rmtree_sftp(conn, file_path, is_cancelled)
                return True, entry_type
            except Exception:
                # Fallback: Als Datei versuchen
                if isinstance(conn, ftplib.FTP):
                    conn.delete(file_path)
                else:
                    conn.remove(file_path)
                return True, "Datei"
        else:
            try:
                if isinstance(conn, ftplib.FTP):
                    conn.delete(file_path)
                else:
                    conn.remove(file_path)
                return True, entry_type
            except Exception:
                # Fallback: Als Ordner versuchen
                if isinstance(conn, ftplib.FTP):
                    cls.rmtree_ftp(conn, file_path, is_cancelled)
                else:
                    cls.rmtree_sftp(conn, file_path, is_cancelled)
                return True, "Ordner"

    @staticmethod
    def clean_remote_cache(
        conn: Any,
        cache_dir: str = "cache",
        skipped_files: list[str] | None = None,
    ) -> int:
        """
        Löscht temporäre Dateien im entfernten Cache-Ordner.
        :return: Anzahl gelöschter Cache-Dateien.
        """
        if skipped_files is None:
            skipped_files = [".htaccess", "index.html", "index.php"]

        deleted_count = 0
        if isinstance(conn, ftplib.FTP):
            try:
                items = conn.nlst(cache_dir)
                for item in items:
                    name = item if not item.startswith(cache_dir + "/") else item[len(cache_dir) + 1 :]
                    if name in (".", "..") or not name or name in skipped_files:
                        continue
                    full_item_path = f"{cache_dir}/{name}"
                    try:
                        conn.delete(full_item_path)
                        deleted_count += 1
                    except ftplib.error_perm:
                        pass
            except Exception as e:
                logger.warning("Cache-Ordner konnte via FTP nicht vollständig geleert werden: %s", e)
        else:
            try:
                for entry in conn.listdir_attr(cache_dir):
                    if entry.filename in (".", "..") or entry.filename in skipped_files:
                        continue
                    if stat.S_ISDIR(entry.st_mode):
                        continue
                    full_item_path = f"{cache_dir}/{entry.filename}"
                    conn.remove(full_item_path)
                    deleted_count += 1
            except Exception as e:
                logger.warning("Cache-Ordner konnte via SFTP nicht vollständig geleert werden: %s", e)

        return deleted_count

    @classmethod
    def scan_bak_files(
        cls,
        conn: Any,
        current_path: str = ".",
        skip_dirs: list[str] | None = None,
        is_cancelled: Callable[[], bool] | None = None,
        progress_cb: Callable[[str], None] | None = None,
        match_cb: Callable[[str], None] | None = None,
    ) -> list[str]:
        """
        Sucht rekursiv nach .bak Dateien auf dem entfernten Server.
        """
        if skip_dirs is None:
            skip_dirs = DEFAULT_SKIP_DIRS

        found: list[str] = []

        def walk(path: str) -> None:
            if is_cancelled and is_cancelled():
                return
            if progress_cb:
                progress_cb(f"Scanne: {path}")

            try:
                if isinstance(conn, ftplib.FTP):
                    try:
                        items = list(conn.mlsd())
                        if not items:
                            raise ValueError("MLSD leer")
                        for name, attrs in items:
                            if name in [".", ".."] or not name or any(sd == name for sd in skip_dirs):
                                continue
                            full_item = name if path == "." else f"{path}/{name}"
                            target_type = attrs.get("type", "").lower() if isinstance(attrs, dict) else ""

                            if target_type == "dir":
                                try:
                                    conn.cwd(name)
                                    walk(full_item)
                                except Exception:
                                    pass
                                finally:
                                    try:
                                        conn.cwd("..")
                                    except Exception:
                                        pass
                            elif target_type in ["file", "os.unix.slink", ""] and full_item.lower().endswith(".bak"):
                                found.append(full_item)
                                if match_cb:
                                    match_cb(full_item)
                    except Exception:
                        names = conn.nlst()
                        for name in names:
                            if name in [".", ".."] or not name or any(sd == name for sd in skip_dirs):
                                continue
                            full_item = name if path == "." else f"{path}/{name}"
                            try:
                                conn.cwd(name)
                                walk(full_item)
                                conn.cwd("..")
                            except Exception:
                                if full_item.lower().endswith(".bak"):
                                    found.append(full_item)
                                    if match_cb:
                                        match_cb(full_item)
                else:
                    # SFTP
                    for attr in conn.listdir_attr("."):
                        name = attr.filename
                        if name in [".", ".."] or any(sd == name for sd in skip_dirs):
                            continue
                        full_item = name if path == "." else f"{path}/{name}"
                        if stat.S_ISDIR(attr.st_mode):
                            try:
                                conn.chdir(name)
                                walk(full_item)
                                conn.chdir("..")
                            except Exception:
                                pass
                        elif full_item.lower().endswith(".bak"):
                            found.append(full_item)
                            if match_cb:
                                match_cb(full_item)
            except Exception as e:
                logger.debug("Fehler beim Durchsuchen von %s: %s", path, e)

        walk(current_path)
        return found

    @staticmethod
    def fetch_logfiles(
        conn: Any,
        log_dir: str = "logfiles",
        max_age_days: int = 30,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Liest Logdateien aus dem logfiles-Verzeichnis und filtert nach Alter.
        """
        if is_cancelled and is_cancelled():
            return []

        try:
            if isinstance(conn, ftplib.FTP):
                conn.cwd(log_dir)
            else:
                conn.chdir(log_dir)
        except Exception as e:
            logger.warning("Konnte Verzeichnis '%s' nicht öffnen: %s", log_dir, e)
            return []

        files: list[dict[str, Any]] = []
        if isinstance(conn, ftplib.FTP):
            try:
                for name, attrs in conn.mlsd():
                    if name in [".", ".."] or attrs.get("type") != "file":
                        continue
                    modify = attrs.get("modify")
                    file_time = None
                    if modify:
                        try:
                            file_time = datetime.datetime.strptime(modify, "%Y%m%d%H%M%S").replace(
                                tzinfo=datetime.timezone.utc
                            )
                        except (ValueError, TypeError):
                            pass
                    files.append({"name": name, "time": file_time})
            except (ftplib.Error, OSError):
                for name in conn.nlst():
                    if name in [".", ".."]:
                        continue
                    file_time = None
                    try:
                        resp = conn.sendcmd(f"MDTM {name}")
                        file_time = datetime.datetime.strptime(resp[4:18], "%Y%m%d%H%M%S").replace(
                            tzinfo=datetime.timezone.utc
                        )
                    except Exception:
                        pass
                    files.append({"name": name, "time": file_time})
        else:
            for attr in conn.listdir_attr("."):
                if attr.filename in [".", ".."] or stat.S_ISDIR(attr.st_mode):
                    continue
                file_time = None
                if attr.st_mtime:
                    file_time = datetime.datetime.fromtimestamp(attr.st_mtime, tz=datetime.timezone.utc)
                files.append({"name": attr.filename, "time": file_time})

        return files
