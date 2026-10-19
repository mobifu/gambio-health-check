import ftplib  # nosec B402 # Für FTP/FTPS Fallback-Unterstützung und Typ-Prüfungen
import hashlib
import io
import json
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any


class HashCheckEngine:
    """
    Berechnet, speichert und vergleicht SHA-256 Hashes von Shop-Dateien über FTP/SFTP.
    Erkennt Abweichungen, fehlende oder manipulierte Dateien und potenzielle Malware-Indikatoren.
    """

    def __init__(
        self,
        profile_name: str,
        conn: Any,
        signal: Any = None,
        logger: Any = None,
        worker: Any = None,
    ):
        self.profile_name = profile_name
        self.conn = conn
        self.signal = signal
        self.logger = logger or logging.getLogger(__name__)
        self.worker = worker

        # Pfadsicherheit via pathlib und Path Traversal Absicherung
        base_profiles_dir = Path("profiles").resolve()
        safe_name = re.sub(r'[\\/*?:"<>| &]', "_", profile_name.strip())
        if not safe_name:
            safe_name = "default"

        target_dir = (base_profiles_dir / safe_name / "hashes").resolve()
        if not target_dir.is_relative_to(base_profiles_dir):
            target_dir = (base_profiles_dir / "default" / "hashes").resolve()

        self.hash_dir = str(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_path = str(target_dir / "baseline.json")
        self.logger.info(f"Hash-Engine bereit. Speicherort: {self.hash_dir}")

        # Startverzeichnis für FTP merken, um Pfad-Desync zu verhindern
        self._ftp_root = "."
        if isinstance(self.conn, ftplib.FTP):
            try:
                self._ftp_root = self.conn.pwd()
            except (ftplib.Error, OSError) as e:
                self.logger.debug(f"Konnte initiales FTP-Arbeitsverzeichnis nicht ermitteln: {e}")

        # Ignorierte Dateien laden
        self.excluded_list: list[str] = []
        if self.worker and hasattr(self.worker, "page") and hasattr(self.worker.page, "config_manager"):
            excluded_str = self.worker.page.config_manager.get_excluded_files()
            if excluded_str:
                self.excluded_list = [f.strip() for f in excluded_str.split(",") if f.strip()]

    def _progress(self, msg: str) -> None:
        """Aktualisiert die Status-Anzeige (oben) via Worker-Signal."""
        if self.worker and hasattr(self.worker, "progress_signal"):
            self.worker.progress_signal.emit(msg)

    def _log(self, msg: str, status: str = "ok", skip_ui: bool = False) -> None:
        """Sendet Nachricht an UI und schreibt ins Datei-Log."""
        if self.logger:
            if status == "ok":
                self.logger.info(msg)
            elif status == "warn":
                self.logger.warning(msg)
            else:
                self.logger.error(msg)

        if self.signal and not skip_ui:
            self.signal.emit(msg, status)

    def generate_hash(self, remote_path: str) -> tuple[str | None, bytes | None]:
        """Lädt eine Datei herunter und berechnet den SHA-256 Hash. Gibt (hash, content) zurück."""
        # Pfad-Validierung gegen Directory Traversal
        normalized = remote_path.replace("\\", "/")
        if ".." in normalized.split("/") or normalized.startswith("/") or ":" in normalized:
            if not (self.worker and getattr(self.worker, "_is_cancelled", False)):
                self._log(
                    f"Ungültiger oder gefährlicher Pfad blockiert: {remote_path}",
                    "warn",
                )
            return None, None

        try:
            buf = io.BytesIO()
            if isinstance(self.conn, ftplib.FTP):
                # Sicherstellen, dass wir im Binärmodus sind
                self.conn.voidcmd("TYPE I")

                # Versuch 1: Direkter Download mit relativem Pfad (meist am stabilsten)
                try:
                    self.conn.retrbinary(f"RETR {remote_path}", buf.write)
                except (ftplib.Error, OSError):
                    # Versuch 2: Fallback mit Navigation (für restriktive Server)
                    buf = io.BytesIO()
                    parts = normalized.split("/")
                    filename = parts[-1]
                    dirs = parts[:-1]
                    self.conn.cwd(self._ftp_root)
                    try:
                        for d in dirs:
                            self.conn.cwd(d)
                        self.conn.retrbinary(f"RETR {filename}", buf.write)
                    finally:
                        self.conn.cwd(self._ftp_root)
            else:
                # SFTP: Expliziter Check ob Verzeichnis
                info = self.conn.stat(remote_path)
                if stat.S_ISDIR(info.st_mode):
                    return None, None
                with self.conn.open(remote_path, "rb") as f:
                    buf.write(f.read())

            data = buf.getvalue()
            return hashlib.sha256(data).hexdigest(), data
        except (ftplib.Error, OSError, EOFError) as e:
            if not (self.worker and getattr(self.worker, "_is_cancelled", False)):
                self._log(f"Datei konnte nicht gelesen werden: {remote_path} ({e})", "warn")
            return None, None
        except Exception as e:  # noqa: BLE001
            if not (self.worker and getattr(self.worker, "_is_cancelled", False)):
                self._log(f"Unerwarteter Fehler beim Lesen: {remote_path} ({e})", "warn")
            return None, None

    def _check_malware_indicators(self, data: bytes | None, path: str) -> None:
        """Sucht nach verdächtigen PHP-Funktionen und Payloads."""
        if not data or not isinstance(data, (bytes, bytearray)):
            return

        indicators = [b"eval", b"base64_decode", b"gzinflate", b"system", b"shell_exec"]
        found = [ind.decode("ascii") for ind in indicators if ind in data]

        # Suche nach langen Base64-Strings (Payload-Verdacht)
        if re.search(rb"[A-Za-z0-9+/]{128,}", data):
            found.append("Langer Base64-Payload")

        if found:
            self._log(f"Verdächtiger Code in {path} ({', '.join(found)} gefunden)", "error")

    def _get_remote_files_recursive(self, path: str = ".") -> list[str]:
        """Listet Dateien rekursiv auf (begrenzt auf relevante Shop-Ordner)."""
        files: list[str] = []
        skip_dirs = {
            "images",
            "cache",
            "logs",
            "export",
            "import",
            "backups",
            "uploads",
            "node_modules",
            ".git",
        }
        media_extensions = (
            ".pdf",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".svg",
        )

        # Startverzeichnis merken für FTP, um es am Ende wiederherzustellen
        start_dir = "."
        if isinstance(self.conn, ftplib.FTP):
            try:
                start_dir = self.conn.pwd()
            except (ftplib.Error, OSError):
                pass

        def walk(current_path: str) -> None:
            if self.worker and getattr(self.worker, "_is_cancelled", False):
                return
            self._progress(f"Scanne: {current_path}")
            try:
                if isinstance(self.conn, ftplib.FTP):
                    # Versuche MLSD (moderner Standard, liefert Typen direkt)
                    try:
                        items = list(self.conn.mlsd())
                        if not items:
                            raise ValueError("MLSD empty")
                        for name, attrs in items:
                            if name in {".", ".."} or not name:
                                continue
                            if name in skip_dirs:
                                continue

                            full_item = name if current_path == "." else f"{current_path}/{name}"
                            target_type = attrs.get("type", "").lower() if isinstance(attrs, dict) else ""

                            if target_type == "dir":
                                try:
                                    self.conn.cwd(name)
                                except (ftplib.Error, OSError):
                                    continue
                                try:
                                    walk(full_item)
                                finally:
                                    self.conn.cwd("..")
                            elif target_type in {"file", "os.unix.slink", ""}:
                                lower_item = full_item.lower()
                                if lower_item.endswith(media_extensions):
                                    continue
                                files.append(full_item)
                                self._log(f"Datei gefunden: {full_item}", skip_ui=True)

                    except Exception:  # noqa: BLE001
                        # Fallback: LIST-Befehl parsen (robuster als nlst)
                        lines: list[str] = []
                        try:
                            self.conn.retrlines("LIST", lines.append)
                        except (ftplib.Error, OSError):
                            pass

                        if not lines:
                            # Letzter Fallback: nlst (für Unit-Tests, da diese oft nur nlst mocken)
                            try:
                                names = self.conn.nlst()
                                for item_name in names:
                                    name = item_name.replace("\\", "/").split("/")[-1]
                                    if name in {".", ".."} or not name:
                                        continue
                                    if name in skip_dirs:
                                        continue

                                    full_item = name if current_path == "." else f"{current_path}/{name}"

                                    if "." in name:
                                        lower_item = full_item.lower()
                                        if lower_item.endswith(media_extensions):
                                            continue
                                        files.append(full_item)
                                        self._log(
                                            f"Datei gefunden (NLST): {full_item}",
                                            skip_ui=True,
                                        )
                                    else:
                                        is_dir = False
                                        try:
                                            self.conn.cwd(name)
                                            is_dir = True
                                        except (ftplib.Error, OSError):
                                            pass

                                        if is_dir:
                                            try:
                                                walk(full_item)
                                            finally:
                                                self.conn.cwd("..")
                                        else:
                                            files.append(full_item)
                            except (ftplib.Error, OSError):
                                pass
                        else:
                            for line in lines:
                                if not line:
                                    continue
                                parts = line.split()
                                if len(parts) < 9:
                                    continue
                                name = line.split(None, 8)[-1]

                                if name in {".", ".."} or not name:
                                    continue
                                if name in skip_dirs:
                                    continue

                                full_item = name if current_path == "." else f"{current_path}/{name}"

                                if line.startswith("d"):
                                    try:
                                        self.conn.cwd(name)
                                    except (ftplib.Error, OSError):
                                        continue
                                    try:
                                        walk(full_item)
                                    finally:
                                        self.conn.cwd("..")
                                elif line.startswith(("-", "l")):
                                    lower_item = full_item.lower()
                                    if lower_item.endswith(media_extensions):
                                        continue
                                    files.append(full_item)
                                    self._log(
                                        f"Datei gefunden (LIST): {full_item}",
                                        skip_ui=True,
                                    )
                                else:
                                    # Unbekanntes Format (z.B. Windows FTP), CWD-Test
                                    is_dir = False
                                    try:
                                        self.conn.cwd(name)
                                        is_dir = True
                                    except (ftplib.Error, OSError):
                                        pass

                                    if is_dir:
                                        try:
                                            walk(full_item)
                                        finally:
                                            self.conn.cwd("..")
                                    else:
                                        lower_item = full_item.lower()
                                        if lower_item.endswith(media_extensions):
                                            continue
                                        files.append(full_item)

                else:  # SFTP
                    for entry in self.conn.listdir_attr(current_path):
                        if entry.filename in {".", ".."} or entry.filename in skip_dirs:
                            continue

                        full_p = f"{current_path}/{entry.filename}".replace("./", "")
                        if stat.S_ISDIR(entry.st_mode):
                            walk(full_p)
                        else:
                            lower_path = full_p.lower()
                            if lower_path.endswith(media_extensions):
                                continue
                            files.append(full_p)
                            self._log(f"Datei gefunden: {full_p}", skip_ui=True)
            except (ftplib.Error, OSError, EOFError) as e:
                if not (self.worker and getattr(self.worker, "_is_cancelled", False)):
                    self.logger.warning(f"Verzeichnis übersprungen oder leer: {current_path} ({e})")
            except Exception as e:  # noqa: BLE001
                if not (self.worker and getattr(self.worker, "_is_cancelled", False)):
                    self.logger.warning(f"Unerwarteter Fehler bei Verzeichnis: {current_path} ({e})")

        walk(path)
        # Am Ende wiederherstellen des ursprünglichen FTP-Arbeitsverzeichnisses
        if isinstance(self.conn, ftplib.FTP):
            try:
                self.conn.cwd(start_dir)
            except (ftplib.Error, OSError):
                pass
        return files

    def generate_baseline(self) -> None:
        """Erzeugt die baseline.json für alle aktuellen Shop-Dateien."""
        self._progress("Suche Dateien auf dem Server...")
        self._log("Suche Dateien für Baseline-Scan...")
        remote_files = self._get_remote_files_recursive()

        if not remote_files:
            self._log(
                "Keine Dateien zum Hashen gefunden. Bitte prüfen Sie den Shop-Pfad und die Berechtigungen.",
                "warn",
            )
            return

        hashes: dict[str, str] = {}
        total = len(remote_files)
        self._log(f"Gefunden: {total} Dateien. Starte Hashing...", "ok")

        try:
            for i, f in enumerate(remote_files):
                if self.worker and getattr(self.worker, "_is_cancelled", False):
                    break

                # Check ignored list
                if any(ex in f for ex in self.excluded_list):
                    continue

                if i % 500 == 0:
                    self._progress(f"Hashe {i + 1}/{total}: {os.path.basename(f)}")

                h, _ = self.generate_hash(f)
                if h:
                    hashes[f] = h
        finally:
            # Immer speichern, auch bei Abbruch (hilft bei Diagnose)
            try:
                with open(self.baseline_path, "w", encoding="utf-8") as out_f:
                    json.dump(hashes, out_f, indent=4)
            except OSError as e:
                self.logger.error(f"Fehler beim Speichern der Baseline in {self.baseline_path}: {e}")

            if not (self.worker and getattr(self.worker, "_is_cancelled", False)) and hashes:
                self._log(f"Baseline erfolgreich erstellt ({len(hashes)} Dateien).", "ok")

    def generate_update_hashes(self, update_version: str, file_list: list[str]) -> None:
        """Speichert Hashes für Dateien eines spezifischen Updates."""
        target_file = Path(self.hash_dir) / f"update_{update_version}.json"
        hashes: dict[str, str] = {}
        for file_item in file_list:
            h, _ = self.generate_hash(file_item)
            if h:
                hashes[file_item] = h
        try:
            with open(target_file, "w", encoding="utf-8") as out_fh:
                json.dump(hashes, out_fh, indent=4)
        except OSError as e:
            self.logger.error(f"Fehler beim Speichern der Update-Hashes in {target_file}: {e}")

    def compare_with_baseline(self) -> None:
        """Vergleicht den aktuellen Server-Zustand mit der Baseline."""
        if not os.path.exists(self.baseline_path):
            self._log("Keine Baseline vorhanden. Bitte zuerst erzeugen.", "warn")
            return

        try:
            with open(self.baseline_path, "r", encoding="utf-8") as in_fh:
                baseline = json.load(in_fh)
        except (OSError, json.JSONDecodeError) as e:
            self._log(f"Fehler beim Laden der Baseline {self.baseline_path}: {e}", "error")
            return

        self._progress("Suche Dateien für Vergleich...")
        self._log("Starte Hash-Vergleich mit Baseline...")
        current_files = self._get_remote_files_recursive()
        total = len(current_files)

        for i, file_path in enumerate(current_files):
            if self.worker and getattr(self.worker, "_is_cancelled", False):
                return

            # Check ignored list
            if any(ex in file_path for ex in self.excluded_list):
                continue

            if i % 500 == 0:
                self._progress(f"Prüfe Datei {i + 1} von {total}...")
            current_h, data = self.generate_hash(file_path)
            if not current_h:
                continue

            if file_path not in baseline:
                self._log(f"Unbekannte Datei gefunden: {file_path}", "warn")
                self._check_malware_indicators(data, file_path)
            elif baseline[file_path] != current_h:
                self._log(
                    f"Datei verändert: {file_path}\nErwartet: {baseline[file_path][:16]}...\nGefunden: {current_h[:16]}...",
                    "warn",
                )
                self._check_malware_indicators(data, file_path)

        for baseline_file in baseline:
            if any(ex in baseline_file for ex in self.excluded_list):
                continue
            if baseline_file not in current_files:
                self._log(f"Datei fehlt: {baseline_file}", "error")

    def compare_with_update_hashes(self, update_version: str) -> None:
        """Prüft, ob Update-Dateien korrekt auf dem Server liegen."""
        target_file = os.path.join(self.hash_dir, f"update_{update_version}.json")
        if not os.path.exists(target_file):
            return

        try:
            with open(target_file, "r", encoding="utf-8") as update_fh:
                update_hashes = json.load(update_fh)
        except (OSError, json.JSONDecodeError) as e:
            self.logger.error(f"Fehler beim Laden der Update-Hashes aus {target_file}: {e}")
            return

        self._log(f"Prüfe Integrität von Update {update_version}...")
        for check_file, expected_h in update_hashes.items():
            if any(ex in check_file for ex in self.excluded_list):
                continue
            current_h, _ = self.generate_hash(check_file)
            if not current_h:
                self._log(f"Update-Datei fehlt: {check_file}", "error")
            elif current_h != expected_h:
                self._log(f"Update-Datei wurde nachträglich verändert: {check_file}", "error")
