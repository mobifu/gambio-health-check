import ftplib
import stat
import io
import os
import re
import json
import hashlib
import logging


class HashCheckEngine:
    """
    Berechnet, speichert und vergleicht SHA-256 Hashes von Shop-Dateien.
    Erkennt Abweichungen und potenzielle Malware-Indikatoren.
    """

    def __init__(self, profile_name, conn, signal=None, logger=None, worker=None):
        self.profile_name = profile_name
        self.conn = conn
        self.signal = signal
        self.logger = logger or logging.getLogger(__name__)
        self.worker = worker
        # Sonderzeichen und Leerzeichen für Pfadsicherheit entfernen
        safe_name = re.sub(r'[\\/*?:"<>| &]', "_", profile_name)
        self.hash_dir = os.path.join("profiles", safe_name, "hashes")
        os.makedirs(self.hash_dir, exist_ok=True)
        self.baseline_path = os.path.join(self.hash_dir, "baseline.json")
        self.logger.info(f"Hash-Engine bereit. Speicherort: {self.hash_dir}")

        # Startverzeichnis für FTP merken, um Pfad-Desync zu verhindern
        self._ftp_root = "."
        if isinstance(self.conn, ftplib.FTP):
            try:
                self._ftp_root = self.conn.pwd()
            except:
                pass

        # Ignorierte Dateien laden
        self.excluded_list = []
        if self.worker and hasattr(self.worker, "page") and hasattr(self.worker.page, "config_manager"):
            excluded_str = self.worker.page.config_manager.get_excluded_files()
            self.excluded_list = [f.strip() for f in excluded_str.split(",") if f.strip()]

    def _progress(self, msg):
        """Aktualisiert die Status-Anzeige (oben) via Worker-Signal."""
        if self.worker:
            self.worker.progress_signal.emit(msg)

    def _log(self, msg, status="ok", skip_ui=False):
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

    def generate_hash(self, remote_path):
        """Lädt eine Datei herunter und berechnet den SHA-256 Hash. Gibt (hash, content) zurück."""
        # Pfad-Validierung gegen Directory Traversal
        normalized = remote_path.replace("\\", "/")
        if ".." in normalized.split("/") or normalized.startswith("/") or ":" in normalized:
            if not (self.worker and self.worker._is_cancelled):
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
                except Exception:
                    # Versuch 2: Fallback mit Navigation (für sehr restriktive Server)
                    buf = io.BytesIO()
                    parts = remote_path.replace("\\", "/").split("/")
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
        except Exception as e:
            if not (self.worker and self.worker._is_cancelled):
                self._log(f"Datei konnte nicht gelesen werden: {remote_path} ({e})", "warn")
            return None, None

    def _check_malware_indicators(self, data, path):
        """Sucht nach verdächtigen PHP-Funktionen und Payloads."""
        indicators = [b"eval", b"base64_decode", b"gzinflate", b"system", b"shell_exec"]
        found = [ind.decode() for ind in indicators if ind in data]

        # Suche nach langen Base64-Strings (Payload-Verdacht)
        if re.search(rb"[A-Za-z0-9+/]{128,}", data):
            found.append("Langer Base64-Payload")

        if found:
            self._log(f"Verdächtiger Code in {path} ({', '.join(found)} gefunden)", "error")

    def _get_remote_files_recursive(self, path="."):
        """Listet Dateien rekursiv auf (begrenzt auf relevante Shop-Ordner)."""
        files = []
        # node_modules bleibt ausgeschlossen, vendor wird nun gehasht
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

        # Startverzeichnis merken für FTP, um es am Ende wiederherzustellen
        start_dir = "."
        if isinstance(self.conn, ftplib.FTP):
            try:
                start_dir = self.conn.pwd()
            except:
                pass

        def walk(current_path):
            if self.worker and self.worker._is_cancelled:
                return
            self._progress(f"Scanne: {current_path}")
            try:
                if isinstance(self.conn, ftplib.FTP):
                    # Versuche MLSD (moderner Standard, liefert Typen direkt)
                    try:
                        items = list(self.conn.mlsd())
                        if not items:
                            raise ValueError("MLSD empty")  # Force fallback in case of mocked MLSD
                        for name, attrs in items:
                            if name in [".", ".."] or not name:
                                continue
                            if any(sd == name for sd in skip_dirs):
                                continue

                            full_item = name if current_path == "." else f"{current_path}/{name}"
                            target_type = attrs.get("type", "").lower() if isinstance(attrs, dict) else ""

                            if target_type == "dir":
                                try:
                                    self.conn.cwd(name)
                                except Exception:
                                    continue
                                try:
                                    walk(full_item)
                                finally:
                                    self.conn.cwd("..")
                            elif target_type in ["file", "os.unix.slink", ""]:
                                # Skip PDF and image files from hashing
                                lower_item = full_item.lower()
                                if lower_item.endswith(".pdf") or lower_item.endswith(
                                    (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg")
                                ):
                                    continue
                                files.append(full_item)
                                self._log(f"Datei gefunden: {full_item}", skip_ui=True)

                    except Exception:
                        # Fallback: LIST-Befehl parsen (robuster als nlst)
                        lines = []
                        try:
                            self.conn.retrlines("LIST", lines.append)
                        except Exception:
                            pass

                        if not lines:
                            # Letzter Fallback: nlst (für Unit-Tests, da diese oft nur nlst mocken)
                            try:
                                names = self.conn.nlst()
                                for item_name in names:
                                    name = item_name.replace("\\", "/").split("/")[-1]
                                    if name in [".", ".."] or not name:
                                        continue
                                    if any(sd == name for sd in skip_dirs):
                                        continue

                                    full_item = name if current_path == "." else f"{current_path}/{name}"

                                    if "." in name:
                                        lower_item = full_item.lower()
                                        if lower_item.endswith(".pdf") or lower_item.endswith(
                                            (
                                                ".png",
                                                ".jpg",
                                                ".jpeg",
                                                ".gif",
                                                ".bmp",
                                                ".svg",
                                            )
                                        ):
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
                                        except Exception:
                                            pass

                                        if is_dir:
                                            try:
                                                walk(full_item)
                                            finally:
                                                self.conn.cwd("..")
                                        else:
                                            files.append(full_item)
                            except Exception:
                                pass
                        else:
                            for line in lines:
                                if not line:
                                    continue
                                # Einfaches Parsing für Unix-Style (erster Buchstabe d=Ordner, -=Datei)
                                parts = line.split()
                                if len(parts) < 9:
                                    continue
                                name = line.split(None, 8)[-1]

                                if name in [".", ".."] or not name:
                                    continue
                                if any(sd == name for sd in skip_dirs):
                                    continue

                                full_item = name if current_path == "." else f"{current_path}/{name}"

                                if line.startswith("d"):
                                    try:
                                        self.conn.cwd(name)
                                    except Exception:
                                        continue
                                    try:
                                        walk(full_item)
                                    finally:
                                        self.conn.cwd("..")
                                elif line.startswith("-") or line.startswith("l"):
                                    lower_item = full_item.lower()
                                    if lower_item.endswith(".pdf") or lower_item.endswith(
                                        (
                                            ".png",
                                            ".jpg",
                                            ".jpeg",
                                            ".gif",
                                            ".bmp",
                                            ".svg",
                                        )
                                    ):
                                        continue
                                    files.append(full_item)
                                    self._log(
                                        f"Datei gefunden (LIST): {full_item}",
                                        skip_ui=True,
                                    )
                                else:
                                    # Unbekanntes Format (z.B. Windows), versuche CWD-Test
                                    is_dir = False
                                    try:
                                        self.conn.cwd(name)
                                        is_dir = True
                                    except Exception:
                                        pass

                                    if is_dir:
                                        try:
                                            walk(full_item)
                                        finally:
                                            self.conn.cwd("..")
                                    else:
                                        lower_item = full_item.lower()
                                        if lower_item.endswith(".pdf") or lower_item.endswith(
                                            (
                                                ".png",
                                                ".jpg",
                                                ".jpeg",
                                                ".gif",
                                                ".bmp",
                                                ".svg",
                                            )
                                        ):
                                            continue
                                        files.append(full_item)

                else:  # SFTP
                    for entry in self.conn.listdir_attr(current_path):
                        if entry.filename in [".", ".."] or entry.filename in skip_dirs:
                            try:
                                continue
                            except:
                                pass

                        full_p = f"{current_path}/{entry.filename}".replace("./", "")
                        if stat.S_ISDIR(entry.st_mode):
                            walk(full_p)
                        else:
                            # Skip PDF and image files from hashing
                            lower_path = full_p.lower()
                            if lower_path.endswith(".pdf") or lower_path.endswith(
                                (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg")
                            ):
                                continue
                            files.append(full_p)
                            self._log(f"Datei gefunden: {full_p}", skip_ui=True)
            except Exception as e:
                if not (self.worker and self.worker._is_cancelled):
                    self.logger.warning(f"Verzeichnis übersprungen oder leer: {current_path} ({e})")

        walk(path)
        # Am Ende sicherstellen, dass wir wieder im Startverzeichnis für den nächsten Schritt sind
        if isinstance(self.conn, ftplib.FTP):
            try:
                self.conn.cwd(start_dir)
            except:
                pass
        return files

    def generate_baseline(self):
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

        hashes = {}
        total = len(remote_files)
        self._log(f"Gefunden: {total} Dateien. Starte Hashing...", "ok")

        processed_count = 0
        try:
            for i, f in enumerate(remote_files):
                if self.worker and self.worker._is_cancelled:
                    break

                # Check ignored list
                if any(ex in f for ex in self.excluded_list):
                    continue

                # UI-Update-Intervall vergrößern für bessere Performance
                if i % 500 == 0:
                    self._progress(f"Hashe {i + 1}/{total}: {os.path.basename(f)}")

                h, _ = self.generate_hash(f)
                if h:
                    hashes[f] = h
                    processed_count += 1

                # Zwischenspeichern für Performance bei großen Shops entfernt
                # Die Daten werden zuverlässig im finally-Block gespeichert.
        finally:
            # Immer speichern, auch bei Abbruch oder leeren Listen (hilft bei Diagnose)
            with open(self.baseline_path, "w", encoding="utf-8") as out_f:
                json.dump(hashes, out_f, indent=4)

            if not (self.worker and self.worker._is_cancelled) and hashes:
                self._log(f"Baseline erfolgreich erstellt ({len(hashes)} Dateien).", "ok")

    def generate_update_hashes(self, update_version, file_list):
        """Speichert Hashes für Dateien eines spezifischen Updates."""
        path = os.path.join(self.hash_dir, f"update_{update_version}.json")
        hashes = {}
        for f in file_list:
            h, _ = self.generate_hash(f)
            if h:
                hashes[f] = h
        with open(path, "w", encoding="utf-8") as f:
            json.dump(hashes, f, indent=4)

    def compare_with_baseline(self):
        """Vergleicht den aktuellen Server-Zustand mit der Baseline."""
        if not os.path.exists(self.baseline_path):
            self._log("Keine Baseline vorhanden. Bitte zuerst erzeugen.", "warn")
            return

        with open(self.baseline_path, "r") as f:
            baseline = json.load(f)

        self._progress("Suche Dateien für Vergleich...")
        self._log("Starte Hash-Vergleich mit Baseline...")
        current_files = self._get_remote_files_recursive()
        total = len(current_files)

        for i, f in enumerate(current_files):
            if self.worker and self.worker._is_cancelled:
                return

            # Check ignored list
            if any(ex in f for ex in self.excluded_list):
                continue

            if i % 500 == 0:
                self._progress(f"Prüfe Datei {i + 1} von {total}...")
            current_h, data = self.generate_hash(f)
            if not current_h:
                continue

            if f not in baseline:
                self._log(f"Unbekannte Datei gefunden: {f}", "warn")
                self._check_malware_indicators(data, f)
            elif baseline[f] != current_h:
                self._log(
                    f"Datei verändert: {f}\nErwartet: {baseline[f][:16]}...\nGefunden: {current_h[:16]}...",
                    "warn",
                )
                self._check_malware_indicators(data, f)
            # else:
            #     self.logger.info(f"Hash OK: {f}") # Deaktiviert für Performance bei >50k Dateien

        for f in baseline:
            if any(ex in f for ex in self.excluded_list):
                continue
            if f not in current_files:
                self._log(f"Datei fehlt: {f}", "error")

    def compare_with_update_hashes(self, update_version):
        """Prüft, ob Update-Dateien korrekt auf dem Server liegen."""
        path = os.path.join(self.hash_dir, f"update_{update_version}.json")
        if not os.path.exists(path):
            return

        with open(path, "r") as f:
            update_hashes = json.load(f)

        self._log(f"Prüfe Integrität von Update {update_version}...")
        for f, expected_h in update_hashes.items():
            if any(ex in f for ex in self.excluded_list):
                continue
            current_h, _ = self.generate_hash(f)
            if not current_h:
                self._log(f"Update-Datei fehlt: {f}", "error")
            elif current_h != expected_h:
                self._log(f"Update-Datei wurde nachträglich verändert: {f}", "error")
