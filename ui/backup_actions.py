"""
Backup-Aktionen und Download-Hilfsroutinen für die Benutzeroberfläche.

Ermöglicht das automatisierte Sichern von Remote-Dateien vor deren Löschung
über FTP und SFTP.
"""

import ftplib
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BackupActions:
    """
    Führt Vorab-Sicherungen von entfernten Dateien über bestehende Verbindungen aus.
    """

    @staticmethod
    def download_remote_file(
        conn: Any,
        remote_path: str,
        local_dest: Path,
    ) -> bool:
        """
        Lädt eine einzelne Remote-Datei (FTP oder SFTP) an den Zielpfad herunter.

        :param conn: Eine aktive ftplib.FTP- oder paramiko.SFTPClient-Verbindung.
        :param remote_path: Pfad auf dem Server.
        :param local_dest: Lokaler Zielpfad der Datei.
        :return: True bei Erfolg, False bei Fehler.
        """
        local_dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if isinstance(conn, ftplib.FTP):
                with open(local_dest, "wb") as f:
                    conn.retrbinary(f"RETR {remote_path}", f.write)
            else:
                # SFTP Client
                conn.get(remote_path, str(local_dest))
            return True
        except (OSError, ftplib.Error) as e:
            logger.error("Fehler beim Herunterladen von %s: %s", remote_path, e)
            return False
        except Exception as e:  # noqa: BLE001
            logger.error("Unerwarteter Fehler beim Herunterladen von %s: %s", remote_path, e)
            return False

    @classmethod
    def backup_remote_files(
        cls,
        conn: Any,
        remote_files: list[str],
        target_dir: Path,
        progress_callback: Callable[[str], None] | None = None,
    ) -> tuple[list[Path], list[str]]:
        """
        Sichert eine Liste entfernter Dateien in ein lokales Zielverzeichnis.

        :param conn: Aktive FTP- oder SFTP-Verbindung.
        :param remote_files: Liste relativer oder absoluter Remote-Pfade.
        :param target_dir: Lokales Basisverzeichnis für die Sicherung.
        :param progress_callback: Optionaler Callback zur Statusmeldung.
        :return: Tupel aus (erfolgreich gesicherte lokale Pfade, fehlgeschlagene Pfade).
        """
        resolved_target = target_dir.resolve()
        resolved_target.mkdir(parents=True, exist_ok=True)

        downloaded: list[Path] = []
        failed: list[str] = []
        total = len(remote_files)

        for i, file_path in enumerate(remote_files, 1):
            if progress_callback:
                progress_callback(f"Sichere ({i}/{total}): {file_path}")

            # Sicheren lokalen Pfad berechnen
            safe_rel_name = file_path.lstrip("/").replace("\\", "/")
            dest_file = (resolved_target / safe_rel_name).resolve()

            # Path Traversal Check
            if not str(dest_file).startswith(str(resolved_target)):
                logger.warning("Ungültiger Pfad übersprungen: %s", file_path)
                failed.append(file_path)
                continue

            success = cls.download_remote_file(conn, file_path, dest_file)
            if success:
                downloaded.append(dest_file)
            else:
                failed.append(file_path)

        return downloaded, failed
