"""
Backup-Manager für das Gambio Health-Check-Modul.

Verwaltet lokale Sicherungsarchive vor Bereinigungsaktionen mit
striktem Schutz gegen Path Traversal und Zip Slip.
"""

import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BackupManager:
    """
    Verwaltet Sicherungen und ZIP-Archive vor Bereinigungsaktionen.
    Alle Pfade werden strikt mittels Path.resolve() gegen Manipulationen abgesichert.
    """

    def __init__(self, backup_dir: str | None = None) -> None:
        if backup_dir:
            self._base_dir: Path = Path(backup_dir).resolve()
        else:
            self._base_dir = (Path.cwd() / "backups").resolve()

        self._ensure_directory()

    @property
    def base_dir(self) -> Path:
        """Gibt das aufgelöste Basis-Backupverzeichnis zurück."""
        return self._base_dir

    def _ensure_directory(self) -> None:
        """Stellt sicher, dass das Backup-Verzeichnis existiert."""
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def _validate_safe_path(self, target_path: Path) -> Path:
        """
        Validiert, dass ein Pfad innerhalb des base_dir liegt (Schutz gegen Path Traversal).
        """
        resolved = target_path.resolve()
        if not str(resolved).startswith(str(self._base_dir)):
            raise ValueError(f"Sicherheitsrisiko erkannt: Pfad liegt außerhalb des Backup-Verzeichnisses: {resolved}")
        return resolved

    def create_archive(
        self,
        files: list[Path],
        archive_name: str | None = None,
        base_source_dir: Path | None = None,
    ) -> Path:
        """
        Erstellt ein ZIP-Archiv aus den übergebenen Dateien.

        :param files: Liste von lokalen Dateipfaden.
        :param archive_name: Optionaler Dateiname für das Archiv.
        :param base_source_dir: Basisverzeichnis für relative Pfade im ZIP.
        :return: Pfad zum erstellten ZIP-Archiv.
        """
        self._ensure_directory()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name = archive_name or f"gambio_backup_{timestamp}.zip"
        if not name.endswith(".zip"):
            name = f"{name}.zip"

        archive_path = self._validate_safe_path(self._base_dir / name)

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for file_path in files:
                resolved_file = file_path.resolve()
                if not resolved_file.exists():
                    logger.warning("Zu sichernde Datei existiert nicht: %s", resolved_file)
                    continue

                if base_source_dir:
                    resolved_base = base_source_dir.resolve()
                    try:
                        arcname = str(resolved_file.relative_to(resolved_base))
                    except ValueError:
                        arcname = resolved_file.name
                else:
                    arcname = resolved_file.name

                zipf.write(resolved_file, arcname=arcname)

        logger.info("Backup-Archiv erfolgreich erstellt: %s", archive_path)
        return archive_path

    def list_backups(self) -> list[dict[str, Any]]:
        """
        Gibt eine Liste aller vorhandenen ZIP-Backups mit Metadaten zurück.
        """
        self._ensure_directory()
        backups: list[dict[str, Any]] = []

        for item in self._base_dir.glob("*.zip"):
            try:
                stat_info = item.stat()
                backups.append(
                    {
                        "filename": item.name,
                        "path": str(item),
                        "size_bytes": stat_info.st_size,
                        "size_mb": round(stat_info.st_size / (1024 * 1024), 2),
                        "created_at": datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc).isoformat(),
                    }
                )
            except OSError as e:
                logger.error("Fehler beim Abrufen der Dateiinfo für %s: %s", item, e)

        backups.sort(key=lambda b: b.get("created_at", ""), reverse=True)
        return backups

    def delete_backup(self, archive_name: str) -> bool:
        """
        Löscht ein Backup-Archiv sicher.

        :param archive_name: Name oder relativer Pfad der Backup-Datei.
        :return: True bei Erfolg, False wenn die Datei nicht existierte.
        """
        target = self._validate_safe_path(self._base_dir / archive_name)
        if target.exists() and target.is_file():
            target.unlink()
            logger.info("Backup-Archiv gelöscht: %s", target)
            return True
        return False

    def restore_archive(self, archive_name: str, target_dir: Path) -> list[str]:
        """
        Stellt ein Backup-Archiv mit Zip-Slip-Schutz in einem Zielverzeichnis wieder her.

        :param archive_name: Name der ZIP-Datei im Backup-Verzeichnis.
        :param target_dir: Zielverzeichnis für die Entpackung.
        :return: Liste der extrahierten Dateipfade.
        """
        archive_path = self._validate_safe_path(self._base_dir / archive_name)
        resolved_target = target_dir.resolve()
        resolved_target.mkdir(parents=True, exist_ok=True)

        extracted_files: list[str] = []
        with zipfile.ZipFile(archive_path, "r") as zipf:
            for member in zipf.infolist():
                # Schutz gegen Zip Slip
                member_target = (resolved_target / member.filename).resolve()
                if not str(member_target).startswith(str(resolved_target)):
                    raise ValueError(f"Zip Slip Versuch erkannt: {member.filename}")

                zipf.extract(member, resolved_target)
                extracted_files.append(str(member_target))

        logger.info("Archiv %s erfolgreich nach %s extrahiert.", archive_name, resolved_target)
        return extracted_files
